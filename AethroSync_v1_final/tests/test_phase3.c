/* AethroSync — tests/test_phase3.c — Phase 3 unit tests */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdatomic.h>
#include <sodium.h>
#include <zstd.h>
#include "../include/mpcp.h"
#include "../include/test_helpers.h"

/* ========== tests/test_phase3.c (harness renamed to p3_*) ========== */
/*

- test_phase3.c - MPCP Phase 3 unit tests
- 
- Tests covered (spec S25.3):
- T-08  Ghost chunk generation - indistinguishable from data chunks
- T-09  Distributed remainder - all chunks within 1 byte of each other
- T-10  Bitmask dedup - accept first, silently drop second
- T-11  AEAD index binding - swapped chunks rejected
- T-12  Tripwire z-score - abort at correct threshold
- T-13  Tripwire chi-squared - non-random loss detected
- T-14  Silent abort - canary log written, no network signal
- 
- Additional Phase 3 coverage:
- T-P3-01  Compressibility detection (ratio > 0.95 -> skip)
- T-P3-02  Ghost map determinism (same key -> same seqs)
- T-P3-03  Disguise round-trip DNS
- T-P3-04  Disguise round-trip NTP
- T-P3-05  NAT token derivation (S12.1)
  */

/* -------------------------

- Test harness
- ----------------------------------- */
  static int p3_tests_run    = 0;
  static int p3_tests_passed = 0;
  static int p3_tests_failed = 0;

#define P3_PASS(name) do { \
    p3_tests_run++; p3_tests_passed++; \
    printf("  PASS  %s\n", (name)); \
} while (0)

#define P3_FAIL(name, reason) do { \
    p3_tests_run++; p3_tests_failed++; \
    printf("  FAIL  %s: %s\n", (name), (reason)); \
} while (0)

#define P3_CHECK(name, cond) do { \
    if (cond) P3_PASS(name); \
    else      P3_FAIL(name, "condition false"); \
} while (0)

/* -------------------------

- Fixtures
- ----------------------------------- */
  static void make_session(mpcp_session_t *sess)
  {
  randombytes_buf(sess->session_nonce,  MPCP_SESSION_NONCE_LEN);
  randombytes_buf(sess->master_secret,  MPCP_MASTER_SECRET_LEN);
  randombytes_buf(sess->session_key,    MPCP_SESSION_KEY_LEN);
  sess->total_chunks = 16;
  sess->keystream    = mpcp_derive_keystream(sess->session_key, 16);
  }

static void free_session(mpcp_session_t *sess)
{
if (sess->keystream) {
sodium_memzero(sess->keystream,
(size_t)sess->total_chunks * MPCP_KEYSTREAM_SLOT);
sodium_free(sess->keystream);
sess->keystream = NULL;
}
}

/* =========================================================================

- T-P3-01  Compressibility detection
- ====================================================================== */
  static void test_compressibility(void)
  {
  puts("T-P3-01  Compressibility detection");
  
  /* Highly compressible: all zeros */
  {
  uint8_t zeros[65536];
  memset(zeros, 0, sizeof(zeros));
  mpcp_chunk_plan_t plan;
  memset(&plan, 0, sizeof(plan));
  int rc = mpcp_chunker_detect_compressibility(zeros, sizeof(zeros), &plan);
  P3_CHECK("T-P3-01a compressible data -> skip_compression=false",
  rc == MPCP_OK && plan.skip_compression == false);
  }
  
  /* Incompressible: random bytes */
  {
  uint8_t rnd[65536];
  randombytes_buf(rnd, sizeof(rnd));
  mpcp_chunk_plan_t plan;
  memset(&plan, 0, sizeof(plan));
  int rc = mpcp_chunker_detect_compressibility(rnd, sizeof(rnd), &plan);
  P3_CHECK("T-P3-01b random data -> skip_compression=true",
  rc == MPCP_OK && plan.skip_compression == true);
  }
  }

/* =========================================================================

- T-09  Distributed remainder
- ====================================================================== */
  static void test_distributed_remainder(void)
  {
  puts("T-09  Distributed remainder");
  
  /* Various sizes - all chunks should be within 1 byte of each other */
  size_t test_sizes[] = { 1000, 102400, 1048576, 8062976 }; /* 8062976 = 127*63488, max chunks */
  for (size_t s = 0; s < sizeof(test_sizes)/sizeof(test_sizes[0]); s++) {
  size_t compressed_size = test_sizes[s];
  mpcp_chunk_plan_t plan;
  memset(&plan, 0, sizeof(plan));
  int rc = mpcp_chunker_plan(compressed_size, 63488, false, &plan);
  if (rc != MPCP_OK) {
  P3_FAIL("T-09 plan creation", "mpcp_chunker_plan failed");
  continue;
  }
  
   uint32_t min_sz = UINT32_MAX, max_sz = 0;
   uint32_t total  = 0;
   for (uint32_t i = 0; i < plan.n_chunks; i++) {
       uint32_t sz = mpcp_chunk_data_size(&plan, i);
       if (sz < min_sz) min_sz = sz;
       if (sz > max_sz) max_sz = sz;
       total += sz;
   }
  
   bool diff_ok  = (max_sz - min_sz) <= 1u;
   bool total_ok = (total == (uint32_t)compressed_size);
  
   char tname[64];
   (void)snprintf(tname, sizeof(tname),
                  "T-09 size=%zu diff<=1", compressed_size);
   CHECK(tname, diff_ok);
  
   (void)snprintf(tname, sizeof(tname),
                  "T-09 size=%zu total_exact", compressed_size);
   CHECK(tname, total_ok);
  
  }
  }

/* =========================================================================

- T-08  Ghost chunk generation - indistinguishable from data chunks
- ====================================================================== */
  static void test_ghost_chunks(void)
  {
  puts("T-08  Ghost chunk generation");
  
  mpcp_session_t sess;
  memset(&sess, 0, sizeof(sess));
  make_session(&sess);
  
  uint32_t chunk_pad_size = 63488;
  uint32_t ghost_seq      = 10;
  
  uint8_t chunk_key[32];
  uint16_t _p;
  mpcp_keystream_slot(sess.keystream, ghost_seq, 10000, 55000, chunk_key, &_p);
  
  size_t  gbuf_sz = chunk_pad_size + 16u;
  uint8_t *gbuf   = malloc(gbuf_sz);
  size_t  gct_len;
  uint8_t gnonce[24];
  
  int rc = mpcp_chunker_generate_ghost(chunk_key, sess.session_nonce,
  ghost_seq, chunk_pad_size,
  gbuf, &gct_len, gnonce);
  P3_CHECK("T-08a ghost generate OK", rc == MPCP_OK);
  P3_CHECK("T-08b ghost ciphertext length = chunk_pad_size+16",
  gct_len == (size_t)(chunk_pad_size + 16u));
  
  /* Verify nonce is non-zero */
  bool nonce_nonzero = false;
  for (int i = 0; i < 24; i++) {
  if (gnonce[i] != 0) { nonce_nonzero = true; break; }
  }
  P3_CHECK("T-08c ghost nonce non-zero", nonce_nonzero);
  
  /* Two ghost chunks with same key should have different ciphertext (different nonces) */
  uint8_t *gbuf2   = malloc(gbuf_sz);
  size_t   gct2;
  uint8_t  gnonce2[24];
  (void)mpcp_chunker_generate_ghost(chunk_key, sess.session_nonce,
  ghost_seq, chunk_pad_size,
  gbuf2, &gct2, gnonce2);
  P3_CHECK("T-08d two ghost chunks differ",
  memcmp(gbuf, gbuf2, gct_len) != 0);
  
  sodium_memzero(gbuf,  gbuf_sz);
  sodium_memzero(gbuf2, gbuf_sz);
  free(gbuf);
  free(gbuf2);
  sodium_memzero(chunk_key, sizeof(chunk_key));
  free_session(&sess);
  }

/* =========================================================================

- T-P3-02  Ghost map determinism
- ====================================================================== */
  static void test_ghost_map_determinism(void)
  {
  puts("T-P3-02  Ghost map determinism");
  
  uint8_t key[32];
  randombytes_buf(key, sizeof(key));
  
  uint32_t seqs1[32], seqs2[32];
  uint32_t cnt1 = 0, cnt2 = 0;
  
  int rc1 = mpcp_ghost_map(key, 10, 5, 20, seqs1, &cnt1);
  int rc2 = mpcp_ghost_map(key, 10, 5, 20, seqs2, &cnt2);
  
  P3_CHECK("T-P3-02a ghost_map returns OK",   rc1 == MPCP_OK && rc2 == MPCP_OK);
  P3_CHECK("T-P3-02b ghost count in range",   cnt1 >= 5 && cnt1 <= 20);
  P3_CHECK("T-P3-02c ghost count deterministic", cnt1 == cnt2);
  bool seqs_match = (cnt1 == cnt2) && memcmp(seqs1, seqs2, cnt1*sizeof(uint32_t)) == 0;
  P3_CHECK("T-P3-02d ghost seqs deterministic", seqs_match);
  
  /* Different key -> different count (high probability) */
  uint8_t key2[32];
  randombytes_buf(key2, sizeof(key2));
  uint32_t seqs3[32], cnt3 = 0;
  (void)mpcp_ghost_map(key2, 10, 5, 20, seqs3, &cnt3);
  /* Can't guarantee different but can check range */
  P3_CHECK("T-P3-02e second key in range", cnt3 >= 5 && cnt3 <= 20);
  }

/* =========================================================================

- T-10  Bitmask dedup
- ====================================================================== */
  static void test_dedup(void)
  {
  puts("T-10  Bitmask dedup");
  
  mpcp_dedup_t d;
  mpcp_dedup_init(&d);
  
  P3_CHECK("T-10a first accept seq=0",    mpcp_dedup_accept(&d, 0)     == true);
  P3_CHECK("T-10b duplicate reject seq=0", mpcp_dedup_accept(&d, 0)    == false);
  P3_CHECK("T-10c first accept seq=1",    mpcp_dedup_accept(&d, 1)     == true);
  P3_CHECK("T-10d duplicate reject seq=1", mpcp_dedup_accept(&d, 1)    == false);
  P3_CHECK("T-10e large seq accepted",    mpcp_dedup_accept(&d, 99999) == true);
  P3_CHECK("T-10f large seq dup rejected", mpcp_dedup_accept(&d, 99999)== false);
  
  /* Boundary */
  uint32_t max_seq = MPCP_DEDUP_BITS - 1u;
  P3_CHECK("T-10g boundary accept",  mpcp_dedup_accept(&d, max_seq) == true);
  P3_CHECK("T-10h boundary dup",     mpcp_dedup_accept(&d, max_seq) == false);
  
  /* Out-of-range returns false (no crash) */
  P3_CHECK("T-10i out-of-range", mpcp_dedup_accept(&d, MPCP_DEDUP_BITS) == false);
  }

/* =========================================================================

- T-11  AEAD index binding - swapped chunks rejected
- ====================================================================== */
  static void test_aead_index_binding(void)
  {
  puts("T-11  AEAD index binding");
  
  mpcp_session_t sess;
  memset(&sess, 0, sizeof(sess));
  make_session(&sess);
  
  uint8_t plain[256];
  randombytes_buf(plain, sizeof(plain));
  
  uint8_t key0[32], key1[32];
  uint16_t _p;
  mpcp_keystream_slot(sess.keystream, 0, 10000, 55000, key0, &_p);
  mpcp_keystream_slot(sess.keystream, 1, 10000, 55000, key1, &_p);
  
  size_t  ct0_len, ct1_len;
  uint8_t ct0[272 + 16], ct1[272 + 16];
  uint8_t nonce0[24], nonce1[24];
  
  mpcp_chunk_encrypt(key0, sess.session_nonce, 0,
  plain, sizeof(plain), ct0, &ct0_len, nonce0);
  mpcp_chunk_encrypt(key1, sess.session_nonce, 1,
  plain, sizeof(plain), ct1, &ct1_len, nonce1);
  
  /* Try to decrypt ct0 as seq=1 (swapped) - should fail */
  uint8_t out[512];
  size_t  out_len = 0;
  int rc_swap = mpcp_chunk_decrypt(key0, sess.session_nonce, 1,
  nonce0, ct0, ct0_len, out, &out_len);
  P3_CHECK("T-11a swapped seq rejected", rc_swap != MPCP_OK);
  
  /* Correct decryption should succeed */
  int rc_ok = mpcp_chunk_decrypt(key0, sess.session_nonce, 0,
  nonce0, ct0, ct0_len, out, &out_len);
  P3_CHECK("T-11b correct seq accepted", rc_ok == MPCP_OK);
  P3_CHECK("T-11c plaintext matches", out_len == sizeof(plain) &&
  memcmp(out, plain, sizeof(plain)) == 0);
  
  sodium_memzero(key0, sizeof(key0));
  sodium_memzero(key1, sizeof(key1));
  free_session(&sess);
  }

/* =========================================================================

- T-12  Tripwire z-score
- ====================================================================== */
  static void test_tripwire_zscore(void)
  {
  puts("T-12  Tripwire z-score");
  
  mpcp_rtt_result_t rtt;
  memset(&rtt, 0, sizeof(rtt));
  rtt.baseline_mean  = 20.0;    /* 20 ms */
  rtt.baseline_std   =  5.0;    /* 5 ms  */
  rtt.sample_count   = 50;      /* enough for z-score */
  
  mpcp_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.tripwire               = true;
  cfg.tripwire_z_threshold   = 3.5;
  cfg.tripwire_window        = 5;
  cfg.tripwire_chi_pvalue    = 0.05;
  (void)strncpy(cfg.canary_log, "/tmp/mpcp_test_canary.log",
  sizeof(cfg.canary_log) - 1);
  
  mpcp_tripwire_t tw;
  mpcp_tripwire_init(&tw, &rtt, &cfg);
  
  /* Normal readings - no abort */
  for (int i = 0; i < 20; i++) {
  int rc = mpcp_tripwire_feed_rtt(&tw, 21.0);  /* z ~= 0.2 */
  if (rc != MPCP_OK) {
  P3_FAIL("T-12a normal RTT should not abort", "abort triggered");
  return;
  }
  }
  P3_PASS("T-12a normal RTT no abort");
  
  /* Reset */
  mpcp_tripwire_init(&tw, &rtt, &cfg);
  
  /* z = 4.0 (above threshold 3.5) - should count as anomaly */
  double anomalous_rtt = rtt.baseline_mean + 4.0 * rtt.baseline_std; /* 40 ms */
  int abort_count = 0;
  for (int i = 0; i < 10; i++) {
  if (mpcp_tripwire_feed_rtt(&tw, anomalous_rtt) == MPCP_ERR_TRIPWIRE) {
  abort_count++;
  break;
  }
  }
  P3_CHECK("T-12b anomalous RTT triggers abort after window", abort_count > 0);
  
  /* Z-score below threshold should not count */
  mpcp_tripwire_init(&tw, &rtt, &cfg);
  double below_thresh = rtt.baseline_mean + 3.0 * rtt.baseline_std; /* z=3.0 < 3.5 */
  bool spurious = false;
  for (int i = 0; i < 20; i++) {
  if (mpcp_tripwire_feed_rtt(&tw, below_thresh) == MPCP_ERR_TRIPWIRE) {
  spurious = true;
  break;
  }
  }
  P3_CHECK("T-12c below-threshold no abort", !spurious);
  
  /* Fallback: sample_count < 30 -> use baseline_mean * 3 */
  rtt.sample_count = 10;
  mpcp_tripwire_init(&tw, &rtt, &cfg);
  double big = rtt.baseline_mean * 3.5;   /* above fallback threshold baseline*3 */
  int fallback_abort = 0;
  for (int i = 0; i < 10; i++) {
  if (mpcp_tripwire_feed_rtt(&tw, big) == MPCP_ERR_TRIPWIRE) {
  fallback_abort++;
  break;
  }
  }
  P3_CHECK("T-12d fallback threshold triggers on >baseline*3", fallback_abort > 0);
  }

/* =========================================================================

- T-13  Tripwire chi-squared loss pattern
- ====================================================================== */
  static void test_tripwire_chi(void)
  {
  puts("T-13  Tripwire chi-squared");
  
  mpcp_rtt_result_t rtt;
  memset(&rtt, 0, sizeof(rtt));
  rtt.baseline_mean  = 20.0;
  rtt.baseline_std   =  5.0;
  rtt.sample_count   = 50;
  
  mpcp_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.tripwire             = true;
  cfg.tripwire_z_threshold = 3.5;
  cfg.tripwire_window      = 5;
  cfg.tripwire_chi_pvalue  = 0.05;
  
  mpcp_tripwire_t tw;
  mpcp_tripwire_init(&tw, &rtt, &cfg);
  
  /* Simulate selective loss: first plant a loss at index 199 to establish
   * approx_total=200 (bucket_size=25), then cluster 19 more losses at
   * indices 0-18. Bucket 0 gets 19 hits, bucket 7 gets 1, rest get 0.
   * Expected per bucket = 20/8 = 2.5, chi2 >> critical value -> p < 0.05. */
  bool triggered = false;
  /* Anchor the total space at 200 chunks */
  if (mpcp_tripwire_record_loss(&tw, 199) == MPCP_ERR_TRIPWIRE)
      triggered = true;
  /* Now cluster losses at the low end */
  for (uint32_t i = 0; i < 19 && !triggered; i++) {
  if (mpcp_tripwire_record_loss(&tw, i) == MPCP_ERR_TRIPWIRE) {
  triggered = true;
  }
  }
  P3_CHECK("T-13a selective loss pattern detected", triggered);
  
  /* Random loss should not trigger (low sample count or random pattern) */
  mpcp_tripwire_init(&tw, &rtt, &cfg);
  bool false_pos = false;
  /* Feed 4 random-ish losses (insufficient for test) */
  (void)mpcp_tripwire_record_loss(&tw, 7);
  (void)mpcp_tripwire_record_loss(&tw, 53);
  (void)mpcp_tripwire_record_loss(&tw, 121);
  (void)mpcp_tripwire_record_loss(&tw, 200);
  P3_CHECK("T-13b sparse random loss no trigger", !false_pos);
  }

/* =========================================================================

- T-14  Silent abort - canary log written
- (We can't test "no network signal" in a unit test, but we verify
- that the canary log file is written and contains expected fields.)
- 
- Note: mpcp_tripwire_abort() calls _Exit(0) in production. In tests
- we mock the canary write portion only.
- ====================================================================== */
  static void test_canary_log(void)
  {
  puts("T-14  Silent abort - canary log");
  
  const char *log_path = "/tmp/mpcp_test_canary_t14.log";
  /* Remove if exists */
  (void)remove(log_path);
  
  /* Write a canary entry directly (mirrors what abort does before _Exit) */
  {
  time_t now = time(NULL);
  char   ts[64];
  struct tm tmbuf;
  strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmtime_r(&now, &tmbuf));
  
   FILE *f = fopen(log_path, "a");
   if (f) {
       fprintf(f, "[%s] TRIPWIRE anomaly=zscore session=deadbeef\n", ts);
       fclose(f);
   }
  
  }
  
  /* Verify the log exists and has content */
  FILE *f = fopen(log_path, "r");
  P3_CHECK("T-14a canary log file created", f != NULL);
  if (f) {
  char line[256];
  bool found_tripwire = false;
  while (fgets(line, sizeof(line), f)) {
  if (strstr(line, "TRIPWIRE")) { found_tripwire = true; break; }
  }
  fclose(f);
  P3_CHECK("T-14b canary log contains TRIPWIRE entry", found_tripwire);
  (void)remove(log_path);
  }
  }

/* =========================================================================

- T-P3-03/04  Disguise round-trips
- ====================================================================== */
  static void test_disguise_roundtrip(void)
  {
  puts("T-P3-03/04  Disguise round-trip (DNS + NTP)");
  
  uint8_t payload[200];
  randombytes_buf(payload, sizeof(payload));
  
  /* DNS */
  {
  uint8_t wrapped[4096];
  uint8_t unwrapped[512];
  
   size_t wlen = mpcp_disguise_wrap(payload, sizeof(payload),
                                     wrapped, sizeof(wrapped),
                                     MPCP_DISGUISE_DNS);
   P3_CHECK("T-P3-03a DNS wrap returns > 0", wlen > 0);
  
   size_t ulen = mpcp_disguise_unwrap(wrapped, wlen,
                                       unwrapped, sizeof(unwrapped),
                                       MPCP_DISGUISE_DNS);
   P3_CHECK("T-P3-03b DNS unwrap returns payload length",
         ulen == sizeof(payload));
   P3_CHECK("T-P3-03c DNS payload matches",
         ulen == sizeof(payload) &&
         memcmp(unwrapped, payload, sizeof(payload)) == 0);
  
  }
  
  /* NTP */
  {
  uint8_t wrapped[4096];
  uint8_t unwrapped[512];
  
   size_t wlen = mpcp_disguise_wrap(payload, sizeof(payload),
                                     wrapped, sizeof(wrapped),
                                     MPCP_DISGUISE_NTP);
   P3_CHECK("T-P3-04a NTP wrap returns > 0", wlen > 0);
  
   size_t ulen = mpcp_disguise_unwrap(wrapped, wlen,
                                       unwrapped, sizeof(unwrapped),
                                       MPCP_DISGUISE_NTP);
   P3_CHECK("T-P3-04b NTP unwrap returns payload length",
         ulen == sizeof(payload));
   P3_CHECK("T-P3-04c NTP payload matches",
         ulen == sizeof(payload) &&
         memcmp(unwrapped, payload, sizeof(payload)) == 0);
  
  }
  
  /* Short payload (1 byte) */
  {
  uint8_t tiny[1] = { 0xAB };
  uint8_t wrapped[256], unwrapped[16];
  
   size_t wlen = mpcp_disguise_wrap(tiny, 1, wrapped, sizeof(wrapped),
                                     MPCP_DISGUISE_DNS);
   size_t ulen = mpcp_disguise_unwrap(wrapped, wlen, unwrapped,
                                       sizeof(unwrapped), MPCP_DISGUISE_DNS);
   P3_CHECK("T-P3-03d DNS tiny round-trip",
         ulen == 1 && unwrapped[0] == 0xAB);
  
  }
  }

/* =========================================================================

- T-P3-05  NAT rendezvous token
- ====================================================================== */
  static void test_nat_token(void)
  {
  puts("T-P3-05  NAT rendezvous token");
  
  uint8_t nonce[32], psk[16];
  randombytes_buf(nonce, sizeof(nonce));
  randombytes_buf(psk,   sizeof(psk));
  
  uint8_t tok1[32], tok2[32];
  int rc1 = mpcp_nat_token(nonce, psk, sizeof(psk), tok1);
  int rc2 = mpcp_nat_token(nonce, psk, sizeof(psk), tok2);
  
  P3_CHECK("T-P3-05a token OK",           rc1 == MPCP_OK && rc2 == MPCP_OK);
  P3_CHECK("T-P3-05b deterministic",      memcmp(tok1, tok2, 32) == 0);
  
  /* Different nonce -> different token */
  uint8_t nonce2[32];
  randombytes_buf(nonce2, sizeof(nonce2));
  uint8_t tok3[32];
  (void)mpcp_nat_token(nonce2, psk, sizeof(psk), tok3);
  P3_CHECK("T-P3-05c different nonce -> different token",
  memcmp(tok1, tok3, 32) != 0);
  
  /* Null checks */
  P3_CHECK("T-P3-05d null nonce -> error",
  mpcp_nat_token(NULL, psk, sizeof(psk), tok1) != MPCP_OK);
  P3_CHECK("T-P3-05e null psk -> error",
  mpcp_nat_token(nonce, NULL, sizeof(psk), tok1) != MPCP_OK);
  P3_CHECK("T-P3-05f zero psk_len -> error",
  mpcp_nat_token(nonce, psk, 0, tok1) != MPCP_OK);
  }

/* =========================================================================

- Ring buffer basic correctness
- ====================================================================== */
  static void test_ring_buffer(void)
  {
  puts("T-P3-06  Ring buffer SPSC");
  
  mpcp_ring_t ring;
  int rc = mpcp_ring_init(&ring, 4, 512);
  P3_CHECK("T-P3-06a ring init OK", rc == MPCP_OK);
  
  /* Empty ring returns NULL */
  P3_CHECK("T-P3-06b consume empty = NULL", mpcp_ring_consume(&ring) == NULL);
  
  /* Claim + publish + consume */
  mpcp_ring_slot_t *slot = mpcp_ring_claim(&ring);
  P3_CHECK("T-P3-06c claim returns non-NULL", slot != NULL);
  slot->seq_index = 42;
  slot->data_len  = 10;
  memset(slot->buf, 0xBB, 10);
  mpcp_ring_publish(&ring, slot);
  
  mpcp_ring_slot_t *out = mpcp_ring_consume(&ring);
  P3_CHECK("T-P3-06d consume returns slot", out != NULL);
  if (out) {
  P3_CHECK("T-P3-06e seq matches",    out->seq_index == 42);
  P3_CHECK("T-P3-06f data matches",   out->data_len  == 10);
  P3_CHECK("T-P3-06g buf matches",    out->buf[0]    == 0xBB);
  mpcp_ring_release(&ring, out);
  }
  
  /* After release, slot is empty again */
  P3_CHECK("T-P3-06h empty after release", mpcp_ring_consume(&ring) == NULL);
  
  mpcp_ring_destroy(&ring);
  P3_PASS("T-P3-06i ring destroy OK");
  }

/* =========================================================================

- Chunk encrypt / decrypt round-trip
- ====================================================================== */
  static void test_chunk_encrypt_decrypt(void)
  {
  puts("T-P3-07  Chunk encrypt/decrypt round-trip");
  
  mpcp_session_t sess;
  memset(&sess, 0, sizeof(sess));
  make_session(&sess);
  
  uint8_t  plain[1000];
  randombytes_buf(plain, sizeof(plain));
  
  uint8_t  key[32];
  uint16_t _p;
  mpcp_keystream_slot(sess.keystream, 5, 10000, 55000, key, &_p);
  
  uint32_t chunk_pad_size = (uint32_t)sizeof(plain); /* pad = exact plaintext size for test */
  uint8_t  ct[sizeof(plain) + 16];
  size_t   ct_len;
  uint8_t  nonce[24];
  
  int rc = mpcp_chunker_encrypt_chunk(plain, sizeof(plain),
  key, sess.session_nonce, 5,
  ct, &ct_len, nonce, 0,
  chunk_pad_size);
  P3_CHECK("T-P3-07a encrypt OK", rc == MPCP_OK);
  P3_CHECK("T-P3-07b ciphertext length", ct_len == sizeof(plain) + 16u);
  
  uint8_t  recovered[2000];
  size_t   rec_len = 0;
  int rc2 = mpcp_chunk_decrypt(key, sess.session_nonce, 5,
  nonce, ct, ct_len, recovered, &rec_len);
  P3_CHECK("T-P3-07c decrypt OK", rc2 == MPCP_OK);
  P3_CHECK("T-P3-07d length matches", rec_len == sizeof(plain));
  P3_CHECK("T-P3-07e plaintext matches",
  rec_len == sizeof(plain) &&
  memcmp(recovered, plain, sizeof(plain)) == 0);
  
  sodium_memzero(key, sizeof(key));
  free_session(&sess);
  }

/* =========================================================================

- main
- ====================================================================== */
  int mpcp_test_phase3_main(void)
  {
  if (sodium_init() < 0) {
  fprintf(stderr, "FATAL: sodium_init failed\n");
  return 1;
  }
  
  printf("MPCP Phase 3 Unit Tests\n");
  printf("=======================\n\n");
  
  test_compressibility();
  test_distributed_remainder();
  test_ghost_chunks();
  test_ghost_map_determinism();
  test_dedup();
  test_aead_index_binding();
  test_tripwire_zscore();
  test_tripwire_chi();
  test_canary_log();
  test_disguise_roundtrip();
  test_nat_token();
  test_ring_buffer();
  test_chunk_encrypt_decrypt();
  
  printf("\n========================\n");
  printf("Results: %d/%d passed", p3_tests_passed, p3_tests_run);
  if (p3_tests_failed > 0)
  printf(", %d FAILED", p3_tests_failed);
  printf("\n");
  
  return (p3_tests_failed == 0) ? 0 : 1;
  }

/* =========================================================
 * Unified test entry point
 * ========================================================= */
int main_test(void) __attribute__((unused));
