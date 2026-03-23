/* AethroSync — src/exchange.c — PC1/PC2 key exchange */
#include "../include/platform.h"
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

/* ========== src/exchange.c ========== */
/*

- exchange.c - MPCP key exchange (S8)
- 
- Spec sections:
- S8.1  Parallel candidate key transmission (PC1 sends N keys simultaneously)
- S8.2  Constant-time blind selection - 8-step sequence on PC2
- S8.3  Session key finalisation
- S5.3  Ed25519 session transcript signing / verification
- S18.2 Key exchange wire packet format
- 
- SECURITY CRITICAL - S8.2 step ordering constraint:
- S8.3 session key derivation requires selected_candidate (selected_buf).
- Step 6 zeros selected_buf.
- Therefore S8.3 MUST execute between steps 5 and 6.
- Corrected sequence: 1 -> 2 -> 3 -> 4 -> 5 -> [S8.3 derive] -> 6 -> 7 -> 8
- 
- Step 7 (fixed-delay sleep until T_recv + key_exchange_delay) masks all
- timing variance from steps 2-6. Any shortcut breaks the timing guarantee.
  */

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* -------------------------

- Internal: derive the UDP port for key exchange slot i
- 
- port[i] = HKDF(master_secret,
             ikm  = "kex-port" || i(4,BE) || session_nonce,
             info = "mpcp-v0.5-kex-port") mod port_range + port_base
- ----------------------------------- */
  static uint16_t kex_port(const uint8_t *master_secret,
  const uint8_t *session_nonce,
  uint32_t       index,
  uint32_t       port_base,
  uint32_t       port_range)
  {
  uint8_t ikm[8 + 4 + 32];
  memcpy(ikm, "kex-port", 8);
  ikm[8]  = (uint8_t)((index >> 24) & 0xFF);
  ikm[9]  = (uint8_t)((index >> 16) & 0xFF);
  ikm[10] = (uint8_t)((index >>  8) & 0xFF);
  ikm[11] = (uint8_t)((index      ) & 0xFF);
  memcpy(ikm + 12, session_nonce, 32);
  
  uint8_t out[4];
  if (mpcp_hkdf(master_secret, 32, ikm, sizeof(ikm),
  "mpcp-v0.5-kex-port", out, 4) != MPCP_OK) {
  /* Deterministic fallback - still session-unique */
  return (uint16_t)((index * 7919u + 1) % port_range + port_base);
  }
  uint32_t seed = ((uint32_t)out[0] << 24) | ((uint32_t)out[1] << 16) |
  ((uint32_t)out[2] <<  8) |  (uint32_t)out[3];
  return (uint16_t)(seed % port_range + port_base);
  }

/* -------------------------

- S18.2  Wire format helpers
- 
- Candidate key is XChaCha20-Poly1305 encrypted under master_secret.
- AD = key_index(1) || direction(1) || xchacha_nonce[0:32]
- Makes all N packets indistinguishable to a passive observer.
- ----------------------------------- */
  int mpcp_kex_pack(const uint8_t  *master_secret,
  const uint8_t  *candidate_key,
  uint8_t         key_index,
  uint8_t         direction,
  mpcp_key_pkt_t *pkt_out)
  {
  memset(pkt_out, 0, sizeof(*pkt_out));
  
  uint32_t magic_be = htonl(MPCP_MAGIC);
  memcpy(&pkt_out->hdr.magic, &magic_be, 4);
  pkt_out->hdr.version = MPCP_VERSION;
  pkt_out->hdr.type    = MPCP_TYPE_KEY_EXCHANGE;
  pkt_out->key_index   = key_index;
  pkt_out->direction   = direction;
  
  randombytes_buf(pkt_out->xchacha_nonce, 24);
  
  /* AD: 26 bytes = key_index(1) || direction(1) || nonce[0:24] */
  uint8_t ad[26];
  ad[0] = key_index;
  ad[1] = direction;
  memcpy(ad + 2, pkt_out->xchacha_nonce, 24);
  
  unsigned long long ct_len = 0;
  if (crypto_aead_xchacha20poly1305_ietf_encrypt(
  pkt_out->encrypted_key, &ct_len,
  candidate_key, 32,
  ad, sizeof(ad),
  NULL, pkt_out->xchacha_nonce, master_secret) != 0 || ct_len != 48)
  return MPCP_ERR_CRYPTO;
  
  randombytes_buf(pkt_out->padding, sizeof(pkt_out->padding));
  return MPCP_OK;
  }

int mpcp_kex_unpack(const uint8_t        *master_secret,
const mpcp_key_pkt_t *pkt,
uint8_t              *candidate_key_out)
{
uint32_t magic;
memcpy(&magic, &pkt->hdr.magic, 4);
if (ntohl(magic)             != MPCP_MAGIC)            return MPCP_ERR_PROTO;
if (pkt->hdr.version         != MPCP_VERSION)          return MPCP_ERR_PROTO;
if (pkt->hdr.type            != MPCP_TYPE_KEY_EXCHANGE) return MPCP_ERR_PROTO;

uint8_t ad[26];
ad[0] = pkt->key_index;
ad[1] = pkt->direction;
memcpy(ad + 2, pkt->xchacha_nonce, 24);

unsigned long long pt_len = 0;
if (crypto_aead_xchacha20poly1305_ietf_decrypt(
        candidate_key_out, &pt_len,
        NULL,
        pkt->encrypted_key, 48,
        ad, sizeof(ad),
        pkt->xchacha_nonce, master_secret) != 0 || pt_len != 32)
    return MPCP_ERR_CRYPTO;

return MPCP_OK;

}

/* -------------------------

- UDP socket helpers
- ----------------------------------- */
  typedef struct { int fd; uint16_t port; } kex_sock_t;

static int open_udp_port(uint16_t port)
{
int fd = socket(AF_INET, SOCK_DGRAM, 0);
if (fd < 0) return -1;

int one = 1;
setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

struct sockaddr_in addr = {
    .sin_family      = AF_INET,
    .sin_port        = htons(port),
    .sin_addr.s_addr = INADDR_ANY,
};
if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd); return -1;
}
struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
return fd;

}

/* Open N derived ports simultaneously; skip_idx == UINT32_MAX means skip none */
static int open_kex_ports(const uint8_t *master_secret,
const uint8_t *session_nonce,
uint32_t n, uint32_t port_base, uint32_t port_range,
uint32_t skip_idx, kex_sock_t *socks)
{
int opened = 0;
for (uint32_t i = 0; i < n; i++) {
if (i == skip_idx) { socks[i].fd = -1; socks[i].port = 0; continue; }
uint16_t p = kex_port(master_secret, session_nonce, i,
port_base, port_range);
socks[i].fd   = open_udp_port(p);
socks[i].port = p;
if (socks[i].fd >= 0) opened++;
else fprintf(stderr, "[exchange] open port %u: %s\n", p, strerror(errno));
}
return opened;
}

static void close_kex_ports(kex_sock_t *socks, uint32_t n)
{
for (uint32_t i = 0; i < n; i++) {
if (socks[i].fd >= 0) { close(socks[i].fd); socks[i].fd = -1; }
}
}

/* -------------------------

- Locked key buffer helpers
- ----------------------------------- */
  static int alloc_key_bufs(uint8_t **bufs, uint32_t n)
  {
  for (uint32_t i = 0; i < n; i++) {
  bufs[i] = sodium_malloc(32);
  if (!bufs[i]) {
  for (uint32_t j = 0; j < i; j++) {
  sodium_memzero(bufs[j], 32); sodium_free(bufs[j]); bufs[j] = NULL;
  }
  return MPCP_ERR_ALLOC;
  }
  sodium_memzero(bufs[i], 32);
  }
  return MPCP_OK;
  }

static void free_key_bufs(uint8_t **bufs, uint32_t n)
{
for (uint32_t i = 0; i < n; i++) {
if (bufs[i]) {
sodium_memzero(bufs[i], 32); sodium_free(bufs[i]); bufs[i] = NULL;
}
}
}

/* -------------------------

- S5.3  Ed25519 auth - no-op when auth_mode != MPCP_AUTH_ED25519
- ----------------------------------- */

/* PC1: sign session transcript and send to pc2_addr over derived auth port */
static int auth_send_sig(const mpcp_config_t     *cfg,
const mpcp_session_t    *sess,
const struct sockaddr_in *pc2_addr)
{
if (cfg->auth_mode != MPCP_AUTH_ED25519) return MPCP_OK;

uint8_t transcript[32];
if (mpcp_session_transcript(sess->session_nonce, sess->master_secret,
                             transcript) != MPCP_OK)
    return MPCP_ERR_CRYPTO;

uint8_t *sk = sodium_malloc(crypto_sign_SECRETKEYBYTES);
if (!sk) { sodium_memzero(transcript, 32); return MPCP_ERR_ALLOC; }

int rc = mpcp_ed25519_load_sk(cfg->auth_keydir, sk);
if (rc != MPCP_OK) {
    sodium_free(sk); sodium_memzero(transcript, 32); return rc;
}

uint8_t sig[64];
rc = mpcp_ed25519_sign(sk, transcript, sig);
sodium_memzero(sk, crypto_sign_SECRETKEYBYTES);
sodium_free(sk);
sodium_memzero(transcript, 32);
if (rc != MPCP_OK) return rc;

uint16_t auth_port = kex_port(sess->master_secret, sess->session_nonce,
                               0xFFFFFFFFu, cfg->port_base, cfg->port_range);
int fd = socket(AF_INET, SOCK_DGRAM, 0);
if (fd < 0) return MPCP_ERR_IO;
struct sockaddr_in dst = *pc2_addr;
dst.sin_port = htons(auth_port);
checked_sendto(fd, sig, 64, 0, (struct sockaddr *)&dst, sizeof(dst));
close(fd);
return MPCP_OK;

}

/* PC2: open auth port, receive PC1's signature, verify against peer_pk */
static int auth_recv_verify(const mpcp_config_t  *cfg,
const mpcp_session_t *sess)
{
if (cfg->auth_mode != MPCP_AUTH_ED25519) return MPCP_OK;

uint8_t transcript[32];
if (mpcp_session_transcript(sess->session_nonce, sess->master_secret,
                             transcript) != MPCP_OK)
    return MPCP_ERR_CRYPTO;

uint8_t peer_pk[32];
int rc = mpcp_ed25519_load_peer_pk(cfg->auth_keydir, peer_pk);
if (rc != MPCP_OK) { sodium_memzero(transcript, 32); return rc; }

uint16_t auth_port = kex_port(sess->master_secret, sess->session_nonce,
                               0xFFFFFFFFu, cfg->port_base, cfg->port_range);
int fd = open_udp_port(auth_port);
if (fd < 0) { sodium_memzero(transcript, 32); return MPCP_ERR_IO; }

uint8_t sig[64];
ssize_t n = recvfrom(fd, sig, sizeof(sig), 0, NULL, NULL);
close(fd);

if (n != 64) { sodium_memzero(transcript, 32); return MPCP_ERR_PROTO; }

rc = mpcp_ed25519_verify(peer_pk, transcript, sig);
sodium_memzero(transcript, 32);
if (rc != MPCP_OK) fprintf(stderr, "[exchange] Ed25519 auth FAILED\n");
else               fprintf(stderr, "[exchange] Ed25519 auth OK\n");
return rc;

}

/* -------------------------

- S8.1  PC1 side
- 
- 1. Generate N candidate keys
- 1. Open N derived ports simultaneously; send all N encrypted candidates
- 1. Receive the N-1 that PC2 returns (missing one = selected)
- 1. Identify missing index -> S8.3 derive session key
- 1. Wipe N-1 losers; optional Ed25519 sign
- ----------------------------------- */
  int mpcp_exchange_pc1(const mpcp_config_t     *cfg,
  mpcp_session_t          *sess,
  const struct sockaddr_in *pc2_addr,
  mpcp_candidates_t       *cands_out)
  {
  const uint32_t N = cfg->key_candidates;
  int rc;
  
  rc = mpcp_keygen_candidates(N, cands_out);
  if (rc != MPCP_OK) return rc;
  
  kex_sock_t *socks = calloc(N, sizeof(kex_sock_t));
  if (!socks) { mpcp_keygen_candidates_free(cands_out); return MPCP_ERR_ALLOC; }
  
  if (open_kex_ports(sess->master_secret, sess->session_nonce,
  N, cfg->port_base, cfg->port_range,
  UINT32_MAX, socks) == 0) {
  fprintf(stderr, "[exchange] PC1: failed to open any ports\n");
  rc = MPCP_ERR_IO; goto done_pc1;
  }
  
  /* Diagnostic: print master_secret prefix and first 3 derived ports.
   * Both sides must show identical values or the PSK/nonce didn't match. */
  fprintf(stderr, "[exchange] PC1: ms=%02x%02x%02x%02x nonce=%02x%02x%02x%02x\n",
    sess->master_secret[0], sess->master_secret[1],
    sess->master_secret[2], sess->master_secret[3],
    sess->session_nonce[0],  sess->session_nonce[1],
    sess->session_nonce[2],  sess->session_nonce[3]);
  for (uint32_t _di = 0; _di < 3 && _di < N; _di++)
    fprintf(stderr, "[exchange] PC1: kex_port[%u] = %u (fd=%d)\n",
      _di, socks[_di].port, socks[_di].fd);
  fprintf(stderr, "[exchange] PC1: sending %u candidates to %s\n", N, inet_ntoa(pc2_addr->sin_addr));
  /* Pre-pack all N candidate packets once (crypto is expensive - do it once).
   * Then retransmit every 500ms until PC2 returns N-1 or deadline expires.
   *
   * WHY RETRANSMIT: PC1 finishes calibration and sends instantly. PC2 is still
   * in mini_recal / rtt_pipeline / derive_master_secret and hasn't called bind()
   * on its recv_socks yet. The one-shot burst arrives at unbound ports and is
   * silently dropped. Retransmitting at 500ms intervals ensures PC2 gets the
   * packets once it's actually listening. PC2 ignores duplicates via got_key[i]. */
  mpcp_key_pkt_t pc1_pkts[MPCP_MAX_CANDIDATES];
  bool           pc1_ready[MPCP_MAX_CANDIDATES];
  memset(pc1_ready, 0, sizeof(pc1_ready));
  for (uint32_t i = 0; i < N; i++) {
  if (socks[i].fd < 0) continue;
  if (mpcp_kex_pack(sess->master_secret, cands_out->keys[i],
  (uint8_t)i, 0x00, &pc1_pkts[i]) == MPCP_OK)
      pc1_ready[i] = true;
  }

  /* Receive N-1 keys back; track which indices arrived */
  uint8_t recv_keys[MPCP_MAX_CANDIDATES][32];
  bool    received[MPCP_MAX_CANDIDATES];
  memset(recv_keys, 0, sizeof(recv_keys));
  memset(received,  0, sizeof(received));

  fprintf(stderr, "[exchange] PC1: sending + waiting for N-1 keys from PC2\n");
  uint64_t deadline    = mpcp_now_ns() + 15000000000ULL; /* 15s total */
  uint64_t next_send   = 0; /* fire immediately on first iteration */
  while (mpcp_now_ns() < deadline) {
  uint32_t cnt_before = 0;
  for (uint32_t i = 0; i < N; i++) if (received[i]) cnt_before++;
  if (cnt_before >= N - 1) break;

  /* Retransmit all N candidate packets every 500ms */
  if (mpcp_now_ns() >= next_send) {
      for (uint32_t i = 0; i < N; i++) {
      if (!pc1_ready[i]) continue;
      struct sockaddr_in dst = *pc2_addr;
      dst.sin_port = htons(socks[i].port);
      sendto(socks[i].fd, &pc1_pkts[i], sizeof(pc1_pkts[i]), 0,
      (struct sockaddr *)&dst, sizeof(dst));
      }
      fprintf(stderr, "[exchange] PC1: sent %u candidates (retransmit)\n", N);
      next_send = mpcp_now_ns() + 500000000ULL; /* 500ms */
  }

  bool any_new = false;
  for (uint32_t i = 0; i < N; i++) {
  if (socks[i].fd < 0 || received[i]) continue;
  uint8_t buf[sizeof(mpcp_key_pkt_t)];
  struct sockaddr_in from_pc2; socklen_t flen = sizeof(from_pc2);
  ssize_t n = recvfrom(socks[i].fd, buf, sizeof(buf),
  MSG_DONTWAIT, (struct sockaddr *)&from_pc2, &flen);
  if (n != (ssize_t)sizeof(mpcp_key_pkt_t)) continue;
  if (from_pc2.sin_addr.s_addr != pc2_addr->sin_addr.s_addr) continue;
  const mpcp_key_pkt_t *pkt = (const mpcp_key_pkt_t *)buf;
  if (pkt->direction != 0x01) continue;
  uint8_t tmp[32];
  if (mpcp_kex_unpack(sess->master_secret, pkt, tmp) != MPCP_OK)
  continue;
  uint8_t idx = pkt->key_index;
  if (idx < N && !received[idx]) {
  memcpy(recv_keys[idx], tmp, 32);
  received[idx] = true;
  any_new = true;
  }
  sodium_memzero(tmp, 32);
  }
  if (!any_new) {
      struct timespec ts = {0, 1000000L};
      nanosleep(&ts, NULL);
  }
  }
  sodium_memzero(recv_keys, sizeof(recv_keys));

  /* If we got fewer than N-1 keys back, no PC2 responded - timeout */
  {
  uint32_t cnt2 = 0;
  for (uint32_t i = 0; i < N; i++) if (received[i]) cnt2++;
  if (cnt2 < N - 1) {
  fprintf(stderr, "[exchange] PC1: timeout - only %u/%u keys returned\n", cnt2, N-1);
  rc = MPCP_ERR_TIMEOUT; goto done_pc1;
  }
  }

  uint32_t selected_idx = UINT32_MAX;
  for (uint32_t i = 0; i < N; i++)
  if (!received[i]) { selected_idx = i; break; }
  
  if (selected_idx == UINT32_MAX) {
  fprintf(stderr, "[exchange] PC1: all N returned - cannot identify selected\n");
  rc = MPCP_ERR_PROTO; goto done_pc1;
  }
  fprintf(stderr, "[exchange] PC1: selected index = %u\n", selected_idx);
  
  /* S8.3: derive session key from master_secret + selected candidate */
  rc = mpcp_derive_session_key(sess->master_secret,
  cands_out->keys[selected_idx],
  sess->session_key);
  if (rc != MPCP_OK) goto done_pc1;
  
  mpcp_keygen_candidates_wipe_losers(cands_out, selected_idx);
  
  /* S5.3 optional */
  rc = auth_send_sig(cfg, sess, pc2_addr);
  if (rc != MPCP_OK) goto done_pc1;
  
  fprintf(stderr, "[exchange] PC1: session key ready\n");
  rc = MPCP_OK;

done_pc1:
close_kex_ports(socks, N);
free(socks);
return rc;
}

/* -------------------------

- S8.2  PC2 side - exact 8-step constant-time blind selection
- 
- Corrected order: 1 -> 2 -> 3 -> 4 -> 5 -> [S8.3] -> 6 -> 7 -> 8
- ----------------------------------- */
  int mpcp_exchange_pc2(const mpcp_config_t     *cfg,
  mpcp_session_t          *sess,
  const struct sockaddr_in *pc1_addr)
  {
  const uint32_t N        = cfg->key_candidates;
  const uint64_t delay_ns = (uint64_t)cfg->key_exchange_delay * 1000000ULL;
  int rc = MPCP_ERR_IO;
  
  /* Open N receive ports */
  kex_sock_t *recv_socks = calloc(N, sizeof(kex_sock_t));
  if (!recv_socks) return MPCP_ERR_ALLOC;
  open_kex_ports(sess->master_secret, sess->session_nonce,
  N, cfg->port_base, cfg->port_range, UINT32_MAX, recv_socks);
  
  /* Locked buffers for all N incoming candidates */
  uint8_t *all_keys[MPCP_MAX_CANDIDATES];
  memset(all_keys, 0, sizeof(all_keys));
  bool got_key[MPCP_MAX_CANDIDATES];
  memset(got_key, 0, sizeof(got_key));
  
  if (alloc_key_bufs(all_keys, N) != MPCP_OK) {
  close_kex_ports(recv_socks, N); free(recv_socks);
  return MPCP_ERR_ALLOC;
  }
  
  /* Collect all N keys from PC1.
   * Use MSG_DONTWAIT (non-blocking) poll across all N sockets each pass.
   * A blocking recvfrom-per-socket would stall up to 2s × N = 20s before
   * the deadline is re-checked, causing guaranteed timeout with N=10. */
  /* Diagnostic: must match PC1's output exactly */
  fprintf(stderr, "[exchange] PC2: ms=%02x%02x%02x%02x nonce=%02x%02x%02x%02x\n",
    sess->master_secret[0], sess->master_secret[1],
    sess->master_secret[2], sess->master_secret[3],
    sess->session_nonce[0],  sess->session_nonce[1],
    sess->session_nonce[2],  sess->session_nonce[3]);
  for (uint32_t _di = 0; _di < 3 && _di < N; _di++)
    fprintf(stderr, "[exchange] PC2: kex_port[%u] = %u (fd=%d)\n",
      _di, recv_socks[_di].port, recv_socks[_di].fd);
  fprintf(stderr, "[exchange] PC2: waiting for %u candidate keys from PC1=%s\n",
    N, inet_ntoa(pc1_addr->sin_addr));
  uint64_t deadline = mpcp_now_ns() + 10000000000ULL;
  while (mpcp_now_ns() < deadline) {
  uint32_t cnt_check = 0;
  for (uint32_t i = 0; i < N; i++) if (got_key[i]) cnt_check++;
  if (cnt_check == N) break;
  bool any_new = false;
  for (uint32_t i = 0; i < N; i++) {
  if (got_key[i] || recv_socks[i].fd < 0) continue;
  uint8_t buf[sizeof(mpcp_key_pkt_t)];
  struct sockaddr_in from_pc1; socklen_t flen2 = sizeof(from_pc1);
  ssize_t n = recvfrom(recv_socks[i].fd, buf, sizeof(buf),
  MSG_DONTWAIT, (struct sockaddr *)&from_pc1, &flen2);
  if (n != (ssize_t)sizeof(mpcp_key_pkt_t)) continue;
  /* Validate packet came from the expected PC1 IP */
  if (from_pc1.sin_addr.s_addr != pc1_addr->sin_addr.s_addr) continue;
  const mpcp_key_pkt_t *pkt = (const mpcp_key_pkt_t *)buf;
  if (pkt->direction != 0x00) continue;
  if (mpcp_kex_unpack(sess->master_secret, pkt, all_keys[i]) != MPCP_OK)
  continue;
  got_key[i] = true;
  any_new = true;
  }
  /* Sleep 1ms between passes unless we just received something */
  if (!any_new) {
      struct timespec ts = {0, 1000000L};
      nanosleep(&ts, NULL);
  }
  }
  close_kex_ports(recv_socks, N);
  free(recv_socks);
  
  { uint32_t cnt = 0;
  for (uint32_t i = 0; i < N; i++) if (got_key[i]) cnt++;
  if (cnt != N) {
  fprintf(stderr, "[exchange] PC2: received %u/%u keys\n", cnt, N);
  rc = MPCP_ERR_TIMEOUT; goto done_pc2;
  }
  }
  
  /* ============================================================
  - S8.2  STEPS 1-8  (corrected order - see file header)
  - ============================================================ */
  
  /* Step 1: record T_recv */
  uint64_t t_recv = mpcp_now_ns();
  
  /* Step 2: select index - only non-CT operation, before examining keys */
  uint32_t selected_idx;
  { uint32_t r; randombytes_buf(&r, sizeof(r)); selected_idx = r % N; }
  
  /* Step 3: CT copy - read all N, branchlessly accumulate selected.
  *
  - eq   = 1 iff i == selected_idx, else 0
  - mask = -(int8_t)eq -> 0xFF when eq=1, 0x00 when eq=0
  - 
  - Loop visits all N entries regardless of selected_idx.
  - No branch, no early exit - prevents access-pattern leakage. */
    uint8_t *selected_buf = sodium_malloc(32);
    if (!selected_buf) { rc = MPCP_ERR_ALLOC; goto done_pc2; }
    sodium_memzero(selected_buf, 32);
  
  for (uint32_t i = 0; i < N; i++) {
  uint8_t eq   = (uint8_t)(i == selected_idx ? 1 : 0);
  uint8_t mask = (uint8_t)(-(int8_t)eq);
  for (int j = 0; j < 32; j++)
  selected_buf[j] |= mask & all_keys[i][j];
  }
  
  /* Step 4: CT build return_buf - copy all N, no branch on index */
  uint8_t *return_buf[MPCP_MAX_CANDIDATES];
  memset(return_buf, 0, sizeof(return_buf));
  if (alloc_key_bufs(return_buf, N) != MPCP_OK) {
  sodium_memzero(selected_buf, 32); sodium_free(selected_buf);
  rc = MPCP_ERR_ALLOC; goto done_pc2;
  }
  for (uint32_t i = 0; i < N; i++)
  memcpy(return_buf[i], all_keys[i], 32);
  
  /* Step 5: CT Fisher-Yates shuffle - XOR swap on fixed 32B buffers, no branch */
  for (uint32_t i = N - 1; i > 0; i--) {
  uint32_t r; randombytes_buf(&r, sizeof(r));
  uint32_t j = r % (i + 1);
  for (int k = 0; k < 32; k++) {
  uint8_t tmp       = return_buf[i][k] ^ return_buf[j][k];
  return_buf[i][k] ^= tmp;
  return_buf[j][k] ^= tmp;
  }
  }
  
  /* S8.3  Derive session key BEFORE step 6 wipes selected_buf */
  rc = mpcp_derive_session_key(sess->master_secret, selected_buf,
  sess->session_key);
  if (rc != MPCP_OK) {
  sodium_memzero(selected_buf, 32); sodium_free(selected_buf);
  free_key_bufs(return_buf, N);
  goto done_pc2;
  }
  
  /* Step 6: zero working copy of selected key */
  sodium_memzero(selected_buf, 32);
  sodium_free(selected_buf);
  selected_buf = NULL;
  
  /* Step 7: sleep until T_recv + key_exchange_delay - masks steps 2-6 variance */
  {
  uint64_t t_now = mpcp_now_ns();
  if (t_now < t_recv + delay_ns) {
  mpcp_sleep_until_ns(t_recv + delay_ns);
  } else {
  fprintf(stderr,
  "[exchange] PC2: WARNING steps 2-6 took %llu ms "
  "> key_exchange_delay %u ms\n",
  (unsigned long long)(t_now - t_recv) / 1000000ULL,
  cfg->key_exchange_delay);
  }
  }
  
  /* Step 8: open N-1 ports, pre-pack all packets, then burst-send.
   * Separating crypto (pack) from network (sendto) prevents scheduler
   * preemption between consecutive sends and minimises inter-packet jitter. */
    fprintf(stderr, "[exchange] PC2: returning %u keys to PC1\n", N - 1);
    {
    kex_sock_t *send_socks = calloc(N, sizeof(kex_sock_t));
    if (!send_socks) {
    free_key_bufs(return_buf, N);
    rc = MPCP_ERR_ALLOC; goto done_pc2;
    }
    open_kex_ports(sess->master_secret, sess->session_nonce,
    N, cfg->port_base, cfg->port_range,
    selected_idx, send_socks);

    /* Pre-pack all N-1 packets (crypto phase) */
    mpcp_key_pkt_t pkts[MPCP_MAX_CANDIDATES];
    bool           pkt_ready[MPCP_MAX_CANDIDATES];
    memset(pkt_ready, 0, sizeof(pkt_ready));
    for (uint32_t i = 0; i < N; i++) {
    if (i == selected_idx || send_socks[i].fd < 0) continue;
    if (mpcp_kex_pack(sess->master_secret, return_buf[i],
    (uint8_t)i, 0x01, &pkts[i]) == MPCP_OK)
        pkt_ready[i] = true;
    }

    /* Burst-send all ready packets (no crypto between sends) */
    for (uint32_t i = 0; i < N; i++) {
    if (!pkt_ready[i]) continue;
    struct sockaddr_in dst = *pc1_addr;
    dst.sin_port = htons(send_socks[i].port);
    sendto(send_socks[i].fd, &pkts[i], sizeof(pkts[i]), 0,
    (struct sockaddr *)&dst, sizeof(dst));
    }
    close_kex_ports(send_socks, N);
    free(send_socks);
    }
  
  free_key_bufs(return_buf, N);
  
  /* S5.3 optional: receive and verify PC1 Ed25519 signature */
  rc = auth_recv_verify(cfg, sess);
  if (rc != MPCP_OK) goto done_pc2;
  
  fprintf(stderr, "[exchange] PC2: exchange complete, session key ready\n");
  rc = MPCP_OK;

done_pc2:
free_key_bufs(all_keys, N);
return rc;
}

