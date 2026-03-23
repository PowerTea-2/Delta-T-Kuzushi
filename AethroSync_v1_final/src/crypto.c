/* AethroSync — src/crypto.c — HKDF, AEAD, Ed25519, master/session key derivation */
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

/* ========== src/crypto.c ========== */
/*

- crypto.c - MPCP cryptographic primitives
- 
- Covers spec sections:
- S7.4  Multi-source HKDF master secret
- S7.5  HKDF keystream (single Expand call)
- S8.3  Session key finalisation
- S9.4  Chunk encryption (XChaCha20-Poly1305)
- S9.7  ACK BLAKE2b hash
- S10   Chunk key zeroing
- S14   Memory safety (sodium_malloc, sodium_mlock)
- SAppendix B  Cryptographic primitive summary
- 
- All key material lives in sodium_malloc()'d regions.
- Per-chunk keys are zeroed immediately after use.
  */

#include <sys/random.h>   /* getrandom() */

/* -------------------------

- Internal HKDF-SHA256 using libsodium primitives
- 
- libsodium does not expose HKDF directly, so we implement RFC 5869
- using crypto_auth_hmacsha256 (HMAC-SHA256).
- 
- HKDF-Extract(salt, ikm)  -> prk
- HKDF-Expand(prk, info, length) -> okm
- ----------------------------------- */

/* HMAC-SHA256(key, data) -> out[32] */
static int hmac_sha256(const uint8_t *key,  size_t key_len,
const uint8_t *data, size_t data_len,
uint8_t out[32])
{
crypto_auth_hmacsha256_state st;
if (crypto_auth_hmacsha256_init(&st, key, key_len) != 0) return -1;
if (crypto_auth_hmacsha256_update(&st, data, data_len) != 0) return -1;
if (crypto_auth_hmacsha256_final(&st, out) != 0) return -1;
return 0;
}

/*

- hkdf_extract - RFC 5869 S2.2
- prk = HMAC-SHA256(salt, ikm)
  */
  static int hkdf_extract(const uint8_t *salt, size_t salt_len,
  const uint8_t *ikm,  size_t ikm_len,
  uint8_t prk[32])
  {
  /* If no salt, use HashLen zeros (RFC 5869) */
  static const uint8_t zero_salt[32] = {0};
  if (!salt || salt_len == 0) {
  salt     = zero_salt;
  salt_len = sizeof(zero_salt);
  }
  return hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
  }

/*

- hkdf_expand - RFC 5869 S2.3
- okm = T(1) || T(2) || ... truncated to length bytes
- T(i) = HMAC-SHA256(prk, T(i-1) || info || i)
- 
- Maximum output: 255 * 32 = 8160 bytes.
  */
  static int hkdf_expand(const uint8_t prk[32],
  const uint8_t *info, size_t info_len,
  uint8_t *okm,  size_t length)
  {
  if (length > 255 * 32) return -1;
  
  uint8_t t[32] = {0};
  size_t  t_len = 0;
  size_t  done  = 0;
  uint8_t counter = 1;
  
  crypto_auth_hmacsha256_state st;
  
  while (done < length) {
  if (crypto_auth_hmacsha256_init(&st, prk, 32) != 0) return -1;
  if (t_len > 0)
  if (crypto_auth_hmacsha256_update(&st, t, t_len) != 0) return -1;
  if (info && info_len > 0)
  if (crypto_auth_hmacsha256_update(&st, info, info_len) != 0) return -1;
  if (crypto_auth_hmacsha256_update(&st, &counter, 1) != 0) return -1;
  if (crypto_auth_hmacsha256_final(&st, t) != 0) return -1;
  t_len = 32;
  counter++;
  
   size_t copy = (length - done < 32) ? (length - done) : 32;
   memcpy(okm + done, t, copy);
   done += copy;
  
  }
  sodium_memzero(t, sizeof(t));
  return 0;
  }

/*

- Public wrapper: HKDF-SHA256(salt, ikm, info) -> okm[out_len]
- okm must be pre-allocated (sodium_malloc or plain malloc).
  */
  int mpcp_hkdf(const uint8_t *salt,  size_t salt_len,
  const uint8_t *ikm,   size_t ikm_len,
  const char    *info,
  uint8_t       *okm,   size_t out_len)
  {
  uint8_t prk[32];
  int rc;
  
  rc = hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
  if (rc != 0) { sodium_memzero(prk, sizeof(prk)); return MPCP_ERR_CRYPTO; }
  
  rc = hkdf_expand(prk, (const uint8_t *)info, info ? strlen(info) : 0,
  okm, out_len);
  sodium_memzero(prk, sizeof(prk));
  return (rc == 0) ? MPCP_OK : MPCP_ERR_CRYPTO;
  }

/* -------------------------

- S7.4  Master secret derivation
- 
- master_secret = HKDF-SHA256(
  salt = session_nonce,
  ikm  = timing_entropy || psk_bytes || getrandom(32) || clock_nanos,
  info = "mpcp-v0.5-master"
- )
- 
- timing_entropy: raw RTT samples as byte array (little-endian doubles).
- Returns MPCP_OK and fills master_secret_out[32] (caller sodium_malloc'd).
- ----------------------------------- */
  int mpcp_derive_master_secret(
  const uint8_t  *session_nonce,        /* 32B - shared via nonce_hint */
  const double   *rtt_samples,          /* unused - kept for ABI compat */
  uint32_t        rtt_count,            /* unused - kept for ABI compat */
  const uint8_t  *psk_bytes,            /* raw PSK - the only shared secret */
  size_t          psk_len,
  uint8_t        *master_secret_out)    /* [32], sodium_malloc'd by caller */
  {
  /* FIX: master_secret must be derived from SHARED inputs only.
   *
   * Original design mixed in getrandom(32) and clock_nanos, which are
   * machine-local random values. Since sender and receiver run on different
   * machines, these values differ, producing different master_secrets that
   * make kex_unpack always fail with MPCP_ERR_CRYPTO.
   *
   * The session_nonce (shared via nonce_hint in calibration pings) and the
   * PSK (shared out-of-band) are the only inputs both sides can agree on.
   * Timing entropy and OS randomness belong in per-session key material
   * that is negotiated via the key exchange, not in the shared bootstrap key.
   *
   * master_secret = HKDF-SHA256(
   *   salt = session_nonce,
   *   ikm  = psk_bytes,
   *   info = "mpcp-v0.5-master"
   * )
   */
  (void)rtt_samples;
  (void)rtt_count;

  uint8_t *ikm = sodium_malloc(psk_len);
  if (!ikm) return MPCP_ERR_ALLOC;

  memcpy(ikm, psk_bytes, psk_len);

  int rc = mpcp_hkdf(session_nonce, MPCP_SESSION_NONCE_LEN,
                     ikm, psk_len,
                     "mpcp-v0.5-master",
                     master_secret_out, MPCP_MASTER_SECRET_LEN);

  sodium_memzero(ikm, psk_len);
  sodium_free(ikm);
  return rc;
  }

/* -------------------------

- S7.5  HKDF keystream - single Expand call
- 
- keystream = HKDF-Expand(session_key, length = total_chunks * 64)
- chunk_key[i]  = keystream[i*64 : i*64+32]
- port_seed[i]  = keystream[i*64+32 : i*64+64]
- port[i]       = port_seed[i] mod port_range + port_base
- 
- Returns sodium_malloc'd keystream pointer. Caller must sodium_free.
- ----------------------------------- */
  uint8_t *mpcp_derive_keystream(const uint8_t *session_key, /* 32B */
  uint32_t total_chunks)
  {
  /* HKDF-Expand is limited to 255 * HashLen = 255 * 32 = 8160 bytes output.
  - Each chunk slot is 64 bytes, so the hard ceiling is 8160/64 = 127 chunks.
  - Callers (sender.c) must split transfers into segments if needed. */
    if (total_chunks == 0 || total_chunks > 127u) {
    fprintf(stderr,
    "[crypto] mpcp_derive_keystream: total_chunks=%u out of range [1,127]\n",
    total_chunks);
    return NULL;
    }
  
  size_t   len = (size_t)total_chunks * MPCP_KEYSTREAM_SLOT;
  uint8_t *ks  = sodium_malloc(len);
  if (!ks) return NULL;
  
  if (mpcp_hkdf(NULL, 0,
  session_key, MPCP_SESSION_KEY_LEN,
  "mpcp-v0.5-keystream",
  ks, len) != MPCP_OK)
  {
  sodium_free(ks);
  return NULL;
  }
  return ks;
  }

/*

- Extract chunk key and port from pre-derived keystream.
- chunk_key_out[32] must be sodium_malloc'd by caller.
- port_out receives the derived port number.
  */
  void mpcp_keystream_slot(const uint8_t *keystream,
  uint32_t       chunk_index,
  uint32_t       port_base,
  uint32_t       port_range,
  uint8_t       *chunk_key_out,   /* [32] */
  uint16_t      *port_out)
  {
  const uint8_t *slot     = keystream + (size_t)chunk_index * MPCP_KEYSTREAM_SLOT;
  const uint8_t *key_part = slot;
  const uint8_t *port_part= slot + MPCP_CHUNK_KEY_LEN;
  
  memcpy(chunk_key_out, key_part, MPCP_CHUNK_KEY_LEN);
  
  /* port_seed mod port_range + port_base.
  - Take first 4 bytes of port_seed as uint32 (big-endian). */
    uint32_t seed = ((uint32_t)port_part[0] << 24) |
    ((uint32_t)port_part[1] << 16) |
    ((uint32_t)port_part[2] <<  8) |
    ((uint32_t)port_part[3]);
    *port_out = (uint16_t)((seed % port_range) + port_base);
    }

/* -------------------------

- S8.3  Session key finalisation
- 
- session_key = HKDF-SHA256(
  salt = master_secret,
  ikm  = selected_candidate,
  info = "mpcp-v0.5-session"
- )
- ----------------------------------- */
  int mpcp_derive_session_key(const uint8_t *master_secret,    /* 32B */
  const uint8_t *selected_candidate,/* 32B */
  uint8_t       *session_key_out)   /* 32B, sodium_malloc'd */
  {
  return mpcp_hkdf(master_secret, MPCP_MASTER_SECRET_LEN,
  selected_candidate, 32,
  "mpcp-v0.5-session",
  session_key_out, MPCP_SESSION_KEY_LEN);
  }

/* -------------------------

- S9.4  Chunk encryption: XChaCha20-Poly1305
- 
- Additional data: seq_index(4B, big-endian) || session_nonce(32B)
- 
- plaintext  - padded to chunk_pad_size before calling this function
- ciphertext - caller allocates: plaintext_len + crypto_aead_xchacha20poly1305_ietf_ABYTES
- 
- nonce_out[24] is filled with a fresh random nonce (caller stores it).
- ----------------------------------- */
  int mpcp_chunk_encrypt(const uint8_t *chunk_key,      /* 32B */
  const uint8_t *session_nonce,  /* 32B */
  uint32_t       seq_index,
  const uint8_t *plaintext,
  size_t         plaintext_len,
  uint8_t       *ciphertext_out,
  size_t        *ciphertext_len_out,
  uint8_t        nonce_out[24])
  {
  /* Build additional data: seq_index(BE 4B) || session_nonce(32B) */
  uint8_t ad[36];
  ad[0] = (uint8_t)((seq_index >> 24) & 0xFF);
  ad[1] = (uint8_t)((seq_index >> 16) & 0xFF);
  ad[2] = (uint8_t)((seq_index >>  8) & 0xFF);
  ad[3] = (uint8_t)((seq_index      ) & 0xFF);
  memcpy(ad + 4, session_nonce, MPCP_SESSION_NONCE_LEN);
  
  /* Fresh random nonce per chunk */
  randombytes_buf(nonce_out, 24);
  
  unsigned long long ct_len = 0;
  int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
  ciphertext_out, &ct_len,
  plaintext,      plaintext_len,
  ad,             sizeof(ad),
  NULL,           /* no secret nonce */
  nonce_out,
  chunk_key);
  
  if (rc != 0) return MPCP_ERR_CRYPTO;
  *ciphertext_len_out = (size_t)ct_len;
  return MPCP_OK;
  }

/* -------------------------

- S10  Chunk decryption: XChaCha20-Poly1305 + index verification
- ----------------------------------- */
  int mpcp_chunk_decrypt(const uint8_t *chunk_key,       /* 32B */
  const uint8_t *session_nonce,   /* 32B */
  uint32_t       seq_index,
  const uint8_t *nonce,           /* 24B, from packet */
  const uint8_t *ciphertext,
  size_t         ciphertext_len,
  uint8_t       *plaintext_out,
  size_t        *plaintext_len_out)
  {
  uint8_t ad[36];
  ad[0] = (uint8_t)((seq_index >> 24) & 0xFF);
  ad[1] = (uint8_t)((seq_index >> 16) & 0xFF);
  ad[2] = (uint8_t)((seq_index >>  8) & 0xFF);
  ad[3] = (uint8_t)((seq_index      ) & 0xFF);
  memcpy(ad + 4, session_nonce, MPCP_SESSION_NONCE_LEN);
  
  unsigned long long pt_len = 0;
  int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
  plaintext_out, &pt_len,
  NULL,          /* no secret nonce */
  ciphertext,    ciphertext_len,
  ad,            sizeof(ad),
  nonce,
  chunk_key);
  
  if (rc != 0) return MPCP_ERR_CRYPTO;   /* tag mismatch or index mismatch */
  *plaintext_len_out = (size_t)pt_len;
  return MPCP_OK;
  }

/* -------------------------

- S9.7  ACK BLAKE2b hash
- 
- ack_hash = BLAKE2b(seq_index, key=session_key, outlen=4)
- seq_index encoded as 4-byte big-endian input.
- ----------------------------------- */
  int mpcp_ack_hash(const uint8_t *session_key, /* 32B */
  uint32_t       seq_index,
  uint8_t        out[4])
  {
  uint8_t msg[4];
  msg[0] = (uint8_t)((seq_index >> 24) & 0xFF);
  msg[1] = (uint8_t)((seq_index >> 16) & 0xFF);
  msg[2] = (uint8_t)((seq_index >>  8) & 0xFF);
  msg[3] = (uint8_t)((seq_index      ) & 0xFF);
  
  /* crypto_generichash = BLAKE2b */
  return (crypto_generichash(out, 4, msg, 4, session_key,
  MPCP_SESSION_KEY_LEN) == 0)
  ? MPCP_OK : MPCP_ERR_CRYPTO;
  }

/* -------------------------

- S18.5  Bounce oracle: BLAKE2b-256 of received chunk ciphertext
- ----------------------------------- */
  int mpcp_bounce_hash(const uint8_t *ciphertext, size_t len,
  uint8_t        out[32])
  {
  return (crypto_generichash(out, 32, ciphertext, len, NULL, 0) == 0)
  ? MPCP_OK : MPCP_ERR_CRYPTO;
  }

/* -------------------------

- S12.1  Rendezvous token
- 
- rendezvous_token = SHA256(session_id || psk_bytes)
- session_id is the first 32B of session_nonce (they are the same value).
- ----------------------------------- */
  int mpcp_rendezvous_token(const uint8_t *session_nonce, /* 32B */
  const uint8_t *psk_bytes,
  size_t         psk_len,
  uint8_t        token_out[32])
  {
  crypto_hash_sha256_state st;
  if (crypto_hash_sha256_init(&st) != 0) return MPCP_ERR_CRYPTO;
  if (crypto_hash_sha256_update(&st, session_nonce, 32) != 0) return MPCP_ERR_CRYPTO;
  if (crypto_hash_sha256_update(&st, psk_bytes, psk_len) != 0) return MPCP_ERR_CRYPTO;
  if (crypto_hash_sha256_final(&st, token_out) != 0) return MPCP_ERR_CRYPTO;
  return MPCP_OK;
  }

/* -------------------------

- S9.8  Retry port derivation
- 
- port_retry[i][r] = HKDF(session_key, "retry"||i||r||session_nonce) mod port_range + port_base
- ----------------------------------- */
  uint16_t mpcp_retry_port(const uint8_t *session_key,    /* 32B */
  const uint8_t *session_nonce,  /* 32B */
  uint32_t       chunk_index,
  uint32_t       retry_count,
  uint32_t       port_base,
  uint32_t       port_range)
  {
  /* IKM = "retry"(5) || chunk_index(4, BE) || retry_count(4, BE) || nonce(32) */
  uint8_t ikm[5 + 4 + 4 + 32];
  memcpy(ikm, "retry", 5);
  ikm[5]  = (uint8_t)((chunk_index >> 24) & 0xFF);
  ikm[6]  = (uint8_t)((chunk_index >> 16) & 0xFF);
  ikm[7]  = (uint8_t)((chunk_index >>  8) & 0xFF);
  ikm[8]  = (uint8_t)((chunk_index      ) & 0xFF);
  ikm[9]  = (uint8_t)((retry_count >> 24) & 0xFF);
  ikm[10] = (uint8_t)((retry_count >> 16) & 0xFF);
  ikm[11] = (uint8_t)((retry_count >>  8) & 0xFF);
  ikm[12] = (uint8_t)((retry_count      ) & 0xFF);
  memcpy(ikm + 13, session_nonce, 32);
  
  uint8_t out[4];
  if (mpcp_hkdf(session_key, MPCP_SESSION_KEY_LEN,
  ikm, sizeof(ikm),
  NULL, out, 4) != MPCP_OK)
  {
  /* On failure, fall back to a deterministic but not HKDF-derived port */
  return (uint16_t)((chunk_index * 1009 + retry_count * 31) % port_range + port_base);
  }
  
  uint32_t seed = ((uint32_t)out[0] << 24) | ((uint32_t)out[1] << 16) |
  ((uint32_t)out[2] <<  8) |  (uint32_t)out[3];
  sodium_memzero(out, sizeof(out));
  return (uint16_t)(seed % port_range + port_base);
  }

/* -------------------------

- S14  Secure memory helpers
- ----------------------------------- */

/* Allocate sodium_malloc'd buffer and zero it */
uint8_t *mpcp_secure_alloc(size_t n)
{
uint8_t *p = sodium_malloc(n);
if (p) sodium_memzero(p, n);
return p;
}

/* Zero and free */
void mpcp_secure_free(uint8_t *p, size_t n)
{
if (!p) return;
sodium_memzero(p, n);
sodium_free(p);
}

/* -------------------------

- S21.5  Abort procedure - zero all live key material
- Call this on any tripwire trigger before exit.
- ----------------------------------- */
  void mpcp_crypto_abort(mpcp_session_t *sess)
  {
  if (!sess) return;
  sodium_memzero(sess->master_secret, MPCP_MASTER_SECRET_LEN);
  sodium_memzero(sess->session_key,   MPCP_SESSION_KEY_LEN);
  if (sess->keystream) {
  size_t ks_len = (size_t)sess->total_chunks * MPCP_KEYSTREAM_SLOT;
  sodium_memzero(sess->keystream, ks_len);
  sodium_free(sess->keystream);
  sess->keystream = NULL;
  }
  sodium_memzero(sess->session_nonce, MPCP_SESSION_NONCE_LEN);
  }

/* -------------------------

- Constant-time memory comparison (wraps sodium_memcmp)
- ----------------------------------- */
  bool mpcp_ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
  {
  return sodium_memcmp(a, b, n) == 0;
  }

/* -------------------------

- Initialise libsodium - call once at program startup
- ----------------------------------- */
  int mpcp_crypto_init(void)
  {
  if (sodium_init() < 0) {
  fprintf(stderr, "[crypto] sodium_init() failed\n");
  return MPCP_ERR_CRYPTO;
  }
  return MPCP_OK;
  }

/* -------------------------

- Error string
- ----------------------------------- */
  const char *mpcp_strerror(mpcp_err_t err)
  {
  switch (err) {
  case MPCP_OK:              return "ok";
  case MPCP_ERR_PARAM:       return "bad parameter";
  case MPCP_ERR_ENTROPY:     return "PSK below minimum entropy";
  case MPCP_ERR_CRYPTO:      return "cryptographic failure";
  case MPCP_ERR_ALLOC:       return "memory allocation failure";
  case MPCP_ERR_IO:          return "I/O error";
  case MPCP_ERR_TIMEOUT:     return "timeout";
  case MPCP_ERR_TRIPWIRE:    return "tripwire - interception detected";
  case MPCP_ERR_PROTO:       return "protocol violation";
  case MPCP_ERR_UNSUPPORTED: return "kernel feature unsupported";
  case MPCP_ERR_NAT:         return "NAT traversal failed";
  default:                   return "unknown error";
  }
  }

/* =========================================================
 * CLI error reporter
 *
 * Prints:  "  error [stage]: <human reason>"
 *          "  hint:  <what to do>"
 * ========================================================= */
void mpcp_perror(const char *stage, int rc)
{
    if (g_ui_colour && isatty(STDERR_FILENO))
        fprintf(stderr, "\n  %s" GLYPH_FAIL " error [%s]:%s %s\n",
                C_ROSE, stage, C_RESET, mpcp_strerror((mpcp_err_t)rc));
    else
        fprintf(stderr, "\n  error [%s]: %s\n", stage, mpcp_strerror((mpcp_err_t)rc));

    const char *hint = NULL;
    const char *icon = GLYPH_ARR;
    switch ((mpcp_err_t)rc) {
        case MPCP_ERR_ENTROPY:   hint = "use 4+ random words or let MPCP generate a PSK"; break;
        case MPCP_ERR_CRYPTO:    hint = "PSK mismatch between sender and receiver, or packet was tampered"; break;
        case MPCP_ERR_TIMEOUT:   hint = "check the receiver is running and listening on the correct port"; break;
        case MPCP_ERR_PROTO:     hint = "version mismatch or corrupted packet - both sides must run the same build"; break;
        case MPCP_ERR_TRIPWIRE:  hint = "anomalous RTT detected - possible interception; session aborted";
                                 icon = GLYPH_SKULL; break;
        case MPCP_ERR_NAT:       hint = "NAT traversal failed - try internet profile or forward the port manually"; break;
        case MPCP_ERR_IO:        hint = "check the file path exists and you have read/write permissions"; break;
        case MPCP_ERR_ALLOC:     hint = "out of memory - try a smaller file or a machine with more RAM"; break;
        case MPCP_ERR_UNSUPPORTED: hint = "kernel feature missing - update kernel or disable memory_lock"; break;
        case MPCP_ERR_PARAM:     hint = "internal parameter error - please report this as a bug"; break;
        default: break;
    }
    if (hint) {
        if (g_ui_colour)
            fprintf(stderr, "  %s%s hint:%s  %s\n", C_GOLD, icon, C_RESET, hint);
        else
            fprintf(stderr, "  hint:  %s\n", hint);
    }
    fprintf(stderr, "\n");
}

