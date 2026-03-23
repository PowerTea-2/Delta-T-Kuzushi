/* AethroSync — mpcp.h — public API
 * All types, constants, error codes, and function prototypes.
 * Included by every .c file in the project.
 */
#pragma once
#ifndef MPCP_H
#define MPCP_H

#include "platform.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sodium.h>
#include <zstd.h>



/* =========================================================

- Declarations (from include headers - guards stripped)
- ========================================================= */

/* -- include/mpcp.h -- */
/*

- MPCP - Multi-Port Catch Protocol
- Protocol Specification v0.5
- 
- Master header: all shared types, constants, and forward declarations.
- Every module includes this file.
- 
- _GNU_SOURCE is set via CFLAGS in the Makefile; do not redefine here.
  */

/* -------------------------

- Version
- ----------------------------------- */
  #define MPCP_VERSION        0x05
  #define MPCP_MAGIC          0x4D435043u   /* 'MCPC' - deliberate mismatch */

/* -------------------------

- Return codes
- ----------------------------------- */
  typedef enum {
  MPCP_OK               =  0,
  MPCP_ERR_PARAM        = -1,   /* bad argument */
  MPCP_ERR_ENTROPY      = -2,   /* PSK below min entropy */
  MPCP_ERR_CRYPTO       = -3,   /* libsodium failure */
  MPCP_ERR_ALLOC        = -4,   /* sodium_malloc / malloc failure */
  MPCP_ERR_IO           = -5,   /* file / socket I/O error */
  MPCP_ERR_TIMEOUT      = -6,   /* calibration or catch timeout */
  MPCP_ERR_TRIPWIRE     = -7,   /* interception detected - abort */
  MPCP_ERR_PROTO        = -8,   /* protocol violation */
  MPCP_ERR_UNSUPPORTED  = -9,   /* kernel feature not available */
  MPCP_ERR_NAT          = -10,  /* NAT traversal failure */
  } mpcp_err_t;

extern const char *mpcp_strerror(mpcp_err_t err);

/* -------------------------

- Sizes and limits (spec S18, S9)
- ----------------------------------- */
  #define MPCP_SESSION_NONCE_LEN   32u
  #define MPCP_MASTER_SECRET_LEN   32u
  #define MPCP_SESSION_KEY_LEN     32u
  #define MPCP_CHUNK_KEY_LEN       32u
  #define MPCP_PORT_SEED_LEN       32u
  #define MPCP_KEYSTREAM_SLOT      64u   /* chunk_key(32) + port_seed(32) */
  #define MPCP_PSK_MAX             256u
  #define MPCP_MAX_CANDIDATES      32u
  #define MPCP_NONCE_HINT_LEN      32u   /* full session_nonce transmitted in pings */

/* Wire packet sizes (spec S18) */
#define MPCP_HDR_LEN             6u    /* magic(4)+version(1)+type(1) */
#define MPCP_CAL_PKT_LEN         64u
#define MPCP_KEY_PKT_LEN         96u
#define MPCP_ACK_PKT_LEN         32u
#define MPCP_BOUNCE_PKT_LEN      58u

/* Chunk overhead: seq(4)+retry(1)+flags(1)+plen(4)+nonce(24)+tag(16) */
#define MPCP_CHUNK_OVERHEAD      (4+1+1+4+24+16)
#define MPCP_DATA_HDR_OFFSET     40u   /* offset where ciphertext starts */

/* -------------------------

- Packet type bytes (spec S18)
- ----------------------------------- */
  #define MPCP_TYPE_PING           0x01
  #define MPCP_TYPE_PONG           0x02
  #define MPCP_TYPE_KEY_EXCHANGE   0x03
  #define MPCP_TYPE_DATA_CHUNK     0x04
  #define MPCP_TYPE_GHOST_CHUNK    0x05
  #define MPCP_TYPE_ACK            0x06
  #define MPCP_TYPE_BOUNCE         0x07

/* -------------------------

- Auth mode
- ----------------------------------- */
  typedef enum {
  MPCP_AUTH_PSK    = 0,
  MPCP_AUTH_ED25519 = 1,
  } mpcp_auth_mode_t;

/* -------------------------

- NAT mode
- ----------------------------------- */
  typedef enum {
  MPCP_NAT_AUTO   = 0,
  MPCP_NAT_DIRECT = 1,
  MPCP_NAT_FORCE  = 2,
  } mpcp_nat_mode_t;

/* -------------------------

- Disguise protocol
- ----------------------------------- */
  typedef enum {
  MPCP_DISGUISE_DNS = 0,
  MPCP_DISGUISE_NTP = 1,
  } mpcp_disguise_proto_t;

/* -------------------------

- Configuration (spec S16.1 - every parameter)
- ----------------------------------- */
  typedef struct {
  /* PSK */
  char        psk[MPCP_PSK_MAX];
  size_t      psk_len;
  uint32_t    psk_min_entropy;    /* bits; default 40 */
  bool        psk_store;
  
  /* Auth */
  mpcp_auth_mode_t auth_mode;
  char        auth_keydir[512];
  
  /* Calibration */
  uint32_t    ping_count_min;     /* default 60  */
  uint32_t    ping_count_max;     /* default 140 */
  uint32_t    batch_size;         /* default 10  */
  bool        slow_mode;
  uint32_t    slow_mode_min_gap;  /* ms; default 2000 */
  uint32_t    slow_mode_max_gap;  /* ms; default 8000 */
  bool        disguise_calibration;
  mpcp_disguise_proto_t disguise_protocol;
  
  /* RTT estimation */
  double      trim_pct;           /* default 10.0 */
  double      ewma_alpha;         /* default 0.15 */
  double      stddev_multiplier;  /* default 4.0  */
  uint32_t    floor_buffer;       /* ms; default 30 */
  uint32_t    max_catch_window;   /* ms; default 500 */
  
  /* Key exchange */
  uint32_t    key_candidates;     /* default 10  */
  uint32_t    key_exchange_delay; /* ms; default 50 */
  
  /* Transfer */
  uint32_t    pipeline_depth;     /* default 1   */
  uint32_t    chunk_pad_size;     /* default 63488 (62KB, fits IPv4 UDP max) */
  int         zstd_level;         /* default 3   */
  bool        ghost_chunks_enabled;
  uint32_t    ghost_chunk_min;    /* default 5   */
  uint32_t    ghost_chunk_max;    /* default 20  */
  uint32_t    ack_jitter_max;     /* ms; default 80 */
  double      chunk_retry_timeout;/* s;  default 2.0 */
  bool        decoy_encoding;
  
  /* Ports */
  uint16_t    port_base;          /* default 10000 */
  uint32_t    port_range;         /* default 55000 */
  
  /* NAT */
  mpcp_nat_mode_t nat_mode;
  char        rendezvous_host[256];
  uint16_t    rendezvous_port;    /* default 7777 */
  uint32_t    rendezvous_timeout; /* s; default 30 */
  uint32_t    hole_punch_attempts;/* default 5    */
  
  /* Memory and I/O */
  bool        memory_lock;        /* default true */
  bool        zerocopy;           /* default true */
  bool        batch_syscalls;     /* default true */
  
  /* Tripwire */
  bool        tripwire;
  double      tripwire_z_threshold;  /* default 3.5 */
  uint32_t    tripwire_window;       /* default 5   */
  double      tripwire_chi_pvalue;   /* default 0.05 */
  char        canary_log[512];
  
  /* Threading */
  uint32_t    ring_depth;         /* default 4   */
  int         timing_core_id;     /* default 0   */
  } mpcp_config_t;

/* -------------------------

- Session state - shared between modules
- ----------------------------------- */
  typedef struct {
  uint8_t  session_nonce[MPCP_SESSION_NONCE_LEN];
  /* Inline arrays - use sodium_memzero to wipe, never sodium_free */
  uint8_t  master_secret[MPCP_MASTER_SECRET_LEN];
  uint8_t  session_key[MPCP_SESSION_KEY_LEN];
  /* Heap-allocated via sodium_malloc - must sodium_free when done */
  uint8_t *keystream;   /* total_chunks * MPCP_KEYSTREAM_SLOT bytes */
  uint32_t total_chunks;
  bool     skip_compression; /* received from transfer_info flags; tells receiver not to ZSTD_decompress */
  bool     decoy_encoding;   /* S22: chunks wrapped as C header files */
  uint8_t  file_sha256[32];  /* SHA256 of original file — sent by sender, verified by receiver */
  void    *sender_progress;  /* mpcp_sender_progress_t* — set by CLI, read by sender_run */
  uint32_t file_counter;     /* incremented per file; mixes into keystream to prevent nonce reuse */
  } mpcp_session_t;

/* -------------------------

- RTT calibration result (spec S7.3)
- ----------------------------------- */
  typedef struct {
  double trimmed_mean;   /* Stage 1 output (ms) */
  double median_rtt;     /* used for MAD */
  double mad;            /* raw MAD (ms) */
  double robust_std;     /* 1.4826 * MAD */
  double ewma_rtt;       /* Stage 3 live estimate (ms) */
  double catch_window;   /* final computed window (ms) */
  double baseline_mean;  /* for tripwire z-score */
  double baseline_std;   /* for tripwire z-score */
  uint32_t sample_count; /* number of usable RTT samples */
  } mpcp_rtt_result_t;

/* -------------------------

- Wire packet structs (spec S18) - packed, big-endian on wire
- All multi-byte integers stored in host order in these structs;
- serialise/deserialise functions handle byte-order conversion.
- ----------------------------------- */

/* Common 6-byte header (every packet) */
typedef struct __attribute__((packed)) {
uint32_t magic;    /* MPCP_MAGIC */
uint8_t  version;  /* MPCP_VERSION */
uint8_t  type;     /* MPCP_TYPE_* */
} mpcp_hdr_t;

/* S18.1 Calibration packet (ping/pong) - 64 bytes total

- Layout: hdr(6) + seq(2) + send_ts(8) + nonce_hint(16) + padding(32) = 64
  */
  typedef struct __attribute__((packed)) {
  mpcp_hdr_t hdr;
  uint16_t   seq;
  uint64_t   send_ts;            /* nanoseconds, big-endian uint64 */
  uint8_t    nonce_hint[32];     /* full 32B session_nonce */
  uint8_t    padding[16];        /* random */
  } mpcp_cal_pkt_t;

/* S18.2 Key exchange packet - 96 bytes total */
typedef struct __attribute__((packed)) {
mpcp_hdr_t hdr;
uint8_t    key_index;
uint8_t    direction;          /* 0x00 PC1->PC2, 0x01 PC2->PC1 */
uint8_t    xchacha_nonce[24];
uint8_t    encrypted_key[48];  /* 32B key + 16B tag */
uint8_t    padding[16];
} mpcp_key_pkt_t;

/* S18.4 ACK packet - 32 bytes total */
typedef struct __attribute__((packed)) {
mpcp_hdr_t hdr;
uint32_t   ack_seq;
uint32_t   ack_hash;           /* BLAKE2b 4-byte */
uint8_t    padding[18];
} mpcp_ack_pkt_t;

/* S18.5 Bounce packet - 58 bytes total */
typedef struct __attribute__((packed)) {
mpcp_hdr_t hdr;
uint32_t   bounce_seq;
uint8_t    chunk_hash[32];     /* BLAKE2b-256 of received ciphertext */
uint8_t    padding[16];
} mpcp_bounce_pkt_t;

/* Data/ghost chunk header (first MPCP_DATA_HDR_OFFSET bytes, spec S18.3) */
typedef struct __attribute__((packed)) {
mpcp_hdr_t hdr;
uint32_t   seq_index;
uint8_t    retry_count;
uint8_t    flags;              /* bit0=skip_compression bit1=last_chunk */
uint32_t   plaintext_len;
uint8_t    xchacha_nonce[24];
/* ciphertext follows: chunk_pad_size + 16B tag */
} mpcp_chunk_hdr_t;

#define MPCP_FLAG_SKIP_COMPRESSION  0x01
#define MPCP_FLAG_DECOY_ENCODING    0x02  /* S22 chunk wrapped as C header */
#define MPCP_FLAG_LAST_CHUNK        0x02

/* Compile-time wire format size assertions (catch struct layout regressions) */
#define MPCP_STATIC_ASSERT(cond, msg) typedef char static_assert_##msg[(cond) ? 1 : -1]
MPCP_STATIC_ASSERT(sizeof(mpcp_hdr_t)        ==  6, hdr_must_be_6);
MPCP_STATIC_ASSERT(sizeof(mpcp_cal_pkt_t)    == 64, cal_pkt_must_be_64);
MPCP_STATIC_ASSERT(sizeof(mpcp_key_pkt_t)    == 96, key_pkt_must_be_96);
MPCP_STATIC_ASSERT(sizeof(mpcp_ack_pkt_t)    == 32, ack_pkt_must_be_32);
MPCP_STATIC_ASSERT(sizeof(mpcp_bounce_pkt_t) == 58, bounce_pkt_must_be_58);

/* -------------------------

- Utility: monotonic nanosecond clock
- ----------------------------------- */
  static inline uint64_t mpcp_now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
  }

static inline uint64_t mpcp_now_realns(void) {
struct timespec ts;
clock_gettime(CLOCK_REALTIME, &ts);
return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline void mpcp_sleep_until_ns(uint64_t target_ns) {
struct timespec ts;
ts.tv_sec  = (time_t)(target_ns / 1000000000ULL);
ts.tv_nsec = (long)(target_ns % 1000000000ULL);
clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
}

/* -- include/crypto.h -- */
/* Initialise libsodium - call once at startup */
int mpcp_crypto_init(void);

/* HKDF-SHA256 general purpose */
int mpcp_hkdf(const uint8_t *salt,  size_t salt_len,
const uint8_t *ikm,   size_t ikm_len,
const char    *info,
uint8_t       *okm,   size_t out_len);

/* S7.4 Master secret from timing + PSK + OS random + timestamp */
int mpcp_derive_master_secret(const uint8_t  *session_nonce,
const double   *rtt_samples,
uint32_t        rtt_count,
const uint8_t  *psk_bytes,
size_t          psk_len,
uint8_t        *master_secret_out);

/* S7.5 HKDF keystream - returns sodium_malloc'd buffer; caller frees */
uint8_t *mpcp_derive_keystream(const uint8_t *session_key,
uint32_t total_chunks);

/* S7.5 Extract chunk_key and port from keystream slot */
void mpcp_keystream_slot(const uint8_t *keystream,
uint32_t       chunk_index,
uint32_t       port_base,
uint32_t       port_range,
uint8_t       *chunk_key_out,
uint16_t      *port_out);

/* S8.3 Session key finalisation */
int mpcp_derive_session_key(const uint8_t *master_secret,
const uint8_t *selected_candidate,
uint8_t       *session_key_out);

/* S9.4 Chunk encrypt */
int mpcp_chunk_encrypt(const uint8_t *chunk_key,
const uint8_t *session_nonce,
uint32_t       seq_index,
const uint8_t *plaintext,
size_t         plaintext_len,
uint8_t       *ciphertext_out,
size_t        *ciphertext_len_out,
uint8_t        nonce_out[24]);

/* S10 Chunk decrypt */
int mpcp_chunk_decrypt(const uint8_t *chunk_key,
const uint8_t *session_nonce,
uint32_t       seq_index,
const uint8_t *nonce,
const uint8_t *ciphertext,
size_t         ciphertext_len,
uint8_t       *plaintext_out,
size_t        *plaintext_len_out);

/* S9.7 ACK BLAKE2b hash - 4 bytes */
int mpcp_ack_hash(const uint8_t *session_key,
uint32_t       seq_index,
uint8_t        out[4]);

/* S18.5 Bounce oracle hash - BLAKE2b-256 */
int mpcp_bounce_hash(const uint8_t *ciphertext, size_t len,
uint8_t        out[32]);

/* S12.1 Rendezvous token SHA256 */
int mpcp_rendezvous_token(const uint8_t *session_nonce,
const uint8_t *psk_bytes,
size_t         psk_len,
uint8_t        token_out[32]);

/* S9.8 Retry port derivation */
uint16_t mpcp_retry_port(const uint8_t *session_key,
const uint8_t *session_nonce,
uint32_t       chunk_index,
uint32_t       retry_count,
uint32_t       port_base,
uint32_t       port_range);

/* Secure memory */
uint8_t *mpcp_secure_alloc(size_t n);
void     mpcp_secure_free(uint8_t *p, size_t n);

/* Constant-time equality */
bool mpcp_ct_eq(const uint8_t *a, const uint8_t *b, size_t n);

/* S21.5 Abort - zero all session key material */
void mpcp_crypto_abort(mpcp_session_t *sess);

/* -- include/config.h -- */
/* Initialise cfg with compiled-in defaults (call before anything else) */
void mpcp_config_defaults(mpcp_config_t *cfg);

/* Load config file at path; ENOENT is silently ok */
int mpcp_config_load_file(mpcp_config_t *cfg, const char *path);

/* Load ~/.config/mpcp/mpcp.conf */
int mpcp_config_load_default(mpcp_config_t *cfg);

/* Apply deterministic CLI profiles (spec S16.2) */
void mpcp_profile_default(mpcp_config_t *cfg);
void mpcp_profile_wifi(mpcp_config_t *cfg);
void mpcp_profile_fast(mpcp_config_t *cfg);
void mpcp_profile_stealth(mpcp_config_t *cfg);
void mpcp_profile_stealth_decoy(mpcp_config_t *cfg);
void mpcp_profile_internet(mpcp_config_t *cfg);

/* S5.1 Entropy check - returns MPCP_ERR_ENTROPY if below threshold */
int mpcp_config_check_psk(const mpcp_config_t *cfg);

/* PSK entropy estimate in bits */
double mpcp_psk_entropy(const char *psk, size_t len);

/* S5.2 Generate strong PSK - writes null-terminated string to out */
int mpcp_generate_psk(char *out, size_t out_size);

/* Sanity-check parameter combinations */
int mpcp_config_validate(const mpcp_config_t *cfg);

/* Dump current config in conf-file format */
void mpcp_config_dump(const mpcp_config_t *cfg, FILE *out);

/* -- include/calibrate.h -- */
#include <netinet/in.h>

/*

- Main calibration entry point - runs full Phase 2.
- Sends pings to peer, collects RTTs, runs trimmed mean + MAD + EWMA pipeline,
- runs mini re-calibration, returns populated result.
  */
  int mpcp_calibrate(const mpcp_config_t     *cfg,
  const mpcp_session_t    *sess,
  const struct sockaddr_in *peer_addr,
  mpcp_rtt_result_t       *result_out);

/*

- Variant that also returns raw RTT samples for use as timing entropy
- in master secret derivation (S7.4). Caller must free(*samples_out).
  */
  int mpcp_calibrate_collect_samples(const mpcp_config_t     *cfg,
  const mpcp_session_t    *sess,
  const struct sockaddr_in *peer,
  double                 **samples_out,
  uint32_t               *count_out,
  mpcp_rtt_result_t      *result_out);

/* Live EWMA update - call on each bounce oracle RTT during transfer */
void mpcp_cal_ewma_update(mpcp_rtt_result_t *result,
double new_rtt_ms,
double alpha);

/* Z-score of a new oracle RTT against calibration baseline */
double mpcp_cal_zscore(const mpcp_rtt_result_t *result, double oracle_rtt_ms);

/* Conservative tripwire fallback when sample_count < 30 */
bool mpcp_cal_tripwire_fallback(const mpcp_rtt_result_t *result,
double oracle_rtt_ms);

/*

- Set up SCHED_FIFO and CPU affinity for the port timing thread.
- Call from within the timing thread (not main thread).
- core_id: CPU core to pin to, or -1 to skip pinning.
  */
  int mpcp_timing_thread_setup(int core_id);

/* -- include/disguise.h -- */
/*

- disguise.c - spec S7.2 / S22 / S25.6 step 10
- 
- Wraps MPCP calibration packets in DNS or NTP-formatted shells
- for DPI resistance. Full implementation is module 10 in build order.
- 
- These stubs pass data through unchanged so calibrate.c compiles
- and works correctly even before disguise.c is fully implemented.
  */

/* Wrap src[src_len] in disguise format -> dst[]. Returns bytes written, 0 on error. */
size_t mpcp_disguise_wrap(const uint8_t       *src,
size_t               src_len,
uint8_t             *dst,
size_t               dst_size,
mpcp_disguise_proto_t proto);

/* Unwrap disguise -> dst[]. Returns payload bytes, 0 on error. */
size_t mpcp_disguise_unwrap(const uint8_t       *src,
size_t               src_len,
uint8_t             *dst,
size_t               dst_size,
mpcp_disguise_proto_t proto);

/* -- include/keygen.h -- */
/*

- keygen.h - MPCP Phase 3: Key generation
- 
- Covers spec sections:
- S8.1  Parallel candidate key generation (PC1)
- S5.3  Ed25519 keypair generation and signing
- S8.3  Session key finalisation (delegates to crypto.c)
  */

/* -------------------------

- Candidate key pool (PC1 side)
- 
- N candidate keys are generated fresh per session.
- All are stored in sodium_malloc'd locked memory.
- All N-1 losers are zeroed immediately after session key is derived.
- ----------------------------------- */
  typedef struct {
  uint32_t  n;                         /* number of candidates (key_candidates) */
  uint8_t **keys;                      /* keys[n][32] - each sodium_malloc'd   */
  } mpcp_candidates_t;

/* Generate N fresh 32-byte candidate keys via getrandom.

- Each key is individually sodium_malloc'd and mlock'd.
- Returns MPCP_OK or MPCP_ERR_ALLOC / MPCP_ERR_CRYPTO. */
  int mpcp_keygen_candidates(uint32_t n, mpcp_candidates_t *out);

/* Zero and free all candidate keys + the struct arrays.

- Safe to call even if mpcp_keygen_candidates partially failed. */
  void mpcp_keygen_candidates_free(mpcp_candidates_t *cands);

/* Zero and free all candidates except the one at keep_idx.

- Used after session key derivation to wipe the N-1 losers. */
  void mpcp_keygen_candidates_wipe_losers(mpcp_candidates_t *cands,
  uint32_t           keep_idx);

/* -------------------------

- Ed25519 keypair management (S5.3)
- ----------------------------------- */

/* Generate a fresh Ed25519 keypair and write to keydir.

- Creates keydir if it does not exist.
- Files: keydir/mpcp_ed25519.sk (secret, mode 0600)
     keydir/mpcp_ed25519.pk (public, mode 0644) */

int mpcp_ed25519_keygen(const char *keydir);

/* Load secret key from keydir/mpcp_ed25519.sk into sk_out[64].

- sk_out must be sodium_malloc'd by caller. */
  int mpcp_ed25519_load_sk(const char *keydir, uint8_t *sk_out);

/* Load public key from keydir/mpcp_ed25519.pk into pk_out[32]. */
int mpcp_ed25519_load_pk(const char *keydir, uint8_t *pk_out);

/* Load peer public key from keydir/mpcp_ed25519_peer.pk into pk_out[32]. */
int mpcp_ed25519_load_peer_pk(const char *keydir, uint8_t *pk_out);

/* Sign a session transcript hash (32 bytes) with our secret key.

- sig_out must be 64 bytes. */
  int mpcp_ed25519_sign(const uint8_t *sk,          /* 64B */
  const uint8_t *transcript,  /* 32B */
  uint8_t       *sig_out);    /* 64B */

/* Verify a peer signature over a transcript hash.

- Returns MPCP_OK if valid, MPCP_ERR_CRYPTO if invalid. */
  int mpcp_ed25519_verify(const uint8_t *peer_pk,    /* 32B */
  const uint8_t *transcript, /* 32B */
  const uint8_t *sig);       /* 64B */

/* -------------------------

- Session transcript hash for Ed25519 (S5.3)
- 
- transcript = BLAKE2b-256(session_nonce || master_secret || "mpcp-v0.5-auth")
- Signed during key exchange phase to authenticate the session.
- ----------------------------------- */
  int mpcp_session_transcript(const uint8_t *session_nonce,  /* 32B */
  const uint8_t *master_secret,  /* 32B */
  uint8_t        transcript_out[32]);

/* -- include/exchange.h -- */
/*

- exchange.h - MPCP key exchange (S8)
- 
- Spec sections:
- S8.1  Parallel candidate key transmission (PC1 sends N keys simultaneously)
- S8.2  Constant-time blind selection - 8-step sequence on PC2
- S8.3  Session key finalisation
- S5.3  Ed25519 session transcript signing / verification
- S18.2 Key exchange wire packet format
  */

#include <netinet/in.h>

/* -------------------------

- S18.2  Wire format helpers
- 
- Encrypt a 32-byte candidate key into a 96-byte key exchange packet.
- Uses XChaCha20-Poly1305 keyed under master_secret.
- AD = key_index(1) || direction(1) || xchacha_nonce[0:32]
- 
- direction: 0x00 = PC1->PC2, 0x01 = PC2->PC1
- ----------------------------------- */
  int mpcp_kex_pack(const uint8_t  *master_secret,  /* 32B */
  const uint8_t  *candidate_key,  /* 32B */
  uint8_t         key_index,
  uint8_t         direction,
  mpcp_key_pkt_t *pkt_out);

/* Decrypt a key exchange packet -> candidate_key_out[32].

- Returns MPCP_ERR_PROTO on bad header, MPCP_ERR_CRYPTO on tag failure. */
  int mpcp_kex_unpack(const uint8_t        *master_secret,  /* 32B */
  const mpcp_key_pkt_t *pkt,
  uint8_t              *candidate_key_out); /* 32B */

/* -------------------------

- S8.1  PC1 (initiator) side of key exchange
- 
- Generates N candidate keys, sends all N in parallel to PC2.
- Waits for PC2 to return N-1 keys, identifies the withheld (selected) key.
- Derives session_key via S8.3, wipes the N-1 losers.
- Optionally signs session transcript (S5.3).
- 
- cands_out is populated with the N keys; caller must free with
- mpcp_keygen_candidates_free() after session teardown.
- ----------------------------------- */
  int mpcp_exchange_pc1(const mpcp_config_t     *cfg,
  mpcp_session_t          *sess,    /* fills sess->session_key */
  const struct sockaddr_in *pc2_addr,
  mpcp_candidates_t       *cands_out);

/* -------------------------

- S8.2  PC2 (responder) side of key exchange
- 
- Implements the 8-step constant-time blind selection exactly.
- Corrected step order: 1->2->3->4->5->[S8.3 derive]->6->7->8
- 
- Step 7 sleep until T_recv + key_exchange_delay masks all timing variance
- from the selection steps.  Optionally verifies PC1 Ed25519 signature.
- ----------------------------------- */
  int mpcp_exchange_pc2(const mpcp_config_t     *cfg,
  mpcp_session_t          *sess,    /* fills sess->session_key */
  const struct sockaddr_in *pc1_addr);

/* -- include/tripwire.h -- */
/*

- tripwire.h - Interception detection (spec S21)
- 
- S21.1  Three anomaly classes; any trigger -> silent abort + canary log
- S21.2  Class 1: z-score timing oracle
      z = (oracle_rtt - baseline_mean) / baseline_std
      fallback if sample_count < 30: threshold = baseline_mean * 3
- S21.3  Class 2: chi-squared loss pattern analysis
- S21.4  Class 3: unexpected decoy response (handled in calibrate)
- S21.5  Abort procedure: sodium_memzero all key material, close sockets,
      write canary log, exit(0) - zero network signal

*/

/* -------------------------

- Running tripwire state - one per active transfer
- ----------------------------------- */
  typedef struct {
  /* S21.2 Z-score oracle */
  double   baseline_mean;        /* from mpcp_rtt_result_t               */
  double   baseline_std;         /* from mpcp_rtt_result_t               */
  uint32_t sample_count;         /* calibration ping count               */
  double   z_threshold;          /* cfg->tripwire_z_threshold            */
  uint32_t window;               /* cfg->tripwire_window                 */
  uint32_t consecutive_anomalies;/* current streak                       */
  
  /* S21.3 Loss pattern */
  uint32_t lost_indices[4096];   /* seq indices of lost chunks           */
  uint32_t lost_count;
  double   chi_pvalue;           /* cfg->tripwire_chi_pvalue             */
  
  bool     triggered;            /* set on first anomaly class fire      */
  } mpcp_tripwire_t;

/* Initialise from calibration result and config */
void mpcp_tripwire_init(mpcp_tripwire_t          *tw,
const mpcp_rtt_result_t  *rtt,
const mpcp_config_t      *cfg);

/*

- S21.2  Feed one bounce RTT measurement (milliseconds).
- Returns MPCP_ERR_TRIPWIRE if abort threshold crossed, else MPCP_OK.
  */
  int mpcp_tripwire_feed_rtt(mpcp_tripwire_t *tw, double oracle_rtt_ms);

/*

- S21.3  Record a lost chunk index for loss-pattern analysis.
- Returns MPCP_ERR_TRIPWIRE if chi-squared test fails, else MPCP_OK.
  */
  int mpcp_tripwire_record_loss(mpcp_tripwire_t *tw, uint32_t seq_index);

/*

- S21.5  Abort: zero key material, close sockets, write canary log.
- sess may be NULL (best-effort zeroing in that case).
  */
  void mpcp_tripwire_abort(mpcp_tripwire_t  *tw,
  mpcp_session_t   *sess,
  const char       *canary_log_path,
  const char       *anomaly_type);

/* -- include/chunker.h -- */
/*

- chunker.h - Chunk planning, padding, encryption, ghost generation (spec S9)
- 
- S9.1  Compressibility detection: sample 64 KB, compress at level 1,
     skip compression if ratio > 0.95
- S9.3  Distributed remainder: first (size % N) chunks get floor+1 bytes
- S9.4  Chunk encryption: pad to chunk_pad_size, XChaCha20-Poly1305,
     AD = seq_index(4B) || session_nonce(32B)
- S9.5  Ghost chunk: full-size random encrypted chunk, indistinguishable
     from data; ghost_map derived deterministically from session_key

*/

/* -------------------------

- S9.3  Chunk plan - computed once per session from compressed file size
- ----------------------------------- */
  typedef struct {
  uint32_t n_chunks;          /* total data chunk count                */
  uint32_t base_chunk_bytes;  /* floor(compressed_size / n_chunks)     */
  uint32_t n_larger;          /* first n_larger chunks are +1 byte     */
  uint32_t chunk_pad_size;    /* padding target (from config)          */
  bool     skip_compression;
  } mpcp_chunk_plan_t;

/*

- S9.1  Compressibility detection.
- src/src_len: first up to 65536 bytes of the raw file.
- Writes plan->skip_compression.  Returns MPCP_OK.
  */
  int mpcp_chunker_detect_compressibility(const uint8_t     *src,
  size_t             src_len,
  mpcp_chunk_plan_t *plan);

/*

- S9.3  Build chunk plan from compressed_size.
- Call after compressibility detection (or with skip_compression=true and
- compressed_size = raw file size).
  */
  int mpcp_chunker_plan(size_t             compressed_size,
  uint32_t           chunk_pad_size,
  bool               skip_compression,
  mpcp_chunk_plan_t *plan_out);

/* S9.3  Byte count for data chunk chunk_idx (0-indexed). */
uint32_t mpcp_chunk_data_size(const mpcp_chunk_plan_t *plan,
uint32_t                 chunk_idx);

/*

- S9.4  Pad plaintext to chunk_pad_size then encrypt.
- plaintext / plaintext_len : compressed chunk data
- chunk_key                 : 32 B from keystream slot seq
- session_nonce             : 32 B
- seq                       : sequence index (in AEAD AD)
- ct_out                    : caller allocates chunk_pad_size + 16 B
- ct_len_out                : filled with ciphertext length
- nonce_out                 : 24 B filled with fresh random nonce
- flags                     : MPCP_FLAG_* (skip_compression, last_chunk)
  */
  int mpcp_chunker_encrypt_chunk(const uint8_t *plaintext,
  uint32_t       plaintext_len,
  const uint8_t *chunk_key,
  const uint8_t *session_nonce,
  uint32_t       seq,
  uint8_t       *ct_out,
  size_t        *ct_len_out,
  uint8_t        nonce_out[24],
  uint8_t        flags,
  uint32_t       chunk_pad_size);

/*

- S9.5  Generate one ghost chunk.
- ghost_seq  : sequence index (>= n_data_chunks)
- chunk_key  : 32 B key from keystream slot ghost_seq
- ct_out     : caller allocates chunk_pad_size + 16 B
  */
  int mpcp_chunker_generate_ghost(const uint8_t *chunk_key,
  const uint8_t *session_nonce,
  uint32_t       ghost_seq,
  uint32_t       chunk_pad_size,
  uint8_t       *ct_out,
  size_t        *ct_len_out,
  uint8_t        nonce_out[24]);

/*

- S9.5  Ghost map: derive ghost count and ghost seq indices.
- Both sender and receiver call this identically to agree on which seqs
- are ghosts.  ghost_seqs_out must hold at least ghost_chunk_max entries.
  */
  int mpcp_ghost_map(const uint8_t *session_key,
  uint32_t       n_data_chunks,
  uint32_t       ghost_chunk_min,
  uint32_t       ghost_chunk_max,
  uint32_t      *ghost_seqs_out,
  uint32_t      *count_out);

/* -- include/nat.h -- */
/*

- nat.h - NAT traversal: rendezvous token and UDP hole punching (spec S12)
- 
- S12.1  rendezvous_token = SHA256(session_nonce || psk_bytes)
      Server sees only opaque token - stateless, discards after exchange.
- S12.2  Hole punching flow: both sides send token to rendezvous server,
      receive each other's public address, then fire simultaneous UDP
      punches (hole_punch_attempts times).

*/

#include <netinet/in.h>

/*

- S12.2  Attempt NAT traversal.
- 
- If cfg->nat_mode == MPCP_NAT_DIRECT: fills peer_addr_out with
- cfg->rendezvous_host:cfg->rendezvous_port and returns MPCP_OK
- (caller must have pre-configured the peer address as the rendezvous).
- 
- If MPCP_NAT_AUTO or MPCP_NAT_FORCE: connects to rendezvous server,
- sends token, receives peer address, performs UDP hole punching.
- 
- On success: peer_addr_out is filled with the peer's reachable address.
- Returns MPCP_OK or MPCP_ERR_NAT.
  */
  int mpcp_nat_traverse(const mpcp_config_t      *cfg,
  mpcp_session_t           *sess,
  struct sockaddr_in       *peer_addr_out);

/*

- S12.1  Compute rendezvous token = SHA256(session_nonce || psk_bytes).
- token_out must be 32 bytes.
  */
  int mpcp_nat_token(const uint8_t *session_nonce,
  const uint8_t *psk_bytes,
  size_t         psk_len,
  uint8_t        token_out[32]);

/* -- include/pipeline.h -- */
/*

- pipeline.h - 4-stage streaming pipeline, ring buffers, sender, receiver
- 
- S9.2   Four-stage lock-free SPSC ring buffer pipeline
      [Reader]->ring0->[Compress]->ring1->[Crypto]->ring2->[Sender+ghost]
- S9.6   Configurable pipeline_depth (1-8)
- S9.7   ACK: BLAKE2b(seq, key=session_key, outlen=4) + jitter
- S9.8   Retry: fresh port from HKDF(session_key,"retry"||i||r||nonce)
- S9.9   MSG_ZEROCOPY / sendmmsg / recvmmsg with graceful fallback
- S10    Reassembly: Receiver->ring0->Verifier->ring1->Decryptor->ring2->Writer
- S11    Silent session termination - no FIN, key zeroing on completion
- S19    Threading model - SCHED_FIFO port-timing thread pinned to core
  */

#include <netinet/in.h>

/* =========================================================================

- S9.2  Lock-free SPSC ring buffer
- ====================================================================== */

typedef enum {
MPCP_SLOT_EMPTY    = 0,   /* producer may claim */
MPCP_SLOT_FILLING  = 1,   /* producer writing - consumer must not read */
MPCP_SLOT_FULL     = 2,   /* consumer may read */
} mpcp_slot_state_t;

typedef struct {
_Atomic(int)  state;       /* mpcp_slot_state_t stored as int       */

uint32_t  seq_index;
uint8_t   flags;
uint32_t  data_len;        /* valid bytes in buf (before padding)   */

uint8_t  *buf;             /* chunk_pad_size + 16 B (tag)           */
size_t    buf_capacity;

uint8_t   nonce[24];       /* filled by crypto stage                */
size_t    ct_len;          /* filled by crypto stage                */

} mpcp_ring_slot_t;

typedef struct {
mpcp_ring_slot_t *slots;
uint32_t          depth;
_Atomic(uint32_t) head;    /* producer index                        */
_Atomic(uint32_t) tail;    /* consumer index                        */
} mpcp_ring_t;

int               mpcp_ring_init(mpcp_ring_t *r, uint32_t depth,
uint32_t chunk_pad_size);
void              mpcp_ring_destroy(mpcp_ring_t *r);
mpcp_ring_slot_t *mpcp_ring_claim(mpcp_ring_t *r);      /* producer      */
void              mpcp_ring_publish(mpcp_ring_t *r, mpcp_ring_slot_t *s);
mpcp_ring_slot_t *mpcp_ring_consume(mpcp_ring_t *r);    /* consumer      */
void              mpcp_ring_release(mpcp_ring_t *r, mpcp_ring_slot_t *s);
void              mpcp_ring_release_plain(mpcp_ring_t *r, mpcp_ring_slot_t *s); /* no wipe */

/* =========================================================================

- S10  Bitmask dedup - 512K-entry bitset, thread-safe atomic bit test-and-set
- ====================================================================== */

#define MPCP_DEDUP_BITS   (512u * 1024u)
#define MPCP_DEDUP_BYTES  (MPCP_DEDUP_BITS / 8u)

typedef struct {
_Atomic(uint8_t) bits[MPCP_DEDUP_BYTES];
} mpcp_dedup_t;

void mpcp_dedup_init(mpcp_dedup_t *d);
/* Returns true if seq was unseen (accept); false = duplicate (drop). */
bool mpcp_dedup_accept(mpcp_dedup_t *d, uint32_t seq);

/* Sender live-progress hook: set before mpcp_sender_run, read from display thread */
typedef struct {
    _Atomic(uint32_t) *acks_received;  /* atomically incremented per ACK */
    uint32_t           n_chunks;       /* total data chunks expected */
} mpcp_sender_progress_t;

/* =========================================================================

- S9.2 / S19  Sender context (shared across all sender threads)
- ====================================================================== */

typedef struct {
const mpcp_config_t      *cfg;
mpcp_session_t           *sess;
const struct sockaddr_in *peer_addr;

mpcp_chunk_plan_t         plan;

mpcp_ring_t               ring0;   /* Reader -> Compressor             */
mpcp_ring_t               ring1;   /* Compressor -> Crypto             */
mpcp_ring_t               ring2;   /* Crypto -> Sender                 */

int                       file_fd;
size_t                    file_size;

/* S9.5  Ghost map */
uint32_t                  ghost_seqs[64];
uint32_t                  ghost_count;

/* ACK tracking */
_Atomic(uint32_t)         acks_received;
mpcp_dedup_t              ack_dedup;

/* Retry system:
 * retry_queue: ring buffer of seq indices that need resending
 * retry_cache: encrypted chunk data indexed by seq (filled by T4, read by retry) */
_Atomic(uint32_t)         retry_queue[256];
_Atomic(uint32_t)         retry_head;
_Atomic(uint32_t)         retry_tail;

/* Cache of encrypted chunks for retry (heap-allocated, freed after all ACKs) */
uint8_t                 **retry_cache;      /* [n_chunks] -> encrypted data */
size_t                   *retry_cache_lens; /* [n_chunks] -> ct_len */
uint8_t                (*retry_nonces)[24]; /* [n_chunks] -> nonce */
uint32_t                 *retry_data_lens;  /* [n_chunks] -> data_len */
uint8_t                  *retry_flags;      /* [n_chunks] -> flags */

/* Sent-but-unacked tracking: bit per seq, for timeout detection */
_Atomic(bool)            *sent_flag;        /* [n_chunks] */
uint64_t                 *sent_time_ns;     /* [n_chunks] -> send timestamp */

_Atomic(bool)             abort_flag;
_Atomic(bool)             t1_done;
_Atomic(bool)             t2_done;
mpcp_tripwire_t           tripwire;
} mpcp_sender_ctx_t;

/* =========================================================================

- S10 / S19  Receiver context
- ====================================================================== */

typedef struct {
const mpcp_config_t      *cfg;
mpcp_session_t           *sess;
const struct sockaddr_in *peer_addr; /* sender IP — used to reject injected chunks */

mpcp_chunk_plan_t         plan;

mpcp_ring_t               ring0;   /* Receiver -> Verifier             */
mpcp_ring_t               ring1;   /* Verifier -> Decryptor            */
mpcp_ring_t               ring2;   /* Decryptor -> Writer              */

int                       out_fd;

mpcp_dedup_t              dedup;

uint32_t                  ghost_seqs[64];
uint32_t                  ghost_count;

/* Output file path (for resume sidecar) */
const char               *out_path;

/* Reorder buffer */
uint8_t                 **chunk_store;
uint32_t                 *chunk_lens;
bool                     *chunk_ready;
uint32_t                  next_write_seq;

/* OPT: reusable per-thread decrypt buffer - eliminates malloc/free per chunk */
uint8_t                  *decrypt_buf;
size_t                    decrypt_buf_sz;

_Atomic(uint32_t)         chunks_verified;
_Atomic(bool)             abort_flag;
/* Pipeline stage completion flags — set by each stage when it has
 * finished producing. Downstream stages wait on these before exiting
 * so no buffered work is lost. abort_flag is for hard errors only. */
_Atomic(bool)             t1_done;   /* T1 finished receiving */
_Atomic(bool)             t2_done;   /* T2 finished verifying */
_Atomic(bool)             t3_done;   /* T3 finished decrypting */
mpcp_tripwire_t           tripwire;

} mpcp_receiver_ctx_t;

/* =========================================================================

- Public entry points
- ====================================================================== */

/*

- S9.2 / S19  Run sender pipeline; blocks until complete or abort.
- file_path -> peer_addr via cfg session.
  */
  int mpcp_sender_run(const mpcp_config_t      *cfg,
  mpcp_session_t           *sess,
  const struct sockaddr_in *peer_addr,
  const char               *file_path);

/*

- S10 / S19  Run receiver pipeline; blocks until complete or abort.
- Writes reassembled file to out_path.
  */
  int mpcp_receiver_run(const mpcp_config_t      *cfg,
  mpcp_session_t            *sess,
  const struct sockaddr_in  *peer_addr,
  const char                *out_path,
  uint32_t                   n_chunks);

/* =========================================================

- Implementation (src/)
- ========================================================= */



/* g_ui_colour: true when colour output is enabled (defined in src/ui.c) */
extern bool g_ui_colour;

/* ── Colour UI macros (active when compiled with -DMPCP_COLOUR_UI=1) ── */
#ifdef MPCP_COLOUR_UI
#define C_PLUM    "\033[38;2;200;150;255m"   /* bright violet       */
#define C_VIOLET  "\033[38;2;160;100;220m"   /* medium purple       */
#define C_GRAPE   "\033[38;2;110;60;170m"    /* deep purple         */
#define C_ORCHID  "\033[38;2;180;120;240m"   /* orchid              */
#define C_WHITE   "\033[38;2;230;220;255m"   /* soft white          */
#define C_GREY    "\033[38;2;130;120;150m"   /* muted grey          */
#define C_LIME    "\033[38;2;140;255;160m"   /* success green       */
#define C_ROSE    "\033[38;2;255;100;110m"   /* error red           */
#define C_GOLD    "\033[38;2;255;220;100m"   /* warning amber       */
#define C_CYAN    "\033[38;2;100;220;255m"   /* info cyan           */
#define C_RESET   "\033[0m"
#define C_BOLD    "\033[1m"
#define C_DIM     "\033[2m"
#define C_BLINK   "\033[5m"
#define C_NOCURSOR "\033[?25l"
#define C_CURSOR   "\033[?25h"
#define GLYPH_DOT   "\xc2\xb7"          /* · middle dot         */
#define GLYPH_STAR  "\xe2\x98\x85"      /* ★ black star         */
#define GLYPH_LOCK  "\xf0\x9f\x94\x92" /* 🔒 padlock (UTF-8)   */
#define GLYPH_BOLT  "\xe2\x9a\xa1"      /* ⚡ lightning         */
#define GLYPH_OK    "\xe2\x9c\x93"      /* ✓ check              */
#define GLYPH_FAIL  "\xe2\x9c\x97"      /* ✗ cross              */
#define GLYPH_ARR   "\xe2\x86\x92"      /* → arrow              */
#define GLYPH_WAVE  "\xe2\x88\xbf"      /* ∿ sine wave          */
#define GLYPH_SKULL "\xe2\x98\xa0"      /* ☠ tripwire warning   */
#define GLYPH_GEM   "\xe2\x97\x86"      /* ◆ diamond            */
#else
/* Headless build: colour macros are empty strings */
#define C_PLUM   "" 
#define C_VIOLET "" 
#define C_GRAPE  "" 
#define C_ORCHID ""
#define C_WHITE  "" 
#define C_GREY   "" 
#define C_LIME   "" 
#define C_ROSE   "" 
#define C_GOLD   "" 
#define C_CYAN   "" 
#define C_RESET  "" 
#define C_BOLD   "" 
#define C_DIM    "" 
#define C_BLINK  "" 
#define C_NOCURSOR ""
#define C_CURSOR ""
#define GLYPH_DOT  "."
#define GLYPH_STAR "*"
#define GLYPH_LOCK "[lock]"
#define GLYPH_BOLT "!"
#define GLYPH_OK   "OK"
#define GLYPH_FAIL "FAIL"
#define GLYPH_ARR  "->"
#define GLYPH_WAVE "~"
#define GLYPH_SKULL "[!]"
#define GLYPH_GEM  "*"
#endif /* MPCP_COLOUR_UI */


/* checked_sendto: retries EINTR, warns on other errors */
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
static inline ssize_t checked_sendto(int sockfd, const void *buf, size_t len,
    int flags, const struct sockaddr *dest, socklen_t destlen)
{
    ssize_t sent;
    do { sent = sendto(sockfd, buf, len, flags, dest, destlen); }
    while (sent < 0 && errno == EINTR);
    if (sent < 0)
        perror("checked_sendto failed");
    return sent;
}

static inline int checked_pthread_create(pthread_t *thread,
    const pthread_attr_t *attr, void *(*start)(void*), void *arg)
{
    int r = pthread_create(thread, attr, start, arg);
    if (r != 0) fprintf(stderr, "pthread_create failed: %s\n", strerror(r));
    return r;
}

/* Resume sidecar helpers (defined in src/cli.c) */

/* ── Forward declarations for CLI / test helpers ── */
/* Defined in src/cli.c */
void  contacts_load(void);
void  cmd_contacts(void);
int   read_line(const char *prompt, char *buf, size_t size);
bool  ask_yn(const char *question, bool default_yes);
bool  resume_exists(const char *out_path);
void  banner(const char *title);
void  fw_maybe_open(uint16_t base, uint32_t range);
void  fw_cleanup(void);
int   run_transfer(void);
int   run_bench(void);
int   run_selftest(void);
int   run_listen_once(void);
int   main_test(void);
void  resume_record(const char *out_path, uint32_t seq);
void  resume_clear(const char *out_path);
uint32_t resume_load(const char *out_path, bool *done, uint32_t max);
int   transfer_info_recv(mpcp_session_t *sess, const mpcp_config_t *cfg,
                          uint32_t *n_chunks_out, uint8_t *flags_out);

/* Defined in src/pipeline.c */
int pong_server(const mpcp_config_t *cfg, struct sockaddr_in *sender_out,
                uint8_t *nonce_hint_out, bool prompt_accept);

/* Test entry points (defined in tests/) */
int mpcp_test_core_main(void);
int mpcp_test_phase3_main(void);

/* Defined in src/crypto.c */
void mpcp_perror(const char *stage, int rc);


int mpcp_turn_relay(const mpcp_config_t *cfg, const mpcp_session_t *sess,
                    struct sockaddr_in *peer_addr_out, bool is_initiator);

/* Decoy encoding (S22) */
size_t mpcp_decoy_max_len(size_t ct_len);
size_t mpcp_decoy_wrap(const uint8_t *ct, size_t ct_len, uint8_t *out, size_t out_cap);
size_t mpcp_decoy_unwrap(const uint8_t *wrapped, size_t wrapped_len, uint8_t *out, size_t out_cap);
#endif /* MPCP_H */
