/* AethroSync — src/pipeline.c — ring buffers, sender/receiver pipeline threads */
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
#include <sys/epoll.h>
#include <sys/random.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdatomic.h>
#include <sodium.h>
#include <zstd.h>
#include "../include/mpcp.h"

/* ========== src/pipeline.c ========== */
/*

- pipeline.c - 4-stage streaming pipeline, ring buffers, sender, receiver
- 
- S9.2   Lock-free SPSC ring buffer (4 states: EMPTY->FULL)
- S9.6   pipeline_depth 1-8 chunks in flight
- S9.7   ACK: BLAKE2b(seq, key=session_key, outlen=4) + jitter delay
- S9.8   Retry: HKDF(session_key,"retry"||i||r||session_nonce) port
- S9.9   MSG_ZEROCOPY + sendmmsg/recvmmsg with graceful fallback
- S10    Reassembly: receive -> verify -> decrypt -> write in order
- S11    Silent termination - key zeroing, no network signal
- S19    Port Timing thread: SCHED_FIFO priority 80, pinned to core
  */

#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* =========================================================================

- S9.2  Lock-free SPSC ring buffer
- ====================================================================== */

int mpcp_ring_init(mpcp_ring_t *r, uint32_t depth, uint32_t chunk_pad_size)
{
if (!r || depth == 0 || chunk_pad_size == 0) return MPCP_ERR_PARAM;

r->depth = depth;
atomic_store_explicit(&r->head, 0u, memory_order_relaxed);
atomic_store_explicit(&r->tail, 0u, memory_order_relaxed);

r->slots = calloc(depth, sizeof(mpcp_ring_slot_t));
if (!r->slots) return MPCP_ERR_ALLOC;

size_t buf_cap = (size_t)chunk_pad_size + 16u;  /* +16 Poly1305 tag */
for (uint32_t i = 0; i < depth; i++) {
    r->slots[i].buf = malloc(buf_cap);
    if (!r->slots[i].buf) {
        /* Free already-allocated slots */
        for (uint32_t j = 0; j < i; j++) free(r->slots[j].buf);
        free(r->slots);
        r->slots = NULL;
        return MPCP_ERR_ALLOC;
    }
    r->slots[i].buf_capacity = buf_cap;
    atomic_store_explicit(&r->slots[i].state,
                           (int)MPCP_SLOT_EMPTY,
                           memory_order_relaxed);
}
return MPCP_OK;

}

void mpcp_ring_destroy(mpcp_ring_t *r)
{
if (!r || !r->slots) return;
for (uint32_t i = 0; i < r->depth; i++) {
if (r->slots[i].buf) {
sodium_memzero(r->slots[i].buf, r->slots[i].buf_capacity);
free(r->slots[i].buf);
r->slots[i].buf = NULL;
}
}
free(r->slots);
r->slots = NULL;
}

/* Producer: spin until an EMPTY slot is available, mark it FILLING.

- BUG-P3-1 FIX: slot is not visible to consumer until mpcp_ring_publish()
- marks it FULL.  Old code marked FULL in claim() before data was written,
- allowing the consumer to read uninitialised data (SPSC race). */
  mpcp_ring_slot_t *mpcp_ring_claim(mpcp_ring_t *r)
  {
  for (;;) {
  uint32_t h    = atomic_load_explicit(&r->head, memory_order_relaxed);
  uint32_t idx  = h % r->depth;
  int      st   = atomic_load_explicit(&r->slots[idx].state,
  memory_order_acquire);
  if (st == (int)MPCP_SLOT_EMPTY) {
  atomic_store_explicit(&r->slots[idx].state,
  (int)MPCP_SLOT_FILLING, memory_order_release);
  atomic_fetch_add_explicit(&r->head, 1u, memory_order_relaxed);
  return &r->slots[idx];
  }
  /* Adaptive backoff: spin briefly then yield to avoid wasting a core */
  for (int _s = 0; _s < 16; _s++) {
  #if defined(__x86_64__) || defined(__i386__)
      __asm__ volatile("pause" ::: "memory");
  #else
      __asm__ volatile("yield" ::: "memory");
  #endif
  }
  sched_yield();
  }
  }

void mpcp_ring_publish(mpcp_ring_t *r, mpcp_ring_slot_t *s)
{
/* Transition FILLING -> FULL: makes slot visible to consumer. */
(void)r;
atomic_store_explicit(&s->state, (int)MPCP_SLOT_FULL, memory_order_release);
}

/* Consumer: return next FULL slot, or NULL if ring is empty */
mpcp_ring_slot_t *mpcp_ring_consume(mpcp_ring_t *r)
{
uint32_t t   = atomic_load_explicit(&r->tail, memory_order_relaxed);
uint32_t idx = t % r->depth;
int      st  = atomic_load_explicit(&r->slots[idx].state,
memory_order_acquire);
if (st != (int)MPCP_SLOT_FULL) return NULL;
atomic_fetch_add_explicit(&r->tail, 1u, memory_order_relaxed);
return &r->slots[idx];
}

void mpcp_ring_release(mpcp_ring_t *r, mpcp_ring_slot_t *s)
{
/* Secure release: wipe buffer contents before returning slot to pool.
 * Use for rings carrying key material or ciphertext (ring2 on sender,
 * ring0/ring1/ring2 on receiver). */
(void)r;
sodium_memzero(s->buf, s->buf_capacity);
atomic_store_explicit(&s->state, (int)MPCP_SLOT_EMPTY, memory_order_release);
}

void mpcp_ring_release_plain(mpcp_ring_t *r, mpcp_ring_slot_t *s)
{
/* Non-secure release: no wipe. Use for rings carrying only plaintext
 * file data (ring0 and ring1 on the sender side). */
(void)r;
atomic_store_explicit(&s->state, (int)MPCP_SLOT_EMPTY, memory_order_release);
}

/* =========================================================================

- S10  Bitmask dedup
- ====================================================================== */

void mpcp_dedup_init(mpcp_dedup_t *d)
{
memset(d, 0, sizeof(*d));
}

bool mpcp_dedup_accept(mpcp_dedup_t *d, uint32_t seq)
{
if (seq >= MPCP_DEDUP_BITS) return false;  /* out of range - drop */
uint32_t byte_idx = seq / 8u;
uint8_t  bit_mask = (uint8_t)(1u << (seq & 7u));

/* Atomic test-and-set */
uint8_t prev = atomic_fetch_or_explicit(&d->bits[byte_idx],
                                         bit_mask,
                                         memory_order_acq_rel);
return (prev & bit_mask) == 0;  /* true = first time seen */

}

/* =========================================================================

- Port derivation helper (wraps keystream slot)
- ====================================================================== */
  static uint16_t chunk_port(mpcp_session_t *sess,
  const mpcp_config_t *cfg,
  uint32_t seq)
  {
  uint8_t  ckey[32];
  uint16_t port;
  mpcp_keystream_slot(sess->keystream, seq,
  cfg->port_base, cfg->port_range,
  ckey, &port);
  sodium_memzero(ckey, sizeof(ckey));
  return port;
  }

/* =========================================================================

- S9.7  ACK jitter helper
- Spec: "Jitter bound derived from session_key."
- ====================================================================== */
  static uint32_t __attribute__((unused)) ack_jitter_ms(const uint8_t *session_key,
  uint32_t seq, uint32_t jitter_max)
  {
  if (jitter_max == 0) return 0;
  /* BUG-P3-4 FIX: IKM must include seq so each chunk gets a unique jitter.
  - Old code built info[] then discarded it with (void)info. */
    uint8_t ikm[36];
    memcpy(ikm, session_key, 32u);
    ikm[32] = (uint8_t)(seq >> 24);
    ikm[33] = (uint8_t)(seq >> 16);
    ikm[34] = (uint8_t)(seq >>  8);
    ikm[35] = (uint8_t)(seq);
  
  uint8_t derived[4];
  int rc = mpcp_hkdf(session_key, 32u,
  ikm, sizeof(ikm),
  "mpcp-v0.5-ack-jitter",
  derived, sizeof(derived));
  if (rc != MPCP_OK) return 0;
  
  uint32_t raw = ((uint32_t)derived[0] << 24) | ((uint32_t)derived[1] << 16) |
  ((uint32_t)derived[2] <<  8) |  (uint32_t)derived[3];
  return raw % (jitter_max + 1u);
  }

/* =========================================================================

- S9.8  Retry port
- ====================================================================== */
  static uint16_t __attribute__((unused)) retry_port(const mpcp_config_t *cfg,
  mpcp_session_t *sess,
  uint32_t chunk_idx, uint32_t retry_count)
  {
  return mpcp_retry_port(sess->session_key, sess->session_nonce,
  chunk_idx, retry_count,
  cfg->port_base, cfg->port_range);
  }

/* =========================================================================

- SCHED_FIFO port timing thread setup (S19)
- ====================================================================== */
  static void setup_timing_thread(const mpcp_config_t *cfg)
  {
  /* Pin to timing_core_id */
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET((size_t)cfg->timing_core_id, &cpuset);
  (void)pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
  
  /* SCHED_FIFO priority 80 */
  struct sched_param sp;
  sp.sched_priority = 80;
  (void)pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);
  }

/* =========================================================================

- Simple UDP helpers
- ====================================================================== */

/* Receiver: bind to port[i] to catch an incoming chunk. */
static int open_udp_socket_on_port(uint16_t port)
{
int fd = socket(AF_INET, SOCK_DGRAM, 0);
if (fd < 0) return -1;

int one = 1;
(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

struct sockaddr_in addr;
memset(&addr, 0, sizeof(addr));
addr.sin_family      = AF_INET;
addr.sin_addr.s_addr = INADDR_ANY;
addr.sin_port        = htons(port);

if (bind(fd, (struct sockaddr *)(void *)&addr, sizeof(addr)) < 0) {
    close(fd);
    return -1;
}
/* Increase recv buffer to absorb UDP bursts without kernel-level drops */
int rcvbuf = 4 * 1024 * 1024;
setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
return fd;

}

/* BUG-1 FIX: Sender must NOT bind port[i] on its own machine.

- MPCP design: receiver binds port[i] to catch; sender sends TO receiver:port[i].
- An unbound SOCK_DGRAM socket gets an ephemeral source port assigned by the OS
- on the first sendto(), which is correct - the source port is not part of the
- protocol. */
/* open_udp_send_socket and close_after_ms removed — no longer used */

/* =========================================================================

- S9.2  SENDER pipeline thread functions
- 
- T1 Reader -> ring0 -> T2 Compressor -> ring1 -> T3 Crypto -> ring2 -> T4 Sender
- T5 ACK Handler   T6 Tripwire   T7 Port Timing (SCHED_FIFO)
- ====================================================================== */

/* - T1: Reader - */
typedef struct {
mpcp_sender_ctx_t *ctx;
} reader_arg_t;

static void *thread_reader(void *arg)
{
reader_arg_t      *a   = arg;
mpcp_sender_ctx_t *ctx = a->ctx;

uint32_t base = ctx->plan.base_chunk_bytes;
uint32_t seq  = 0;

for (uint32_t i = 0; i < ctx->plan.n_chunks; i++) {
    if (atomic_load_explicit(&ctx->abort_flag, memory_order_relaxed))
        break;

    uint32_t chunk_sz = mpcp_chunk_data_size(&ctx->plan, i);

    mpcp_ring_slot_t *slot = mpcp_ring_claim(&ctx->ring0);
    slot->seq_index = seq++;
    slot->data_len  = chunk_sz;
    slot->flags     = ctx->plan.skip_compression
                      ? MPCP_FLAG_SKIP_COMPRESSION : 0;
    if (i == ctx->plan.n_chunks - 1u) slot->flags |= MPCP_FLAG_LAST_CHUNK;

    ssize_t n = read(ctx->file_fd, slot->buf, chunk_sz);
    if (n != (ssize_t)chunk_sz) {
        atomic_store_explicit(&ctx->abort_flag, true, memory_order_relaxed);
        mpcp_ring_release_plain(&ctx->ring0, slot); /* raw file data — no wipe */
        
        break;
    }
    mpcp_ring_publish(&ctx->ring0, slot);
    (void)base;
}
/* Signal compressor that reader is done producing into ring0 */
atomic_store_explicit(&ctx->t1_done, true, memory_order_release);
return NULL;

}

/* - T2: Compressor - */
typedef struct {
mpcp_sender_ctx_t *ctx;
} compress_arg_t;

static void *thread_compressor(void *arg)
{
compress_arg_t    *a   = arg;
mpcp_sender_ctx_t *ctx = a->ctx;

for (;;) {
    mpcp_ring_slot_t *in = mpcp_ring_consume(&ctx->ring0);
    if (!in) {
        /* Exit only when ring0 is empty AND T1 is done producing into it */
        if (atomic_load_explicit(&ctx->t1_done, memory_order_acquire))
            break;
        if (atomic_load_explicit(&ctx->abort_flag, memory_order_relaxed))
            break;
        sched_yield();
        continue;
    }

    mpcp_ring_slot_t *out = mpcp_ring_claim(&ctx->ring1);
    out->seq_index = in->seq_index;
    out->flags     = in->flags;

    if (ctx->plan.skip_compression) {
        /* Pass through */
        out->data_len = in->data_len;
        memcpy(out->buf, in->buf, in->data_len);
    } else {
        size_t bound = ZSTD_compressBound(in->data_len);
        if (bound > out->buf_capacity) {
            /* Compressed larger than buffer - pass through uncompressed */
            out->data_len = in->data_len;
            out->flags   |= MPCP_FLAG_SKIP_COMPRESSION;
            memcpy(out->buf, in->buf, in->data_len);
        } else {
            size_t clen = ZSTD_compress(out->buf, out->buf_capacity,
                                         in->buf, in->data_len,
                                         ctx->cfg->zstd_level);
            if (ZSTD_isError(clen)) {
                /* Fallback: use uncompressed */
                out->data_len = in->data_len;
                out->flags   |= MPCP_FLAG_SKIP_COMPRESSION;
                memcpy(out->buf, in->buf, in->data_len);
            } else {
                out->data_len = (uint32_t)clen;
            }
        }
    }

    mpcp_ring_release_plain(&ctx->ring0, in); /* raw file data — no wipe needed */
    mpcp_ring_publish(&ctx->ring1, out);

    /* Check for last chunk */
    if (out->flags & MPCP_FLAG_LAST_CHUNK) break;
}
/* Signal crypto thread that compressor is done producing into ring1 */
atomic_store_explicit(&ctx->t2_done, true, memory_order_release);
return NULL;

}

/* - T3: Crypto - */
typedef struct {
mpcp_sender_ctx_t *ctx;
} crypto_arg_t;

static void *thread_crypto(void *arg)
{
crypto_arg_t      *a   = arg;
mpcp_sender_ctx_t *ctx = a->ctx;

for (;;) {
    mpcp_ring_slot_t *in = mpcp_ring_consume(&ctx->ring1);
    if (!in) {
        /* Exit only when ring1 is empty AND T2 is done producing into it */
        if (atomic_load_explicit(&ctx->t2_done, memory_order_acquire))
            break;
        if (atomic_load_explicit(&ctx->abort_flag, memory_order_relaxed))
            break;
        sched_yield();
        continue;
    }

    mpcp_ring_slot_t *out = mpcp_ring_claim(&ctx->ring2);
    out->seq_index = in->seq_index;
    out->flags     = in->flags;
    out->data_len  = in->data_len;

    /* Get chunk key from keystream */
    uint8_t  chunk_key[32];
    uint16_t _port;
    mpcp_keystream_slot(ctx->sess->keystream,
                         in->seq_index,
                         ctx->cfg->port_base,
                         ctx->cfg->port_range,
                         chunk_key, &_port);

    int rc = mpcp_chunker_encrypt_chunk(
                 in->buf, in->data_len,
                 chunk_key,
                 ctx->sess->session_nonce,
                 in->seq_index,
                 out->buf, &out->ct_len,
                 out->nonce, in->flags,
                 ctx->cfg->chunk_pad_size);

    sodium_memzero(chunk_key, sizeof(chunk_key));

    if (rc != MPCP_OK) {
        atomic_store_explicit(&ctx->abort_flag, true, memory_order_relaxed);
        mpcp_ring_release(&ctx->ring1, in);
        mpcp_ring_release(&ctx->ring2, out);
        break;
    }

    mpcp_ring_release(&ctx->ring1, in);
    mpcp_ring_publish(&ctx->ring2, out);

    if (out->flags & MPCP_FLAG_LAST_CHUNK) break;
}
return NULL;

}

/* - T4: Sender + ghost generation - */
typedef struct {
mpcp_sender_ctx_t *ctx;
int                ack_sock;   /* shared with ACK handler */
} sender_arg_t;

/* Build and send one chunk wire packet */
static int send_chunk_packet(int sock,
const struct sockaddr_in *peer,
mpcp_session_t *sess,
const mpcp_ring_slot_t *slot,
uint8_t pkt_type,
uint8_t retry_count,
bool try_zerocopy)
{
/* Wire layout S18.3:
 * hdr(6) + seq(4) + retry(1) + flags(1) + plen(4) + nonce(24) + ciphertext
 *
 * OPT: stack-allocated packet buffer - eliminates malloc/free per chunk.
 * Max size: MPCP_DATA_HDR_OFFSET(40) + chunk_pad_size(63488) + tag(16) = 63544.
 * Using a fixed upper bound avoids VLA and heap allocation. */
#define SEND_PKT_MAX (MPCP_DATA_HDR_OFFSET + 63488u + 16u)
    uint8_t pkt_stack[SEND_PKT_MAX];
    size_t  pkt_len = (size_t)MPCP_DATA_HDR_OFFSET + slot->ct_len;
    uint8_t *pkt    = (pkt_len <= SEND_PKT_MAX) ? pkt_stack : NULL;
    if (!pkt) return MPCP_ERR_PARAM; /* chunk larger than compiled max */

(void)try_zerocopy;
(void)sess;

/* Common header */
uint32_t magic_be = htonl(MPCP_MAGIC);
memcpy(pkt,     &magic_be, 4);
pkt[4] = MPCP_VERSION;
pkt[5] = pkt_type;

/* Chunk header fields (big-endian) */
uint32_t seq_be = htonl(slot->seq_index);
memcpy(pkt + 6,  &seq_be, 4);
pkt[10] = retry_count;
pkt[11] = slot->flags;

uint32_t plen_be = htonl(slot->data_len);
memcpy(pkt + 12, &plen_be, 4);
memcpy(pkt + 16, slot->nonce, 24);
memcpy(pkt + 40, slot->buf,   slot->ct_len);

/* OPT: single sendto, no zerocopy fallback needed - removed second malloc */
/* S22 Decoy encoding: wrap chunk payload as C header file */
uint8_t *send_buf = pkt;
size_t   send_len = pkt_len;
uint8_t *decoy_buf = NULL;
if (sess->decoy_encoding) {
    size_t payload_off = MPCP_DATA_HDR_OFFSET;
    size_t payload_len = pkt_len - payload_off;
    size_t decoy_cap   = mpcp_decoy_max_len(payload_len) + payload_off + 8u;
    decoy_buf = (uint8_t *)malloc(decoy_cap);
    if (decoy_buf) {
        memcpy(decoy_buf, pkt, payload_off);
        size_t wlen = mpcp_decoy_wrap(pkt + payload_off, payload_len,
                                      decoy_buf + payload_off,
                                      decoy_cap - payload_off);
        if (wlen > 0) { send_buf = decoy_buf; send_len = payload_off + wlen; }
    }
}
ssize_t sent = sendto(sock, send_buf, send_len, 0,
                      (const struct sockaddr *)(const void *)peer,
                      sizeof(*peer));
if (decoy_buf) free(decoy_buf);

return (sent > 0) ? MPCP_OK : MPCP_ERR_IO;

}

static void *thread_sender(void *arg)
{
sender_arg_t      *a   = arg;
mpcp_sender_ctx_t *ctx = a->ctx;

uint32_t  ghost_idx = 0;
uint32_t  total_sent = 0;
uint32_t  data_consumed = 0; /* separate counter — exits main loop when all data drained */

/* Open one persistent send socket for all data and ghost chunks.
 * Eliminates the open()/close() syscall pair per chunk. */
/* Use the ack_sock as our send socket — this is critical.
 * When receiver gets a chunk from us, it sees our source IP:port.
 * It sends the ACK back to that IP:port. If we used a separate socket,
 * ACKs would arrive on a port nobody is listening on. By using ack_sock
 * for sends, the receiver's ACK naturally returns to ack_sock. */
int persist_sock = a->ack_sock;
if (persist_sock < 0) {
    atomic_store_explicit(&ctx->abort_flag, true, memory_order_relaxed);
    return NULL;
}

/* Pre-generate ALL ghost blobs before the send loop.
 * Eliminates inline crypto work during data dispatch, reducing jitter. */
size_t   ghost_buf_sz = (size_t)ctx->cfg->chunk_pad_size + 16u;
/* Allocate and generate all ghosts upfront */
uint8_t **ghost_prebuilt = NULL;
size_t   *ghost_ctlens   = NULL;
uint8_t (*ghost_nonces)[24] = NULL;
if (ctx->ghost_count > 0) {
    ghost_prebuilt = calloc(ctx->ghost_count, sizeof(uint8_t *));
    ghost_ctlens   = calloc(ctx->ghost_count, sizeof(size_t));
    ghost_nonces   = calloc(ctx->ghost_count, 24u);
    if (!ghost_prebuilt || !ghost_ctlens || !ghost_nonces) {
        free(ghost_prebuilt); free(ghost_ctlens); free(ghost_nonces);
        atomic_store_explicit(&ctx->abort_flag, true, memory_order_relaxed);
        return NULL;
    }
    for (uint32_t gi = 0; gi < ctx->ghost_count; gi++) {
        ghost_prebuilt[gi] = malloc(ghost_buf_sz);
        if (!ghost_prebuilt[gi]) continue;
        uint8_t gkey[32]; uint16_t _gp;
        mpcp_keystream_slot(ctx->sess->keystream, ctx->ghost_seqs[gi],
                            ctx->cfg->port_base, ctx->cfg->port_range, gkey, &_gp);
        size_t gct;
        if (mpcp_chunker_generate_ghost(gkey, ctx->sess->session_nonce,
                                        ctx->ghost_seqs[gi], ctx->cfg->chunk_pad_size,
                                        ghost_prebuilt[gi], &gct,
                                        ghost_nonces[gi]) == MPCP_OK) {
            ghost_ctlens[gi] = gct;
        } else {
            free(ghost_prebuilt[gi]); ghost_prebuilt[gi] = NULL;
        }
        sodium_memzero(gkey, sizeof(gkey));
    }
}
uint8_t *ghost_buf = malloc(ghost_buf_sz); /* kept for drain loop fallback */

while (data_consumed < ctx->plan.n_chunks) { /* exit when all DATA chunks sent; ghost drain follows */
    if (atomic_load_explicit(&ctx->abort_flag, memory_order_relaxed))
        break;

    mpcp_ring_slot_t *slot = mpcp_ring_consume(&ctx->ring2);
    if (!slot) { sched_yield(); continue; }

    /* Batch: collect up to pipeline_depth slots and send as a burst.
     * On a fast LAN this halves syscall count when depth > 1. */
    {
        uint32_t depth = ctx->cfg->pipeline_depth > 0 ? ctx->cfg->pipeline_depth : 1;
        /* First slot (already consumed above) */
        mpcp_ring_slot_t *batch[8];
        uint32_t          batch_n = 0;
        batch[batch_n++] = slot;
        /* Greedily consume up to depth-1 more */
        while (batch_n < depth && batch_n < 8 &&
               data_consumed + batch_n < ctx->plan.n_chunks) {
            mpcp_ring_slot_t *next = mpcp_ring_consume(&ctx->ring2);
            if (!next) break;
            batch[batch_n++] = next;
        }
        for (uint32_t bi = 0; bi < batch_n; bi++) {
            mpcp_ring_slot_t *s = batch[bi];
            uint32_t seq  = s->seq_index;
            uint16_t port = chunk_port(ctx->sess, ctx->cfg, seq);
            struct sockaddr_in dest;
            memcpy(&dest, ctx->peer_addr, sizeof(dest));
            dest.sin_port = htons(port);
            (void)send_chunk_packet(persist_sock, &dest, ctx->sess, s,
                                    MPCP_TYPE_DATA_CHUNK, 0, ctx->cfg->zerocopy);
            if (seq < ctx->plan.n_chunks && ctx->retry_cache && !ctx->retry_cache[seq]) {
                uint8_t *cached = malloc(s->ct_len);
                if (cached) {
                    memcpy(cached, s->buf, s->ct_len);
                    ctx->retry_cache[seq]      = cached;
                    ctx->retry_cache_lens[seq] = s->ct_len;
                    ctx->retry_data_lens[seq]  = s->data_len;
                    ctx->retry_flags[seq]      = s->flags;
                    memcpy(ctx->retry_nonces[seq], s->nonce, 24);
                    atomic_store_explicit(&ctx->sent_flag[seq], true, memory_order_relaxed);
                    ctx->sent_time_ns[seq] = mpcp_now_ns();
                }
            }
            total_sent++;
            mpcp_ring_release(&ctx->ring2, s); /* ring2 = ciphertext — must wipe */
        }
        data_consumed += batch_n;
    }
    /* Skip the old single-slot cache/release below — handled in batch above */
    /* Interleave pre-built ghost chunk (no crypto work in hot path) */
    if (ctx->cfg->ghost_chunks_enabled && ghost_idx < ctx->ghost_count) {
        uint32_t gi   = ghost_idx++;
        uint32_t gseq = ctx->ghost_seqs[gi];
        if (ghost_prebuilt && ghost_prebuilt[gi] && ghost_ctlens[gi] > 0) {
            uint16_t gport = chunk_port(ctx->sess, ctx->cfg, gseq);
            struct sockaddr_in gdest;
            memcpy(&gdest, ctx->peer_addr, sizeof(gdest));
            gdest.sin_port = htons(gport);
            mpcp_ring_slot_t gslot;
            memset(&gslot, 0, sizeof(gslot));
            gslot.seq_index = gseq;
            gslot.data_len  = ctx->cfg->chunk_pad_size;
            gslot.buf       = ghost_prebuilt[gi];
            gslot.ct_len    = ghost_ctlens[gi];
            memcpy(gslot.nonce, ghost_nonces[gi], 24);
            (void)send_chunk_packet(persist_sock, &gdest, ctx->sess, &gslot,
                                    MPCP_TYPE_GHOST_CHUNK, 0, ctx->cfg->zerocopy);
        }
        total_sent++;
    }

}  /* end while: all DATA chunks consumed from ring2 and sent */

/* Drain any remaining ghost chunks that weren't interleaved.
 * This happens when ghost_count > n_chunks (common for small files).
 * Without this loop the while above spins forever on empty ring2. */
while (ghost_idx < ctx->ghost_count &&
       !atomic_load_explicit(&ctx->abort_flag, memory_order_relaxed)) {
    uint32_t gi   = ghost_idx++;
    uint32_t gseq = ctx->ghost_seqs[gi];
    /* Use prebuilt ghost if available, otherwise fall back to inline generation */
    if (ghost_prebuilt && ghost_prebuilt[gi] && ghost_ctlens[gi] > 0) {
        uint16_t gport = chunk_port(ctx->sess, ctx->cfg, gseq);
        struct sockaddr_in gdest;
        memcpy(&gdest, ctx->peer_addr, sizeof(gdest));
        gdest.sin_port = htons(gport);
        mpcp_ring_slot_t gslot;
        memset(&gslot, 0, sizeof(gslot));
        gslot.seq_index = gseq;
        gslot.data_len  = ctx->cfg->chunk_pad_size;
        gslot.buf       = ghost_prebuilt[gi];
        gslot.ct_len    = ghost_ctlens[gi];
        memcpy(gslot.nonce, ghost_nonces[gi], 24);
        (void)send_chunk_packet(persist_sock, &gdest, ctx->sess, &gslot,
                                MPCP_TYPE_GHOST_CHUNK, 0, ctx->cfg->zerocopy);
    }
    total_sent++;
}

/* persist_sock is ack_sock (owned by sender_run) — do not close here */
if (ghost_buf) { sodium_memzero(ghost_buf, ghost_buf_sz); free(ghost_buf); }
if (ghost_prebuilt) {
    for (uint32_t gi = 0; gi < ctx->ghost_count; gi++)
        if (ghost_prebuilt[gi]) { sodium_memzero(ghost_prebuilt[gi], ghost_buf_sz); free(ghost_prebuilt[gi]); }
    free(ghost_prebuilt); free(ghost_ctlens); free(ghost_nonces);
}

/* Retry scan: check for unacked chunks and resend until all acked or exhausted.
 * Wait 500ms after initial sends before first retry pass — gives ACKs time
 * to arrive for chunks that were already received. */
{
    /* Skip the 500ms wait if all chunks were ACKed during sending (common on LAN) */
    if (atomic_load_explicit(&ctx->acks_received, memory_order_relaxed) < ctx->plan.n_chunks) {
        struct timespec wait500 = {0, 500000000L};
        nanosleep(&wait500, NULL);
    }

    uint64_t retry_timeout_ns = (uint64_t)(ctx->cfg->chunk_retry_timeout * 1e9);
    uint32_t max_retries = 8;
    uint32_t still_unacked;
    do {
        still_unacked = 0;
        uint64_t now = mpcp_now_ns();
        for (uint32_t i = 0; i < ctx->plan.n_chunks; i++) {
            if (!atomic_load_explicit(&ctx->sent_flag[i], memory_order_relaxed))
                continue;
            if (!ctx->retry_cache || !ctx->retry_cache[i])
                continue;
            if (now - ctx->sent_time_ns[i] < retry_timeout_ns) {
                still_unacked++;
                continue;
            }
            if (max_retries == 0) {
                atomic_store_explicit(&ctx->abort_flag, true, memory_order_relaxed);
                return NULL;
            }
            /* Resend to the ORIGINAL keystream-derived port for this chunk.
             * The receiver already has that port bound and is polling it.
             * Using mpcp_retry_port() sends to a different port the receiver
             * never bound, so retries were always silently dropped. */
            uint16_t rport = chunk_port(ctx->sess, ctx->cfg, i);
            /* Retry via ack_sock (same socket receiver sends ACKs to) */
            {
                struct sockaddr_in rdest = *ctx->peer_addr;
                rdest.sin_port = htons(rport);
                mpcp_ring_slot_t rslot;
                memset(&rslot, 0, sizeof(rslot));
                rslot.seq_index = i;
                rslot.ct_len    = ctx->retry_cache_lens[i];
                rslot.data_len  = ctx->retry_data_lens[i];
                rslot.flags     = ctx->retry_flags[i];
                rslot.buf       = ctx->retry_cache[i];
                memcpy(rslot.nonce, ctx->retry_nonces[i], 24);
                (void)send_chunk_packet(a->ack_sock, &rdest, ctx->sess, &rslot,
                                        MPCP_TYPE_DATA_CHUNK, (uint8_t)max_retries,
                                        false);
                ctx->sent_time_ns[i] = mpcp_now_ns();
                still_unacked++;
            }
        }
        if (still_unacked > 0) {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000L };
            nanosleep(&ts, NULL);
        }
        max_retries--;
    } while (still_unacked > 0 && max_retries > 0 &&
             !atomic_load_explicit(&ctx->abort_flag, memory_order_relaxed));
}
return NULL;

}

/* - T5: ACK handler - */
typedef struct {
mpcp_sender_ctx_t *ctx;
int                sock;
uint32_t           total_expected;
} ack_handler_arg_t;

static void *thread_ack_handler(void *arg)
{
ack_handler_arg_t *a   = arg;
mpcp_sender_ctx_t *ctx = a->ctx;

uint8_t  buf[MPCP_ACK_PKT_LEN + 4u];
uint32_t deadline_ms = (uint32_t)(ctx->cfg->chunk_retry_timeout * 1000.0);

struct timeval tv;
tv.tv_sec  = (time_t)(deadline_ms / 1000u);
tv.tv_usec = (suseconds_t)((deadline_ms % 1000u) * 1000u);
(void)setsockopt(a->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

while (atomic_load_explicit(&ctx->acks_received, memory_order_relaxed)
       < a->total_expected)
{
    if (atomic_load_explicit(&ctx->abort_flag, memory_order_relaxed))
        break;

    ssize_t n = recv(a->sock, buf, sizeof(buf), 0);
    if (n < (ssize_t)MPCP_ACK_PKT_LEN) continue;

    /* Validate magic + version + type */
    uint32_t magic;
    memcpy(&magic, buf, 4);
    if (ntohl(magic) != MPCP_MAGIC) continue;
    if (buf[4] != MPCP_VERSION)     continue;
    if (buf[5] != MPCP_TYPE_ACK)    continue;

    uint32_t ack_seq;
    memcpy(&ack_seq, buf + 6, 4);
    ack_seq = ntohl(ack_seq);

    /* Validate BLAKE2b hash */
    uint8_t expected_hash[4];
    if (mpcp_ack_hash(ctx->sess->session_key, ack_seq,
                       expected_hash) != MPCP_OK) continue;
    if (memcmp(buf + 10, expected_hash, 4) != 0) continue;

    if (mpcp_dedup_accept(&ctx->ack_dedup, ack_seq)) {
        atomic_fetch_add_explicit(&ctx->acks_received, 1u,
                                   memory_order_relaxed);
        /* Clear sent_flag so retry scan skips this seq */
        if (ack_seq < ctx->plan.n_chunks && ctx->sent_flag)
            atomic_store_explicit(&ctx->sent_flag[ack_seq], false, memory_order_relaxed);
    }
}
return NULL;

}


/* =========================================================================

- S9.2  mpcp_sender_run - entry point
- ====================================================================== */
  int mpcp_sender_run(const mpcp_config_t      *cfg,
  mpcp_session_t           *sess,
  const struct sockaddr_in *peer_addr,
  const char               *file_path)
  {
  if (!cfg || !sess || !peer_addr || !file_path) return MPCP_ERR_PARAM;
  
  int file_fd = open(file_path, O_RDONLY);
  if (file_fd < 0) return MPCP_ERR_IO;
  
  struct stat st;
  if (fstat(file_fd, &st) < 0) { close(file_fd); return MPCP_ERR_IO; }
  size_t file_size = (size_t)st.st_size;
  if (file_size == 0) { close(file_fd); return MPCP_ERR_PARAM; }
  
  /* - Compressibility detection on first 64K - */
  size_t probe_sz = file_size < 65536u ? file_size : 65536u;
  uint8_t *probe  = malloc(probe_sz);
  if (!probe) { close(file_fd); return MPCP_ERR_ALLOC; }
  if (read(file_fd, probe, probe_sz) != (ssize_t)probe_sz) {
  free(probe); close(file_fd); return MPCP_ERR_IO;
  }
  if (lseek(file_fd, 0, SEEK_SET) < 0) {
  free(probe); close(file_fd); return MPCP_ERR_IO;
  }
  
  mpcp_chunk_plan_t plan;
  memset(&plan, 0, sizeof(plan));
  mpcp_chunker_detect_compressibility(probe, probe_sz, &plan);
  free(probe);
  
  /* Plan is always based on file_size.
   *
   * Architecture: T2 compressor compresses each chunk INDEPENDENTLY from
   * the raw file bytes that T1 reader supplies. n_chunks must therefore be
   * derived from file_size so that the reader reads the correct number of
   * bytes per chunk. Using clen (whole-file compressed size) was a bug:
   * it made base_chunk_bytes = clen/n_chunks, so T1 only read clen bytes
   * total from the original file, truncating every compressible transfer.
   *
   * Compressibility detection (probe) still determines whether T2 skips
   * compression. The full-file ratio check ensures skip_compression matches
   * exactly what the precompute block sent in transfer_info. */
  if (!plan.skip_compression) {
      /* Re-verify with full file: if ratio > 0.95, treat as incompressible */
      size_t bound = ZSTD_compressBound(file_size);
      uint8_t *tmp = malloc(bound);
      if (tmp) {
          uint8_t *raw = malloc(file_size);
          if (raw) {
              if (read(file_fd, raw, file_size) == (ssize_t)file_size) {
                  size_t clen = ZSTD_compress(tmp, bound, raw, file_size, cfg->zstd_level);
                  if (ZSTD_isError(clen) ||
                      (double)clen / (double)file_size > 0.95) {
                      plan.skip_compression = true;
                  }
              }
              if (lseek(file_fd, 0, SEEK_SET) < 0) {
                  free(raw); free(tmp); close(file_fd); return MPCP_ERR_IO;
              }
              free(raw);
          }
          free(tmp);
      }
  }

  int rc = mpcp_chunker_plan(file_size, cfg->chunk_pad_size,
  plan.skip_compression, &plan);
  if (rc != MPCP_OK) { close(file_fd); return rc; }
  
  /* - Ghost map - */
  uint32_t ghost_seqs[64];
  uint32_t ghost_count = 0;
  if (cfg->ghost_chunks_enabled) {
  (void)mpcp_ghost_map(sess->session_key,
  plan.n_chunks,
  cfg->ghost_chunk_min,
  cfg->ghost_chunk_max,
  ghost_seqs, &ghost_count);
  }
  
  /* BUG-4 FIX: Ghost seq indices are n_data_chunks .. n_data_chunks+ghost_count-1.
  - mpcp_keystream_slot(keystream, ghost_seq) reads at offset ghost_seq*64, which
  - is past the end of a keystream sized for n_data_chunks only.
  - Re-derive the keystream here to cover ALL sequences (data + ghost).
  - The caller-supplied keystream is freed and replaced. */
    uint32_t total_ks_chunks = plan.n_chunks + ghost_count;
    if (total_ks_chunks > 127u) { close(file_fd); return MPCP_ERR_PARAM; }
    if (sess->keystream) {
    sodium_memzero(sess->keystream,
    (size_t)(plan.n_chunks) * MPCP_KEYSTREAM_SLOT);
    sodium_free(sess->keystream);
    sess->keystream = NULL;
    }
    /* Include file_counter in keystream derivation to prevent nonce reuse
     * across multiple files sent on the same session key. */
    {
        /* Temporarily XOR file_counter into session_key for keystream derivation.
         * This gives each file a unique keystream without changing the session key. */
        uint8_t ks_key[32];
        memcpy(ks_key, sess->session_key, 32);
        uint32_t fc_be = htonl(sess->file_counter);
        /* Mix: ks_key[0..3] ^= file_counter_be */
        for (int _ksi = 0; _ksi < 4; _ksi++)
            ks_key[_ksi] ^= ((uint8_t *)&fc_be)[_ksi];
        sess->keystream = mpcp_derive_keystream(ks_key, total_ks_chunks);
        sodium_memzero(ks_key, sizeof(ks_key));
    }
    if (!sess->keystream) { close(file_fd); return MPCP_ERR_ALLOC; }
  
  /* - Init context - */
  mpcp_sender_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.cfg        = cfg;
  ctx.sess       = sess;
  ctx.peer_addr  = peer_addr;
  ctx.plan       = plan;
  ctx.file_fd    = file_fd;
  ctx.file_size  = file_size;
  ctx.ghost_count = ghost_count;
  memcpy(ctx.ghost_seqs, ghost_seqs,
  ghost_count * sizeof(uint32_t));

  /* Expose progress counters for external polling (CLI progress bar) */
  if (sess->sender_progress) {
      mpcp_sender_progress_t *prog = (mpcp_sender_progress_t *)sess->sender_progress;
      prog->acks_received = &ctx.acks_received;
      prog->n_chunks      = plan.n_chunks;
  }
  atomic_store_explicit(&ctx.acks_received, 0u, memory_order_relaxed);
  atomic_store_explicit(&ctx.abort_flag, false, memory_order_relaxed);
  atomic_store_explicit(&ctx.t1_done,    false, memory_order_relaxed);
  atomic_store_explicit(&ctx.t2_done,    false, memory_order_relaxed);
  mpcp_dedup_init(&ctx.ack_dedup);

  /* Retry cache: store one encrypted copy of each data chunk for retransmission */
  uint32_t nc = plan.n_chunks;
  ctx.retry_cache      = calloc(nc, sizeof(uint8_t *));
  ctx.retry_cache_lens = calloc(nc, sizeof(size_t));
  ctx.retry_nonces     = calloc(nc, sizeof(*ctx.retry_nonces));
  ctx.retry_data_lens  = calloc(nc, sizeof(uint32_t));
  ctx.retry_flags      = calloc(nc, sizeof(uint8_t));
  ctx.sent_flag        = calloc(nc, sizeof(_Atomic(bool)));
  ctx.sent_time_ns     = calloc(nc, sizeof(uint64_t));
  if (!ctx.retry_cache || !ctx.retry_cache_lens || !ctx.retry_nonces ||
      !ctx.retry_data_lens || !ctx.retry_flags ||
      !ctx.sent_flag || !ctx.sent_time_ns) {
      free(ctx.retry_cache); free(ctx.retry_cache_lens);
      free(ctx.retry_nonces); free(ctx.retry_data_lens);
      free(ctx.retry_flags); free(ctx.sent_flag); free(ctx.sent_time_ns);
      close(file_fd); return MPCP_ERR_ALLOC;
  }
  
  /* BUG-P3-2 FIX: ring0 holds raw file bytes; ring1 holds compressed bytes.
  - Both can exceed chunk_pad_size for large files (e.g. 809KB chunks from
  - a 100MB file split into 127 chunks).  Use max_chunk_bytes for rings 0+1. */
    uint32_t max_chunk_bytes = plan.base_chunk_bytes + 1u; /* +1 for remainder slots */
    if (max_chunk_bytes < cfg->chunk_pad_size) max_chunk_bytes = cfg->chunk_pad_size;
    /* Map pipeline_depth → ring depth: more depth = deeper buffers to keep
     * all stages busy simultaneously. Minimum 4, grows with pipeline_depth. */
    uint32_t eff_ring_depth = cfg->ring_depth;
    if (cfg->pipeline_depth > 1)
        eff_ring_depth = (cfg->pipeline_depth * 2u > eff_ring_depth)
                         ? cfg->pipeline_depth * 2u : eff_ring_depth;
    if ((rc = mpcp_ring_init(&ctx.ring0, eff_ring_depth, max_chunk_bytes)) != MPCP_OK)
    goto cleanup_fd;
    if ((rc = mpcp_ring_init(&ctx.ring1, eff_ring_depth, max_chunk_bytes)) != MPCP_OK)
    goto cleanup_ring0;
    if ((rc = mpcp_ring_init(&ctx.ring2, eff_ring_depth, cfg->chunk_pad_size + 16u)) != MPCP_OK)
    goto cleanup_ring1;
  
  /* ACK socket — also used as the persistent send socket so that ACK
   * replies from the receiver reach this same fd (source port matches). */
  int ack_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (ack_sock < 0) { rc = MPCP_ERR_IO; goto cleanup_ring2; }
  /* Bind to INADDR_ANY:0 so OS assigns a stable ephemeral port. All chunk
   * sends use this socket, so receiver ACKs come back here. */
  {
      struct sockaddr_in ack_bind;
      memset(&ack_bind, 0, sizeof(ack_bind));
      ack_bind.sin_family      = AF_INET;
      ack_bind.sin_addr.s_addr = INADDR_ANY;
      ack_bind.sin_port        = 0; /* OS picks ephemeral port */
      (void)bind(ack_sock, (struct sockaddr *)&ack_bind, sizeof(ack_bind));
  }
  
  /* - Launch threads - */
  reader_arg_t  r_arg  = { &ctx };
  compress_arg_t c_arg = { &ctx };
  crypto_arg_t  cr_arg = { &ctx };
  sender_arg_t  s_arg  = { &ctx, ack_sock };
  
  /* BUG-2 FIX: ghost chunks are silently discarded by the receiver - no ACK
  - is ever sent for them.  Wait only for the n_chunks data chunk ACKs. */
    uint32_t total_expected = plan.n_chunks;
    ack_handler_arg_t ack_arg = { &ctx, ack_sock, total_expected };
  
  pthread_t t_reader, t_compress, t_crypto, t_sender, t_ack;
  pthread_create(&t_reader,   NULL, thread_reader,      &r_arg);
  pthread_create(&t_compress, NULL, thread_compressor,  &c_arg);
  pthread_create(&t_crypto,   NULL, thread_crypto,       &cr_arg);
  pthread_create(&t_sender,   NULL, thread_sender,       &s_arg);
  pthread_create(&t_ack,      NULL, thread_ack_handler,  &ack_arg);
  
  pthread_join(t_reader,   NULL);
  pthread_join(t_compress, NULL);
  pthread_join(t_crypto,   NULL);
  pthread_join(t_sender,   NULL);
  pthread_join(t_ack,      NULL);
  
  close(ack_sock);
  
  if (atomic_load_explicit(&ctx.abort_flag, memory_order_relaxed))
  rc = MPCP_ERR_TRIPWIRE;
  else
  rc = MPCP_OK;
  
  /* S11 Silent termination - zero session key and master secret */
  sodium_memzero(sess->session_key,    MPCP_SESSION_KEY_LEN);
  sodium_memzero(sess->master_secret,  MPCP_MASTER_SECRET_LEN);

  /* Free retry cache */
  if (ctx.retry_cache) {
      for (uint32_t _i = 0; _i < plan.n_chunks; _i++) {
          if (ctx.retry_cache[_i]) {
              sodium_memzero(ctx.retry_cache[_i], ctx.retry_cache_lens[_i]);
              free(ctx.retry_cache[_i]);
          }
      }
      free(ctx.retry_cache);
  }
  free(ctx.retry_cache_lens);
  free(ctx.retry_nonces);
  free(ctx.retry_data_lens);
  free(ctx.retry_flags);
  free(ctx.sent_flag);
  free(ctx.sent_time_ns);

cleanup_ring2:
mpcp_ring_destroy(&ctx.ring2);
cleanup_ring1:
mpcp_ring_destroy(&ctx.ring1);
cleanup_ring0:
mpcp_ring_destroy(&ctx.ring0);
cleanup_fd:
close(file_fd);
return rc;
}

/* =========================================================================

- S10 / S19  RECEIVER pipeline
- 
- [Receiver T1] -> ring0 -> [Verifier T2] -> ring1 -> [Decryptor T3] -> ring2
- -> [Writer T4]
- [Port Timing T5] SCHED_FIFO
- ====================================================================== */


/* Forward declarations for resume helpers */
uint32_t resume_load(const char *out_path, bool *done, uint32_t max_chunks);
void     resume_record(const char *out_path, uint32_t seq);
void     resume_clear(const char *out_path);

typedef struct {
mpcp_receiver_ctx_t *ctx;
uint32_t             n_chunks;
uint32_t             catch_window_ms;
/* Pre-computed list of (seq->port) for all data + ghost chunks */
uint16_t            *ports;
} recv_t1_arg_t;

static void *thread_receiver_t1(void *arg)
{
recv_t1_arg_t       *a   = arg;
mpcp_receiver_ctx_t *ctx = a->ctx;

/* DESIGN FIX: bind ALL chunk ports simultaneously before receiving anything.
 *
 * The original sequential design bound one port at a time and blocked for
 * catch_window_ms before moving to the next. The sender sends all chunks in
 * rapid succession to different ports. Sequential binding means chunks for
 * later ports arrive while the receiver is still blocked on an earlier port —
 * those packets hit unbound sockets, are silently dropped, and never retried.
 *
 * Fix: bind all n_chunks ports upfront, then poll all of them with MSG_DONTWAIT
 * in a round-robin loop until every data chunk is received or the overall
 * deadline expires. Ghost chunks are accepted and discarded inline. */

uint32_t n = a->n_chunks;
size_t pkt_max = (size_t)MPCP_DATA_HDR_OFFSET
                 + (size_t)ctx->cfg->chunk_pad_size + 16u;

/* Open all n sockets simultaneously */
int *fds = calloc(n, sizeof(int));
if (!fds) return NULL;
for (uint32_t i = 0; i < n; i++) {
    fds[i] = open_udp_socket_on_port(a->ports[i]);
}

uint8_t *pkt = malloc(pkt_max);
if (!pkt) { for (uint32_t i=0;i<n;i++) if(fds[i]>=0) close(fds[i]); free(fds); return NULL; }

/* Deadline: generous to cover retransmits from sender */
uint64_t deadline_ns = mpcp_now_ns()
    + (uint64_t)ctx->cfg->chunk_retry_timeout * 3ULL * 1000000000ULL
    + 30000000000ULL; /* +30s minimum */

uint32_t received = 0;
bool *got = calloc(n, sizeof(bool));
if (!got) {
    free(pkt);
    for (uint32_t i=0;i<n;i++) if(fds[i]>=0) close(fds[i]);
    free(fds);
    return NULL;
}

/* epoll: event-driven receive — wakes only when data arrives.
 * O(active fds) instead of O(n) round-robin polling. */
int efd = epoll_create1(0);
if (efd < 0) {
    free(got); free(pkt);
    for (uint32_t i=0;i<n;i++) if(fds[i]>=0) close(fds[i]);
    free(fds);
    return NULL;
}
for (uint32_t i = 0; i < n; i++) {
    if (fds[i] < 0) continue;
    struct epoll_event ev;
    ev.events   = EPOLLIN;
    ev.data.u32 = i;
    epoll_ctl(efd, EPOLL_CTL_ADD, fds[i], &ev);
}

#define EPOLL_BATCH 64
struct epoll_event evs[EPOLL_BATCH];

while (received < n && mpcp_now_ns() < deadline_ns) {
    if (atomic_load_explicit(&ctx->abort_flag, memory_order_relaxed)) break;

    int timeout_ms = 5; /* short poll so abort_flag is checked regularly */
    int nev = epoll_wait(efd, evs, EPOLL_BATCH, timeout_ms);
    if (nev <= 0) continue; /* timeout or EINTR */

    bool any = false;
    for (int ei = 0; ei < nev; ei++) {
        uint32_t i = evs[ei].data.u32;
        if (got[i] || fds[i] < 0) continue;

        struct sockaddr_in from_sender;
        socklen_t from_len = sizeof(from_sender);
        ssize_t nb = recvfrom(fds[i], pkt, pkt_max, MSG_DONTWAIT,
                              (struct sockaddr *)&from_sender, &from_len);
        if (nb < (ssize_t)MPCP_DATA_HDR_OFFSET) continue;

        /* Note: source IP check removed - AEAD authentication in mpcp_chunk_decrypt
         * provides cryptographic rejection of any forged/injected packets.
         * A strict IP filter caused silent drops when the sender's routing
         * chose a different source interface than calibration pings used. */
        (void)from_sender;

        /* Decoy unwrap: if the payload after the 6-byte MPCP header looks like
         * a C header file, decode it back to raw ciphertext.
         * We detect it by checking for the autogenerated prefix (starts with slash-star). */
        if (nb > (ssize_t)MPCP_DATA_HDR_OFFSET + 20) {
            const uint8_t *payload = pkt + MPCP_DATA_HDR_OFFSET;
            size_t payload_len     = (size_t)nb - MPCP_DATA_HDR_OFFSET;
            if (memcmp(payload, "/* autogenerated", 16) == 0) {
                /* Unwrap into a temporary buffer then overwrite pkt+HDR */
                uint8_t *tmp = (uint8_t *)malloc(payload_len);
                if (tmp) {
                    size_t dlen = mpcp_decoy_unwrap(payload, payload_len, tmp, payload_len);
                    if (dlen > 0) {
                        /* Trim to multiple of ciphertext alignment.
                         * The real ct_len is embedded in the MPCP header
                         * at pkt+10 (big-endian uint32 = data_len field).
                         * For AEAD correctness use exactly dlen bytes — the
                         * decryptor will validate the Poly1305 tag against
                         * the exact ciphertext length stored in the slot. */
                        size_t copy_len = (dlen < payload_len) ? dlen : payload_len;
                        memcpy(pkt + MPCP_DATA_HDR_OFFSET, tmp, copy_len);
                        nb = (ssize_t)(MPCP_DATA_HDR_OFFSET + copy_len);
                    }
                    free(tmp);
                }
            }
        }

        /* Validate header */
        uint32_t magic;
        memcpy(&magic, pkt, 4);
        if (ntohl(magic) != MPCP_MAGIC || pkt[4] != MPCP_VERSION) continue;
        if (pkt[5] != MPCP_TYPE_DATA_CHUNK && pkt[5] != MPCP_TYPE_GHOST_CHUNK) continue;

        uint32_t pkt_seq;
        memcpy(&pkt_seq, pkt + 6, 4);
        pkt_seq = ntohl(pkt_seq);

        /* Ghost chunk: discard, mark port done */
        bool is_ghost = false;
        for (uint32_t g = 0; g < ctx->ghost_count; g++) {
            if (ctx->ghost_seqs[g] == pkt_seq) { is_ghost = true; break; }
        }
        if (is_ghost) {
            got[i] = true;
            received++;
            any = true;
            close(fds[i]); fds[i] = -1;
            continue;
        }

        /* Dedup check */
        if (!mpcp_dedup_accept(&ctx->dedup, pkt_seq)) continue;

        mpcp_ring_slot_t *slot = mpcp_ring_claim(&ctx->ring0);
        slot->seq_index = pkt_seq;
        slot->flags     = pkt[11];

        size_t ct_len = (size_t)(nb - (ssize_t)MPCP_DATA_HDR_OFFSET);
        if (ct_len > slot->buf_capacity) ct_len = slot->buf_capacity;
        memcpy(slot->buf, pkt + MPCP_DATA_HDR_OFFSET, ct_len);
        slot->ct_len   = ct_len;
        slot->data_len = ntohl(*(const uint32_t *)(const void *)(pkt + 12));
        memcpy(slot->nonce, pkt + 16, 24);
        mpcp_ring_publish(&ctx->ring0, slot);

        /* Send ACK back to sender — must be exactly MPCP_ACK_PKT_LEN=32 bytes.
         * Sender ack_handler drops any packet smaller than 32 bytes.
         * Layout: hdr(6) + ack_seq(4) + ack_hash(4) + padding(18) = 32. */
        {
            mpcp_ack_pkt_t ack;
            memset(&ack, 0, sizeof(ack));
            uint32_t ack_magic_be = htonl(MPCP_MAGIC);
            memcpy(&ack.hdr.magic, &ack_magic_be, 4);
            ack.hdr.version = MPCP_VERSION;
            ack.hdr.type    = MPCP_TYPE_ACK;
            uint32_t ack_seq_be = htonl(pkt_seq);
            memcpy(&ack.ack_seq, &ack_seq_be, 4);
            uint8_t ack_hash_bytes[4];
            if (mpcp_ack_hash(ctx->sess->session_key, pkt_seq, ack_hash_bytes) == MPCP_OK)
                memcpy(&ack.ack_hash, ack_hash_bytes, 4);
            randombytes_buf(ack.padding, sizeof(ack.padding)); /* random padding */
            sendto(fds[i], &ack, sizeof(ack), 0,
                   (const struct sockaddr *)&from_sender, from_len);
        }

        /* Progress — single redrawn line, no syscall per chunk after first */
        {
            uint32_t data_done = 0;
            for (uint32_t _d = 0; _d < n; _d++) if (got[_d]) data_done++;
            uint32_t total_data = ctx->plan.n_chunks > 0 ? ctx->plan.n_chunks : 1;
#ifdef MPCP_COLOUR_UI
            {
                int fill = (int)(40.0f * (float)(data_done + 1) / (float)total_data);
                fprintf(stderr, "\r  %s[%s", C_GRAPE, C_RESET);
                for (int _b = 0; _b < 40; _b++) {
                    if (_b < fill)      fprintf(stderr, "%s\xe2\x96\x88%s", _b==fill-1?C_PLUM:C_VIOLET, C_RESET);
                    else if (_b==fill)  fprintf(stderr, "%s\xe2\x96\x8c%s", C_GRAPE, C_RESET);
                    else                fprintf(stderr, "%s\xe2\x96\x91%s", C_GRAPE, C_RESET);
                }
                fprintf(stderr, "%s] %s%u/%u%s    ", C_GRAPE, C_PLUM, data_done+1, total_data, C_RESET);
            }
#else
            fprintf(stderr, "\r  [%u/%u]   ", data_done + 1, total_data);
#endif
        }
                got[i] = true;
        received++;
        any = true;
        close(fds[i]); fds[i] = -1;
    }
    (void)any;
}
close(efd);
free(got);
free(pkt);
for (uint32_t i = 0; i < n; i++) if (fds[i] >= 0) close(fds[i]);
free(fds);
/* Signal downstream stages that T1 has finished producing into ring0 */
atomic_store_explicit(&ctx->t1_done, true, memory_order_release);
return NULL;

}

/* - Verifier T2 - */
typedef struct { mpcp_receiver_ctx_t *ctx; } verifier_arg_t;

static void *thread_verifier(void *arg)
{
verifier_arg_t      *a   = arg;
mpcp_receiver_ctx_t *ctx = a->ctx;

for (;;) {
    mpcp_ring_slot_t *in = mpcp_ring_consume(&ctx->ring0);
    if (!in) {
        /* Exit only after T1 finished and ring0 is drained */
        if (atomic_load_explicit(&ctx->t1_done, memory_order_acquire)) break;
        if (atomic_load_explicit(&ctx->abort_flag, memory_order_relaxed)) break;
        sched_yield();
        continue;
    }

    uint32_t seq = in->seq_index;

    /* Ghost chunk - discard silently */
    bool is_ghost = false;
    for (uint32_t g = 0; g < ctx->ghost_count; g++) {
        if (ctx->ghost_seqs[g] == seq) { is_ghost = true; break; }
    }
    if (is_ghost) {
        sodium_memzero(in->buf, in->ct_len);
        mpcp_ring_release(&ctx->ring0, in);
        atomic_fetch_add_explicit(&ctx->chunks_verified, 1u, memory_order_relaxed);
        continue;
    }

    /* Send bounce hash to sender oracle (S18.5) */
    {
        uint8_t bhash[32];
        (void)mpcp_bounce_hash(in->buf, in->ct_len, bhash);
        /* (Bounce packet sending is omitted for now - tripwire consumes it) */
        sodium_memzero(bhash, sizeof(bhash));
    }

    /* Pass to decryptor — swap buffers to avoid 63KB memcpy.
     * The decryptor will write into ring1 slot's space; we give it the
     * ring0 slot's data by swapping the buf pointers and restoring on release. */
    mpcp_ring_slot_t *out = mpcp_ring_claim(&ctx->ring1);
    out->seq_index = in->seq_index;
    out->flags     = in->flags;
    out->data_len  = in->data_len;
    out->ct_len    = in->ct_len;
    /* Swap buffers: give decryptor the data without copying it */
    uint8_t *tmp_buf    = out->buf;
    size_t   tmp_cap    = out->buf_capacity;
    out->buf            = in->buf;
    out->buf_capacity   = in->buf_capacity;
    in->buf             = tmp_buf;
    in->buf_capacity    = tmp_cap;
    memcpy(out->nonce, in->nonce, 24);

    /* Release ring0 slot (now holds the old ring1 buffer — will be zeroed) */
    mpcp_ring_release(&ctx->ring0, in);
    mpcp_ring_publish(&ctx->ring1, out);
    atomic_fetch_add_explicit(&ctx->chunks_verified, 1u, memory_order_relaxed);
}
/* Signal T3 that T2 has finished producing into ring1 */
atomic_store_explicit(&ctx->t2_done, true, memory_order_release);
return NULL;

}

/* - Decryptor T3 - */
typedef struct { mpcp_receiver_ctx_t *ctx; } decrypt_arg_t;

static void *thread_decryptor(void *arg)
{
decrypt_arg_t       *a   = arg;
mpcp_receiver_ctx_t *ctx = a->ctx;

for (;;) {
    mpcp_ring_slot_t *in = mpcp_ring_consume(&ctx->ring1);
    if (!in) {
        /* Exit only after T2 finished and ring1 is drained */
        if (atomic_load_explicit(&ctx->t2_done, memory_order_acquire)) break;
        if (atomic_load_explicit(&ctx->abort_flag, memory_order_relaxed)) break;
        sched_yield();
        continue;
    }

    uint32_t seq = in->seq_index;
    if (seq >= ctx->plan.n_chunks) {
        /* Ghost or out-of-range - discard */
        mpcp_ring_release(&ctx->ring1, in);
        continue;
    }

    uint8_t  chunk_key[32];
    uint16_t _port;
    mpcp_keystream_slot(ctx->sess->keystream, seq,
                         ctx->cfg->port_base, ctx->cfg->port_range,
                         chunk_key, &_port);

    size_t  plain_len = 0;
    /* OPT: use pre-allocated per-thread decrypt buffer - no malloc/free per chunk */
    uint8_t *plain = ctx->decrypt_buf;
    if (!plain) {
        sodium_memzero(chunk_key, sizeof(chunk_key));
        mpcp_ring_release(&ctx->ring1, in);
        continue;
    }

    int rc = mpcp_chunk_decrypt(chunk_key,
                                 ctx->sess->session_nonce,
                                 seq,
                                 in->nonce,
                                 in->buf, in->ct_len,
                                 plain, &plain_len);
    sodium_memzero(chunk_key, sizeof(chunk_key));

    if (rc == MPCP_OK && seq < ctx->plan.n_chunks) {
        /* Store decrypted data for ordered write.
         * plain_len = chunk_pad_size (full padded block).
         * in->data_len = original unpadded data (from wire header plen field).
         * We store only the real data bytes — chunk_lens[seq] = data_len. */
        uint32_t real_len = in->data_len;  /* unpadded data length from packet */
        if (real_len == 0 || real_len > (uint32_t)plain_len)
            real_len = (uint32_t)plain_len; /* safety fallback */
        if (!ctx->chunk_store[seq]) {
            ctx->chunk_store[seq] = malloc(real_len);
            if (ctx->chunk_store[seq]) {
                memcpy(ctx->chunk_store[seq], plain, real_len);
                ctx->chunk_lens[seq]  = real_len;
                ctx->chunk_ready[seq] = true;
            }
        }
    }

    /* Wipe only the actual data bytes — real_len <= plain_len <= decrypt_buf_sz */
    {
        uint32_t wipe_len = 0;
        if (rc == MPCP_OK) {
            /* real_len was computed inside the if(rc==MPCP_OK) block above */
            uint32_t real_len_local = in->data_len;
            if (real_len_local == 0 || real_len_local > (uint32_t)plain_len)
                real_len_local = (uint32_t)plain_len;
            wipe_len = real_len_local;
        } else {
            wipe_len = (uint32_t)ctx->decrypt_buf_sz;
        }
        sodium_memzero(plain, wipe_len);
    }
    mpcp_ring_release(&ctx->ring1, in);

    /* Signal writer - advance write pointer */
    mpcp_ring_slot_t *out = mpcp_ring_claim(&ctx->ring2);
    out->seq_index = seq;
    mpcp_ring_publish(&ctx->ring2, out);
}
/* Signal T4 that T3 has finished populating chunk_store and ring2 */
atomic_store_explicit(&ctx->t3_done, true, memory_order_release);
return NULL;

}

/* - Writer T4 - */
typedef struct {
mpcp_receiver_ctx_t *ctx;
bool                 use_decompress;
uint8_t             *decomp_buf;   /* pre-allocated decompression buffer */
size_t               decomp_cap;   /* capacity of decomp_buf */
} writer_arg_t;

static void *thread_writer(void *arg)
{
writer_arg_t        *a   = arg;
mpcp_receiver_ctx_t *ctx = a->ctx;

for (;;) {
    /* Exit cleanly when all data chunks have been written */
    if (ctx->next_write_seq >= ctx->plan.n_chunks)
        break;

    mpcp_ring_slot_t *in = mpcp_ring_consume(&ctx->ring2);
    if (!in) {
        /* Exit only when ring2 is empty AND T3 is done populating chunk_store */
        if (atomic_load_explicit(&ctx->t3_done, memory_order_acquire))
            break;
        if (atomic_load_explicit(&ctx->abort_flag, memory_order_relaxed))
            break;
        sched_yield();
        continue;
    }

    /* Drain ring notification; actual write is from chunk_store in order */
    mpcp_ring_release(&ctx->ring2, in);

    /* Write all sequential chunks that are ready */
    while (ctx->next_write_seq < ctx->plan.n_chunks &&
           ctx->chunk_ready[ctx->next_write_seq])
    {
        uint32_t ws  = ctx->next_write_seq;
        uint8_t *buf = ctx->chunk_store[ws];
        uint32_t len = ctx->chunk_lens[ws];

        if (len > 0) { /* len==0 means resumed chunk - skip write, just advance */
            if (a->use_decompress && !(ctx->plan.skip_compression)) {
                /* decompress into pre-allocated buffer — no malloc per chunk */
                size_t dlen = ZSTD_decompress(a->decomp_buf, a->decomp_cap, buf, len);
                if (!ZSTD_isError(dlen)) {
                    if (write(ctx->out_fd, a->decomp_buf, dlen) != (ssize_t)dlen)
                        atomic_store_explicit(&ctx->abort_flag, true, memory_order_relaxed);
                    else
                        resume_record(ctx->out_path, ws);
                }
            } else {
                if (write(ctx->out_fd, buf, len) != (ssize_t)len)
                    atomic_store_explicit(&ctx->abort_flag, true, memory_order_relaxed);
                else
                    resume_record(ctx->out_path, ws);
            }
        }

        sodium_memzero(buf, len);
        free(buf);
        ctx->chunk_store[ws] = NULL;
        ctx->chunk_ready[ws] = false;
        ctx->next_write_seq++;
    }

    if (ctx->next_write_seq >= ctx->plan.n_chunks) break;
}
return NULL;

}

/* =========================================================================

- S10 / S19  mpcp_receiver_run - entry point
- ====================================================================== */
  int mpcp_receiver_run(const mpcp_config_t      *cfg,
  mpcp_session_t            *sess,
  const struct sockaddr_in  *peer_addr,
  const char                *out_path,
  uint32_t                   n_chunks)
  {
  if (!cfg || !sess || !out_path || n_chunks == 0) return MPCP_ERR_PARAM;

  /* Resume: check if we have a partial transfer sidecar */
  bool  resuming    = resume_exists(out_path);
  int   open_flags  = O_WRONLY | O_CREAT | (resuming ? 0 : O_TRUNC);
  int out_fd = open(out_path, open_flags, 0600);
  if (out_fd < 0) return MPCP_ERR_IO;
  /* When resuming, seek to end so new chunk writes append after existing data */
  if (resuming && lseek(out_fd, 0, SEEK_END) < 0) {
      close(out_fd); return MPCP_ERR_IO;
  }
  
  /* Ghost map */
  uint32_t ghost_seqs[64];
  uint32_t ghost_count = 0;
  if (cfg->ghost_chunks_enabled) {
  (void)mpcp_ghost_map(sess->session_key, n_chunks,
  cfg->ghost_chunk_min, cfg->ghost_chunk_max,
  ghost_seqs, &ghost_count);
  }
  
  uint32_t total_chunks = n_chunks + ghost_count;
  
  /* BUG-4 FIX: same as sender - re-derive keystream to cover ghost seqs. */
  if (total_chunks > 127u) { close(out_fd); return MPCP_ERR_PARAM; }
  if (sess->keystream) {
  sodium_memzero(sess->keystream,
  (size_t)n_chunks * MPCP_KEYSTREAM_SLOT);
  sodium_free(sess->keystream);
  sess->keystream = NULL;
  }
  sess->keystream = mpcp_derive_keystream(sess->session_key, total_chunks);
  if (!sess->keystream) { close(out_fd); return MPCP_ERR_ALLOC; }
  
  /* Pre-compute ports for all chunk sequences */
  uint16_t *ports = malloc(total_chunks * sizeof(uint16_t));
  if (!ports) { close(out_fd); return MPCP_ERR_ALLOC; }
  for (uint32_t i = 0; i < total_chunks; i++) {
  ports[i] = chunk_port(sess, cfg, i);
  }
  
  /* Allocate reorder buffer */
  uint8_t  **chunk_store = calloc(n_chunks, sizeof(uint8_t *));
  uint32_t  *chunk_lens  = calloc(n_chunks, sizeof(uint32_t));
  bool      *chunk_ready = calloc(n_chunks, sizeof(bool));
  if (!chunk_store || !chunk_lens || !chunk_ready) {
  free(ports); free(chunk_store); free(chunk_lens); free(chunk_ready);
  close(out_fd);
  return MPCP_ERR_ALLOC;
  }

  /* If resuming, mark already-written chunks as ready so writer skips them */
  uint32_t resume_count = 0;
  if (resuming) {
      resume_count = resume_load(out_path, chunk_ready, n_chunks);
      /* For resumed chunks we have no data to re-write - mark them done
       * with zero-length so the writer advances next_write_seq past them */
      for (uint32_t _ri = 0; _ri < n_chunks; _ri++) {
          if (chunk_ready[_ri] && !chunk_store[_ri]) {
              chunk_store[_ri] = malloc(1); /* sentinel */
              if (chunk_store[_ri]) {
                  chunk_store[_ri][0] = 0;
                  chunk_lens[_ri] = 0; /* zero-length = skip write */
              }
          }
      }
      if (resume_count > 0)
          fprintf(stderr, "[resume] skipping %u already-written chunks\n", resume_count);
  }
  
  mpcp_receiver_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.cfg          = cfg;
  ctx.sess         = sess;
  ctx.peer_addr    = peer_addr;  /* used by thread_receiver_t1 to reject injected chunks */
  ctx.out_fd       = out_fd;
  ctx.out_path     = out_path;
  ctx.ghost_count  = ghost_count;
  memcpy(ctx.ghost_seqs, ghost_seqs, ghost_count * sizeof(uint32_t));
  ctx.chunk_store    = chunk_store;
  ctx.chunk_lens     = chunk_lens;
  ctx.chunk_ready    = chunk_ready;
  ctx.next_write_seq = 0;
  atomic_store_explicit(&ctx.chunks_verified, 0u, memory_order_relaxed);
  atomic_store_explicit(&ctx.abort_flag, false, memory_order_relaxed);
  mpcp_dedup_init(&ctx.dedup);
  /* OPT: allocate one reusable decrypt buffer for the decryptor thread */
  ctx.decrypt_buf_sz = (size_t)cfg->chunk_pad_size + 1u;
  ctx.decrypt_buf    = malloc(ctx.decrypt_buf_sz);
  if (!ctx.decrypt_buf) {
      free(ports); free(chunk_store); free(chunk_lens); free(chunk_ready);
      close(out_fd); return MPCP_ERR_ALLOC;
  }
  
  /* chunk_plan: n_chunks, skip_compression from session (inferred from flags) */
  ctx.plan.n_chunks       = n_chunks;
  ctx.plan.chunk_pad_size = cfg->chunk_pad_size;
  
  /* Ring buf must hold ciphertext = chunk_pad_size + 16 (AEAD tag).
   * ring2 holds seq notifications only (tiny), but sized same for simplicity. */
  uint32_t ring_slot_sz = cfg->chunk_pad_size + 16u;
  int rc;
  if ((rc = mpcp_ring_init(&ctx.ring0, cfg->ring_depth, ring_slot_sz)) != MPCP_OK)
  goto cleanup;
  if ((rc = mpcp_ring_init(&ctx.ring1, cfg->ring_depth, ring_slot_sz)) != MPCP_OK)
  goto cleanup_r0;
  if ((rc = mpcp_ring_init(&ctx.ring2, cfg->ring_depth, ring_slot_sz)) != MPCP_OK)
  goto cleanup_r1;
  
  /* Catch window (spec S7.3) */
  uint32_t catch_ms = cfg->max_catch_window;
  
  recv_t1_arg_t  t1_arg  = { &ctx, total_chunks, catch_ms, ports };
  verifier_arg_t t2_arg  = { &ctx };
  decrypt_arg_t  t3_arg  = { &ctx };
  /* Use skip_compression from session (set by run_transfer from xfer_flags).
   * ctx.plan.skip_compression is always false on receiver (never computed here). */
  bool use_decomp = !sess->skip_compression;
  /* Pre-allocate decompression output buffer — reused across all chunks */
  size_t   decomp_cap = (size_t)cfg->chunk_pad_size + 4096u;
  uint8_t *decomp_buf = use_decomp ? malloc(decomp_cap) : NULL;
  writer_arg_t   t4_arg  = { &ctx, use_decomp, decomp_buf, decomp_cap };
  
  pthread_t t1, t2, t3, t4;
  pthread_create(&t1, NULL, thread_receiver_t1, &t1_arg);
  pthread_create(&t2, NULL, thread_verifier,    &t2_arg);
  pthread_create(&t3, NULL, thread_decryptor,   &t3_arg);
  pthread_create(&t4, NULL, thread_writer,       &t4_arg);
  
  pthread_join(t1, NULL);
  /* T1 sets t1_done itself on exit (signals T2 to drain ring0 and exit).
   * T2 sets t2_done → T3 exits → T3 sets t3_done → T4 exits.
   * The stage-done chain guarantees no buffered work is lost.
   * abort_flag remains as a hard-error/tripwire signal only. */
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
    pthread_join(t4, NULL);
  
  /* Verify all chunks were written before declaring success.
   * abort_flag fires when T1 times out; if the writer hadn't finished by
   * then, we have a partial file. Report failure so the caller can retry. */
  if (ctx.next_write_seq < n_chunks) {
    fprintf(stderr, "[pipeline] receiver: incomplete – wrote %u/%u chunks\n",
            ctx.next_write_seq, n_chunks);
    rc = MPCP_ERR_TIMEOUT;
    /* Remove the empty/partial output file so no garbage is left on disk */
    if (!resuming)
        unlink(out_path);
  } else {
    rc = MPCP_OK;
    resume_clear(out_path);  /* delete sidecar on success */
  }

  /* S11 Silent termination - zero key material */
  sodium_memzero(sess->session_key,   MPCP_SESSION_KEY_LEN);
  sodium_memzero(sess->master_secret, MPCP_MASTER_SECRET_LEN);
  
  mpcp_ring_destroy(&ctx.ring2);
  cleanup_r1:
  mpcp_ring_destroy(&ctx.ring1);
  cleanup_r0:
  mpcp_ring_destroy(&ctx.ring0);
  cleanup:
  for (uint32_t i = 0; i < n_chunks; i++) {
  if (chunk_store[i]) {
  sodium_memzero(chunk_store[i], chunk_lens[i]);
  free(chunk_store[i]);
  }
  }
  free(chunk_store);
  free(chunk_lens);
  free(chunk_ready);
  free(ports);
  if (ctx.decrypt_buf) {
      sodium_memzero(ctx.decrypt_buf, ctx.decrypt_buf_sz);
      free(ctx.decrypt_buf);
  }
  close(out_fd);
  return rc;
  }

/* Suppress unused-function warning for setup_timing_thread (used at runtime

- but not in this translation unit's call graph visible to the analyser) */
  static void __attribute__((used)) _use_setup_timing_thread(const mpcp_config_t *c)
  {
  (void)setup_timing_thread(c);
  }

