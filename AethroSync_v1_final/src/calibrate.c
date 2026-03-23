/* AethroSync — src/calibrate.c — ping/pong, RTT pipeline, slow mode */
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

/* ========== src/calibrate.c ========== */
/*

- calibrate.c - MPCP Phase 2: RTT calibration
- 
- Covers spec sections:
- S7.1  Randomised ping count (getrandom mod range)
- S7.2  Standard mode / slow mode / disguised calibration
- S7.3  RTT estimation pipeline: trimmed mean + MAD + EWMA
- S13   WiFi considerations (handled via config profile)
- S19   SCHED_FIFO port timing thread (used here for ping send thread)
- S25.2 SCHED_FIFO setup
- 
- Calibration produces mpcp_rtt_result_t consumed by:
- - crypto.c (timing entropy for master secret)
- - sender.c / receiver.c (catch_window for port open timing)
- - tripwire.c (baseline_mean + baseline_std for z-score)
- 
- Threading: calibration runs in caller's thread. The port timing thread
- from S19 is set up once by the caller via mpcp_timing_thread_setup().
  */

#include <sys/random.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* For disguised calibration (stub: full DNS/NTP formatting is in disguise.c) */

/* -------------------------

- Internal helpers: sorting (qsort comparator for double)
- ----------------------------------- */
  static int cmp_double(const void *a, const void *b)
  {
  double da = *(const double *)a;
  double db = *(const double *)b;
  return (da > db) - (da < db);
  }

/* Return median of a sorted array */
static double median_sorted(const double *sorted, size_t n)
{
if (n == 0) return 0.0;
if (n % 2 == 1) return sorted[n / 2];
return (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0;
}

/* -------------------------

- S7.3 Stage 1 - Trimmed mean
- 
- Sort all N samples. Discard bottom trim_pct% and top trim_pct%.
- Compute mean of remaining (1 - 2*trim_pct/100)*N samples.
- ----------------------------------- */
  static double trimmed_mean(const double *rtts, size_t n, double trim_pct,
  double *sorted_out) /* caller provides n-element buffer */
  {
  memcpy(sorted_out, rtts, n * sizeof(double));
  qsort(sorted_out, n, sizeof(double), cmp_double);
  
  size_t lo = (size_t)floor((double)n * trim_pct / 100.0);
  size_t hi = n - lo;
  if (lo >= hi) {
  /* trim_pct so high there's nothing left - return simple mean */
  double s = 0.0;
  for (size_t i = 0; i < n; i++) s += rtts[i];
  return s / (double)n;
  }
  double sum = 0.0;
  for (size_t i = lo; i < hi; i++) sum += sorted_out[i];
  return sum / (double)(hi - lo);
  }

/* -------------------------

- S7.3 Stage 2 - MAD (Median Absolute Deviation)
- 
- median_rtt = median(rtts)
- deviations[i] = |rtt[i] - median_rtt|
- MAD = median(deviations)
- robust_std = 1.4826 * MAD
- ----------------------------------- */
  static double compute_mad(const double *rtts, size_t n,
  double *tmp) /* caller provides n-element buffer */
  {
  /* Copy and find median of original samples */
  memcpy(tmp, rtts, n * sizeof(double));
  qsort(tmp, n, sizeof(double), cmp_double);
  double med = median_sorted(tmp, n);
  
  /* Compute absolute deviations */
  for (size_t i = 0; i < n; i++)
  tmp[i] = fabs(rtts[i] - med);
  
  /* Median of deviations */
  qsort(tmp, n, sizeof(double), cmp_double);
  return median_sorted(tmp, n);
  }

/* -------------------------

- S7.3 Stage 3 - EWMA update
- 
- ewma = alpha * new_sample + (1 - alpha) * ewma
- ----------------------------------- */
  static inline double ewma_update(double current, double new_sample, double alpha)
  {
  return alpha * new_sample + (1.0 - alpha) * current;
  }

/* -------------------------

- S7.3 Catch window formula
- 
- flight_avg    = ewma_rtt / 2
- flight_spread = robust_std / 2
- catch_window  = min(flight_avg + multiplier * flight_spread + floor_buffer,
                  max_catch_window)
- All inputs/outputs in milliseconds.
- ----------------------------------- */
  static double compute_catch_window(double ewma_rtt_ms,
  double robust_std_ms,
  double stddev_multiplier,
  double floor_buffer_ms,
  double max_catch_window_ms)
  {
  double flight_avg    = ewma_rtt_ms / 2.0;
  double flight_spread = robust_std_ms / 2.0;
  double cw = flight_avg + stddev_multiplier * flight_spread + floor_buffer_ms;
  if (cw > max_catch_window_ms) cw = max_catch_window_ms;
  return cw;
  }

/* Maximum wire buffer size: cal packet (64B) + disguise overhead headroom */
#define MPCP_CAL_WIRE_BUF   512u

/*

- UDP ping/pong internals for raw calibration.
- PC2 sends pings, PC1 reflects as pongs. Both sides timestamp for RTT.
- PC2 (sender) side is here; PC1 pong reflection is in receiver.c.
  */

/* Minimal UDP socket for calibration pings.

- Returns fd, or -1 on error. Bound to any local port. */
  static int cal_socket_open(void)
  {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) { perror("calibrate: socket"); return -1; }
  
  /* Set receive timeout: 2 seconds per pong */
  struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
  perror("calibrate: setsockopt SO_RCVTIMEO");
  
  return fd;
  }

/* Build a calibration ping packet (spec S18.1, 64 bytes) */
static void build_ping(mpcp_cal_pkt_t *pkt,
uint16_t seq,
const uint8_t session_nonce[MPCP_SESSION_NONCE_LEN])
{
memset(pkt, 0, sizeof(*pkt));

/* Header */
uint32_t magic_be = htonl(MPCP_MAGIC);
memcpy(&pkt->hdr.magic, &magic_be, 4);
pkt->hdr.version = MPCP_VERSION;
pkt->hdr.type    = MPCP_TYPE_PING;

/* Sequence number (big-endian) */
pkt->seq = htons(seq);

/* Timestamp: CLOCK_MONOTONIC nanoseconds (informational field in packet,
 * not used for RTT calculation — RTT uses local send_times[] array). */
uint64_t ts = mpcp_now_ns();
pkt->send_ts = __builtin_bswap64(ts);

/* Nonce hint: first 16 bytes of session nonce */
memcpy(pkt->nonce_hint, session_nonce, MPCP_NONCE_HINT_LEN);

/* Random padding - return value intentionally ignored (best-effort entropy) */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
(void)getrandom(pkt->padding, sizeof(pkt->padding), 0);
#pragma GCC diagnostic pop

}

/* Parse a pong packet, extract send_ts and seq for RTT calculation */
static bool parse_pong(const uint8_t *buf, size_t len,
uint16_t expected_seq,
uint64_t *send_ts_out)
{
if (len < sizeof(mpcp_cal_pkt_t)) return false;

const mpcp_cal_pkt_t *pkt = (const mpcp_cal_pkt_t *)buf;

/* Check magic */
uint32_t magic;
memcpy(&magic, &pkt->hdr.magic, 4);
if (ntohl(magic) != MPCP_MAGIC) return false;
if (pkt->hdr.version != MPCP_VERSION) return false;
if (pkt->hdr.type != MPCP_TYPE_PONG) return false;

/* Sequence */
if (ntohs(pkt->seq) != expected_seq) return false;

*send_ts_out = __builtin_bswap64(pkt->send_ts);
return true;

}

/* -------------------------

- S7.1  Randomised ping count
- ----------------------------------- */
  static uint32_t random_ping_count(uint32_t min, uint32_t max)
  {
  if (min >= max) return min;
  uint32_t r;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
  (void)getrandom(&r, sizeof(r), 0);  /* best-effort; fallback to whatever r was if it fails */
#pragma GCC diagnostic pop
  return (r % (max - min + 1)) + min;  /* inclusive [min, max] */
  }

/* -------------------------

- S7.2  Standard mode ping burst
- 
- Sends pings in batches of batch_size. Within each batch, pings go out
- in rapid succession (~=1 RTT total per batch). Waits for pongs.
- 
- Returns number of successful RTT samples collected.
- ----------------------------------- */
  static size_t calibrate_standard(int sock_fd,
  const struct sockaddr_in *peer,
  uint32_t ping_count,
  uint32_t batch_size,
  const uint8_t *session_nonce,
  double *rtts_out,   /* pre-allocated [ping_count] */
  bool   disguise,
  mpcp_disguise_proto_t disguise_proto)
  {
  size_t collected = 0;
  uint16_t seq = 0;
  
  for (uint32_t batch_start = 0;
  batch_start < ping_count;
  batch_start += batch_size)
  {
  uint32_t batch_end = batch_start + batch_size;
  if (batch_end > ping_count) batch_end = ping_count;
  uint32_t this_batch = batch_end - batch_start;
  if (this_batch > 64) this_batch = 64; /* safety cap on batch size */
  
   /* Record local send timestamps per ping in this batch.
    * Zero-init: slots not filled by sendto() stay 0 so pong matching
    * detects "never sent" correctly on all compilers/optimisation levels. */
   uint64_t send_times[64] = {0};
  
   /* Send all pings in this batch */
   for (uint32_t i = 0; i < this_batch; i++) {
       mpcp_cal_pkt_t pkt;
       build_ping(&pkt, (uint16_t)(seq + i), session_nonce);
  
       uint8_t wire_buf[MPCP_CAL_WIRE_BUF];
       size_t  wire_len = sizeof(mpcp_cal_pkt_t);
  
       if (disguise) {
           wire_len = mpcp_disguise_wrap(
               (const uint8_t *)&pkt, sizeof(pkt),
               wire_buf, sizeof(wire_buf),
               disguise_proto);
           if (wire_len == 0) { send_times[i] = 0; continue; }
       } else {
           memcpy(wire_buf, &pkt, sizeof(pkt));
       }
  
       /* Capture send time with CLOCK_MONOTONIC: immune to NTP steps/slews.
        * CLOCK_REALTIME can jump during calibration and corrupt RTT values.
        * NOTE: timestamp is taken strictly before sendto() so it measures
        * departure time, not post-syscall time. */
       send_times[i] = mpcp_now_ns();
       sendto(sock_fd, wire_buf, wire_len, 0,
              (const struct sockaddr *)peer, sizeof(*peer));
       /* No fprintf/fflush here: fflush is a blocking write syscall that
        * adds variable jitter between consecutive pings in the batch.
        * Progress is printed once after the full batch is sent. */
   }
   /* Single progress line after burst: batch sent, now collecting pongs */
   fprintf(stderr, "\r  [pings %u-%u/%u] sent, collecting pongs...   ",
           seq + 1, seq + this_batch, ping_count);
   fflush(stderr);
   {
  
   /* Collect pongs for this batch (best-effort, timeout per pong).
    * matched[] guards against duplicate pongs inflating collected count. */
   uint8_t recv_buf[MPCP_CAL_WIRE_BUF];
   bool matched[64] = {false};  /* tracks which seqs already yielded an RTT */
   uint32_t matched_count = 0;
   for (uint32_t i = 0; i < this_batch && matched_count < this_batch; i++) {
       struct sockaddr_in from_addr;
       socklen_t from_len = sizeof(from_addr);
       ssize_t n = recvfrom(sock_fd, recv_buf, sizeof(recv_buf), 0,
                            (struct sockaddr *)&from_addr, &from_len);
       if (n < 0) continue; /* timeout or error - skip this pong */
  
       /* Reject packets not from the expected peer IP.
        * Without this, any UDP traffic on the LAN (another MPCP instance,
        * a residual process, broadcast noise) can be counted as a valid
        * pong, making calibration succeed when the receiver is not running. */
       if (from_addr.sin_addr.s_addr != peer->sin_addr.s_addr) continue;
       if ((size_t)n < sizeof(mpcp_cal_pkt_t)) continue;
  
       /* recv_ts: CLOCK_MONOTONIC for consistent delta with send_times[i] */
       uint64_t recv_ts = mpcp_now_ns();
  
       /* Unwrap disguise if needed (in-place is safe: unwrap <= wrap size) */
       size_t payload_len = (size_t)n;
       if (disguise) {
           payload_len = mpcp_disguise_unwrap(
               recv_buf, (size_t)n,
               recv_buf, sizeof(recv_buf),
               disguise_proto);
           if (payload_len == 0) continue;
       }
  
       /* Match pong to any unmatched ping in this batch by sequence */
       uint64_t pkt_send_ts;
       for (uint32_t j = 0; j < this_batch; j++) {
           if (!parse_pong(recv_buf, payload_len, (uint16_t)(seq + j), &pkt_send_ts))
               continue;
           /* Use local round-trip: recv_ts - send_times[j].
            * This avoids dependence on clock synchronisation between peers. */
           if (send_times[j] == 0) break; /* ping was never sent */
           if (matched[j]) break;         /* duplicate pong - already counted */
           double rtt_ms = (double)(recv_ts - send_times[j]) / 1e6;
           /* Accept 0.01ms–5000ms window. LAN RTT never exceeds a few hundred ms;
            * values above 5s are stale packets or scheduler glitches. */
           if (rtt_ms > 0.01 && rtt_ms < 5000.0) {
               rtts_out[collected++] = rtt_ms;
               matched[j] = true;
               matched_count++;
               fprintf(stderr, "\r  [pong %zu/~%u] RTT %.2f ms   ",
                       collected, ping_count, rtt_ms);
           }
           break;
       }
   }
   } /* end pong collection block */
   seq += (uint16_t)this_batch;
  
  }
  return collected;
  }

/* -------------------------

- S7.2  Slow mode: one ping per randomised interval over minutes
- ----------------------------------- */
  static size_t calibrate_slow(int sock_fd,
  const struct sockaddr_in *peer,
  uint32_t ping_count,
  uint32_t min_gap_ms,
  uint32_t max_gap_ms,
  const uint8_t *session_nonce,
  double *rtts_out,
  bool disguise,
  mpcp_disguise_proto_t disguise_proto)
  {
  size_t collected = 0;
  
  for (uint32_t i = 0; i < ping_count; i++) {
  /* Random inter-ping delay */
  uint32_t rng;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
  (void)getrandom(&rng, sizeof(rng), 0);  /* best-effort */
#pragma GCC diagnostic pop
  uint32_t gap_ms = (rng % (max_gap_ms - min_gap_ms + 1)) + min_gap_ms;  /* inclusive [min, max] */
  
   /* Sleep gap_ms milliseconds */
   struct timespec ts = {
       .tv_sec  = gap_ms / 1000,
       .tv_nsec = (long)(gap_ms % 1000) * 1000000L
   };
   nanosleep(&ts, NULL);
  
   mpcp_cal_pkt_t pkt;
   build_ping(&pkt, (uint16_t)i, session_nonce);
  
   uint8_t wire_buf[MPCP_CAL_WIRE_BUF];
   size_t  wire_len = sizeof(pkt);
   if (disguise) {
       wire_len = mpcp_disguise_wrap(
           (const uint8_t *)&pkt, sizeof(pkt),
           wire_buf, sizeof(wire_buf), disguise_proto);
   } else {
       memcpy(wire_buf, &pkt, sizeof(pkt));
   }
  
   /* CLOCK_MONOTONIC: stable across NTP adjustments */
   uint64_t send_ts = mpcp_now_ns();
   sendto(sock_fd, wire_buf, wire_len, 0,
          (const struct sockaddr *)peer, sizeof(*peer));
  
   uint8_t recv_buf[MPCP_CAL_WIRE_BUF];
   struct sockaddr_in from_s; socklen_t flen_s = sizeof(from_s);
   ssize_t n = recvfrom(sock_fd, recv_buf, sizeof(recv_buf), 0,
                        (struct sockaddr *)&from_s, &flen_s);
   if (n < 0) continue;
   if (from_s.sin_addr.s_addr != peer->sin_addr.s_addr) continue;
   if ((size_t)n < sizeof(mpcp_cal_pkt_t)) continue;
  
   uint64_t recv_ts = mpcp_now_ns();  /* CLOCK_MONOTONIC: matches send_ts */
  
   if (disguise) {
       size_t ul = mpcp_disguise_unwrap(recv_buf, (size_t)n,
                                        recv_buf, sizeof(recv_buf),
                                        disguise_proto);
       if (ul == 0) continue;
   }
  
   uint64_t pkt_send_ts;
   if (!parse_pong(recv_buf, (size_t)n, (uint16_t)i, &pkt_send_ts))
       continue;
  
   /* Use recv_ts - send_ts (local clock, avoids clock skew) */
   double rtt_ms = (double)(recv_ts - send_ts) / 1e6;
   if (rtt_ms > 0.01 && rtt_ms < 5000.0)
       rtts_out[collected++] = rtt_ms;
  
  }
  return collected;
  }

/* -------------------------

- Mini re-calibration: 10 pings, EWMA updated each sample (spec S7.3 Stage 3)
- Called just before key exchange to freshen the EWMA estimate.
- ----------------------------------- */
  static void mini_recal(int sock_fd,
  const struct sockaddr_in *peer,
  const mpcp_config_t *cfg,
  const uint8_t *session_nonce,   /* must match what pong_server captured */
  double *ewma_rtt_inout)
  {
  const int MINI_PINGS = 10;
  double rtts[10];
  /* FIX: must pass the real session_nonce.
   * The receiver's pong_server validates nonce_hint against the first ping.
   * Passing a zeroed buffer meant every mini-recal ping was silently rejected
   * (nonce mismatch) and no pongs were ever reflected, making the EWMA
   * update a no-op. */
  size_t got = calibrate_standard(sock_fd, peer, MINI_PINGS, MINI_PINGS,
  session_nonce,
  rtts,
  cfg->disguise_calibration,
  cfg->disguise_protocol);
  for (size_t i = 0; i < got; i++)
  *ewma_rtt_inout = ewma_update(*ewma_rtt_inout, rtts[i], cfg->ewma_alpha);
  }

/* -------------------------

- S7.3  Full RTT estimation pipeline
- 
- Applies trimmed mean -> MAD -> EWMA to the collected samples.
- Stores all derived values in result.
- ----------------------------------- */
  static int rtt_pipeline(const double *rtts, size_t n,
  const mpcp_config_t *cfg,
  mpcp_rtt_result_t *result)
  {
  if (n < 3) {
  fprintf(stderr, "[calibrate] too few RTT samples (%zu); need >= 3\n", n);
  return MPCP_ERR_TIMEOUT;
  }
  
  double *sorted = malloc(n * sizeof(double));
  double *tmp    = malloc(n * sizeof(double));
  if (!sorted || !tmp) {
  free(sorted); free(tmp);
  return MPCP_ERR_ALLOC;
  }
  
  /* Stage 1 - Trimmed mean */
  result->trimmed_mean = trimmed_mean(rtts, n, cfg->trim_pct, sorted);
  
  /* Median (from sorted array computed above) */
  result->median_rtt   = median_sorted(sorted, n);
  
  /* Stage 2 - MAD */
  result->mad          = compute_mad(rtts, n, tmp);
  result->robust_std   = 1.4826 * result->mad;
  
  /* Stage 3 - EWMA initialised from trimmed_mean */
  result->ewma_rtt     = result->trimmed_mean;
  
  /* Baseline for z-score tripwire: use sorted array mean and std */
  double baseline_mean = 0.0;
  for (size_t i = 0; i < n; i++) baseline_mean += rtts[i];
  baseline_mean /= (double)n;
  result->baseline_mean = baseline_mean;
  
  double var = 0.0;
  for (size_t i = 0; i < n; i++) {
  double d = rtts[i] - baseline_mean;
  var += d * d;
  }
  result->baseline_std = (n > 1) ? sqrt(var / (double)(n - 1)) : result->robust_std;
  
  /* Catch window */
  result->catch_window = compute_catch_window(
  result->ewma_rtt,
  result->robust_std,
  cfg->stddev_multiplier,
  (double)cfg->floor_buffer,
  (double)cfg->max_catch_window);
  
  result->sample_count = (uint32_t)n;
  
  free(sorted);
  free(tmp);
  return MPCP_OK;
  }

/* -------------------------

- S21.2  Z-score tripwire note: if sample_count < 30, flag it
- ----------------------------------- */
  static void warn_if_low_samples(const mpcp_rtt_result_t *r)
  {
  if (r->sample_count < 30) {
  fprintf(stderr,
  "[calibrate] WARNING: only %u RTT samples collected (< 30). "
  "Z-score tripwire will use conservative fallback threshold "
  "(baseline_mean * 3) per spec S21.2.\n",
  r->sample_count);
  }
  }

/* -------------------------

- S19 / S25.2  SCHED_FIFO setup for the port timing thread
- 
- Call from the port timing thread itself (not from main thread).
- Requires CAP_SYS_NICE or rtprio limit set in /etc/security/limits.conf.
- ----------------------------------- */
  int mpcp_timing_thread_setup(int core_id)
  {
  /* Set SCHED_FIFO priority 80 */
  struct sched_param sp = { .sched_priority = 80 };
  if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp) != 0) {
  perror("[calibrate] pthread_setschedparam SCHED_FIFO");
  fprintf(stderr,
  "[calibrate] WARNING: SCHED_FIFO failed. "
  "Add to /etc/security/limits.conf:\n"
  "    %s hard rtprio 80\n"
  "    %s soft rtprio 80\n",
  getenv("USER") ? getenv("USER") : "youruser",
  getenv("USER") ? getenv("USER") : "youruser");
  /* Non-fatal: degraded timing precision */
  }
  
  /* Pin to isolated core via pthread_setaffinity_np */
  if (core_id >= 0) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET((size_t)core_id, &cpuset);
  if (pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset) != 0) {
  perror("[calibrate] pthread_setaffinity_np");
  fprintf(stderr,
  "[calibrate] WARNING: CPU affinity failed for core %d.\n"
  "  For maximum timing precision, add to kernel cmdline:\n"
  "  isolcpus=%d nohz_full=%d rcu_nocbs=%d\n",
  core_id, core_id, core_id, core_id);
  }
  }
  return MPCP_OK;
  }

/* -------------------------

- Public API: mpcp_calibrate()
- 
- Main entry point. Handles all of S7:
- 1. Randomise ping count
- 1. Run standard or slow mode pings (with optional disguise)
- 1. Apply three-stage RTT pipeline
- 1. Run 10-ping mini re-calibration, update EWMA
- 1. Recompute catch window with updated EWMA
- 1. Log result summary
- ----------------------------------- */
  int mpcp_calibrate(const mpcp_config_t    *cfg,
  const mpcp_session_t   *sess,
  const struct sockaddr_in *peer_addr,
  mpcp_rtt_result_t      *result_out)
  {
  int rc = MPCP_ERR_IO;
  
  /* S7.1 Random ping count */
  uint32_t ping_count = random_ping_count(cfg->ping_count_min,
  cfg->ping_count_max);
  fprintf(stderr, "[calibrate] ping_count=%u (range [%u,%u])\n",
  ping_count, cfg->ping_count_min, cfg->ping_count_max);
  
  /* Allocate sample buffer */
  double *rtts = calloc(ping_count, sizeof(double));
  if (!rtts) return MPCP_ERR_ALLOC;
  
  /* Open UDP socket */
  int sock = cal_socket_open();
  if (sock < 0) { free(rtts); return MPCP_ERR_IO; }
  
  /* S7.2 Standard or slow mode */
  size_t n_collected;
  if (cfg->slow_mode) {
  fprintf(stderr, "[calibrate] slow mode: %u pings over ~%u-%u seconds\n",
  ping_count,
  ping_count * cfg->slow_mode_min_gap / 1000,
  ping_count * cfg->slow_mode_max_gap / 1000);
  n_collected = calibrate_slow(
  sock, peer_addr, ping_count,
  cfg->slow_mode_min_gap, cfg->slow_mode_max_gap,
  sess->session_nonce, rtts,
  cfg->disguise_calibration, cfg->disguise_protocol);
  } else {
  n_collected = calibrate_standard(
  sock, peer_addr, ping_count, cfg->batch_size,
  sess->session_nonce, rtts,
  cfg->disguise_calibration, cfg->disguise_protocol);
  }
  
  fprintf(stderr, "[calibrate] collected %zu/%u RTT samples\n",
  n_collected, ping_count);
  
  if (n_collected < 3) {
  fprintf(stderr, "[calibrate] insufficient samples\n");
  rc = MPCP_ERR_TIMEOUT;
  goto done;
  }
  
  /* S7.3 Three-stage RTT pipeline */
  rc = rtt_pipeline(rtts, n_collected, cfg, result_out);
  if (rc != MPCP_OK) goto done;
  
  /* Mini re-calibration: 10 pings, update EWMA */
  fprintf(stderr, "[calibrate] mini re-cal (10 pings)...\n");
  mini_recal(sock, peer_addr, cfg, sess->session_nonce, &result_out->ewma_rtt);
  
  /* Recompute catch window with updated EWMA */
  result_out->catch_window = compute_catch_window(
  result_out->ewma_rtt,
  result_out->robust_std,
  cfg->stddev_multiplier,
  (double)cfg->floor_buffer,
  (double)cfg->max_catch_window);
  
  warn_if_low_samples(result_out);
  
  fprintf(stderr,
  "[calibrate] results:\n"
  "  trimmed_mean = %.3f ms\n"
  "  median_rtt   = %.3f ms\n"
  "  MAD          = %.3f ms\n"
  "  robust_std   = %.3f ms\n"
  "  ewma_rtt     = %.3f ms\n"
  "  catch_window = %.3f ms\n"
  "  baseline_mean= %.3f ms\n"
  "  baseline_std = %.3f ms\n",
  result_out->trimmed_mean,
  result_out->median_rtt,
  result_out->mad,
  result_out->robust_std,
  result_out->ewma_rtt,
  result_out->catch_window,
  result_out->baseline_mean,
  result_out->baseline_std);
  
  rc = MPCP_OK;
  done:
  close(sock);
  free(rtts);
  return rc;
  }

/* -------------------------

- Live EWMA update during transfer (called by tripwire.c on bounce RTT)
- ----------------------------------- */
  void mpcp_cal_ewma_update(mpcp_rtt_result_t *result,
  double new_rtt_ms,
  double alpha)
  {
  result->ewma_rtt = ewma_update(result->ewma_rtt, new_rtt_ms, alpha);
  }

/* -------------------------

- S21.2  Z-score computation (used by tripwire.c)
- ----------------------------------- */
  double mpcp_cal_zscore(const mpcp_rtt_result_t *result, double oracle_rtt_ms)
  {
  if (result->baseline_std < 1e-9) return 0.0;
  return (oracle_rtt_ms - result->baseline_mean) / result->baseline_std;
  }

/* -------------------------

- S21.2  Conservative fallback: oracle_rtt > baseline_mean * 3
- Used when sample_count < 30.
- ----------------------------------- */
  bool mpcp_cal_tripwire_fallback(const mpcp_rtt_result_t *result,
  double oracle_rtt_ms)
  {
  return oracle_rtt_ms > result->baseline_mean * 3.0;
  }

/* -------------------------

- Collect raw RTT samples as entropy source for master secret (S7.4)
- Returns pointer to internal rtt array - valid until result is freed.
- Caller copies needed samples before result is destroyed.
- 
- Since rtt_pipeline() doesn't retain the raw array, we expose a
- separate path to collect + return them.
- ----------------------------------- */
  int mpcp_calibrate_collect_samples(const mpcp_config_t     *cfg,
  const mpcp_session_t    *sess,
  const struct sockaddr_in *peer,
  double                  **samples_out,
  uint32_t                *count_out,
  mpcp_rtt_result_t       *result_out)
  {
  uint32_t ping_count = random_ping_count(cfg->ping_count_min,
  cfg->ping_count_max);
  double *rtts = calloc(ping_count, sizeof(double));
  if (!rtts) return MPCP_ERR_ALLOC;
  
  int sock = cal_socket_open();
  if (sock < 0) { free(rtts); return MPCP_ERR_IO; }
  
  size_t n;
  if (cfg->slow_mode)
  n = calibrate_slow(sock, peer, ping_count,
  cfg->slow_mode_min_gap, cfg->slow_mode_max_gap,
  sess->session_nonce, rtts,
  cfg->disguise_calibration, cfg->disguise_protocol);
  else
  n = calibrate_standard(sock, peer, ping_count, cfg->batch_size,
  sess->session_nonce, rtts,
  cfg->disguise_calibration, cfg->disguise_protocol);
  close(sock);
  
  /* Require at least 10 valid pong samples before declaring calibration
   * successful. Getting fewer than 10 pongs out of 60-140 pings sent
   * strongly indicates the receiver is not running. */
  if (n < 10) { free(rtts); return MPCP_ERR_TIMEOUT; }
  
  int rc = rtt_pipeline(rtts, n, cfg, result_out);
  if (rc != MPCP_OK) { free(rtts); return rc; }
  
  *samples_out = rtts;   /* caller must free() */
  *count_out   = (uint32_t)n;
  return MPCP_OK;
  }

