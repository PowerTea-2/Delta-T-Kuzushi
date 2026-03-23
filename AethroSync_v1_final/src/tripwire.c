/* AethroSync — src/tripwire.c — chi-squared loss pattern detector */
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

/* ========== src/tripwire.c ========== */
/*

- tripwire.c - Interception detection (spec S21)
- 
- S21.1  Overview: three anomaly classes, any trigger -> silent abort
- S21.2  Class 1: z-score timing oracle
      fallback to baseline_mean*3 when sample_count < 30
- S21.3  Class 2: chi-squared loss pattern (Pearson goodness-of-fit)
- S21.5  Abort: sodium_memzero all key material, write canary log, exit(0)
  */

/* -------------------------

- Minimum calibration pings for a reliable z-score baseline (spec S21.2)
- ----------------------------------- */
  #define TRIPWIRE_MIN_SAMPLES_FOR_ZSCORE  30u

/* -------------------------

- S21.1  Init
- ----------------------------------- */
  void mpcp_tripwire_init(mpcp_tripwire_t         *tw,
  const mpcp_rtt_result_t *rtt,
  const mpcp_config_t     *cfg)
  {
  memset(tw, 0, sizeof(*tw));
  tw->baseline_mean  = rtt->baseline_mean;
  tw->baseline_std   = rtt->baseline_std;
  tw->sample_count   = rtt->sample_count;
  tw->z_threshold    = cfg->tripwire_z_threshold;
  tw->window         = cfg->tripwire_window;
  tw->chi_pvalue     = cfg->tripwire_chi_pvalue;
  tw->triggered      = false;
  }

/* -------------------------

- S21.2  Feed one bounce RTT measurement (milliseconds).
- ----------------------------------- */
  int mpcp_tripwire_feed_rtt(mpcp_tripwire_t *tw, double oracle_rtt_ms)
  {
  if (!tw || tw->triggered) return MPCP_ERR_TRIPWIRE;
  
  double z;
  
  if (tw->sample_count >= TRIPWIRE_MIN_SAMPLES_FOR_ZSCORE
  && tw->baseline_std > 1e-9)
  {
  /* spec S21.2 - z-score path */
  z = (oracle_rtt_ms - tw->baseline_mean) / tw->baseline_std;
  if (z > tw->z_threshold) {
  tw->consecutive_anomalies++;
  } else {
  tw->consecutive_anomalies = 0;
  }
  } else {
  /* spec S21.2 - conservative fallback: threshold = baseline_mean * 3 */
  double threshold = tw->baseline_mean * 3.0;
  if (oracle_rtt_ms > threshold) {
  tw->consecutive_anomalies++;
  } else {
  tw->consecutive_anomalies = 0;
  }
  }
  
  if (tw->consecutive_anomalies > tw->window) {
  tw->triggered = true;
  return MPCP_ERR_TRIPWIRE;
  }
  
  return MPCP_OK;
  }

/* -------------------------

- S21.3  Chi-squared test for non-random loss pattern.
- 
- Pearson goodness-of-fit: under random loss with probability p, the
- expected count in each of K equal-sized index buckets is n*p/K.
- We use K=8 buckets over the full chunk index space.  If the observed
- distribution deviates at p < chi_pvalue we flag it.
- 
- For very small loss counts (< 5) there is insufficient data;
- we skip the test to avoid false positives.
- ----------------------------------- */
  #define CHI_BUCKETS  8u

static double chi_squared_pvalue(const uint32_t *indices, uint32_t n,
uint32_t total_chunks)
{
if (n < 5 || total_chunks == 0) return 1.0;  /* not enough data */

uint32_t observed[CHI_BUCKETS];
memset(observed, 0, sizeof(observed));

uint32_t bucket_size = (total_chunks + CHI_BUCKETS - 1u) / CHI_BUCKETS;
if (bucket_size == 0) bucket_size = 1;

for (uint32_t i = 0; i < n; i++) {
    uint32_t b = indices[i] / bucket_size;
    if (b >= CHI_BUCKETS) b = CHI_BUCKETS - 1u;
    observed[b]++;
}

double expected = (double)n / (double)CHI_BUCKETS;
double chi2 = 0.0;
for (uint32_t b = 0; b < CHI_BUCKETS; b++) {
    double diff = (double)observed[b] - expected;
    chi2 += (diff * diff) / expected;
}

/*
 * Chi-squared CDF approximation for df = CHI_BUCKETS-1 = 7.
 * We use the Wilson-Hilferty cube-root transformation to get an
 * approximate p-value without requiring a full statistical library.
 * p ~= 1 - Phi( (x/df)^(1/3) - (1 - 2/(9*df)) ) / sqrt(2/(9*df)) )
 * where Phi is the standard normal CDF.
 */
double df       = (double)(CHI_BUCKETS - 1u);
double x        = chi2;
double mu       = 1.0 - 2.0 / (9.0 * df);
double sigma    = sqrt(2.0 / (9.0 * df));
double z_approx = (pow(x / df, 1.0 / 3.0) - mu) / sigma;

/* Complementary error function for one-sided upper-tail p-value */
double p_value = 0.5 * erfc(z_approx / sqrt(2.0));

return p_value;

}

int mpcp_tripwire_record_loss(mpcp_tripwire_t *tw, uint32_t seq_index)
{
if (!tw || tw->triggered) return MPCP_ERR_TRIPWIRE;

if (tw->lost_count < 4096u) {
    tw->lost_indices[tw->lost_count++] = seq_index;
}

/*
 * Only run the chi-squared test once we have enough data.
 * total_chunks is not stored in tripwire_t; approximate from
 * the maximum seen seq index.
 */
uint32_t max_seen = 0;
for (uint32_t i = 0; i < tw->lost_count; i++) {
    if (tw->lost_indices[i] > max_seen) max_seen = tw->lost_indices[i];
}
uint32_t approx_total = max_seen + 1u;

double pval = chi_squared_pvalue(tw->lost_indices, tw->lost_count,
                                 approx_total);
if (pval < tw->chi_pvalue) {
    tw->triggered = true;
    return MPCP_ERR_TRIPWIRE;
}

return MPCP_OK;

}

/* -------------------------

- S21.5  Abort procedure
- ----------------------------------- */
  void mpcp_tripwire_abort(mpcp_tripwire_t *tw  __attribute__((unused)),
  mpcp_session_t  *sess,
  const char      *canary_log_path,
  const char      *anomaly_type)
  {
  /* Zero all key material first */
  if (sess) {
  mpcp_crypto_abort(sess);
  }
  
  /* Write canary log entry */
  if (canary_log_path && canary_log_path[0] != '\0') {
  FILE *f = fopen(canary_log_path, "a");
  if (f) {
  time_t now     = time(NULL);
  char   ts[64];
  struct tm tmbuf;
  strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ",
  gmtime_r(&now, &tmbuf));
  
       /* Log: timestamp, anomaly type, HMAC-SHA256(canary_key, session_nonce).
        * Keyed hash prevents an adversary who can read the log from confirming
        * whether a specific session nonce triggered an abort. */
       uint8_t nonce_tag[32];
       char    nonce_hex[65];
       if (sess) {
           /* Load or generate canary key from ~/.config/mpcp/canary.key */
           uint8_t canary_key[32];
           const char *home = getenv("HOME");
           char keypath[512] = {0};
           if (home) snprintf(keypath, sizeof(keypath),
                              "%s/.config/mpcp/canary.key", home);
           bool got_key = false;
           if (keypath[0] != '\0') {
               int kfd = open(keypath, O_RDONLY);
               if (kfd >= 0) {
                   got_key = (read(kfd, canary_key, 32) == 32);
                   close(kfd);
               }
               if (!got_key) {
                   /* Generate and persist */
                   randombytes_buf(canary_key, 32);
                   int kfd2 = open(keypath, O_WRONLY|O_CREAT|O_TRUNC, 0600);
                   if (kfd2 >= 0) {
                       (void)write(kfd2, canary_key, 32);
                       close(kfd2);
                       got_key = true;
                   }
               }
           }
           if (!got_key) randombytes_buf(canary_key, 32); /* ephemeral fallback */
           /* HMAC-SHA256(canary_key, session_nonce) */
           crypto_auth_hmacsha256(nonce_tag,
                                  sess->session_nonce, MPCP_SESSION_NONCE_LEN,
                                  canary_key);
           sodium_memzero(canary_key, sizeof(canary_key));
           for (size_t i = 0; i < 32u; i++)
               (void)snprintf(nonce_hex + (int)(i*2u), 3, "%02x", nonce_tag[i]);
           nonce_hex[64] = '\0';
       } else {
           (void)strncpy(nonce_hex, "unknown", sizeof(nonce_hex) - 1);
           nonce_hex[sizeof(nonce_hex)-1] = '\0';
       }
  
       fprintf(f, "[%s] TRIPWIRE anomaly=%s session=%s\n",
               ts,
               anomaly_type ? anomaly_type : "unknown",
               nonce_hex);
       fclose(f);
   }
  
  }
  
  /* S21.5: exit(0) - silent, no network signal */
  _Exit(0);
  }

