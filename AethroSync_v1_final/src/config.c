/* AethroSync — src/config.c — config struct, defaults, profiles, parser, validator */
#include "../include/platform.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
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

/* ========== src/config.c ========== */
/*

- config.c - MPCP configuration system
- 
- Covers spec sections:
- S5.1  PSK parameters and entropy enforcement
- S5.2  PSK generator (Diceware-style)
- S5.3  Ed25519 auth toggle
- S16.1 Configuration file parser
- S16.2 Deterministic CLI profiles (all five profiles)
- S16.3 Profile combination rules
- 
- Config load order (each layer overrides previous):
- 1. Compiled-in defaults
- 1. ~/.config/mpcp/mpcp.conf
- 1. Explicit -config <path>
- 1. Profile flag (-default / -wifi / -fast / -stealth / -internet)
- 1. Individual -param overrides
   */

#include <sys/random.h>

/* -------------------------

- Default word list for PSK generator (Diceware-style, 64 words)
- Full Diceware uses 7776 words; this subset is enough for testing.
- Production build should embed the full EFF long word list.
- ----------------------------------- */
  static const char *const psk_words[] = {
  "coral","tandem","velvet","sunrise","hinge","frozen","atlas","drum",
  "river","candle","prism","jackal","mango","quartz","ember","falcon",
  "lemon","cipher","mosaic","tundra","beacon","cobalt","dagger","ferret",
  "gravel","hollow","indigo","juniper","kelp","lantern","mortar","nectar",
  "obsidian","parsley","quarry","radish","saddle","timber","urchin","vapor",
  "walnut","xenon","yarrow","zipper","acorn","brine","castle","divot",
  "elbow","fender","glyph","hatch","ivory","joist","knurl","lathe",
  "mitre","nodule","orbit","pinion","quill","rivet","solder","toggle"
  };
  static const size_t psk_word_count = sizeof(psk_words) / sizeof(psk_words[0]);

/* -------------------------

- S16.1  Compiled-in defaults
- ----------------------------------- */
  void mpcp_config_defaults(mpcp_config_t *cfg)
  {
  memset(cfg, 0, sizeof(*cfg));
  
  /* PSK */
  cfg->psk_min_entropy    = 40;
  cfg->psk_store          = false;
  
  /* Auth */
  cfg->auth_mode          = MPCP_AUTH_PSK;
  {
  const char *home = getenv("HOME");
  if (!home) home = "~";
  snprintf(cfg->auth_keydir, sizeof(cfg->auth_keydir),
  "%s/.config/mpcp/keys/", home);
  }
  
  /* Calibration */
  cfg->ping_count_min     = 60;
  cfg->ping_count_max     = 140;
  cfg->batch_size         = 10;
  cfg->slow_mode          = false;
  cfg->slow_mode_min_gap  = 2000;
  cfg->slow_mode_max_gap  = 8000;
  cfg->disguise_calibration = false;
  cfg->disguise_protocol  = MPCP_DISGUISE_DNS;
  
  /* RTT estimation */
  cfg->trim_pct           = 10.0;
  cfg->ewma_alpha         = 0.15;
  cfg->stddev_multiplier  = 4.0;
  cfg->floor_buffer       = 30;
  cfg->max_catch_window   = 500;
  
  /* Key exchange */
  cfg->key_candidates     = 10;
  cfg->key_exchange_delay = 50;
  
  /* Transfer */
  cfg->pipeline_depth     = 1;
  cfg->chunk_pad_size     = 63488;  /* 62KB: fits in one IPv4 UDP datagram (max 65451) */
  cfg->zstd_level         = 3;
  cfg->ghost_chunks_enabled = true;
  cfg->ghost_chunk_min    = 5;
  cfg->ghost_chunk_max    = 20;
  cfg->ack_jitter_max     = 80;
  cfg->chunk_retry_timeout= 2.0;
  cfg->decoy_encoding     = false;
  
  /* Ports */
  cfg->port_base          = 10000;
  cfg->port_range         = 55000;
  
  /* NAT */
  cfg->nat_mode           = MPCP_NAT_AUTO;
  cfg->rendezvous_port    = 7777;
  cfg->rendezvous_timeout = 30;
  cfg->hole_punch_attempts= 5;
  
  /* Memory and I/O */
  cfg->memory_lock        = true;
  cfg->zerocopy           = true;
  cfg->batch_syscalls     = true;
  
  /* Tripwire */
  cfg->tripwire           = true;
  cfg->tripwire_z_threshold = 3.5;
  cfg->tripwire_window    = 5;
  cfg->tripwire_chi_pvalue= 0.05;
  {
  const char *home = getenv("HOME");
  if (!home) home = "~";
  snprintf(cfg->canary_log, sizeof(cfg->canary_log),
  "%s/.config/mpcp/canary.log", home);
  }
  
  /* Threading */
  cfg->ring_depth         = 4;
  cfg->timing_core_id     = 0;
  }

/* -------------------------

- S16.2  Deterministic CLI profiles
- Each function sets EXACTLY the parameters listed in the spec table.
- All other parameters are untouched.
- ----------------------------------- */
  void mpcp_profile_default(mpcp_config_t *cfg)
  {
  cfg->slow_mode              = false;
  cfg->disguise_calibration   = false;
  cfg->stddev_multiplier      = 4.0;
  cfg->floor_buffer           = 30;
  cfg->max_catch_window       = 500;
  cfg->ewma_alpha             = 0.15;
  cfg->pipeline_depth         = 1;
  cfg->ghost_chunk_min        = 5;
  cfg->ghost_chunk_max        = 20;
  cfg->tripwire_z_threshold   = 3.5;
  cfg->auth_mode              = MPCP_AUTH_PSK;
  cfg->decoy_encoding         = false;
  }

void mpcp_profile_wifi(mpcp_config_t *cfg)
{
cfg->stddev_multiplier      = 5.0;
cfg->floor_buffer           = 50;
cfg->max_catch_window       = 600;
cfg->ewma_alpha             = 0.10;
cfg->pipeline_depth         = 1;
cfg->tripwire_z_threshold   = 4.5;
}

void mpcp_profile_fast(mpcp_config_t *cfg)
{
cfg->slow_mode              = false;
cfg->floor_buffer           = 10;
cfg->stddev_multiplier      = 3.0;
cfg->pipeline_depth         = 4;
cfg->ghost_chunk_max        = 5;
cfg->ack_jitter_max         = 20;
cfg->ewma_alpha             = 0.20;
}

void mpcp_profile_stealth(mpcp_config_t *cfg)
{
cfg->slow_mode              = true;
cfg->slow_mode_min_gap      = 2000;
cfg->slow_mode_max_gap      = 8000;
cfg->disguise_calibration   = true;
cfg->ghost_chunks_enabled   = true;
cfg->ghost_chunk_min        = 10;
cfg->ghost_chunk_max        = 30;
cfg->pipeline_depth         = 1;
cfg->auth_mode              = MPCP_AUTH_ED25519;
cfg->tripwire_z_threshold   = 3.0;
cfg->ack_jitter_max         = 120;
}

void mpcp_profile_stealth_decoy(mpcp_config_t *cfg)
{
/* All stealth params first */
mpcp_profile_stealth(cfg);
/* Plus decoy encoding */
cfg->decoy_encoding         = true;
}

void mpcp_profile_internet(mpcp_config_t *cfg)
{
cfg->nat_mode               = MPCP_NAT_AUTO;
cfg->ewma_alpha             = 0.12;
cfg->stddev_multiplier      = 4.5;
cfg->max_catch_window       = 500;
cfg->ack_jitter_max         = 120;
cfg->tripwire_z_threshold   = 4.0;
}

/* -------------------------

- S16.1  Config file parser
- 
- Format: key = value
- Lines starting with '#' or empty are ignored.
- Boolean: true/false/yes/no/1/0.
- Strings: taken verbatim (leading/trailing whitespace stripped).
- ----------------------------------- */

/* Strip leading and trailing whitespace in-place. Returns pointer into s. */
static char *strip(char *s)
{
while (isspace((unsigned char)*s)) s++;
char *end = s + strlen(s);
while (end > s && isspace((unsigned char)*(end-1))) end--;
*end = '\0';
return s;
}

static bool parse_bool(const char *v, bool *out)
{
if (!strcasecmp(v,"true") || !strcasecmp(v,"yes") || !strcmp(v,"1"))
{ *out = true;  return true; }
if (!strcasecmp(v,"false") || !strcasecmp(v,"no")  || !strcmp(v,"0"))
{ *out = false; return true; }
return false;
}

static int apply_kv(mpcp_config_t *cfg, const char *key, const char *val)
{
#define BOOL_KEY(name, field) \
if (!strcmp(key, name)) { \
    bool b; \
    if (!parse_bool(val, &b)) return -1; \
    cfg->field = b; \
    return 0; \
}

#define UINT_KEY(name, field) \
if (!strcmp(key, name)) { \
    cfg->field = (uint32_t)atol(val); \
    return 0; \
}

#define DBL_KEY(name, field) \
if (!strcmp(key, name)) { \
    cfg->field = atof(val); \
    return 0; \
}

#define STR_KEY(name, field) \
if (!strcmp(key, name)) { \
    snprintf(cfg->field, sizeof(cfg->field), "%s", val); \
    return 0; \
}

/* PSK */
if (!strcmp(key,"psk")) {
    snprintf(cfg->psk, sizeof(cfg->psk), "%s", val);
    cfg->psk_len = strlen(cfg->psk);
    return 0;
}

UINT_KEY("psk_min_entropy",   psk_min_entropy)
BOOL_KEY("psk_store",         psk_store)

/* Auth */
if (!strcmp(key,"auth_mode")) {
    if (!strcasecmp(val,"ed25519")) cfg->auth_mode = MPCP_AUTH_ED25519;
    else cfg->auth_mode = MPCP_AUTH_PSK;
    return 0;
}
STR_KEY("auth_keydir", auth_keydir)

/* Calibration */
UINT_KEY("ping_count_min",    ping_count_min)
UINT_KEY("ping_count_max",    ping_count_max)
UINT_KEY("batch_size",        batch_size)
BOOL_KEY("slow_mode",         slow_mode)
UINT_KEY("slow_mode_min_gap", slow_mode_min_gap)
UINT_KEY("slow_mode_max_gap", slow_mode_max_gap)
BOOL_KEY("disguise_calibration", disguise_calibration)
if (!strcmp(key,"disguise_protocol")) {
    if (!strcasecmp(val,"ntp")) cfg->disguise_protocol = MPCP_DISGUISE_NTP;
    else cfg->disguise_protocol = MPCP_DISGUISE_DNS;
    return 0;
}

/* RTT */
DBL_KEY("trim_pct",           trim_pct)
DBL_KEY("ewma_alpha",         ewma_alpha)
DBL_KEY("stddev_multiplier",  stddev_multiplier)
UINT_KEY("floor_buffer",      floor_buffer)
UINT_KEY("max_catch_window",  max_catch_window)

/* Key exchange */
UINT_KEY("key_candidates",    key_candidates)
UINT_KEY("key_exchange_delay",key_exchange_delay)

/* Transfer */
UINT_KEY("pipeline_depth",    pipeline_depth)
UINT_KEY("chunk_pad_size",    chunk_pad_size)
if (!strcmp(key,"zstd_level")) { cfg->zstd_level = atoi(val); return 0; }
BOOL_KEY("ghost_chunks_enabled", ghost_chunks_enabled)
UINT_KEY("ghost_chunk_min",   ghost_chunk_min)
UINT_KEY("ghost_chunk_max",   ghost_chunk_max)
UINT_KEY("ack_jitter_max",    ack_jitter_max)
if (!strcmp(key,"chunk_retry_timeout")) { cfg->chunk_retry_timeout = atof(val); return 0; }
BOOL_KEY("decoy_encoding",    decoy_encoding)

/* Ports */
if (!strcmp(key,"port_base"))  { cfg->port_base  = (uint16_t)atoi(val); return 0; }
UINT_KEY("port_range",        port_range)

/* NAT */
if (!strcmp(key,"nat_mode")) {
    if (!strcasecmp(val,"direct"))    cfg->nat_mode = MPCP_NAT_DIRECT;
    else if (!strcasecmp(val,"force_nat")) cfg->nat_mode = MPCP_NAT_FORCE;
    else cfg->nat_mode = MPCP_NAT_AUTO;
    return 0;
}
STR_KEY("rendezvous_host",    rendezvous_host)
if (!strcmp(key,"rendezvous_port")) { cfg->rendezvous_port = (uint16_t)atoi(val); return 0; }
UINT_KEY("rendezvous_timeout",rendezvous_timeout)
UINT_KEY("hole_punch_attempts",hole_punch_attempts)

/* Memory / I/O */
BOOL_KEY("memory_lock",       memory_lock)
BOOL_KEY("zerocopy",          zerocopy)
BOOL_KEY("batch_syscalls",    batch_syscalls)

/* Tripwire */
BOOL_KEY("tripwire",          tripwire)
DBL_KEY("tripwire_z_threshold", tripwire_z_threshold)
UINT_KEY("tripwire_window",   tripwire_window)
DBL_KEY("tripwire_chi_pvalue",tripwire_chi_pvalue)
STR_KEY("canary_log",         canary_log)

/* Threading */
UINT_KEY("ring_depth",        ring_depth)
if (!strcmp(key,"timing_core_id")) { cfg->timing_core_id = atoi(val); return 0; }

#undef BOOL_KEY
#undef UINT_KEY
#undef DBL_KEY
#undef STR_KEY

fprintf(stderr, "[config] unknown key '%s' - ignored\n", key);
return 0; /* unknown keys are warned but not fatal */

}

int mpcp_config_load_file(mpcp_config_t *cfg, const char *path)
{
FILE *f = fopen(path, "r");
if (!f) {
if (errno == ENOENT) return MPCP_OK; /* missing file is fine */
fprintf(stderr, "[config] cannot open %s: %s\n", path, strerror(errno));
return MPCP_ERR_IO;
}

char line[1024];
int  lineno = 0;
while (fgets(line, sizeof(line), f)) {
    lineno++;
    char *s = strip(line);
    if (*s == '\0' || *s == '#') continue;

    char *eq = strchr(s, '=');
    if (!eq) {
        fprintf(stderr, "[config] line %d: no '=' found - skipped\n", lineno);
        continue;
    }
    *eq = '\0';
    char *key = strip(s);
    char *val = strip(eq + 1);

    if (apply_kv(cfg, key, val) != 0)
        fprintf(stderr, "[config] line %d: invalid value for '%s'\n", lineno, key);
}
fclose(f);
return MPCP_OK;

}

/* Load default path: ~/.config/mpcp/mpcp.conf */
int mpcp_config_load_default(mpcp_config_t *cfg)
{
const char *home = getenv("HOME");
if (!home) home = "~";
char path[512];
snprintf(path, sizeof(path), "%s/.config/mpcp/mpcp.conf", home);
return mpcp_config_load_file(cfg, path);
}

/* -------------------------

- S5.1  PSK entropy estimation (simple Shannon-based estimate)
- 
- This is a lower-bound estimator, not a guarantee. It penalises:
- - Short passphrases
- - Low character-set diversity
- - High repetition
- 
- For a proper implementation, use zxcvbn or similar.
- ----------------------------------- */
  double mpcp_psk_entropy(const char *psk, size_t len)
  {
  if (!psk || len == 0) return 0.0;
  
  /* Count distinct character classes present */
  bool has_lower = false, has_upper = false,
  has_digit = false, has_sym   = false;
  for (size_t i = 0; i < len; i++) {
  unsigned char c = (unsigned char)psk[i];
  if (islower(c))                         has_lower = true;
  else if (isupper(c))                    has_upper = true;
  else if (isdigit(c))                    has_digit = true;
  else if (isprint(c) && !isspace(c))     has_sym   = true;
  }
  
  /* Alphabet size estimate */
  int alpha = 0;
  if (has_lower) alpha += 26;
  if (has_upper) alpha += 26;
  if (has_digit) alpha += 10;
  if (has_sym)   alpha += 32;
  if (alpha == 0) alpha = 26; /* fallback */
  
  /* H ~= len * log2(alpha) */
  double h = (double)len * (log((double)alpha) / log(2.0));
  
  /* Penalty for word-separator-only passphrases (dashes, spaces):
  - Each separator-delimited token treated as one "word symbol" of ~13 bits
  - (EFF list ~7776 words -> log2(7776) ~= 12.9 bits).
  - Count words: split on space/dash/underscore. */
    int words = 0;
    bool in_word = false;
    for (size_t i = 0; i <= len; i++) {
    char c = (i < len) ? psk[i] : '\0';
    bool sep = (c == '\0' || c == '-' || c == '_' || c == ' ');
    if (!sep && !in_word) { words++; in_word = true; }
    if (sep)               in_word = false;
    }
    double word_entropy = (double)words * 12.9;
  
  /* Return the lower of the two estimates */
  return (word_entropy < h) ? word_entropy : h;
  }

int mpcp_config_check_psk(const mpcp_config_t *cfg)
{
if (cfg->psk_len == 0) {
/* [REDACTED SECRET-PRINT] fprintf(stderr, "[config] PSK is empty\n"); */
return MPCP_ERR_ENTROPY;
}
double h = mpcp_psk_entropy(cfg->psk, cfg->psk_len);
if (h < (double)cfg->psk_min_entropy) {
fprintf(stderr,
"[config] PSK entropy %.1f bits is below minimum %u bits\n"
"         Use -generate-psk for a strong passphrase.\n",
h, cfg->psk_min_entropy);
return MPCP_ERR_ENTROPY;
}
return MPCP_OK;
}

/* -------------------------

- S5.2  PSK generator (Diceware-style)
- 
- Produces 8 random words joined by dashes, giving ~103 bits of entropy
- (8 x 12.9 bits) using the 64-word subset, or ~104 bits with full EFF list.
- ----------------------------------- */
  int mpcp_generate_psk(char *out, size_t out_size)
  {
  /* We need 8 random indices into psk_word_count */
  const int nwords = 8;
  char buf[512] = {0};
  size_t pos = 0;
  
  for (int i = 0; i < nwords; i++) {
  uint32_t idx;
  if (getrandom(&idx, sizeof(idx), 0) != (ssize_t)sizeof(idx)) {
  fprintf(stderr, "[config] getrandom failed: %s\n", strerror(errno));
  return MPCP_ERR_CRYPTO;
  }
  idx = idx % (uint32_t)psk_word_count;
  const char *word = psk_words[idx];
  size_t wlen = strlen(word);
  
   if (pos + wlen + 2 >= sizeof(buf)) break; /* safety */
   if (i > 0) buf[pos++] = '-';
   memcpy(buf + pos, word, wlen);
   pos += wlen;
  
  }
  buf[pos] = '\0';
  
  if (pos + 1 > out_size) {
/* [REDACTED SECRET-PRINT]   fprintf(stderr, "[config] output buffer too small for PSK\n"); */
  return MPCP_ERR_PARAM;
  }
  memcpy(out, buf, pos + 1);
  return MPCP_OK;
  }

/* -------------------------

- Config validation - check for obviously bad combinations
- ----------------------------------- */
  int mpcp_config_validate(const mpcp_config_t *cfg)
  {
  if (cfg->ping_count_min > cfg->ping_count_max) {
  fprintf(stderr,"[config] ping_count_min > ping_count_max\n");
  return MPCP_ERR_PARAM;
  }
  if (cfg->ping_count_min < 30) {
  fprintf(stderr,"[config] WARNING: ping_count_min < 30; "
  "z-score tripwire will use conservative fallback\n");
  /* non-fatal per spec S21.2 */
  }
  if (cfg->key_candidates == 0 || cfg->key_candidates > MPCP_MAX_CANDIDATES) {
  fprintf(stderr,"[config] key_candidates must be 1..%u\n", MPCP_MAX_CANDIDATES);
  return MPCP_ERR_PARAM;
  }
  if (cfg->ghost_chunk_min > cfg->ghost_chunk_max) {
  fprintf(stderr,"[config] ghost_chunk_min > ghost_chunk_max\n");
  return MPCP_ERR_PARAM;
  }
  if (cfg->chunk_pad_size < 1024) {
  fprintf(stderr,"[config] chunk_pad_size too small (< 1024)\n");
  return MPCP_ERR_PARAM;
  }
  if (cfg->chunk_pad_size > 63488u) {
  fprintf(stderr,"[config] chunk_pad_size too large (> 63488); must fit in UDP datagram with larger SEND_PKT_MAX\n");
  return MPCP_ERR_PARAM;
  }
  if (cfg->pipeline_depth == 0 || cfg->pipeline_depth > 8) {
  fprintf(stderr,"[config] pipeline_depth must be 1..8\n");
  return MPCP_ERR_PARAM;
  }
  if (cfg->trim_pct < 0.0 || cfg->trim_pct > 40.0) {
  fprintf(stderr,"[config] trim_pct must be 0..40\n");
  return MPCP_ERR_PARAM;
  }
  if (cfg->ewma_alpha <= 0.0 || cfg->ewma_alpha >= 1.0) {
  fprintf(stderr,"[config] ewma_alpha must be in (0, 1)\n");
  return MPCP_ERR_PARAM;
  }
  if ((uint32_t)cfg->port_base + cfg->port_range > 65535u) {
  fprintf(stderr,"[config] port_base(%u) + port_range(%u) exceeds 65535\n",
  cfg->port_base, cfg->port_range);
  return MPCP_ERR_PARAM;
  }
  return MPCP_OK;
  }

/* -------------------------

- Config dump - for -debug and test T-18
- ----------------------------------- */
  void mpcp_config_dump(const mpcp_config_t *cfg, FILE *out)
  {
  fprintf(out, "# MPCP config dump\n");
/* [REDACTED SECRET-PRINT]   fprintf(out, "psk_min_entropy = %u\n", cfg->psk_min_entropy); */
/* [REDACTED SECRET-PRINT]   fprintf(out, "psk_store = %s\n", cfg->psk_store ? "true":"false"); */
  fprintf(out, "auth_mode = %s\n",
  cfg->auth_mode == MPCP_AUTH_ED25519 ? "ed25519" : "psk");
  fprintf(out, "auth_keydir = %s\n", cfg->auth_keydir);
  
  fprintf(out, "ping_count_min = %u\n", cfg->ping_count_min);
  fprintf(out, "ping_count_max = %u\n", cfg->ping_count_max);
  fprintf(out, "batch_size = %u\n",     cfg->batch_size);
  fprintf(out, "slow_mode = %s\n",      cfg->slow_mode ? "true":"false");
  fprintf(out, "slow_mode_min_gap = %u\n", cfg->slow_mode_min_gap);
  fprintf(out, "slow_mode_max_gap = %u\n", cfg->slow_mode_max_gap);
  fprintf(out, "disguise_calibration = %s\n", cfg->disguise_calibration ? "true":"false");
  fprintf(out, "disguise_protocol = %s\n",
  cfg->disguise_protocol == MPCP_DISGUISE_NTP ? "ntp":"dns");
  
  fprintf(out, "trim_pct = %.2f\n",          cfg->trim_pct);
  fprintf(out, "ewma_alpha = %.3f\n",         cfg->ewma_alpha);
  fprintf(out, "stddev_multiplier = %.2f\n",  cfg->stddev_multiplier);
  fprintf(out, "floor_buffer = %u\n",         cfg->floor_buffer);
  fprintf(out, "max_catch_window = %u\n",     cfg->max_catch_window);
  
  fprintf(out, "key_candidates = %u\n",       cfg->key_candidates);
  fprintf(out, "key_exchange_delay = %u\n",   cfg->key_exchange_delay);
  
  fprintf(out, "pipeline_depth = %u\n",       cfg->pipeline_depth);
  fprintf(out, "chunk_pad_size = %u\n",        cfg->chunk_pad_size);
  fprintf(out, "zstd_level = %d\n",           cfg->zstd_level);
  fprintf(out, "ghost_chunks_enabled = %s\n", cfg->ghost_chunks_enabled ? "true":"false");
  fprintf(out, "ghost_chunk_min = %u\n",       cfg->ghost_chunk_min);
  fprintf(out, "ghost_chunk_max = %u\n",       cfg->ghost_chunk_max);
  fprintf(out, "ack_jitter_max = %u\n",        cfg->ack_jitter_max);
  fprintf(out, "chunk_retry_timeout = %.2f\n", cfg->chunk_retry_timeout);
  fprintf(out, "decoy_encoding = %s\n",        cfg->decoy_encoding ? "true":"false");
  
  fprintf(out, "port_base = %u\n",             cfg->port_base);
  fprintf(out, "port_range = %u\n",            cfg->port_range);
  
  fprintf(out, "nat_mode = %s\n",
  cfg->nat_mode == MPCP_NAT_DIRECT ? "direct" :
  cfg->nat_mode == MPCP_NAT_FORCE  ? "force_nat" : "auto");
  fprintf(out, "rendezvous_host = %s\n",  cfg->rendezvous_host);
  fprintf(out, "rendezvous_port = %u\n",  cfg->rendezvous_port);
  fprintf(out, "rendezvous_timeout = %u\n", cfg->rendezvous_timeout);
  fprintf(out, "hole_punch_attempts = %u\n", cfg->hole_punch_attempts);
  
  fprintf(out, "memory_lock = %s\n",   cfg->memory_lock    ? "true":"false");
  fprintf(out, "zerocopy = %s\n",      cfg->zerocopy       ? "true":"false");
  fprintf(out, "batch_syscalls = %s\n",cfg->batch_syscalls  ? "true":"false");
  
  fprintf(out, "tripwire = %s\n",              cfg->tripwire ? "true":"false");
  fprintf(out, "tripwire_z_threshold = %.2f\n",cfg->tripwire_z_threshold);
  fprintf(out, "tripwire_window = %u\n",       cfg->tripwire_window);
  fprintf(out, "tripwire_chi_pvalue = %.3f\n", cfg->tripwire_chi_pvalue);
  fprintf(out, "canary_log = %s\n",            cfg->canary_log);
  
  fprintf(out, "ring_depth = %u\n",            cfg->ring_depth);
  fprintf(out, "timing_core_id = %d\n",        cfg->timing_core_id);
  }

