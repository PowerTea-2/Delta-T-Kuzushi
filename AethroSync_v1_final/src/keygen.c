/* AethroSync — src/keygen.c — candidate key generation and management */
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

/* ========== src/keygen.c ========== */
/*

- keygen.c - MPCP candidate key generation and Ed25519 auth
- 
- Covers spec sections:
- S8.1  Candidate key generation (PC1 generates N fresh 32-byte keys)
- S5.3  Ed25519 keypair management (optional auth mode)
- 
- Security properties:
- - Each candidate key is a fresh 32-byte getrandom() output
- - All candidates stored in sodium_malloc()'d locked memory
- - N-1 losers zeroed immediately after session key derivation
- - Ed25519 keys stored 0600/0644 in auth_keydir
    */

#include <sys/stat.h>
#include <sys/random.h>

/* -------------------------

- S8.1  Candidate key generation
- ----------------------------------- */

int mpcp_keygen_candidates(uint32_t n, mpcp_candidates_t *out)
{
if (!out || n == 0 || n > MPCP_MAX_CANDIDATES)
return MPCP_ERR_PARAM;

out->n    = 0;
out->keys = NULL;

/* Allocate array of pointers (plain heap - the keys themselves are locked) */
out->keys = calloc(n, sizeof(uint8_t *));
if (!out->keys) return MPCP_ERR_ALLOC;

for (uint32_t i = 0; i < n; i++) {
    /* Each key individually sodium_malloc'd and mlock'd */
    out->keys[i] = sodium_malloc(32);
    if (!out->keys[i]) {
        mpcp_keygen_candidates_free(out);
        return MPCP_ERR_ALLOC;
    }

    /* Fill with OS CSPRNG */
    randombytes_buf(out->keys[i], 32);
    out->n++;
}
return MPCP_OK;

}

void mpcp_keygen_candidates_free(mpcp_candidates_t *cands)
{
if (!cands) return;
if (cands->keys) {
for (uint32_t i = 0; i < cands->n; i++) {
if (cands->keys[i]) {
sodium_memzero(cands->keys[i], 32);
sodium_free(cands->keys[i]);
cands->keys[i] = NULL;
}
}
free(cands->keys);
cands->keys = NULL;
}
cands->n = 0;
}

void mpcp_keygen_candidates_wipe_losers(mpcp_candidates_t *cands,
uint32_t           keep_idx)
{
if (!cands || !cands->keys) return;
for (uint32_t i = 0; i < cands->n; i++) {
if (i == keep_idx) continue;
if (cands->keys[i]) {
sodium_memzero(cands->keys[i], 32);
sodium_free(cands->keys[i]);
cands->keys[i] = NULL;
}
}
}

/* -------------------------

- Ed25519 key storage helpers
- ----------------------------------- */

/* Build a full path: keydir/filename into buf[buf_size] */
static int key_path(const char *keydir, const char *filename,
char *buf, size_t buf_size)
{
int n = snprintf(buf, buf_size, "%s/%s", keydir, filename);
if (n < 0 || (size_t)n >= buf_size) return MPCP_ERR_PARAM;
return MPCP_OK;
}

/* Recursively mkdir -p equivalent for a single directory path */
static int mkdir_p(const char *path)
{
char tmp[512];
snprintf(tmp, sizeof(tmp), "%s", path);
size_t len = strlen(tmp);
if (len && tmp[len-1] == '/') tmp[len-1] = '\0';

for (char *p = tmp + 1; *p; p++) {
    if (*p == '/') {
        *p = '\0';
        if (mkdir(tmp, 0700) != 0 && errno != EEXIST) return MPCP_ERR_IO;
        *p = '/';
    }
}
if (mkdir(tmp, 0700) != 0 && errno != EEXIST) return MPCP_ERR_IO;
return MPCP_OK;

}

/* Write len bytes to path with mode. Overwrites existing file. */
static int write_key_file(const char *path, mode_t mode,
const uint8_t *data, size_t len)
{
int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
if (fd < 0) {
fprintf(stderr, "[keygen] open %s: %s\n", path, strerror(errno));
return MPCP_ERR_IO;
}
ssize_t written = write(fd, data, len);
close(fd);
if (written != (ssize_t)len) {
fprintf(stderr, "[keygen] write %s: short write\n", path);
return MPCP_ERR_IO;
}
return MPCP_OK;
}

/* Read exactly len bytes from path into buf. */
static int read_key_file(const char *path, uint8_t *buf, size_t len)
{
int fd = open(path, O_RDONLY);
if (fd < 0) {
fprintf(stderr, "[keygen] open %s: %s\n", path, strerror(errno));
return MPCP_ERR_IO;
}
ssize_t n = read(fd, buf, len);
close(fd);
if (n != (ssize_t)len) {
fprintf(stderr, "[keygen] read %s: expected %zu got %zd\n", path, len, n);
return MPCP_ERR_IO;
}
return MPCP_OK;
}

/* -------------------------

- S5.3  Ed25519 keypair generation
- 
- Generates a fresh keypair on first run.
- sk (secret key): 64 bytes, mode 0600
- pk (public key): 32 bytes, mode 0644
- 
- libsodium Ed25519:
- crypto_sign_keypair(pk[32], sk[64])
- sk contains the seed concatenated with pk (libsodium convention)
- ----------------------------------- */
  int mpcp_ed25519_keygen(const char *keydir)
  {
  if (!keydir) return MPCP_ERR_PARAM;
  
  /* Create keydir if missing */
  int rc = mkdir_p(keydir);
  if (rc != MPCP_OK) return rc;
  
  char sk_path[512], pk_path[512];
  if (key_path(keydir, "mpcp_ed25519.sk", sk_path, sizeof(sk_path)) != MPCP_OK)
  return MPCP_ERR_PARAM;
  if (key_path(keydir, "mpcp_ed25519.pk", pk_path, sizeof(pk_path)) != MPCP_OK)
  return MPCP_ERR_PARAM;
  
  /* Don't overwrite existing keypair */
  if (access(sk_path, F_OK) == 0) {
  fprintf(stderr, "[keygen] keypair already exists in %s\n", keydir);
  return MPCP_OK;
  }
  
  /* Generate fresh keypair in locked memory */
  uint8_t *pk = sodium_malloc(crypto_sign_PUBLICKEYBYTES);
  uint8_t *sk = sodium_malloc(crypto_sign_SECRETKEYBYTES);
  if (!pk || !sk) {
  sodium_free(pk); sodium_free(sk);
  return MPCP_ERR_ALLOC;
  }
  
  if (crypto_sign_keypair(pk, sk) != 0) {
  sodium_memzero(sk, crypto_sign_SECRETKEYBYTES);
  sodium_free(pk); sodium_free(sk);
  return MPCP_ERR_CRYPTO;
  }
  
  /* Write files */
  rc = write_key_file(sk_path, 0600, sk, crypto_sign_SECRETKEYBYTES);
  if (rc == MPCP_OK)
  rc = write_key_file(pk_path, 0644, pk, crypto_sign_PUBLICKEYBYTES);
  
  sodium_memzero(sk, crypto_sign_SECRETKEYBYTES);
  sodium_free(pk);
  sodium_free(sk);
  
  if (rc == MPCP_OK)
  fprintf(stderr, "[keygen] Ed25519 keypair written to %s\n", keydir);
  
  return rc;
  }

int mpcp_ed25519_load_sk(const char *keydir, uint8_t *sk_out)
{
char path[512];
if (key_path(keydir, "mpcp_ed25519.sk", path, sizeof(path)) != MPCP_OK)
return MPCP_ERR_PARAM;
return read_key_file(path, sk_out, crypto_sign_SECRETKEYBYTES);
}

int mpcp_ed25519_load_pk(const char *keydir, uint8_t *pk_out)
{
char path[512];
if (key_path(keydir, "mpcp_ed25519.pk", path, sizeof(path)) != MPCP_OK)
return MPCP_ERR_PARAM;
return read_key_file(path, pk_out, crypto_sign_PUBLICKEYBYTES);
}

int mpcp_ed25519_load_peer_pk(const char *keydir, uint8_t *pk_out)
{
char path[512];
if (key_path(keydir, "mpcp_ed25519_peer.pk", path, sizeof(path)) != MPCP_OK)
return MPCP_ERR_PARAM;
return read_key_file(path, pk_out, crypto_sign_PUBLICKEYBYTES);
}

/* -------------------------

- S5.3  Ed25519 sign / verify
- ----------------------------------- */
  int mpcp_ed25519_sign(const uint8_t *sk,
  const uint8_t *transcript,
  uint8_t       *sig_out)
  {
  unsigned long long sig_len = 0;
  /* crypto_sign_detached produces a 64-byte detached signature */
  if (crypto_sign_detached(sig_out, &sig_len, transcript, 32, sk) != 0)
  return MPCP_ERR_CRYPTO;
  if (sig_len != 64) return MPCP_ERR_CRYPTO;
  return MPCP_OK;
  }

int mpcp_ed25519_verify(const uint8_t *peer_pk,
const uint8_t *transcript,
const uint8_t *sig)
{
if (crypto_sign_verify_detached(sig, transcript, 32, peer_pk) != 0)
return MPCP_ERR_CRYPTO;
return MPCP_OK;
}

/* -------------------------

- Session transcript hash (S5.3)
- 
- transcript = BLAKE2b-256(session_nonce || master_secret || "mpcp-v0.5-auth")
- ----------------------------------- */
  int mpcp_session_transcript(const uint8_t *session_nonce,
  const uint8_t *master_secret,
  uint8_t        transcript_out[32])
  {
  static const uint8_t label[] = "mpcp-v0.5-auth";
  crypto_generichash_state st;
  
  if (crypto_generichash_init(&st, NULL, 0, 32) != 0)
  return MPCP_ERR_CRYPTO;
  if (crypto_generichash_update(&st, session_nonce, 32) != 0)
  return MPCP_ERR_CRYPTO;
  if (crypto_generichash_update(&st, master_secret, 32) != 0)
  return MPCP_ERR_CRYPTO;
  if (crypto_generichash_update(&st, label, sizeof(label) - 1) != 0)
  return MPCP_ERR_CRYPTO;
  if (crypto_generichash_final(&st, transcript_out, 32) != 0)
  return MPCP_ERR_CRYPTO;
  
  return MPCP_OK;
  }

