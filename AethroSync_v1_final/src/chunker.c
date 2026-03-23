/* AethroSync — src/chunker.c — chunk planning, pad+encrypt, ghost generation */
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

/* ========== src/chunker.c ========== */
/*

- chunker.c - Chunk planning, padding, encryption, ghost generation (spec S9)
- 
- S9.1  Compressibility detection (zstd level-1 probe on 64 KB sample)
- S9.3  Distributed remainder: no short final chunk
- S9.4  Pad to chunk_pad_size, XChaCha20-Poly1305 encrypt
- S9.5  Ghost chunk: random ciphertext, indistinguishable from data
     ghost_map: deterministic count and seq indices from session_key

*/

/* -------------------------

- S9.1  Compressibility detection
- ----------------------------------- */
  int mpcp_chunker_detect_compressibility(const uint8_t     *src,
  size_t             src_len,
  mpcp_chunk_plan_t *plan)
  {
  if (!src || !plan) return MPCP_ERR_PARAM;
  
  plan->skip_compression = false;
  
  if (src_len == 0) {
  plan->skip_compression = true;
  return MPCP_OK;
  }
  
  size_t probe_len = src_len < 65536u ? src_len : 65536u;
  
  size_t bound   = ZSTD_compressBound(probe_len);
  void  *scratch = malloc(bound);
  if (!scratch) {
  /* Cannot test - conservatively try compression */
  return MPCP_OK;
  }
  
  size_t compressed = ZSTD_compress(scratch, bound, src, probe_len, 1);
  free(scratch);
  
  if (ZSTD_isError(compressed)) {
  /* Compression failed - skip it */
  plan->skip_compression = true;
  return MPCP_OK;
  }
  
  /* spec S9.1: ratio > 0.95 -> skip compression */
  double ratio = (double)compressed / (double)probe_len;
  if (ratio > 0.95) {
  plan->skip_compression = true;
  }
  
  return MPCP_OK;
  }

/* -------------------------

- S9.3  Build chunk plan
- ----------------------------------- */

int mpcp_chunker_plan(size_t             compressed_size,
uint32_t           chunk_pad_size,
bool               skip_compression,
mpcp_chunk_plan_t *plan_out)
{
if (!plan_out || chunk_pad_size == 0) return MPCP_ERR_PARAM;
if (compressed_size == 0) return MPCP_ERR_PARAM;

/* Use chunk_pad_size as the target chunk size.
 * target_chunk_size() returns 100-256KB which exceeds the UDP max payload
 * of 65507 bytes once wire overhead is added. chunk_pad_size is the
 * configured maximum that fits in one UDP datagram. */
uint32_t target = chunk_pad_size;

/* Round up: at least 1 chunk */
uint32_t n = (uint32_t)((compressed_size + target - 1u) / target);
if (n == 0) n = 1;

/* BUG-P3-5 FIX: HKDF-Expand limit is 255*32=8160 bytes = 127 slots of 64B.
 * Silently clamping to 127 would silently drop trailing chunks of large files.
 * Caller (sender.c) must segment the file into <=127-chunk sessions. */
if (n > 127u) return MPCP_ERR_PARAM;

plan_out->n_chunks         = n;
plan_out->base_chunk_bytes = (uint32_t)(compressed_size / n);
plan_out->n_larger         = (uint32_t)(compressed_size % n);
plan_out->chunk_pad_size   = chunk_pad_size;
plan_out->skip_compression = skip_compression;

return MPCP_OK;

}

/* -------------------------

- S9.3  Per-chunk byte count
- ----------------------------------- */
  uint32_t mpcp_chunk_data_size(const mpcp_chunk_plan_t *plan,
  uint32_t                 chunk_idx)
  {
  if (!plan || chunk_idx >= plan->n_chunks) return 0;
  return plan->base_chunk_bytes + (chunk_idx < plan->n_larger ? 1u : 0u);
  }

/* -------------------------

- S9.4  Pad + encrypt one data chunk
- ----------------------------------- */
  int mpcp_chunker_encrypt_chunk(const uint8_t *plaintext,
  uint32_t       plaintext_len,
  const uint8_t *chunk_key,
  const uint8_t *session_nonce,
  uint32_t       seq,
  uint8_t       *ct_out,
  size_t        *ct_len_out,
  uint8_t        nonce_out[24],
  uint8_t        flags,
  uint32_t       chunk_pad_size)
  {
  if (!plaintext || !chunk_key || !session_nonce ||
  !ct_out || !ct_len_out || !nonce_out)
  return MPCP_ERR_PARAM;
  (void)flags;  /* flags are in the wire header, not in the ciphertext */

  /* S9.4: Pad plaintext to chunk_pad_size with random bytes before encrypting.
   * This ensures all data chunks have identical wire size (chunk_pad_size + 16),
   * indistinguishable from ghost chunks. Without padding, variable-length data
   * chunks may exceed the IPv4 UDP max (65507 bytes). */
  uint32_t pad_size = chunk_pad_size;
  if (plaintext_len > pad_size) {
      /* Should never happen if chunker_plan set target = chunk_pad_size */
      fprintf(stderr, "[chunker] BUG: plaintext_len %u > chunk_pad_size %u\n",
              plaintext_len, pad_size);
      return MPCP_ERR_PARAM;
  }
  uint8_t *padded = malloc(pad_size);
  if (!padded) return MPCP_ERR_ALLOC;
  memcpy(padded, plaintext, plaintext_len);
  if (plaintext_len < pad_size)
      randombytes_buf(padded + plaintext_len, pad_size - plaintext_len);

  int rc = mpcp_chunk_encrypt(chunk_key, session_nonce, seq,
                               padded, pad_size,
                               ct_out, ct_len_out, nonce_out);
  sodium_memzero(padded, pad_size);
  free(padded);
  return rc;
  }

/* -------------------------

- S9.5  Generate one ghost chunk
- 
- "Full-size encrypted chunk containing only random padding." (spec S3)
- The ghost chunk type byte in the wire header (0x05) makes it a ghost
- on the wire; here we produce just the ciphertext, identical in size
- and appearance to a data chunk.
- ----------------------------------- */
  int mpcp_chunker_generate_ghost(const uint8_t *chunk_key,
  const uint8_t *session_nonce,
  uint32_t       ghost_seq,
  uint32_t       chunk_pad_size,
  uint8_t       *ct_out,
  size_t        *ct_len_out,
  uint8_t        nonce_out[24])
  {
  if (!chunk_key || !session_nonce || !ct_out || !ct_len_out || !nonce_out)
  return MPCP_ERR_PARAM;
  if (chunk_pad_size == 0) return MPCP_ERR_PARAM;
  
  /* Generate a full chunk_pad_size random plaintext */
  uint8_t *random_plain = malloc(chunk_pad_size);
  if (!random_plain) return MPCP_ERR_ALLOC;
  
  randombytes_buf(random_plain, chunk_pad_size);
  
  int rc = mpcp_chunk_encrypt(chunk_key, session_nonce, ghost_seq,
  random_plain, chunk_pad_size,
  ct_out, ct_len_out, nonce_out);
  
  sodium_memzero(random_plain, chunk_pad_size);
  free(random_plain);
  return rc;
  }

/* -------------------------

- S9.5  Ghost map - deterministic ghost count from session_key
- 
- Derive a 4-byte value via HKDF(session_key, "ghost-count", nonce=""),
- mod (ghost_max - ghost_min + 1) + ghost_min.
- Ghost seq indices are consecutive starting at n_data_chunks.
- ----------------------------------- */
  int mpcp_ghost_map(const uint8_t *session_key,
  uint32_t       n_data_chunks,
  uint32_t       ghost_chunk_min,
  uint32_t       ghost_chunk_max,
  uint32_t      *ghost_seqs_out,
  uint32_t      *count_out)
  {
  if (!session_key || !ghost_seqs_out || !count_out) return MPCP_ERR_PARAM;
  if (ghost_chunk_min > ghost_chunk_max)             return MPCP_ERR_PARAM;
  
  /* BUG-P3-6 FIX: HKDF requires salt != IKM for proper extraction.
  - Use a fixed all-zero salt (mpcp_hkdf NULL salt = 0x00..0 by spec). */
    uint8_t derived[4];
    int rc = mpcp_hkdf(NULL, 0,
    session_key, MPCP_SESSION_KEY_LEN,
    "mpcp-v0.5-ghost-count",
    derived, sizeof(derived));
    if (rc != MPCP_OK) return rc;
  
  uint32_t raw = ((uint32_t)derived[0] << 24) |
  ((uint32_t)derived[1] << 16) |
  ((uint32_t)derived[2] <<  8) |
  (uint32_t)derived[3];
  
  uint32_t range = ghost_chunk_max - ghost_chunk_min + 1u;
  uint32_t count = (raw % range) + ghost_chunk_min;
  
  *count_out = count;
  for (uint32_t i = 0; i < count; i++) {
  ghost_seqs_out[i] = n_data_chunks + i;
  }
  
  return MPCP_OK;
  }


/* =========================================================================
 * S22  Decoy Encoding
 *
 * Wraps encrypted chunk ciphertext in a syntactically valid C header file.
 * Social misdirection only — the payload is already XChaCha20-encrypted.
 * Enable with decoy_encoding = true in config or --stealth-decoy profile.
 *
 * Wire overhead: ~3x (hex encoding doubles size, header/footer adds ~80 bytes)
 * ========================================================================= */

/* Estimate max decoy output size for a given ciphertext length */
size_t mpcp_decoy_max_len(size_t ct_len)
{
    /* hex encoding: 2 chars + "0x" + ", " per byte = ~6 chars per byte
     * plus ~120 bytes of header/footer */
    return ct_len * 14u + 256u;
}

/* Wrap ciphertext in C header format.
 * out must have at least mpcp_decoy_max_len(ct_len) bytes.
 * Returns actual bytes written, or 0 on error. */
size_t mpcp_decoy_wrap(const uint8_t *ct, size_t ct_len,
                        uint8_t *out,      size_t out_cap)
{
    if (!ct || !out || ct_len == 0) return 0;

    /* Generate a pseudorandom-looking guard name from first 4 bytes */
    char guard[32];
    snprintf(guard, sizeof(guard), "%02X%02X%02X%02X",
             ct[0], ct[1], ct[2], ct[3]);

    /* Write header */
    int hlen = snprintf((char *)out, out_cap,
        "/* autogenerated -- do not edit */\n"
        "#ifndef __TABLE_%s_H\n"
        "#define __TABLE_%s_H\n"
        "static const uint32_t __init_table[] = {\n    ",
        guard, guard);
    if (hlen <= 0 || (size_t)hlen >= out_cap) return 0;

    size_t pos = (size_t)hlen;
    uint32_t col = 0;

    /* Encode ciphertext as hex uint32 values (4 bytes each, padded if needed) */
    for (size_t i = 0; i < ct_len; i += 4) {
        uint32_t word = 0;
        for (int b = 0; b < 4 && (i + b) < ct_len; b++)
            word |= ((uint32_t)ct[i + b]) << (b * 8);

        int n = snprintf((char *)out + pos, out_cap - pos, "0x%08x,", word);
        if (n <= 0 || pos + (size_t)n >= out_cap) return 0;
        pos += (size_t)n;
        col++;
        if (col % 4 == 0 && i + 4 < ct_len) {
            if (pos + 6 >= out_cap) return 0;
            memcpy(out + pos, "\n    ", 6);
            pos += 5;
        } else if (i + 4 < ct_len) {
            if (pos + 1 >= out_cap) return 0;
            out[pos++] = ' ';
        }
    }

    /* Write footer */
    int flen = snprintf((char *)out + pos, out_cap - pos,
        "\n};\n#endif /* __TABLE_%s_H */\n", guard);
    if (flen <= 0 || pos + (size_t)flen >= out_cap) return 0;
    pos += (size_t)flen;
    return pos;
}

/* Unwrap: locate the hex data inside a C header and decode it back.
 * Returns decoded ciphertext length, or 0 on failure.
 * Decodes in-place: out must hold at least (wrapped_len / 14 + 4) bytes. */
size_t mpcp_decoy_unwrap(const uint8_t *wrapped, size_t wrapped_len,
                          uint8_t *out,            size_t out_cap)
{
    if (!wrapped || !out || wrapped_len < 20) return 0;

    const char *p   = (const char *)wrapped;
    const char *end = p + wrapped_len;

    /* Find the opening brace of the array */
    const char *brace = NULL;
    for (const char *q = p; q < end - 1; q++) {
        if (*q == '{') { brace = q + 1; break; }
    }
    if (!brace) return 0;

    /* Find the closing brace */
    const char *cbrace = NULL;
    for (const char *q = brace; q < end; q++) {
        if (*q == '}') { cbrace = q; break; }
    }
    if (!cbrace) return 0;

    size_t out_pos = 0;
    const char *q = brace;
    while (q < cbrace) {
        /* Skip whitespace and commas */
        while (q < cbrace && (*q == ' ' || *q == '\t' ||
               *q == '\n' || *q == '\r' || *q == ',')) q++;
        if (q >= cbrace) break;
        /* Parse 0xXXXXXXXX */
        if (q[0] == '0' && (q[1] == 'x' || q[1] == 'X')) {
            char *endp = NULL;
            uint32_t word = (uint32_t)strtoul(q, &endp, 16);
            if (!endp || endp == q) break;
            q = endp;
            /* Write word as 4 little-endian bytes */
            for (int b = 0; b < 4; b++) {
                if (out_pos >= out_cap) return 0;
                out[out_pos++] = (uint8_t)((word >> (b * 8)) & 0xFF);
            }
        } else {
            q++; /* skip unexpected chars */
        }
    }
    return out_pos;
}

