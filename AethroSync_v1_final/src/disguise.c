/* AethroSync — src/disguise.c — DNS/NTP traffic disguise wrap/unwrap */
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

/* ========== src/disguise.c ========== */
/*

- disguise.c - DNS / NTP packet formatting for DPI resistance (spec S7.2 / S22)
- 
- S22  DECOY_ENCODING toggle - disabled by default.
    Wraps MPCP packets in syntactically valid DNS or NTP shells.
    Social misdirection layer only; data is already XChaCha20-encrypted.
- 
- DNS wrapping:
- Payload placed in the RDATA of a TXT answer record inside a spoofed
- DNS response.  Header flags: QR=1 AA=1 RD=1 RA=1 RCODE=0.
- Wire layout:
  DNS header(12) | QNAME | QTYPE/QCLASS | ANAME | TYPE/CLASS/TTL/RDLEN | TXT
- 
- NTP wrapping:
- Payload carried in a RFC 5905 extension field appended after a 48-byte
- NTP client header.
- Wire layout:
  NTP header(48) | ext_type(2) | ext_len(2) | payload | 4B alignment pad
- 
- Both formats are social misdirection only.
  */

/* -------------------------

- Internal helpers
- ----------------------------------- */
  static void put_u16_be(uint8_t *p, uint16_t v)
  {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)(v);
  }

static void put_u32_be(uint8_t *p, uint32_t v)
{
p[0] = (uint8_t)(v >> 24);
p[1] = (uint8_t)(v >> 16);
p[2] = (uint8_t)(v >>  8);
p[3] = (uint8_t)(v);
}

static uint16_t get_u16_be(const uint8_t *p)
{
return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/* -------------------------

- DNS constants
- 
- QNAME encodes "mpcp.local" in DNS wire format:
- \x04 m p c p \x05 l o c a l \x00  (12 bytes)
- ----------------------------------- */
  #define DNS_HDR_LEN     12u
  static const uint8_t DNS_QNAME[12] = {
  0x04, 'm','p','c','p',
  0x05, 'l','o','c','a','l',
  0x00
  };
  #define DNS_QNAME_LEN   12u
  #define DNS_FLAGS_RESP  0x8580u   /* QR=1 AA=1 RD=1 RA=1 RCODE=0 */
  #define DNS_TYPE_TXT    0x0010u
  #define DNS_CLASS_IN    0x0001u
  #define DNS_TTL         0x00000078u  /* 120 s */

/* Minimum overhead: hdr(12)+qname(12)+qt/qc(4)+aname(12)+type/cls/ttl/rdlen(10)+txtlen(1) */
#define DNS_OVERHEAD    (DNS_HDR_LEN + DNS_QNAME_LEN + 4u + DNS_QNAME_LEN + 10u + 1u)

static size_t dns_wrap(const uint8_t *src, size_t src_len,
uint8_t *dst, size_t dst_size)
{
/* BUG-P3-7 FIX: DNS TXT RDATA uses a 1-byte length prefix per string (RFC 1035 S3.3.14).
* Max value of that byte = 255. Payloads > 255 bytes cannot be encoded in a single
* TXT string. The previous guard (> 0xFFFEu) would allow 65534-byte payloads that
* then get silently truncated by the uint8_t cast on the length byte. */
if (src_len > 255u) return 0;
size_t total = DNS_OVERHEAD + src_len;
if (total > dst_size) return 0;

uint8_t *p = dst;

/* Header */
put_u16_be(p, 0x1234u); p += 2;  /* transaction ID */
put_u16_be(p, DNS_FLAGS_RESP); p += 2;
put_u16_be(p, 1u); p += 2;  /* QDCOUNT */
put_u16_be(p, 1u); p += 2;  /* ANCOUNT */
put_u16_be(p, 0u); p += 2;  /* NSCOUNT */
put_u16_be(p, 0u); p += 2;  /* ARCOUNT */

/* Question */
memcpy(p, DNS_QNAME, DNS_QNAME_LEN); p += DNS_QNAME_LEN;
put_u16_be(p, DNS_TYPE_TXT);  p += 2;
put_u16_be(p, DNS_CLASS_IN);  p += 2;

/* Answer RR */
memcpy(p, DNS_QNAME, DNS_QNAME_LEN); p += DNS_QNAME_LEN;
put_u16_be(p, DNS_TYPE_TXT);  p += 2;
put_u16_be(p, DNS_CLASS_IN);  p += 2;
put_u32_be(p, DNS_TTL);       p += 4;

/* RDLENGTH = 1 (TXT-string length byte) + payload */
put_u16_be(p, (uint16_t)(1u + src_len)); p += 2;

/* TXT string: length byte + data */
*p++ = (uint8_t)(src_len & 0xFFu);
memcpy(p, src, src_len); p += src_len;

return (size_t)(p - dst);

}

static size_t dns_unwrap(const uint8_t *src, size_t src_len,
uint8_t *dst, size_t dst_size)
{
if (src_len < DNS_OVERHEAD) return 0;

const uint8_t *p = src;

/* Skip header + question + answer name/type/class/ttl */
p += DNS_HDR_LEN + DNS_QNAME_LEN + 4u + DNS_QNAME_LEN + 8u;

/* RDLENGTH */
if ((size_t)(p - src) + 2u > src_len) return 0;
uint16_t rdlen = get_u16_be(p); p += 2;
if (rdlen < 1u) return 0;

/* TXT length byte */
if ((size_t)(p - src) + rdlen > src_len) return 0;
p++;   /* skip TXT length byte */

size_t payload_len = (size_t)(rdlen - 1u);
if (payload_len > dst_size) return 0;
memcpy(dst, p, payload_len);
return payload_len;

}

/* -------------------------

- NTP constants
- ----------------------------------- */
  #define NTP_HDR_LEN          48u
  #define NTP_EXT_TYPE_MPCP    0x0421u
  #define NTP_EXT_HDR_LEN      4u

static size_t ntp_wrap(const uint8_t *src, size_t src_len,
uint8_t *dst, size_t dst_size)
{
size_t pad     = (4u - (src_len & 3u)) & 3u;
size_t ext_len = NTP_EXT_HDR_LEN + src_len + pad;
size_t total   = NTP_HDR_LEN + ext_len;
if (total > dst_size) return 0;

uint8_t *p = dst;

/* NTP header - mode 3 (client), version 4 */
memset(p, 0, NTP_HDR_LEN);
p[0] = (uint8_t)((4u << 3) | 3u);  /* LI=0 VN=4 MODE=3 */
p[1] = 0;                            /* stratum 0 (unspecified) */
p[2] = 6;                            /* poll = 2^6 = 64s */
p[3] = (uint8_t)0xEC;               /* precision ~= -20 */
put_u32_be(p + 40, 0xE6D89A00u);    /* plausible transmit timestamp */
p += NTP_HDR_LEN;

/* Extension field */
put_u16_be(p, NTP_EXT_TYPE_MPCP); p += 2;
put_u16_be(p, (uint16_t)(ext_len & 0xFFFFu)); p += 2;
memcpy(p, src, src_len); p += src_len;
if (pad > 0) { memset(p, 0, pad); p += pad; }

return (size_t)(p - dst);

}

static size_t ntp_unwrap(const uint8_t *src, size_t src_len,
uint8_t *dst, size_t dst_size)
{
if (src_len < NTP_HDR_LEN + NTP_EXT_HDR_LEN) return 0;

const uint8_t *p         = src + NTP_HDR_LEN;
size_t         remaining  = src_len - NTP_HDR_LEN;

while (remaining >= NTP_EXT_HDR_LEN) {
    uint16_t type = get_u16_be(p);
    uint16_t elen = get_u16_be(p + 2);
    if (elen < NTP_EXT_HDR_LEN || (size_t)elen > remaining) return 0;

    if (type == NTP_EXT_TYPE_MPCP) {
        size_t payload_len = (size_t)(elen - NTP_EXT_HDR_LEN);
        if (payload_len > dst_size) return 0;
        memcpy(dst, p + NTP_EXT_HDR_LEN, payload_len);
        return payload_len;
    }
    p         += elen;
    remaining -= elen;
}
return 0;

}

/* -------------------------

- Public API
- ----------------------------------- */
  size_t mpcp_disguise_wrap(const uint8_t        *src,
  size_t                src_len,
  uint8_t              *dst,
  size_t                dst_size,
  mpcp_disguise_proto_t proto)
  {
  if (!src || !dst || src_len == 0 || dst_size == 0) return 0;
  
  switch (proto) {
  case MPCP_DISGUISE_DNS: return dns_wrap(src, src_len, dst, dst_size);
  case MPCP_DISGUISE_NTP: return ntp_wrap(src, src_len, dst, dst_size);
  default:
  if (src_len > dst_size) return 0;
  memcpy(dst, src, src_len);
  return src_len;
  }
  }

size_t mpcp_disguise_unwrap(const uint8_t        *src,
size_t                src_len,
uint8_t              *dst,
size_t                dst_size,
mpcp_disguise_proto_t proto)
{
if (!src || !dst || src_len == 0 || dst_size == 0) return 0;

switch (proto) {
case MPCP_DISGUISE_DNS: return dns_unwrap(src, src_len, dst, dst_size);
case MPCP_DISGUISE_NTP: return ntp_unwrap(src, src_len, dst, dst_size);
default:
    if (src_len > dst_size) return 0;
    memcpy(dst, src, src_len);
    return src_len;
}

}

