/* AethroSync — src/nat.c — NAT traversal, rendezvous, hole punching */
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

/* ========== src/nat.c ========== */
/*

- nat.c - NAT traversal: rendezvous token and UDP hole punching (spec S12)
- 
- S12.1  Token = SHA256(session_nonce || psk_bytes) - opaque to server
- S12.2  Hole punching flow: connect to rendezvous, exchange peer addrs,
      fire hole_punch_attempts simultaneous UDP packets in each direction

*/

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* -------------------------

- S12.1  Rendezvous token
- ----------------------------------- */
  int mpcp_nat_token(const uint8_t *session_nonce,
  const uint8_t *psk_bytes,
  size_t         psk_len,
  uint8_t        token_out[32])
  {
  if (!session_nonce || !psk_bytes || psk_len == 0 || !token_out)
  return MPCP_ERR_PARAM;
  
  /* SHA256(session_nonce || psk_bytes) */
  crypto_hash_sha256_state st;
  if (crypto_hash_sha256_init(&st) != 0) return MPCP_ERR_CRYPTO;
  if (crypto_hash_sha256_update(&st, session_nonce, MPCP_SESSION_NONCE_LEN) != 0)
  return MPCP_ERR_CRYPTO;
  if (crypto_hash_sha256_update(&st, psk_bytes, psk_len) != 0)
  return MPCP_ERR_CRYPTO;
  if (crypto_hash_sha256_final(&st, token_out) != 0)
  return MPCP_ERR_CRYPTO;
  
  return MPCP_OK;
  }

/* -------------------------

- Internal: resolve hostname -> struct sockaddr_in
- ----------------------------------- */
  static int resolve_host(const char *host, uint16_t port,
  struct sockaddr_in *out)
  {
  struct addrinfo hints, *res;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  
  char port_str[8];
  (void)snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
  
  int err = getaddrinfo(host, port_str, &hints, &res);
  if (err != 0 || !res) return MPCP_ERR_NAT;
  
  *out = *(const struct sockaddr_in *)(const void *)res->ai_addr;
  freeaddrinfo(res);
  return MPCP_OK;
  }

/* -------------------------

- S12.2  Simple rendezvous wire protocol (UDP, stateless server):
- 
- Client -> Server:  token(32) || our_public_ip(4) || our_public_port(2)
- Server -> Client:  peer_ip(4) || peer_port(2)
- 
- The server matches two clients with identical tokens and sends each
- other's address.  It discards state immediately after exchange.
- ----------------------------------- */
  #define RENDEZVOUS_SEND_LEN  38u   /* 32 + 4 + 2 */
  #define RENDEZVOUS_RECV_LEN   6u   /* 4 + 2       */

static int rendezvous_exchange(const uint8_t          *token,
const mpcp_config_t    *cfg,
struct sockaddr_in     *peer_out)
{
struct sockaddr_in srv_addr;
int rc = resolve_host(cfg->rendezvous_host, cfg->rendezvous_port,
&srv_addr);
if (rc != MPCP_OK) return rc;

int sock = socket(AF_INET, SOCK_DGRAM, 0);
if (sock < 0) return MPCP_ERR_IO;

/* Set receive timeout = rendezvous_timeout seconds */
struct timeval tv;
tv.tv_sec  = (time_t)cfg->rendezvous_timeout;
tv.tv_usec = 0;
(void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

/* Build send buffer: token || 0.0.0.0 || 0 (server fills actual IP) */
uint8_t sendbuf[RENDEZVOUS_SEND_LEN];
memcpy(sendbuf, token, 32u);
memset(sendbuf + 32u, 0, 6u);   /* server derives our public addr */

ssize_t sent = checked_sendto(sock, sendbuf, sizeof(sendbuf), 0,
                      (const struct sockaddr *)(const void *)&srv_addr,
                      sizeof(srv_addr));
if (sent != (ssize_t)sizeof(sendbuf)) {
    close(sock);
    return MPCP_ERR_IO;
}

/* Wait for peer address */
uint8_t recvbuf[RENDEZVOUS_RECV_LEN];
struct sockaddr_in from;
socklen_t fromlen = sizeof(from);
ssize_t n = recvfrom(sock, recvbuf, sizeof(recvbuf), 0,
                      (struct sockaddr *)(void *)&from, &fromlen);
close(sock);

if (n != (ssize_t)RENDEZVOUS_RECV_LEN) return MPCP_ERR_NAT;

memset(peer_out, 0, sizeof(*peer_out));
peer_out->sin_family = AF_INET;
memcpy(&peer_out->sin_addr.s_addr, recvbuf, 4u);
uint16_t port_be;
memcpy(&port_be, recvbuf + 4u, 2u);
peer_out->sin_port = port_be;   /* already network byte order */

return MPCP_OK;

}

/* -------------------------

- S12.2  UDP hole punching
- 
- Fire hole_punch_attempts simultaneous UDP packets toward peer.
- The peer does the same.  If the NAT is full-cone or restricted-cone,
- the first packet from the peer will pass after our outbound ones open
- the mapping.
- ----------------------------------- */
  #define PUNCH_PROBE_LEN  6u   /* minimal valid probe */

static int hole_punch(const struct sockaddr_in *peer_addr,
uint32_t                  attempts)
{
int sock = socket(AF_INET, SOCK_DGRAM, 0);
if (sock < 0) return MPCP_ERR_IO;

/* Non-blocking: we just fire and don't wait */
int flags = fcntl(sock, F_GETFL, 0);
if (flags >= 0) (void)fcntl(sock, F_SETFL, flags | O_NONBLOCK);

uint8_t probe[PUNCH_PROBE_LEN];
randombytes_buf(probe, sizeof(probe));

for (uint32_t i = 0; i < attempts; i++) {
    (void)sendto(sock, probe, sizeof(probe), 0,
                 (const struct sockaddr *)(const void *)peer_addr,
                 sizeof(*peer_addr));
    /* Small delay between probes to avoid burst drop */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000L }; /* 10 ms */
    nanosleep(&ts, NULL);
}

close(sock);
return MPCP_OK;

}

/* -------------------------

- S12.2  Main entry point
- ----------------------------------- */
  int mpcp_nat_traverse(const mpcp_config_t  *cfg,
  mpcp_session_t       *sess,
  struct sockaddr_in   *peer_addr_out)
  {
  if (!cfg || !sess || !peer_addr_out) return MPCP_ERR_PARAM;
  
  /* DIRECT mode: caller configured peer address directly; nothing to do */
  if (cfg->nat_mode == MPCP_NAT_DIRECT) {
  if (cfg->rendezvous_host[0] == '\0') return MPCP_ERR_PARAM;
  return resolve_host(cfg->rendezvous_host, cfg->rendezvous_port,
  peer_addr_out);
  }
  
  /* AUTO / FORCE_NAT: use rendezvous server */
  if (cfg->rendezvous_host[0] == '\0') {
  /* No rendezvous configured; cannot proceed */
  return MPCP_ERR_NAT;
  }
  
  /* Compute token */
  uint8_t token[32];
  int rc = mpcp_nat_token(sess->session_nonce,
  (const uint8_t *)cfg->psk, cfg->psk_len,
  token);
  if (rc != MPCP_OK) return rc;
  
  /* Exchange via rendezvous server */
  struct sockaddr_in peer;
  rc = rendezvous_exchange(token, cfg, &peer);
  sodium_memzero(token, sizeof(token));
  if (rc != MPCP_OK) return rc;
  
  /* Fire hole-punch probes */
  rc = hole_punch(&peer, cfg->hole_punch_attempts);
  if (rc != MPCP_OK) return rc;
  
  *peer_addr_out = peer;
  return MPCP_OK;
  }



/* =========================================================================
 * TURN-style relay fallback (spec extension)
 *
 * When NAT hole punching fails (symmetric NAT / CGNAT), both sides connect
 * to the same relay server over TCP. The server forwards UDP datagrams
 * between the two endpoints. Wire protocol:
 *
 *   Client -> Relay: token(32) || direction(1: 0=initiator 1=peer)
 *   Relay buffers until both sides connect with same token, then pipes UDP.
 *
 * This is a best-effort fallback — not part of the core MPCP spec.
 * ========================================================================= */

#define RELAY_CONNECT_TIMEOUT_S  30
#define RELAY_HEADER_LEN         33   /* token(32) + direction(1) */

int mpcp_turn_relay(const mpcp_config_t     *cfg,
                    const mpcp_session_t    *sess,
                    struct sockaddr_in      *peer_addr_out,
                    bool                     is_initiator)
{
    if (!cfg || !sess || !peer_addr_out) return MPCP_ERR_PARAM;
    if (cfg->rendezvous_host[0] == '\0') return MPCP_ERR_NAT;

    /* Compute token (same as hole punch token) */
    uint8_t token[32];
    int rc = mpcp_nat_token(sess->session_nonce,
                            (const uint8_t *)cfg->psk, cfg->psk_len, token);
    if (rc != MPCP_OK) return rc;

    /* Connect to relay server via TCP on rendezvous_port+1 */
    struct sockaddr_in relay_addr;
    rc = resolve_host(cfg->rendezvous_host, cfg->rendezvous_port + 1, &relay_addr);
    sodium_memzero(token, sizeof(token));
    if (rc != MPCP_OK) return rc;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return MPCP_ERR_IO;

    struct timeval tv = { .tv_sec = RELAY_CONNECT_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&relay_addr, sizeof(relay_addr)) < 0) {
        close(sock); return MPCP_ERR_NAT;
    }

    /* Re-compute token for the header */
    rc = mpcp_nat_token(sess->session_nonce,
                        (const uint8_t *)cfg->psk, cfg->psk_len, token);
    if (rc != MPCP_OK) { close(sock); return rc; }

    uint8_t header[RELAY_HEADER_LEN];
    memcpy(header, token, 32);
    header[32] = is_initiator ? 0x00 : 0x01;
    sodium_memzero(token, sizeof(token));

    if (send(sock, header, sizeof(header), 0) != (ssize_t)sizeof(header)) {
        close(sock); return MPCP_ERR_IO;
    }

    /* Relay server responds with peer's public address: ip(4) + port(2) */
    uint8_t resp[6];
    if (recv(sock, resp, sizeof(resp), MSG_WAITALL) != (ssize_t)sizeof(resp)) {
        close(sock); return MPCP_ERR_NAT;
    }
    close(sock);

    memset(peer_addr_out, 0, sizeof(*peer_addr_out));
    peer_addr_out->sin_family = AF_INET;
    memcpy(&peer_addr_out->sin_addr.s_addr, resp, 4);
    uint16_t port_be;
    memcpy(&port_be, resp + 4, 2);
    peer_addr_out->sin_port = port_be;

    return MPCP_OK;
}
