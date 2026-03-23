/* AethroSync — include/platform.h
 * Cross-platform compatibility shim: Linux ↔ Windows (MinGW-w64)
 *
 * Include this FIRST in every .c file before any system headers.
 * On Linux this is mostly empty. On Windows it maps POSIX → Win32.
 */
#pragma once
#ifndef MPCP_PLATFORM_H
#define MPCP_PLATFORM_H

/* ── Detect platform ─────────────────────────────────────────────────── */
#if defined(_WIN32) || defined(_WIN64)
#  define MPCP_WINDOWS 1
#else
#  define MPCP_LINUX   1
#endif

/* ======================================================================
 * WINDOWS SHIMS
 * ====================================================================== */
#ifdef MPCP_WINDOWS

/* Must come before any other includes */
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0A00   /* Windows 10+ for WSAPoll */
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>    /* BCryptGenRandom */
#include <iphlpapi.h>  /* GetAdaptersAddresses */
#include <mmsystem.h>  /* timeBeginPeriod */

/* ── Socket type differences ──────────────────────────────────────────── */
typedef SOCKET mpcp_sock_t;
#define MPCP_INVALID_SOCK  INVALID_SOCKET
#define mpcp_sock_close(s) closesocket(s)
#define mpcp_sock_valid(s) ((s) != INVALID_SOCKET)

/* Map close() on sockets to closesocket() */
static inline int mpcp_close_socket(SOCKET s) { return closesocket(s); }

/* socklen_t is not defined by MinGW winsock by default */
#ifndef socklen_t
typedef int socklen_t;
#endif

/* ── getrandom → BCryptGenRandom ─────────────────────────────────────── */
static inline ssize_t mpcp_getrandom(void *buf, size_t len, unsigned int flags)
{
    (void)flags;
    if (BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0)
        return (ssize_t)len;
    return -1;
}
#define getrandom(buf, len, flags) mpcp_getrandom(buf, len, flags)

/* ── nanosleep → Sleep ───────────────────────────────────────────────── */
#ifndef HAVE_NANOSLEEP
struct timespec { long tv_sec; long tv_nsec; };
#endif
static inline int nanosleep(const struct timespec *req, struct timespec *rem)
{
    (void)rem;
    DWORD ms = (DWORD)(req->tv_sec * 1000 + req->tv_nsec / 1000000);
    if (ms == 0 && req->tv_nsec > 0) ms = 1;
    Sleep(ms);
    return 0;
}

/* ── clock_gettime → QueryPerformanceCounter ─────────────────────────── */
#ifndef CLOCK_MONOTONIC
#  define CLOCK_MONOTONIC 1
#endif
static inline int clock_gettime(int clk_id, struct timespec *ts)
{
    (void)clk_id;
    LARGE_INTEGER freq, cnt;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&cnt);
    ts->tv_sec  = (long)(cnt.QuadPart / freq.QuadPart);
    ts->tv_nsec = (long)((cnt.QuadPart % freq.QuadPart) * 1000000000LL
                         / freq.QuadPart);
    return 0;
}

/* ── epoll → WSAPoll ─────────────────────────────────────────────────── */
/* WSAPoll is available on Windows Vista+. We map the Linux epoll API
 * to a thin wrapper around WSAPoll for the T1 receiver loop. */
typedef struct {
    uint32_t events;
    union { void *ptr; int fd; uint32_t u32; uint64_t u64; } data;
} mpcp_epoll_event_t;
#define EPOLLIN  POLLRDNORM

typedef struct {
    WSAPOLLFD *pfds;
    uint32_t  *idx_map;   /* pfds[i] → original fd index */
    int        nfds;
    int        cap;
} mpcp_epoll_t;

static inline int epoll_create1(int flags)
{
    (void)flags;
    /* Return a fake "fd" — we use a heap-allocated struct indexed by this */
    mpcp_epoll_t *ep = (mpcp_epoll_t *)calloc(1, sizeof(mpcp_epoll_t));
    if (!ep) return -1;
    /* Store pointer as int (works on 32-bit; on 64-bit use a global table) */
    /* For simplicity, use a static table of up to 128 epoll instances */
    /* In practice only one is active at a time in MPCP */
    static mpcp_epoll_t *ep_table[128] = {0};
    for (int i = 1; i < 128; i++) {
        if (!ep_table[i]) { ep_table[i] = ep; return i; }
    }
    free(ep); return -1;
}

/* Thread-local epoll table lookup */
static mpcp_epoll_t *_ep_get(int efd) {
    extern mpcp_epoll_t *_ep_table_get(int);
    return _ep_table_get(efd);
}

/* Simplified: use global table (single-threaded epoll usage in MPCP T1) */
static mpcp_epoll_t *_g_ep_table[128] = {0};
static inline mpcp_epoll_t *_ep_lookup(int efd)
{
    if (efd < 1 || efd >= 128) return NULL;
    return _g_ep_table[efd];
}

static inline int epoll_ctl(int efd, int op, int fd, mpcp_epoll_event_t *ev)
{
    mpcp_epoll_t *ep = _ep_lookup(efd);
    if (!ep) return -1;
    if (op == EPOLL_CTL_ADD) {
        if (ep->nfds >= ep->cap) {
            int newcap = ep->cap ? ep->cap * 2 : 16;
            ep->pfds    = (WSAPOLLFD *)realloc(ep->pfds, newcap * sizeof(WSAPOLLFD));
            ep->idx_map = (uint32_t *)realloc(ep->idx_map, newcap * sizeof(uint32_t));
            ep->cap = newcap;
        }
        ep->pfds[ep->nfds].fd      = (SOCKET)fd;
        ep->pfds[ep->nfds].events  = POLLRDNORM;
        ep->pfds[ep->nfds].revents = 0;
        ep->idx_map[ep->nfds]      = ev->data.u32;
        ep->nfds++;
    } else if (op == EPOLL_CTL_DEL) {
        for (int i = 0; i < ep->nfds; i++) {
            if (ep->pfds[i].fd == (SOCKET)fd) {
                ep->pfds[i]    = ep->pfds[ep->nfds-1];
                ep->idx_map[i] = ep->idx_map[ep->nfds-1];
                ep->nfds--;
                break;
            }
        }
    }
    return 0;
}
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

static inline int epoll_wait(int efd, mpcp_epoll_event_t *evs, int maxev, int timeout_ms)
{
    mpcp_epoll_t *ep = _ep_lookup(efd);
    if (!ep || ep->nfds == 0) { Sleep(timeout_ms > 0 ? timeout_ms : 1); return 0; }
    int r = WSAPoll(ep->pfds, (ULONG)ep->nfds, timeout_ms);
    if (r <= 0) return r < 0 ? -1 : 0;
    int n = 0;
    for (int i = 0; i < ep->nfds && n < maxev; i++) {
        if (ep->pfds[i].revents & POLLRDNORM) {
            evs[n].events    = EPOLLIN;
            evs[n].data.u32  = ep->idx_map[i];
            n++;
        }
    }
    return n;
}

static inline int epoll_destroy(int efd)
{
    mpcp_epoll_t *ep = _ep_lookup(efd);
    if (!ep) return -1;
    free(ep->pfds);
    free(ep->idx_map);
    free(ep);
    _g_ep_table[efd] = NULL;
    return 0;
}
/* On Linux close(efd) destroys the epoll fd; map it */
static inline int _epoll_or_real_close(int fd)
{
    if (fd > 0 && fd < 128 && _g_ep_table[fd]) return epoll_destroy(fd);
    return closesocket((SOCKET)fd);
}
#define close(fd) _epoll_or_real_close(fd)

/* ── MSG_DONTWAIT → non-blocking socket mode ─────────────────────────── */
#ifndef MSG_DONTWAIT
#  define MSG_DONTWAIT 0  /* handled via ioctlsocket before the call */
#endif

/* Wrapper: sets non-blocking, calls recv, restores blocking */
static inline ssize_t recvfrom_dontwait(SOCKET s, void *buf, size_t len,
    struct sockaddr *from, socklen_t *fromlen)
{
    u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
    ssize_t r = recvfrom(s, (char*)buf, (int)len, 0, from, fromlen);
    nb = 0; ioctlsocket(s, FIONBIO, &nb);
    return r;
}

/* ── POSIX file I/O ──────────────────────────────────────────────────── */
#include <io.h>
#include <fcntl.h>
#ifndef O_RDONLY
#  define O_RDONLY _O_RDONLY
#  define O_WRONLY _O_WRONLY
#  define O_CREAT  _O_CREAT
#  define O_TRUNC  _O_TRUNC
#endif
/* open/read/write map to _open/_read/_write via io.h */
#define open   _open
#define read   _read
#define write  _write

/* ── SCHED_FIFO → no-op ──────────────────────────────────────────────── */
#ifndef SCHED_FIFO
#  define SCHED_FIFO 1
#endif
struct sched_param { int sched_priority; };
static inline int sched_setscheduler(int pid, int pol, const struct sched_param *p)
{ (void)pid;(void)pol;(void)p; return 0; }
static inline int pthread_setschedparam(pthread_t t, int pol, const struct sched_param *p)
{ (void)t;(void)pol;(void)p; return 0; }

/* ── getifaddrs → GetAdaptersAddresses ───────────────────────────────── */
/* Minimal ifaddrs shim for IP display in cli.c */
struct ifaddrs {
    struct ifaddrs      *ifa_next;
    char                *ifa_name;
    unsigned int         ifa_flags;
    struct sockaddr     *ifa_addr;
};

static inline int getifaddrs(struct ifaddrs **ifap)
{
    ULONG sz = 15000;
    PIP_ADAPTER_ADDRESSES buf = (PIP_ADAPTER_ADDRESSES)malloc(sz);
    if (!buf) return -1;
    if (GetAdaptersAddresses(AF_INET, 0, NULL, buf, &sz) != ERROR_SUCCESS) {
        free(buf); return -1;
    }
    struct ifaddrs *head = NULL, *tail = NULL;
    for (PIP_ADAPTER_ADDRESSES a = buf; a; a = a->Next) {
        for (PIP_ADAPTER_UNICAST_ADDRESS u = a->FirstUnicastAddress; u; u = u->Next) {
            struct ifaddrs *ifa = (struct ifaddrs *)calloc(1, sizeof(struct ifaddrs));
            struct sockaddr_in *sa = (struct sockaddr_in *)calloc(1, sizeof(struct sockaddr_in));
            memcpy(sa, u->Address.lpSockaddr, sizeof(struct sockaddr_in));
            ifa->ifa_addr = (struct sockaddr *)sa;
            /* Convert adapter name from wide to narrow */
            char name[256] = {0};
            WideCharToMultiByte(CP_ACP, 0, a->FriendlyName, -1, name, 255, NULL, NULL);
            ifa->ifa_name = _strdup(name);
            if (!head) head = tail = ifa;
            else { tail->ifa_next = ifa; tail = ifa; }
        }
    }
    free(buf);
    *ifap = head;
    return 0;
}

static inline void freeifaddrs(struct ifaddrs *ifa)
{
    while (ifa) {
        struct ifaddrs *next = ifa->ifa_next;
        free(ifa->ifa_addr);
        free(ifa->ifa_name);
        free(ifa);
        ifa = next;
    }
}

/* ── termios → Windows Console ───────────────────────────────────────── */
struct termios { unsigned int c_lflag; };
#define ECHO 0x0008
static inline int tcgetattr(int fd, struct termios *t) { (void)fd; t->c_lflag=ECHO; return 0; }
static inline int tcsetattr(int fd, int a, const struct termios *t)
{
    (void)fd; (void)a;
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD m = 0; GetConsoleMode(h, &m);
    if (t->c_lflag & ECHO) m |= ENABLE_ECHO_INPUT;
    else m &= ~ENABLE_ECHO_INPUT;
    SetConsoleMode(h, m);
    return 0;
}
#define TCSANOW 0

/* ── Winsock init/cleanup ────────────────────────────────────────────── */
static inline void mpcp_winsock_init(void)
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
    /* 1ms timer resolution for Sleep() accuracy */
    timeBeginPeriod(1);
}
static inline void mpcp_winsock_cleanup(void)
{
    timeEndPeriod(1);
    WSACleanup();
}

/* ── Firewall: no-op on Windows (user must open manually) ───────────── */
/* fw_maybe_open and fw_cleanup are defined in cli.c with #ifdef guards */

/* ── errno for Winsock ───────────────────────────────────────────────── */
#ifndef EINTR
#  define EINTR  WSAEINTR
#endif

/* ======================================================================
 * LINUX — everything is native, just a few convenience macros
 * ====================================================================== */
#else /* MPCP_LINUX */

#include <sys/epoll.h>
#include <sys/random.h>
#include <ifaddrs.h>
#include <termios.h>
#include <sched.h>
#include <sys/mman.h>
#include <time.h>

typedef int mpcp_sock_t;
#define MPCP_INVALID_SOCK  (-1)
#define mpcp_sock_close(s) close(s)
#define mpcp_sock_valid(s) ((s) >= 0)

/* epoll close is just close() on Linux */
/* No epoll_destroy needed */

static inline void mpcp_winsock_init(void)    {}
static inline void mpcp_winsock_cleanup(void) {}

#endif /* MPCP_LINUX */

/* ======================================================================
 * COMMON — things that differ slightly but share the same API
 * ====================================================================== */


#endif /* MPCP_PLATFORM_H */
