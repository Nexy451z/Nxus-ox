#include "nxus_net.h"
#include "nxus_log.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* Short enough that a preempting connection, a reset request or the stop flag is
   noticed within ~200 ms; long enough that the idle sysmodule stays cheap. */
#define NXUS_NET_POLL_SLICE_MS       200
/* No byte at all for 20 s means the peer is gone: the PC sends a heartbeat every
   4 s, so a live session never reaches this, while a half-open socket (the
   console slept, the PC vanished without a FIN) is reaped deterministically. */
#define NXUS_NET_IDLE_TIMEOUT_NS     20000000000ull
/* A packet that started but made no progress for 5 s is desynced: drop it rather
   than block the protocol thread forever on the rest of the frame. */
#define NXUS_NET_PAYLOAD_STALL_NS    5000000000ull
/* Period of the getsockname() health probe on the listen socket. */
#define NXUS_NET_HEALTH_INTERVAL_NS  2000000000ull
/* Connection backlog.  One session is served; the rest queue up so a reconnect is
   never refused while the previous connection is still being torn down. */
#define NXUS_NET_BACKLOG             8
/* Wait between bsd session rebuild attempts (Wi-Fi may still be reconnecting). */
#define NXUS_NET_REBUILD_DELAY_NS    500000000ull

static int             g_ListenFd = -1;
static int             g_ClientFd = -1;
static Thread          g_ServerThread;
static bool            g_Running = false;
static Mutex           g_SendMutex;
static Mutex           g_ClientMutex;
static NxusNetHandler  g_Handler = NULL;
static void           *g_HandlerUser = NULL;
static u16             g_Port = NXUS_DEFAULT_PORT;
static u8             *g_RxBuffer = NULL;
/* Set by nxusNetRequestReset() (any thread) and consumed by the server thread.
   volatile: the polling loops re-read it every slice. */
static volatile bool   g_ResetRequested = false;
/* Last armGetSystemTick() at which a packet was received or sent completely.
   Written by the server/sender threads and read by the watchdog in main.c; an
   aligned 64-bit store is atomic on AArch64, so no lock is needed. */
static volatile u64    g_LastActivityTick = 0;

static int setClientFd(int fd) {
    mutexLock(&g_ClientMutex);
    g_ClientFd = fd;
    mutexUnlock(&g_ClientMutex);
    return fd;
}

int nxusNetClientFd(void) {
    mutexLock(&g_ClientMutex);
    int fd = g_ClientFd;
    mutexUnlock(&g_ClientMutex);
    return fd;
}

u64 nxusNetLastActivityTick(void) {
    return g_LastActivityTick;
}

/* Milliseconds elapsed since `from`.  armGetSystemTick() keeps counting across a
   sleep, so a suspend shows up as one huge delta - exactly what the idle/stall
   deadlines must treat as "this connection is dead". */
static u64 elapsedNs(u64 from, u64 now) {
    return armTicksToNs(now - from);
}

/* ---- listen socket lifecycle ------------------------------------------- */

/* Open, configure and bind the listen socket.  Returns false (and leaves
   g_ListenFd == -1) on any failure, so the caller can decide whether the bsd
   session itself needs to be rebuilt. */
static bool createListenerSocket(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        NXUS_LOG("listener: socket() failed errno=%d", errno);
        return false;
    }

    int one = 1;
    /* SO_REUSEADDR: a socket left in TIME_WAIT by the previous session must not
       keep the port unusable; SO_KEEPALIVE lets the stack reap a peer that
       disappeared without a FIN. */
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_Port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        NXUS_LOG("listener: bind(0.0.0.0:%u) failed errno=%d", (unsigned)g_Port, errno);
        close(fd);
        return false;
    }
    if (listen(fd, NXUS_NET_BACKLOG) != 0) {
        NXUS_LOG("listener: listen(%u) failed errno=%d", (unsigned)NXUS_NET_BACKLOG, errno);
        close(fd);
        return false;
    }

    g_ListenFd = fd;
    return true;
}

/* Cheap probe that detects a stale listener: a bsd session that died during a
   sleep can still hand out descriptors whose kernel object is gone, in which case
   poll()/accept() fail later but getsockname() already looks wrong. */
static bool listenerHealthy(void) {
    if (g_ListenFd < 0) return false;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    socklen_t len = (socklen_t)sizeof(addr);
    if (getsockname(g_ListenFd, (struct sockaddr *)&addr, &len) != 0) {
        NXUS_LOG("listener: health check failed errno=%d", errno);
        return false;
    }
    if (addr.sin_family != AF_INET || ntohs(addr.sin_port) != g_Port) {
        NXUS_LOG("listener: health check saw the wrong endpoint (family=%d port=%u)",
                 (int)addr.sin_family, (unsigned)ntohs(addr.sin_port));
        return false;
    }
    return true;
}

/* Re-create the listen socket, in two escalating steps:

     1. reopen it on the current bsd session (a transient accept()/poll() error,
        a dropped connection, the port still in TIME_WAIT);
     2. tear the bsd service session itself down and reconnect it
        (sleep/wake, Wi-Fi rejoin, a stale descriptor).  This retries every
        500 ms until the network answers, so the sysmodule never stays offline
        waiting for a manual restart.

   `full_bsd_reset` skips step 1 because the caller already knows the session is
   stale (explicit reset request, poll() error, dead listener). */
static void rebuildListener(bool full_bsd_reset) {
    if (!g_Running) return;

    if (g_ListenFd >= 0) {
        close(g_ListenFd);
        g_ListenFd = -1;
    }

    if (!full_bsd_reset && createListenerSocket()) {
        NXUS_LOG("listener rebuilt on 0.0.0.0:%u", (unsigned)g_Port);
        return;
    }

    for (u32 attempt = 0; g_Running && g_ListenFd < 0; attempt++) {
        /* Drop the (stale) session, give the Wi-Fi supplicant half a second to
           come back, then open a fresh one.  Retrying at 500 ms keeps the port
           unavailable for as short a time as the network allows. */
        socketExit();
        svcSleepThread(NXUS_NET_REBUILD_DELAY_NS);
        if (!g_Running) break;

        Result rc = socketInitializeDefault();
        if (R_FAILED(rc)) {
            NXUS_LOG("listener: socketInitializeDefault failed rc=0x%08X (attempt %u)",
                     (unsigned)rc, (unsigned)(attempt + 1));
            continue;
        }
        if (createListenerSocket()) {
            NXUS_LOG("listener: bsd session rebuilt, listening on 0.0.0.0:%u (attempt %u)",
                     (unsigned)g_Port, (unsigned)(attempt + 1));
            return;
        }
    }
    NXUS_LOG("listener: rebuild stopped (running=%d)", g_Running ? 1 : 0);
}

/* Drop the registered client.  Called from the server thread only.  The send
   mutex is held while closing so a sender on another thread (debug events) can
   never write into a descriptor that was just handed back to the kernel. */
static void dropClient(void) {
    int fd = nxusNetClientFd();
    if (fd < 0) return;
    mutexLock(&g_SendMutex);
    setClientFd(-1);
    shutdown(fd, SHUT_RDWR);
    close(fd);
    mutexUnlock(&g_SendMutex);
}

/* ---- receive ------------------------------------------------------------ */

/* Receive exactly `length` bytes, but never unconditionally:

   The previous implementation looped on recv() alone (SO_RCVTIMEO -> EAGAIN ->
   retry) while SO_RCVTIMEO kept firing.  A half-open connection (the console
   slept, the PC vanished without a FIN) therefore parked the protocol thread
   inside recvAll() forever: the listen socket was never serviced again, so every
   reconnect was refused or timed out, and only a sysmodule restart helped.

   Every wait now goes through poll() in 200 ms slices:

     - while waiting for the NEXT command header (is_header && got == 0) the
       LISTEN socket is part of the same poll set.  Incoming traffic there means
       "a new client, or the reconnect after a sleep" -> return false at once, the
       caller closes the stale socket and the server loop accepts the new one.
       This kick-out is what removes the half-open lockout completely.
     - a reset request or a listener error (POLLERR/POLLHUP/POLLNVAL) also
       returns false immediately.
     - 20 s without a single byte while `got == 0` and 5 s without progress once a
       payload has started are fatal, so dead sockets are always reaped
       (the PC heartbeats every 4 s, so a healthy idle session is never cut). */
static bool recvExact(int fd, void *buffer, u32 length, bool is_header) {
    u8 *out = (u8 *)buffer;
    u32 got = 0;
    u64 last_progress = armGetSystemTick();

    while (got < length) {
        if (!g_Running) return false;
        if (g_ResetRequested) {
            NXUS_LOG("recv: reset requested while fd=%d was idle - dropping client", fd);
            return false;
        }

        /* Only a client that is between commands may be preempted: in the middle
           of a frame the bytes already consumed would be lost. */
        const bool watch_listener = is_header && got == 0;

        struct pollfd pfds[2];
        pfds[0].fd = fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = watch_listener ? g_ListenFd : -1;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;

        const nfds_t nfds = watch_listener ? (nfds_t)2 : (nfds_t)1;
        const int pr = poll(pfds, nfds, NXUS_NET_POLL_SLICE_MS);
        if (pr < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            NXUS_LOG("recv: poll(fd=%d) failed errno=%d - dropping client", fd, errno);
            return false;
        }

        if (watch_listener) {
            if (pfds[1].revents & POLLIN) {
                NXUS_LOG("recv: new connection pending while fd=%d idles - preempting it", fd);
                return false;
            }
            if (pfds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                NXUS_LOG("recv: listener error (revents=0x%X) - dropping fd=%d",
                         (unsigned)pfds[1].revents, fd);
                return false;
            }
        }

        if (pr > 0 && (pfds[0].revents & POLLIN)) {
            const int n = recv(fd, out + got, (int)(length - got), 0);
            if (n > 0) {
                got += (u32)n;
                last_progress = armGetSystemTick();
                /* A byte on the wire is a live PC: the sleep/wake heuristic in
                   main.c must never reset the network while traffic flows. */
                g_LastActivityTick = last_progress;
            } else if (n == 0) {
                return false;               /* orderly shutdown by the peer */
            } else if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                /* SO_RCVTIMEO expired between poll() and recv(): poll again. */
            } else {
                NXUS_LOG("recv: fd=%d failed errno=%d - dropping client", fd, errno);
                return false;
            }
        } else if (pr > 0 && (pfds[0].revents & (POLLERR | POLLHUP | POLLNVAL))) {
            NXUS_LOG("recv: fd=%d error/hangup (revents=0x%X)", fd, (unsigned)pfds[0].revents);
            return false;
        }

        const u64 now = armGetSystemTick();
        const u64 idle_ns = elapsedNs(last_progress, now);
        if (got == 0) {
            if (idle_ns > NXUS_NET_IDLE_TIMEOUT_NS) {
                NXUS_LOG("recv: fd=%d idle for %llu ms - dropping client", fd,
                         (unsigned long long)(idle_ns / 1000000ull));
                return false;
            }
        } else if (idle_ns > NXUS_NET_PAYLOAD_STALL_NS) {
            NXUS_LOG("recv: fd=%d stalled at %u/%u bytes for %llu ms - dropping client", fd,
                     (unsigned)got, (unsigned)length,
                     (unsigned long long)(idle_ns / 1000000ull));
            return false;
        }
    }
    return true;
}

/* Write exactly `length` bytes. Returns false on a hard error or when the socket's
   SO_SNDTIMEO expires (a PC that stops reading a large reply). `*out_sent` always
   receives the number of bytes actually written, so the caller can tell a clean
   failure (nothing on the wire) from a partial send that desynced the stream. */
static bool sendAll(int fd, const void *buffer, u32 length, u32 *out_sent) {
    const u8 *out = (const u8 *)buffer;
    u32 sent = 0;
    while (sent < length) {
        const int n = send(fd, out + sent, (int)(length - sent), 0);
        if (n > 0) { sent += (u32)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    if (out_sent != NULL) *out_sent = sent;
    return sent == length;
}

Result nxusNetSendFd(int fd, u16 type, u16 flags, u32 seq, const void *payload, u32 length) {
    if (fd < 0) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    if (length > NXUS_NET_BUF_SIZE) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    if (length > 0 && payload == NULL) return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    NxusPacketHeader header;
    nxusHeaderInit(&header, type, flags, length, seq);

    mutexLock(&g_SendMutex);

    /* Zero-copy write: the 16-byte header goes straight from the stack and the
       payload straight from the caller's buffer.  Copying both into one scratch
       malloc added a ~1 MiB allocation plus a ~1 MiB memcpy to every large reply
       (notably the 1 MiB Read response) - exactly the spike that ran the shared
       8 MB heap out of memory in the middle of a scan.  The two send loops cost
       no extra round trip: TCP never waits for an ACK between them, and the
       peer's recv loop reassembles header + payload from the same stream. */
    u32 sent_header = 0;
    u32 sent_total  = 0;
    bool failed = !sendAll(fd, &header, (u32)sizeof(header), &sent_header);
    sent_total += sent_header;

    if (!failed && length > 0) {
        u32 sent_payload = 0;
        failed = !sendAll(fd, payload, length, &sent_payload);
        sent_total += sent_payload;
    }

    Result rc = 0;
    if (failed) {
        /* Once part of a packet is on the wire the peer's framing is lost for
           good: it will parse payload bytes as the next header.  Tear the
           connection down (the server loop then reconnects cleanly) instead of
           returning an error that leaves the stream permanently desynced. */
        if (sent_total > 0) shutdown(fd, SHUT_RDWR);
        rc = MAKERESULT(Module_Libnx, LibnxError_ShouldNotHappen);
    } else {
        g_LastActivityTick = armGetSystemTick();
    }

    mutexUnlock(&g_SendMutex);
    return rc;
}

Result nxusNetSend(u16 type, u16 flags, u32 seq, const void *payload, u32 length) {
    int fd = nxusNetClientFd();
    if (fd < 0) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    return nxusNetSendFd(fd, type, flags, seq, payload, length);
}

Result nxusNetSendAck(u32 seq)   { return nxusNetSend(seq, 0, seq, NULL, 0); }
Result nxusNetSendError(u32 seq, Result rc) {
    s32 value = (s32)rc;
    return nxusNetSend(seq, NXUS_FLAG_ERROR, seq, &value, sizeof(value));
}
Result nxusNetSendEvent(u16 type, const void *payload, u32 length) {
    return nxusNetSend(type, NXUS_FLAG_ASYNC, 0, payload, length);
}
Result nxusNetRespond(u32 seq, const void *payload, u32 length) {
    u16 type = NxusCmd_Nop;
    /* The caller passes the response type through the payload buffer convention:
       we keep it simple and let callers use nxusNetSend for typed replies. */
    return nxusNetSend(type, 0, seq, payload, length);
}

static void serveClient(int fd) {
    NXUS_LOG("client connected (fd=%d)", fd);

    /* 1s receive timeout so a recv() that raced with poll() cannot block for good.
       The real wait is poll()'s 200 ms slice, so this only bounds a rare race. */
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* ...and the same for sending: a PC that stops reading a large reply (or a
       dropped link) would otherwise block this thread inside send() for good,
       which also keeps the watchdog disabled (see g_CommandActive). */
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    while (g_Running && nxusNetClientFd() == fd) {
        NxusPacketHeader header;
        /* Header: preemptible by a new connection (kick-out path). */
        if (!recvExact(fd, &header, sizeof(header), true)) break;

        if (header.magic != NXUS_MAGIC) {
            NXUS_LOG("bad magic 0x%08X - closing", (unsigned)header.magic);
            break;
        }
        if (header.length > NXUS_NET_BUF_SIZE) {
            NXUS_LOG("payload too large (%u) - closing", (unsigned)header.length);
            break;
        }

        u32 length = header.length;
        if (length > 0) {
            if (g_RxBuffer == NULL) g_RxBuffer = (u8 *)malloc(NXUS_NET_BUF_SIZE);
            /* Payload: a started frame must finish, so no listener in the set. */
            if (g_RxBuffer == NULL || !recvExact(fd, g_RxBuffer, length, false)) break;
        }

        if (g_Handler != NULL) {
            g_Handler(fd, &header, g_RxBuffer, length, g_HandlerUser);
        }
    }

    NXUS_LOG("client disconnected (fd=%d)", fd);
    /* Same lock order as dropClient(): a sender on another thread must not be
       inside send() on a descriptor that is handed back to the kernel here. */
    mutexLock(&g_SendMutex);
    mutexLock(&g_ClientMutex);
    if (g_ClientFd == fd) g_ClientFd = -1;
    mutexUnlock(&g_ClientMutex);
    close(fd);
    mutexUnlock(&g_SendMutex);
}

/* ---- accept loop -------------------------------------------------------- */

static void serverThread(void *arg) {
    (void)arg;
    u64 last_health = armGetSystemTick();

    while (g_Running) {
        /* 1. explicit reset (sleep/wake from main.c, external request). */
        if (g_ResetRequested) {
            g_ResetRequested = false;
            NXUS_LOG("network reset requested - dropping client and rebuilding listener");
            dropClient();
            rebuildListener(true);
            last_health = armGetSystemTick();
            continue;
        }

        /* 2. no listener at all (previous rebuild was interrupted by shutdown). */
        if (g_ListenFd < 0) {
            rebuildListener(true);
            last_health = armGetSystemTick();
            continue;
        }

        /* 3. wait for a connection, but never park here on a broken bsd session:
              a 500 ms timeout doubles as the health-probe tick. */
        struct pollfd pfd;
        pfd.fd = g_ListenFd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        const int pr = poll(&pfd, 1, 500);
        if (pr < 0) {
            /* EINTR/EAGAIN are normal; ENETDOWN/EBADF/EPIPE after a sleep are not. */
            if (errno == EINTR || errno == EAGAIN) continue;
            NXUS_LOG("listener: poll failed errno=%d - rebuilding", errno);
            rebuildListener(true);
            last_health = armGetSystemTick();
            continue;
        }
        if (pfd.revents & (POLLERR | POLLNVAL)) {
            NXUS_LOG("listener: poll reported error (revents=0x%X) - rebuilding",
                     (unsigned)pfd.revents);
            rebuildListener(true);
            last_health = armGetSystemTick();
            continue;
        }
        if (pfd.revents & POLLHUP) {
            NXUS_LOG("listener: poll reported hangup - rebuilding");
            rebuildListener(false);
            last_health = armGetSystemTick();
            continue;
        }

        /* 4. periodic health probe: catches a listener whose kernel object died
              without the socket call itself failing. */
        const u64 now = armGetSystemTick();
        if (elapsedNs(last_health, now) >= NXUS_NET_HEALTH_INTERVAL_NS) {
            last_health = now;
            if (!listenerHealthy()) {
                rebuildListener(true);
                continue;
            }
        }

        if (!(pfd.revents & POLLIN)) continue;

        const int fd = accept(g_ListenFd, NULL, NULL);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            NXUS_LOG("accept() failed errno=%d - rebuilding listener", errno);
            rebuildListener(true);
            last_health = armGetSystemTick();
            continue;
        }

        /* A new connection always wins.  serveClient() already returns as soon as
           traffic shows up on the listener, so this only fires for a stale
           registration - but closing it keeps the "one session" invariant without
           ever refusing a reconnect. */
        const int prev = nxusNetClientFd();
        if (prev >= 0) {
            NXUS_LOG("preempting stale client fd=%d with new fd=%d", prev, fd);
            dropClient();
        }
        setClientFd(fd);
        serveClient(fd);
        last_health = armGetSystemTick();
    }
}

/* ---- public API --------------------------------------------------------- */

Result nxusNetInit(u16 port, NxusNetHandler handler, void *user) {
    if (g_Running) return 0;

    mutexInit(&g_SendMutex);
    mutexInit(&g_ClientMutex);
    g_Handler = handler;
    g_HandlerUser = user;
    g_Port = port;
    g_ResetRequested = false;
    g_LastActivityTick = armGetSystemTick();

#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif

    Result rc = socketInitializeDefault();
    if (R_FAILED(rc)) {
        NXUS_RESULT("socketInitializeDefault", rc);
        return rc;
    }
    NXUS_LOG("socketInitializeDefault ok");

    g_Running = true;
    if (!createListenerSocket()) {
        g_Running = false;
        socketExit();
        return MAKERESULT(Module_Libnx, LibnxError_ShouldNotHappen);
    }

    alignas(0x1000) static u8 serverStack[0x8000];
    rc = threadCreate(&g_ServerThread, serverThread, NULL, serverStack, sizeof(serverStack), 0x2C, -2);
    NXUS_RESULT("threadCreate(core -2)", rc);
    if (R_FAILED(rc)) {
        /* libnx wants -2 (default) or 0..3; anything else is an invalid core id */
        rc = threadCreate(&g_ServerThread, serverThread, NULL, serverStack, sizeof(serverStack), 0x2C, 3);
        NXUS_RESULT("threadCreate(core 3)", rc);
    }
    if (R_FAILED(rc)) {
        g_Running = false;
        if (g_ListenFd >= 0) close(g_ListenFd);
        g_ListenFd = -1;
        socketExit();
        return rc;
    }
    threadStart(&g_ServerThread);

    NXUS_LOG("listening on 0.0.0.0:%u", (unsigned)g_Port);
    return 0;
}

void nxusNetRequestReset(const char *reason) {
    NXUS_LOG("network reset requested from outside (%s)", (reason != NULL) ? reason : "?");
    g_ResetRequested = true;

    /* Also wake the protocol thread if it is blocked in recv(): shutdown() makes
       poll() report the hangup instead of waiting for the next slice.  The server
       thread stays the only owner of the descriptor, so it does the close(). */
    const int fd = nxusNetClientFd();
    if (fd >= 0) shutdown(fd, SHUT_RDWR);
}

void nxusNetExit(void) {
    if (!g_Running) return;
    g_Running = false;

    int fd = nxusNetClientFd();
    if (fd >= 0) shutdown(fd, SHUT_RDWR);
    if (g_ListenFd >= 0) shutdown(g_ListenFd, SHUT_RDWR);

    threadWaitForExit(&g_ServerThread);
    threadClose(&g_ServerThread);

    if (g_ListenFd >= 0) close(g_ListenFd);
    g_ListenFd = -1;
    setClientFd(-1);
    free(g_RxBuffer);
    g_RxBuffer = NULL;
    socketExit();
}

bool nxusNetIsRunning(void) { return g_Running; }
