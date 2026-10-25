#include "nxus_net.h"
#include "nxus_log.h"

#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>
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
/* Upper bound for one rebuildListener() burst: 120 * 500 ms = 60 s.  A Wi-Fi
   rejoin normally succeeds within a few tries; past this the network is simply
   gone (flight mode, no AP in range) and spinning forever burns a core for
   nothing.  Giving up keeps g_Running set, so the server loop / the next reset
   request / a sleep-wake tick retries later. */
#define NXUS_NET_REBUILD_MAX_ATTEMPTS 120u
/* Pause between two rebuild bursts (see the server loop): without it a console
   with no network at all would run the 60 s burst back to back forever. */
#define NXUS_NET_REBUILD_RETRY_PAUSE_NS 10000000000ull
/* Upper bound for waiting on the server thread in nxusNetExit().  libnx has no
   timed thread join, and the connection thread may be parked inside a long
   handler (a pointer scan runs ~90 s), so waiting for it unconditionally used to
   block __appExit() for minutes.  2 s is far more than a normal teardown needs
   (one 200 ms poll slice plus the socket close), so anything longer means
   "abandon the thread": the descriptors are still shut down and closed, while the
   thread handle, g_RxBuffer and the bsd session are left to process exit - see
   the table above nxusNetExit() for why each one is or is not released. */
#define NXUS_NET_EXIT_WAIT_MS           2000u
/* Granularity of that bounded wait: short enough that the exit returns as soon as
   the thread raises its done flag, long enough that the poll loop stays free. */
#define NXUS_NET_EXIT_POLL_NS           10000000ull

/* Both descriptor slots are the registration AND the close token: to close a
   descriptor, a party first replaces it in its slot with -1 through a
   compare-exchange, and only the winner of that CAS may call close().  That is
   what lets the exit path close without a joined thread while the server thread
   may be closing the same descriptor: the second close() would otherwise hit an
   unrelated socket once the kernel recycled the number.  They are atomic because
   they are also read without the send lock (nxusNetClientFd() from the
   UI/watchdog threads, the listener probe in recvExact()). */
static atomic_int      g_ListenFd = -1;
static atomic_int      g_ClientFd = -1;
static Thread          g_ServerThread;
static atomic_bool     g_Running = false;   /* read from the server thread, written by init/exit */

static bool nxusNetRunning(void) {
    return atomic_load_explicit(&g_Running, memory_order_acquire);
}
static Mutex           g_SendMutex;
static NxusNetHandler  g_Handler = NULL;
static void           *g_HandlerUser = NULL;
static u16             g_Port = NXUS_DEFAULT_PORT;
static u8             *g_RxBuffer = NULL;
/* Set by nxusNetRequestReset() (any thread) and consumed by the server thread.
   atomic: the consumer clears it with exchange(), so a request raised while the
   server thread is between its load and its clear can no longer be swallowed by
   a plain read-then-store (lost update). */
static atomic_bool     g_ResetRequested = false;
/* Raised by serverThread() as its very last statement, polled by nxusNetExit().
   threadWaitForExit() cannot be given a timeout in libnx, so this flag is what
   makes the shutdown bounded: the exit path joins/closes the thread only after
   seeing it, and abandons the handle (reclaimed by process exit) when the
   deadline expires.  The sockets are closed either way; see the teardown table
   above nxusNetExit().  atomic: written by the server thread, read by the exit
   thread. */
static atomic_bool     g_ServerDone = false;
/* Last armGetSystemTick() at which a packet was received or sent completely.
   Written by the server/sender threads and read by the watchdog in main.c; an
   aligned 64-bit store is atomic on AArch64, so no lock is needed. */
static volatile u64    g_LastActivityTick = 0;

/* ---- Result handling ----------------------------------------------------
 *
 * The error flag of a HOS Result is bit 31, but libnx defines R_FAILED(res) as
 * (res)!=0, so a success-shaped non-zero code (0x00001759 was observed on
 * hardware) used to be reported as a failure here: nxusNetInit() then returned
 * it, main.c retried forever and the module never came up even though the bsd
 * session was fine.  Under the SDK's bit-31 R_FAILED() the opposite happens and
 * the code is accepted silently, which leaves a failure-looking "rc=0x........"
 * in the log with no explanation.
 *
 * Decide on the bit, and name the step when the code is ambiguous: bit 31 clear
 * means "the call worked, the value is odd", which is reported and treated as
 * success.  Anything with bit 31 set, or a failed socket/bind/listen afterwards,
 * still reaches the caller as a real failure.
 */
static bool netCallSucceeded(Result rc, const char *what) {
    if (rc == 0) return true;
    if ((((u32)rc) & 0x80000000u) != 0) return false;
    NXUS_LOG("%s: non-zero success code 0x%08X (no error bit) - continuing",
             what, (unsigned)rc);
    return true;
}

/* ---- descriptor slots ----------------------------------------------------
 *
 * The slot is both the registration and the close token (see the globals above).
 * Closing a descriptor therefore means: claim it (CAS the slot from `fd` to -1),
 * then close the claimed number.  Readers that never close (the health probe, the
 * poll sets) just load the slot.
 *
 * Every close of a *published* descriptor runs under g_SendMutex, so the exit
 * path's shutdown() can never land on a number that was closed and recycled in
 * between; the CAS is what settles ownership between the exit path and the server
 * thread, which both reach a close on the timeout path.
 */

/* The registered client descriptor, or -1.  A snapshot only (see nxus_net.h). */
static int peekClientFd(void) {
    return atomic_load_explicit(&g_ClientFd, memory_order_acquire);
}

static void publishClientFd(int fd) {
    atomic_store_explicit(&g_ClientFd, fd, memory_order_release);
}

/* Claim `fd` for a close.  Returns fd when this caller won, -1 when the slot no
   longer holds it (already closed elsewhere, or replaced by a newer client that
   this caller does not own and must leave alone). */
static int claimClientFd(int fd) {
    if (fd < 0) return -1;
    int expected = fd;
    return atomic_compare_exchange_strong_explicit(&g_ClientFd, &expected, -1,
                                                   memory_order_acq_rel,
                                                   memory_order_acquire)
               ? fd : -1;
}

static int peekListenFd(void) {
    return atomic_load_explicit(&g_ListenFd, memory_order_acquire);
}

/* Same contract as claimClientFd(), for the listener slot. */
static int claimListenFd(int fd) {
    if (fd < 0) return -1;
    int expected = fd;
    return atomic_compare_exchange_strong_explicit(&g_ListenFd, &expected, -1,
                                                   memory_order_acq_rel,
                                                   memory_order_acquire)
               ? fd : -1;
}

/* Claim whatever the listener slot holds right now; -1 when it is empty or when
   another party claimed it first. */
static int takeListenFd(void) {
    int fd = peekListenFd();
    while (fd >= 0) {
        if (claimListenFd(fd) == fd) return fd;
        fd = peekListenFd();
    }
    return -1;
}

int nxusNetClientFd(void) {
    return peekClientFd();
}

/* Consume a pending reset request: exactly one reader wins.  The old
   read-then-clear pair could lose a request that nxusNetRequestReset() raised
   between the two steps. */
static bool takeResetRequest(void) {
    return atomic_exchange_explicit(&g_ResetRequested, false, memory_order_acq_rel);
}

static bool resetRequested(void) {
    return atomic_load_explicit(&g_ResetRequested, memory_order_acquire);
}

/* Sleep in short slices instead of one long svcSleepThread(), returning early on
   shutdown or on a reset request, so a sleep/wake wake-up is never delayed by a
   backoff that is already running. */
static void backoffSleep(u64 total_ns) {
    const u64 slice_ns = 250000000ull;
    for (u64 slept = 0; slept < total_ns; slept += slice_ns) {
        if (!nxusNetRunning() || resetRequested()) return;
        svcSleepThread(slice_ns);
    }
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

/* Open, configure and bind the listen socket.  Returns false (and leaves the
   listener slot empty) on any failure, so the caller can decide whether the bsd
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

    /* Publish under the send lock, which is also the lock every close takes: an
       exit that already flipped g_Running takes (or has taken) the slot under that
       lock, so a listener created afterwards is refused here instead of being
       published past the teardown snapshot, where nothing would ever close it. */
    mutexLock(&g_SendMutex);
    const bool live = nxusNetRunning();
    if (live) atomic_store_explicit(&g_ListenFd, fd, memory_order_release);
    mutexUnlock(&g_SendMutex);

    if (!live) {
        close(fd);
        return false;
    }
    return true;
}

/* Cheap probe that detects a stale listener: a bsd session that died during a
   sleep can still hand out descriptors whose kernel object is gone, in which case
   poll()/accept() fail later but getsockname() already looks wrong. */
static bool listenerHealthy(void) {
    /* One load only: if the exit path claims the slot in between, getsockname()
       fails with EBADF below and reports "unhealthy", which is the right answer
       for a listener that is gone. */
    const int fd = peekListenFd();
    if (fd < 0) return false;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    socklen_t len = (socklen_t)sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
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
        500 ms, up to NXUS_NET_REBUILD_MAX_ATTEMPTS (60 s) per call, so a
        reconnect during a normal Wi-Fi rejoin is immediate while a network that
        is genuinely gone stops burning a core.  g_Running stays true when the
        budget runs out: the server loop, the next explicit reset or the
        sleep/wake tick simply calls us again.

   `full_bsd_reset` skips step 1 because the caller already knows the session is
   stale (explicit reset request, poll() error, dead listener). */
static void rebuildListener(bool full_bsd_reset) {
    if (!nxusNetRunning()) return;

    /* Claim the old listener before closing it, under the send lock.  Holding the
       lock keeps the exit path from shutting the descriptor down between the claim
       and the close, and the claim keeps a number another party already closed
       (and the kernel already recycled) from being closed a second time. */
    mutexLock(&g_SendMutex);
    const int old_fd = takeListenFd();
    if (old_fd >= 0) close(old_fd);
    mutexUnlock(&g_SendMutex);

    if (!full_bsd_reset && createListenerSocket()) {
        NXUS_LOG("listener rebuilt on 0.0.0.0:%u", (unsigned)g_Port);
        return;
    }

    u32 attempt = 0;
    for (; attempt < NXUS_NET_REBUILD_MAX_ATTEMPTS && nxusNetRunning() && peekListenFd() < 0;
         attempt++) {
        /* Drop the (stale) session, give the Wi-Fi supplicant half a second to
           come back, then open a fresh one.  Retrying at 500 ms keeps the port
           unavailable for as short a time as the network allows. */
        socketExit();
        svcSleepThread(NXUS_NET_REBUILD_DELAY_NS);
        if (!nxusNetRunning()) break;

        Result rc = socketInitializeDefault();
        if (!netCallSucceeded(rc, "socketInitializeDefault")) {
            NXUS_LOG("listener: socketInitializeDefault failed rc=0x%08X (attempt %u/%u)",
                     (unsigned)rc, (unsigned)(attempt + 1),
                     (unsigned)NXUS_NET_REBUILD_MAX_ATTEMPTS);
            continue;
        }
        if (createListenerSocket()) {
            NXUS_LOG("listener: bsd session rebuilt, listening on 0.0.0.0:%u (attempt %u)",
                     (unsigned)g_Port, (unsigned)(attempt + 1));
            return;
        }
        /* createListenerSocket() already logged the failing step (socket/bind/
           listen); keep the attempt counter visible so the log shows progress. */
        NXUS_LOG("listener: rebuild attempt %u/%u failed",
                 (unsigned)(attempt + 1), (unsigned)NXUS_NET_REBUILD_MAX_ATTEMPTS);
    }

    if (!nxusNetRunning()) {
        NXUS_LOG("listener: rebuild aborted after %u attempt(s) (shutdown)", (unsigned)attempt);
        return;
    }

    NXUS_LOG("listener: giving up after %u attempts (~%u s) - the network is still "
             "unreachable; the server loop retries on its next tick or reset request",
             (unsigned)attempt,
             (unsigned)(((u64)attempt * NXUS_NET_REBUILD_DELAY_NS) / 1000000000ull));
}

/* Drop the registered client.  The send mutex is held while the descriptor is
   read, claimed and closed, so a sender on another thread (debug events) can never
   write into a descriptor that was just handed back to the kernel - and never into
   the descriptor number that the kernel hands out to the next client.  The claim
   (CAS to -1) is what makes the close single-owner; nxusNetExit() claims the same
   way when it has to close without a joined thread. */
static void dropClient(void) {
    mutexLock(&g_SendMutex);
    const int fd = claimClientFd(peekClientFd());
    if (fd >= 0) {
        /* The claim already unregistered the descriptor: any sender that takes the
           mutex from here on sees -1 and refuses to send. */
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }
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
        if (!nxusNetRunning()) return false;
        if (resetRequested()) {
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
        pfds[1].fd = watch_listener ? peekListenFd() : -1;
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

/* Core writer.  The caller must already hold g_SendMutex: that is the same lock
   dropClient()/serveClient() take around close(), so the descriptor cannot be
   closed (and its number recycled into a new client) between the check and the
   last byte written. */
static Result sendFrameLocked(int fd, u16 type, u16 flags, u32 seq,
                              const void *payload, u32 length) {
    if (fd < 0) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    if (length > NXUS_NET_BUF_SIZE) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    if (length > 0 && payload == NULL) return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    NxusPacketHeader header;
    nxusHeaderInit(&header, type, flags, length, seq);

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

    return rc;
}

Result nxusNetSendFd(int fd, u16 type, u16 flags, u32 seq, const void *payload, u32 length) {
    /* Lock first, look afterwards.  Resolving the fd through nxusNetClientFd()
       before taking g_SendMutex was the injection bug: dropClient() could close
       the descriptor and the kernel hand the very same number to the next client
       in that window, so the event went to a session that never asked for it. */
    mutexLock(&g_SendMutex);

    Result rc = MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    /* Only the currently registered client is writable; a descriptor a handler
       kept across a reconnect is stale and must not be reused either. */
    if (fd >= 0 && fd == peekClientFd()) {
        rc = sendFrameLocked(fd, type, flags, seq, payload, length);
    }

    mutexUnlock(&g_SendMutex);
    return rc;
}

Result nxusNetSend(u16 type, u16 flags, u32 seq, const void *payload, u32 length) {
    /* Same rule as nxusNetSendFd(): the descriptor is read under g_SendMutex,
       never through nxusNetClientFd() before taking it. */
    mutexLock(&g_SendMutex);
    Result rc = sendFrameLocked(peekClientFd(), type, flags, seq, payload, length);
    mutexUnlock(&g_SendMutex);
    return rc;
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

    /* SO_KEEPALIVE on the listen socket is NOT inherited by accepted sockets, so
       it has to be set again here or a peer that vanished without a FIN is only
       noticed by the 20 s idle timeout.  With the tuned probe a dead link is
       reaped in ~16 s (10 s idle + 3 probes every 2 s), and the listen socket's
       copy keeps the guard for anything accepted between the two calls. */
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
#ifdef TCP_KEEPIDLE
    int keep_idle  = 10;   /* seconds of silence before the first probe */
    int keep_intvl = 2;    /* seconds between probes                    */
    int keep_cnt   = 3;    /* unanswered probes before the socket dies  */
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  &keep_idle,  sizeof(keep_idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keep_intvl, sizeof(keep_intvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,   &keep_cnt,   sizeof(keep_cnt));
#endif

    while (nxusNetRunning() && peekClientFd() == fd) {
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
    /* Under the same lock as dropClient(): a sender on another thread must not be
       inside send() on a descriptor that is handed back to the kernel here.  The
       close is claim-guarded like every other close of a published descriptor:
       nxusNetExit() may already have claimed and closed this number (it gives up
       on the thread after 2 s), and a second close() would hit whatever socket the
       kernel recycled it into. */
    mutexLock(&g_SendMutex);
    const int claimed = claimClientFd(fd);
    if (claimed >= 0) close(claimed);
    mutexUnlock(&g_SendMutex);
}

/* ---- accept loop -------------------------------------------------------- */

/* True for the source addresses a home LAN / VPN actually uses.  The protocol has
   no authentication, so this is the cheap guard that keeps it off the internet:
   127/8 (loopback), 10/8, 172.16/12, 192.168/16 (RFC1918), 169.254/16 (link-local)
   and 100.64/10 (CGNAT - Tailscale and friends hand out addresses from there). */
static bool nxusNetPeerIsPrivate(const struct sockaddr_in *peer) {
    const u32 ip = ntohl(peer->sin_addr.s_addr);
    if ((ip >> 24) == 127u) return true;                        /* 127.0.0.0/8   */
    if ((ip >> 24) == 10u) return true;                         /* 10.0.0.0/8    */
    if ((ip >> 20) == 0xAC1u) return true;                      /* 172.16.0.0/12 */
    if ((ip >> 16) == 0xC0A8u) return true;                     /* 192.168.0.0/16*/
    if ((ip >> 16) == 0xA9FEu) return true;                     /* 169.254.0.0/16*/
    if ((ip >> 22) == 0x191u) return true;                      /* 100.64.0.0/10 */
    return false;
}

static void serverThread(void *arg) {
    (void)arg;
    u64 last_health = armGetSystemTick();

    while (nxusNetRunning()) {
        /* 1. explicit reset (sleep/wake from main.c, external request). */
        if (takeResetRequest()) {
            NXUS_LOG("network reset requested - dropping client and rebuilding listener");
            dropClient();
            rebuildListener(true);
            last_health = armGetSystemTick();
            continue;
        }

        /* 2. no listener at all (a rebuild burst ran out of attempts, or the
              previous rebuild was interrupted by shutdown).  Wait before asking
              for another burst: rebuildListener() already retried for 60 s, so
              hammering it again immediately would just reproduce the same loop on
              a console that has no network.  The sleep is sliced and aborts on a
              reset request, so a wake-up is still handled within ~250 ms. */
        if (peekListenFd() < 0) {
            backoffSleep(NXUS_NET_REBUILD_RETRY_PAUSE_NS);
            if (!nxusNetRunning()) break;
            rebuildListener(true);
            last_health = armGetSystemTick();
            continue;
        }

        /* 3. wait for a connection, but never park here on a broken bsd session:
              a 500 ms timeout doubles as the health-probe tick.  The descriptor is
              a snapshot: the exit path may claim and close it underneath this
              poll(), which then reports POLLNVAL and ends the loop (g_Running is
              already false by then). */
        struct pollfd pfd;
        pfd.fd = peekListenFd();
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

        const int listen_fd = peekListenFd();
        if (listen_fd < 0) continue;   /* claimed by an exit: the loop ends there */

        struct sockaddr_in peer;
        memset(&peer, 0, sizeof(peer));
        socklen_t peer_len = (socklen_t)sizeof(peer);
        const int fd = accept(listen_fd, (struct sockaddr *)&peer, &peer_len);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            NXUS_LOG("accept() failed errno=%d - rebuilding listener", errno);
            rebuildListener(true);
            last_health = armGetSystemTick();
            continue;
        }

        /* Nxus speaks an unauthenticated read/write/debug protocol, so it must not
           be reachable from outside the LAN: a port-forward or a misconfigured
           network would otherwise let anyone on the internet edit memory and take
           the debug handle.  Only private / loopback sources are served; anything
           else is closed immediately (and logged, so a mistake is visible). */
        if (!nxusNetPeerIsPrivate(&peer)) {
            NXUS_LOG("accept: refused non-private peer %u.%u.%u.%u:%u",
                     (unsigned)(ntohl(peer.sin_addr.s_addr) >> 24) & 0xFF,
                     (unsigned)(ntohl(peer.sin_addr.s_addr) >> 16) & 0xFF,
                     (unsigned)(ntohl(peer.sin_addr.s_addr) >> 8) & 0xFF,
                     (unsigned)ntohl(peer.sin_addr.s_addr) & 0xFF,
                     (unsigned)ntohs(peer.sin_port));
            close(fd);
            continue;
        }

        /* A new connection always wins.  serveClient() already returns as soon as
           traffic shows up on the listener, so this only fires for a stale
           registration - but closing it keeps the "one session" invariant without
           ever refusing a reconnect. */
        const int prev = peekClientFd();
        if (prev >= 0) {
            NXUS_LOG("preempting stale client fd=%d with new fd=%d", prev, fd);
            dropClient();
        }
        publishClientFd(fd);
        serveClient(fd);
        last_health = armGetSystemTick();
    }

    /* Single exit path: the loop above is the whole body and every way out of it
       is a `break`/loop-condition failure, so this is always reached.  It must be
       the LAST statement - nxusNetExit() treats the flag as "the thread has
       finished" and only then calls threadWaitForExit() (which returns at once)
       and threadClose().  If a future return is added above it, the flag has to
       be raised on that path as well or the exit would wait for the deadline and
       abandon the handle. */
    atomic_store_explicit(&g_ServerDone, true, memory_order_release);
}

/* ---- public API --------------------------------------------------------- */

Result nxusNetInit(u16 port, NxusNetHandler handler, void *user) {
    if (nxusNetRunning()) return 0;

    mutexInit(&g_SendMutex);
    g_Handler = handler;
    g_HandlerUser = user;
    g_Port = port;
    atomic_store_explicit(&g_ResetRequested, false, memory_order_relaxed);
    /* Cleared before threadStart(): the flag is only meaningful for the thread
       this Init is about to create. */
    atomic_store_explicit(&g_ServerDone, false, memory_order_release);
    g_LastActivityTick = armGetSystemTick();

#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif

    Result rc = socketInitializeDefault();
    if (!netCallSucceeded(rc, "socketInitializeDefault")) {
        NXUS_RESULT("socketInitializeDefault", rc);
        return rc;
    }
    NXUS_LOG("socketInitializeDefault ok");

    atomic_store_explicit(&g_Running, true, memory_order_release);
    if (!createListenerSocket()) {
        atomic_store_explicit(&g_Running, false, memory_order_release);
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
        atomic_store_explicit(&g_Running, false, memory_order_release);
        /* No server thread exists yet, so this is a plain claim+close. */
        const int listen_fd = takeListenFd();
        if (listen_fd >= 0) close(listen_fd);
        socketExit();
        return rc;
    }
    threadStart(&g_ServerThread);

    NXUS_LOG("listening on 0.0.0.0:%u", (unsigned)g_Port);
    return 0;
}

void nxusNetRequestReset(const char *reason) {
    NXUS_LOG("network reset requested from outside (%s)", (reason != NULL) ? reason : "?");

    /* Release store: the server thread's exchange() is the only consumer, so the
       request is applied exactly once even if it lands mid-poll. */
    atomic_store_explicit(&g_ResetRequested, true, memory_order_release);

    /* Also wake the protocol thread if it is blocked in recv(): shutdown() makes
       poll() report the hangup instead of waiting for the next slice.  The server
       thread stays the owner of the close(), so this only shuts the socket down.

       The shutdown runs under g_SendMutex and reads the descriptor once, with the
       lock held: every close of a published descriptor (dropClient(), the
       serveClient() teardown, the exit path) takes the same lock, so the number
       cannot be closed and recycled into a brand-new client while this runs.  The
       lock is taken with try-lock so this stays non-blocking for its callers
       (HID/UI threads) even while a 1 MiB reply is being written; a missed
       shutdown only costs one 200 ms poll slice, since the atomic flag above is
       what actually drives the reset. */
    if (!mutexTryLock(&g_SendMutex)) return;

    const int fd = peekClientFd();
    if (fd >= 0) shutdown(fd, SHUT_RDWR);
    mutexUnlock(&g_SendMutex);
}

/* Wait (bounded) for serverThread() to raise g_ServerDone.
 *
 * libnx's threadWaitForExit() has no timeout parameter, and the connection thread
 * may sit inside a long handler (ptrscan is ~90 s), so an unconditional join made
 * __appExit() block for minutes.  Polling the done flag in 10 ms steps caps that
 * at `timeout_ms`: true means the thread already finished (or is finishing, so
 * threadWaitForExit() returns immediately), false means the deadline expired. */
static bool waitServerThreadDone(u32 timeout_ms) {
    const u64 deadline = armGetSystemTick() + armNsToTicks((u64)timeout_ms * 1000000ull);
    while (!atomic_load_explicit(&g_ServerDone, memory_order_acquire)) {
        if (armGetSystemTick() >= deadline) return false;
        svcSleepThread(NXUS_NET_EXIT_POLL_NS);
    }
    return true;
}

/* ---- teardown ------------------------------------------------------------
 *
 * nxusNetExit() runs as __appExit() is about to end the process, but it must not
 * block it: the connection thread can be parked inside a long handler (a pointer
 * scan runs ~90 s) and libnx has no timed join, so the wait is a 2 s poll of
 * g_ServerDone and the thread is *abandoned* past that deadline.
 *
 * What is released therefore depends on whether the thread actually stopped
 * (nxusNetExit() implements exactly this table):
 *
 *   object                   thread joined in time      deadline expired
 *   -----------------------  -------------------------  ---------------------------
 *   server Thread handle     threadClose()              LEFT OPEN - the thread is
 *                                                       still running, so closing its
 *                                                       handle would pull the object
 *                                                       from under it (process exit
 *                                                       reclaims it)
 *   client socket (fd)       claim -> close             claim -> close (after the
 *                                                       phase-1 shutdown)
 *   listener socket (fd)     claim -> close             claim -> close (after the
 *                                                       phase-1 shutdown)
 *   g_RxBuffer               free() + NULL              LEFT ALLOCATED - recvExact()
 *                                                       or the handler may still be
 *                                                       writing the frame into it
 *   bsd session (socketExit) socketExit()               LEFT OPEN - socketExit() while
 *                                                       the thread is alive is
 *                                                       undefined behaviour (logged)
 *
 * Closing the two descriptors on the deadline path is safe because both were
 * shutdown() first and because each close is claim-guarded (CAS of the slot to -1):
 * the exit path and the server thread can race, but only one of them ever closes a
 * given number, so the close can never land on a socket that recycled it.
 *
 * This is a one-way door: after an abandoned exit, nxusNetInit() must not be
 * called while the old thread (and its bsd session) is still alive - it would
 * share g_ServerThread/g_ServerDone and re-initialise a live bsd session.  The
 * single boot-then-exit lifecycle in main.c guarantees that.
 */
void nxusNetExit(void) {
    if (!nxusNetRunning()) return;
    atomic_store_explicit(&g_Running, false, memory_order_release);

    /* Phase 1 - stop the I/O.  Both descriptors are shut down (never closed) under
       g_SendMutex, which is also the lock every close of a published descriptor
       takes: while it is held the numbers cannot be recycled, so both shutdowns
       hit their own socket and not one that replaced it.  This wakes the server
       thread out of poll()/recv()/accept() immediately instead of at its next
       slice, and it is the precondition for phase 3 closing the descriptors. */
    mutexLock(&g_SendMutex);
    const int client_fd = peekClientFd();
    if (client_fd >= 0) shutdown(client_fd, SHUT_RDWR);
    const int listen_fd = peekListenFd();
    if (listen_fd >= 0) shutdown(listen_fd, SHUT_RDWR);
    mutexUnlock(&g_SendMutex);

    /* Phase 2 - bounded join. */
    const bool joined = waitServerThreadDone(NXUS_NET_EXIT_WAIT_MS);
    if (joined) {
        /* The flag is the thread's last statement, so this cannot block for long. */
        threadWaitForExit(&g_ServerThread);
        threadClose(&g_ServerThread);
    } else {
        NXUS_LOG_ERROR("net exit: server thread still busy after %u ms - abandoning the join",
                       (unsigned)NXUS_NET_EXIT_WAIT_MS);
        NXUS_LOG("net exit: bsd session left to process exit (socketExit() would run "
                 "while the thread still uses it); thread handle and rx buffer (ptr=%p) "
                 "left to process exit as well - the shut-down sockets are still closed",
                 (void *)g_RxBuffer);
    }

    /* Phase 3 - descriptors, on both paths.  After a joined thread the slots are
       stable, so claim whatever they hold now (a listener rebuilt between phase 1
       and the join would otherwise leak).  On the deadline path only the numbers
       shut down in phase 1 may be closed: anything newer was never shut down and
       belongs to the thread that is still running. */
    mutexLock(&g_SendMutex);
    const int claimed_client = claimClientFd(joined ? peekClientFd() : client_fd);
    if (claimed_client >= 0) close(claimed_client);
    const int claimed_listen = claimListenFd(joined ? peekListenFd() : listen_fd);
    if (claimed_listen >= 0) close(claimed_listen);
    mutexUnlock(&g_SendMutex);

    /* Phase 4 - only safe once the thread is really gone (see the table above). */
    if (!joined) return;

    free(g_RxBuffer);
    g_RxBuffer = NULL;
    socketExit();
}

bool nxusNetIsRunning(void) { return nxusNetRunning(); }
