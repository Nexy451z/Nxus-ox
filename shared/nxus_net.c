#include "nxus_net.h"
#include "nxus_heap.h"
#include "nxus_log.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
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

/* Short enough that a reset request or the stop flag is noticed within ~200 ms;
   long enough that the idle sysmodule stays cheap. */
#define NXUS_NET_POLL_SLICE_MS       200
/* No byte at all for 20 s means the peer is gone: the PC sends a heartbeat every
   4 s, so a live session never reaches this, while a half-open socket (the
   console slept, the PC vanished without a FIN) is reaped deterministically.
   Every connection is reaped on its own clock, so one stale client never blocks
   the others. */
#define NXUS_NET_IDLE_TIMEOUT_NS     20000000000ull
/* A packet that started but made no progress for 5 s is desynced: drop it rather
   than block that connection's thread forever on the rest of the frame. */
#define NXUS_NET_PAYLOAD_STALL_NS    5000000000ull
/* Period of the getsockname() health probe on the listen socket. */
#define NXUS_NET_HEALTH_INTERVAL_NS  2000000000ull
/* Connection backlog.  Up to NXUS_NET_MAX_CLIENTS are served; the rest queue up
   so a reconnect is never refused while the previous connection is being torn
   down. */
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
/* Slice of the drain wait when a listener rebuild has to wait for the client
   threads: short enough that the rebuild happens as soon as the last one leaves,
   long enough not to spin the accept thread. */
#define NXUS_NET_REBUILD_DRAIN_NS 50000000ull
/* Upper bound for the whole teardown in nxusNetExit(): the accept thread, then
   every client thread.  libnx has no timed thread join and a connection thread
   may be parked inside a long handler (a pointer scan runs ~90 s), so waiting
   unconditionally used to block __appExit() for minutes.  2 s is far more than a
   normal teardown needs (one 200 ms poll slice plus the socket close), so
   anything longer means "abandon the thread": the descriptors are still shut down
   and closed, while the Thread handles, stacks and receive buffers are left to
   process exit - see the table above nxusNetExit() for why each one is or is not
   released. */
#define NXUS_NET_EXIT_WAIT_MS           2000u
/* Granularity of that bounded wait: short enough that the exit returns as soon as
   the threads raise their done flag, long enough that the poll loop stays free. */
#define NXUS_NET_EXIT_POLL_NS           10000000ull

/* ---- per-connection state ----------------------------------------------- */

/* The already-joined static half of the transport: the listener slot, the accept
   thread and the shared handler/close hooks. */
static atomic_int      g_ListenFd = -1;
static Thread          g_ServerThread;
static atomic_bool     g_Running = false;   /* read from every thread, written by init/exit */
/* Serialises listener publication/close.  Every close of the LISTEN descriptor
   takes it, so the exit path's shutdown() can never land on a number that was
   closed and recycled in between. */
static Mutex           g_ListenMutex;
static NxusNetHandler  g_Handler = NULL;
static void           *g_HandlerUser = NULL;
static NxusNetCloseHandler g_CloseHandler = NULL;
static void           *g_CloseUser = NULL;
static u16             g_Port = NXUS_DEFAULT_PORT;
/* Set by nxusNetRequestReset() (any thread) and consumed by the accept thread.
   atomic: the consumer clears it with exchange(), so a request raised while the
   accept thread is between its load and its clear can no longer be swallowed by
   a plain read-then-store (lost update). */
static atomic_bool     g_ResetRequested = false;
/* Raised by serverThread() as its very last statement, polled by nxusNetExit().
   threadWaitForExit() cannot be given a timeout in libnx, so this flag is what
   makes the shutdown bounded: the exit path joins/closes the thread only after
   seeing it, and abandons the handle (reclaimed by process exit) when the
   deadline expires. */
static atomic_bool     g_ServerDone = false;
/* Set when a listener rebuild (which may tear the bsd session down) has to wait
   for the client threads to leave their sockets first.  See rebuildOrDefer(). */
static atomic_bool g_RebuildPending = false;

/* Last armGetSystemTick() at which a packet was received or sent completely.
   Written by every connection thread and read by the watchdog in main.c; an
   aligned 64-bit store is atomic on AArch64, so no lock is needed. */
static volatile u64    g_LastActivityTick = 0;

/* One served connection.  The published part (fd/in_use/done/generation) lives in
   the slot table the header defines, because that policy is host-tested;
   everything below is transport-private and only touched by the connection's own
   thread (rx, last_rx_tick) or by the reaper after the thread has been joined
   (stack).
 *
 * A state object is NOT tied to a slot index for life.  When the stale watchdog
 * force-releases a slot whose thread is still alive, the state object is detached
 * (zombie = true, retired_fd = the descriptor it still owns) and the slot can be
 * claimed again with a fresh state object.  That separation is what lets the
 * stale path be "leak, never UAF": the old thread keeps writing to its own state
 * object, while the new owner uses a different one.  A retired state is reclaimed
 * (thread joined, stack/rx freed, descriptor closed) once `finished` is published. */
typedef struct {
    atomic_bool  reserved;  /* this state object belongs to a served connection  */
    atomic_bool  zombie;    /* detached from its slot; the thread may still run  */
    atomic_bool  finished;  /* the serving thread's last statement              */
    /* Atomic for the same reason as generation: a send path may have snapshotted
       this state and load the pointer after it was released and reused (see
       clientStateRelease()). */
    atomic_uintptr_t slot;  /* &g_Slots[index] while serving                    */
    atomic_uint  generation;/* slot generation this state was claimed for       */
    int          retired_fd;/* zombie only: descriptor this state still owns    */
    Mutex        send_lock; /* serialises frame writes and fd teardown          */
    Thread       thread;
    u8          *rx;        /* receive buffer (owned by the client thread)      */
    u32          rx_cap;
    u8          *stack;     /* heap thread stack (freed by the reaper)          */
    u64          last_rx_tick;
    u64          rx_big_tick;   /* last frame that needed > NXUS_NET_RX_IDLE_SIZE */
    char         peer[32];
} NxusNetClient;

/* There are as many connection state objects as client slots plus spares for the
 * force-released ones.  A zombie is reclaimed as soon as its thread exits, so the
 * spare count only has to cover the threads that are simultaneously stuck. */
#define NXUS_NET_CLIENT_STATE_MAX (NXUS_NET_MAX_CLIENTS + 4)

static NxusNetSlot   g_Slots[NXUS_NET_MAX_CLIENTS];
static NxusNetClient g_ClientStates[NXUS_NET_CLIENT_STATE_MAX];
/* Slot -> connection state currently serving it (NULL when free/reaped).  Atomic
 * because the send paths read it without the accept thread's involvement. */
static atomic_uintptr_t g_SlotClient[NXUS_NET_MAX_CLIENTS];
/* True between the mutex/table setup in nxusNetInit() and the start of
   nxusNetExit().  The slot array is zero-initialised statically (fd == 0, which
   is a perfectly valid descriptor number), so every path that may run before Init
   or during the teardown - nxusNetSendEvent() from the cheat worker, the
   watchdog's nxusNetClientFd(), a reset request - must refuse to touch it unless
   this flag is set. */
static atomic_bool  g_TableReady = false;

static bool nxusNetRunning(void) {
    return atomic_load_explicit(&g_Running, memory_order_acquire);
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

/* Monotonic nanoseconds for the per-slot I/O clock.  armGetSystemTick() keeps
 * counting across a sleep, so a suspend shows up as one large gap - exactly what
 * the stale watchdog must treat as "this connection is dead".  A 0 stamp means
 * "never stamped" and is never considered stale. */
static u64 ioNowNs(void) {
    return armTicksToNs(armGetSystemTick());
}

/* Sleep in short slices instead of one long svcSleepThread(), returning early on
   shutdown or on a reset request, so a sleep/wake wake-up is never delayed by a
   backoff that is already running. */
static void backoffSleep(u64 total_ns) {
    const u64 slice_ns = 250000000ull;
    for (u64 slept = 0; slept < total_ns; slept += slice_ns) {
        if (!nxusNetRunning() || atomic_load_explicit(&g_ResetRequested, memory_order_acquire))
            return;
        svcSleepThread(slice_ns);
    }
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

/* ---- listener descriptor slot -------------------------------------------
 *
 * The listener slot is both the registration and the close token: to close it, a
 * party first replaces it with -1 through a compare-exchange, and only the
 * winner of that CAS may call close().  It is atomic because the slot is also
 * read without the lock (the health probe, the accept poll).
 */
static int peekListenFd(void) {
    return atomic_load_explicit(&g_ListenFd, memory_order_acquire);
}

/* Claim `fd` for a close.  Returns fd when this caller won, -1 when the slot no
   longer holds it (already closed elsewhere, or replaced by a newer listener that
   this caller does not own and must leave alone). */
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

    /* Publish under the listener lock, which is also the lock every close takes:
       an exit that already flipped g_Running takes (or has taken) the slot under
       that lock, so a listener created afterwards is refused here instead of being
       published past the teardown snapshot, where nothing would ever close it. */
    mutexLock(&g_ListenMutex);
    const bool live = nxusNetRunning();
    if (live) atomic_store_explicit(&g_ListenFd, fd, memory_order_release);
    mutexUnlock(&g_ListenMutex);

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

    /* Claim the old listener before closing it, under the listener lock.  Holding
       the lock keeps the exit path from shutting the descriptor down between the
       claim and the close, and the claim keeps a number another party already
       closed (and the kernel already recycled) from being closed a second time. */
    mutexLock(&g_ListenMutex);
    const int old_fd = takeListenFd();
    if (old_fd >= 0) close(old_fd);
    mutexUnlock(&g_ListenMutex);

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

/* ---- connection table helpers ------------------------------------------- */

/* Connection state currently published for a slot (NULL when free/reaped). */
static NxusNetClient *slotClient(int index) {
    if (index < 0 || index >= NXUS_NET_MAX_CLIENTS) return NULL;
    return (NxusNetClient *)(uintptr_t)atomic_load_explicit(&g_SlotClient[index],
                                                           memory_order_acquire);
}

static void slotSetClient(int index, NxusNetClient *client) {
    if (index < 0 || index >= NXUS_NET_MAX_CLIENTS) return;
    atomic_store_explicit(&g_SlotClient[index], (uintptr_t)client, memory_order_release);
}

/* The client whose slot currently holds `fd`, or NULL.  A snapshot only: the
   caller must re-check the slot (and its generation) after taking its send lock. */
static NxusNetClient *clientForFd(int fd) {
    if (fd < 0 || !atomic_load_explicit(&g_TableReady, memory_order_acquire)) return NULL;
    for (int i = 0; i < NXUS_NET_MAX_CLIENTS; i++) {
        if (nxusNetSlotFd(&g_Slots[i]) == fd) return slotClient(i);
    }
    return NULL;
}

/* The slot generation a state object was claimed for.  Atomic so a stale send path
   that snapshotted the object just before it was released reads a defined value
   (0 after release, which no claimed slot ever has) instead of racing a reuse. */
static u32 clientGeneration(const NxusNetClient *client) {
    return atomic_load_explicit(&client->generation, memory_order_acquire);
}

static void clientSetGeneration(NxusNetClient *client, u32 generation) {
    atomic_store_explicit(&client->generation, generation, memory_order_release);
}

/* The slot a state object currently serves.  Never NULL by construction: Init
 * seeds every object with a valid table entry and startClient() repoints it before
 * the object is published, so a stale send path cannot dereference NULL. */
static NxusNetSlot *clientSlot(const NxusNetClient *client) {
    return (NxusNetSlot *)(uintptr_t)atomic_load_explicit(&client->slot,
                                                          memory_order_acquire);
}

static void clientSetSlot(NxusNetClient *client, NxusNetSlot *slot) {
    atomic_store_explicit(&client->slot, (uintptr_t)slot, memory_order_release);
}

int nxusNetClientFd(void) {
    if (!atomic_load_explicit(&g_TableReady, memory_order_acquire)) return -1;
    for (int i = 0; i < NXUS_NET_MAX_CLIENTS; i++) {
        const int fd = nxusNetSlotFd(&g_Slots[i]);
        if (fd >= 0) return fd;
    }
    return -1;
}

int nxusNetClientCount(void) {
    if (!atomic_load_explicit(&g_TableReady, memory_order_acquire)) return 0;
    int count = 0;
    for (int i = 0; i < NXUS_NET_MAX_CLIENTS; i++) {
        if (nxusNetSlotFd(&g_Slots[i]) >= 0) count++;
    }
    return count;
}

/* Shut the connection's socket down (not close): wakes its poll()/recv() without
   handing the descriptor back to the kernel, so the owning thread is still the
   only one that closes it.  The generation check is the force-release guard: if
   this state object was detached and its slot reused, shutdown() must not land on
   the new owner's descriptor. */
static void clientShutdown(NxusNetClient *client) {
    mutexLock(&client->send_lock);
    if (nxusNetSlotGeneration(clientSlot(client)) == clientGeneration(client)) {
        const int fd = nxusNetSlotFd(clientSlot(client));
        if (fd >= 0) shutdown(fd, SHUT_RDWR);
    }
    mutexUnlock(&client->send_lock);
}

/* Unregister the connection's descriptor under its send lock.  Returns the
   descriptor when this call owned it (and the caller must close it), -1 when it
   was already taken by the exit path/stale watchdog or when the slot now belongs
   to another generation.  Unregistering before close() is what makes the close
   handler's fd unambiguous: the number cannot be recycled while the socket is
   still open, and no sender can reach it any more.
 *
 * nxusNetSlotTakeFd() is a generation-checked CAS, so a force-released old thread
 * that wakes up late returns -1 instead of clearing a descriptor its slot no
 * longer owns. */
static int clientTakeFd(NxusNetClient *client) {
    mutexLock(&client->send_lock);
    const int fd = nxusNetSlotTakeFd(clientSlot(client), clientGeneration(client));
    mutexUnlock(&client->send_lock);
    return fd;
}

/* ---- connection state objects ------------------------------------------- */

/* Reserve a state object for a new connection, or NULL when every object is in
 * use (a pathological run of force-released threads that never exit).  The
 * send_lock is initialised once per process by nxusNetInit(); re-initialising a
 * mutex another thread could still hold is undefined behaviour. */
static NxusNetClient *clientStateAcquire(void) {
    for (int i = 0; i < NXUS_NET_CLIENT_STATE_MAX; i++) {
        NxusNetClient *client = &g_ClientStates[i];
        bool expected = false;
        if (!atomic_compare_exchange_strong_explicit(&client->reserved, &expected, true,
                                                     memory_order_acq_rel,
                                                     memory_order_acquire)) {
            continue;
        }
        /* slot/generation are set by startClient() before the object is published
           in g_SlotClient; leaving the previous (valid) slot pointer here keeps a
           stale sender's late check safe instead of dereferencing NULL. */
        clientSetGeneration(client, 0);
        client->retired_fd = -1;
        client->rx = NULL;
        client->rx_cap = 0;
        client->stack = NULL;
        client->last_rx_tick = 0;
        client->rx_big_tick = 0;
        client->peer[0] = '\0';
        atomic_store_explicit(&client->zombie, false, memory_order_relaxed);
        atomic_store_explicit(&client->finished, false, memory_order_relaxed);
        return client;
    }
    return NULL;
}

/* Give a state object back after its thread was joined and its stack freed.  A
 * zombie is never released here until it has finished (see reapRetiredClients).
 *
 * `slot` is deliberately left pointing at the slot table: a send path may have
 * snapshotted this object just before it was released and still be waiting for its
 * send lock.  Clearing the pointer would turn that race into a NULL dereference;
 * leaving it means the late check (fd + generation) simply refuses, because the
 * slot has been retired (generation bumped) or reused for another connection. */
static void clientStateRelease(NxusNetClient *client) {
    clientSetGeneration(client, 0);
    client->retired_fd = -1;
    client->rx = NULL;
    client->rx_cap = 0;
    client->stack = NULL;
    atomic_store_explicit(&client->zombie, false, memory_order_relaxed);
    atomic_store_explicit(&client->finished, false, memory_order_relaxed);
    atomic_store_explicit(&client->reserved, false, memory_order_release);
}

static bool clientFinished(const NxusNetClient *client) {
    return atomic_load_explicit(&client->finished, memory_order_acquire);
}

/* Publish `finished` as the serving thread's very last statement.  Order matters:
 * slot state (done/fd) and the rx buffer are already released by then, so a
 * reaper that sees this flag may join the Thread and free the stack safely. */
static void clientPublishFinished(NxusNetClient *client) {
    atomic_store_explicit(&client->finished, true, memory_order_release);
}

/* Wait (bounded) for one connection's serving thread to publish `finished`. */
static bool waitClientFinished(NxusNetClient *client, u64 deadline) {
    while (!clientFinished(client)) {
        if (!nxusNetRunning()) return false;
        if (armGetSystemTick() >= deadline) return false;
        svcSleepThread(NXUS_NET_SLOT_STALE_POLL_NS);
    }
    return true;
}

/* ---- BUSY refusal ------------------------------------------------------- */

/* Defined after sendFrameLocked(); used by sendBusyAndClose() below. */
static Result sendFrameLocked(int fd, u16 type, u16 flags, u32 seq,
                              const void *payload, u32 length);

/* "a.b.c.d:port" of the connected peer.  getpeername() is authoritative after
   accept(); `fallback` carries the accept() sockaddr for the (rare) case the
   stack cannot report it again. */
static void formatPeer(int fd, const struct sockaddr_in *fallback, char *out, size_t cap) {
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    socklen_t len = (socklen_t)sizeof(peer);
    bool ok = getpeername(fd, (struct sockaddr *)&peer, &len) == 0 &&
              peer.sin_family == AF_INET;
    if (!ok && fallback != NULL && fallback->sin_family == AF_INET) {
        peer = *fallback;
        ok = true;
    }
    if (!ok) {
        snprintf(out, cap, "?");
        return;
    }
    const u32 ip = ntohl(peer.sin_addr.s_addr);
    snprintf(out, cap, "%u.%u.%u.%u:%u",
             (unsigned)((ip >> 24) & 0xFFu), (unsigned)((ip >> 16) & 0xFFu),
             (unsigned)((ip >> 8) & 0xFFu), (unsigned)(ip & 0xFFu),
             (unsigned)ntohs(peer.sin_port));
}

/* Refuse a connection that cannot be served (every slot in use, or no memory for
   its thread stack / receive buffer): send the BUSY error frame (s32 Result +
   u32 reason, as replyErrorReason() does) and close at once.  The descriptor is
   not registered in any slot, so this cannot race a sender.
 *
 * `why` names a non-slot reason (allocation/thread failure) for the log.  Passing
 * NULL keeps the pinned "all N client slots are in use" line, so a reader can still
 * tell a truly full server from one that merely ran out of heap - the two used to be
 * indistinguishable in the log. */
static void sendBusyAndClose(int new_fd, const char *peer_text, const char *why) {
    s32 payload[2];
    nxusNetFillBusyPayload(payload);
    (void)sendFrameLocked(new_fd, NxusCmd_Nop, NXUS_FLAG_ERROR, 0,
                          payload, (u32)sizeof(payload));

    /* The shipped PC clients send their first request immediately after connect.
       close() while those bytes are still unread makes the stack send RST, which
       can discard the BUSY frame that was just queued (observed on the host: the
       client saw only a reset).  Drain what has arrived with a short timeout, so
       the close is a clean FIN and the peer actually reads the refusal. */
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 10000;   /* 10 ms: one LAN round trip, then give up */
    setsockopt(new_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    u8 sink[512];
    for (int i = 0; i < 8; i++) {
        if (recv(new_fd, sink, (int)sizeof(sink), 0) <= 0) break;
    }

    if (why == NULL) {
        NXUS_LOG(NXUS_NET_LOG_BUSY_FMT, peer_text, new_fd, NXUS_NET_MAX_CLIENTS);
    } else {
        NXUS_LOG("client busy: refused new connection from %s (fd=%d) - %s "
                 "(free=%u KiB)",
                 peer_text, new_fd, why, (unsigned)nxusHeapFreeKiB());
    }
    close(new_fd);
}

/* ---- receive ------------------------------------------------------------ */

/* Grow the connection's receive buffer to at least `need` bytes.  Never beyond
   NXUS_NET_BUF_SIZE (the largest protocol payload), so the per-connection ceiling
   documented in nxus_net.h holds.  A frame larger than the idle size also stamps
   rx_big_tick: the shrink below is about "this connection has not needed a big
   buffer for a while", not about the heartbeat traffic that keeps last_rx_tick
   fresh - otherwise a client that once uploaded a 512 KiB cheat upload would hold
   that buffer for the rest of the session just because it keeps heartbeating. */
static bool clientRxEnsure(NxusNetClient *client, u32 need) {
    if (need > NXUS_NET_BUF_SIZE) return false;
    if (need > NXUS_NET_RX_IDLE_SIZE) client->rx_big_tick = armGetSystemTick();
    if (need <= client->rx_cap) return true;
    u8 *bigger = (u8 *)realloc(client->rx, need);
    if (bigger == NULL) {
        /* The frame is already queued, so the caller refuses it with BAD_LENGTH and
           drops the connection (see serveClient): say how much heap was left, so a
           stream of "does not fit" lines can be told apart from a protocol error. */
        NXUS_LOG("recv: fd=%d receive buffer grow %u -> %u B failed (free=%u KiB)",
                 nxusNetSlotFd(clientSlot(client)), (unsigned)client->rx_cap, (unsigned)need,
                 (unsigned)nxusHeapFreeKiB());
        return false;
    }
    NXUS_LOG("recv: fd=%d grew the receive buffer %u -> %u B",
             nxusNetSlotFd(clientSlot(client)), (unsigned)client->rx_cap, (unsigned)need);
    client->rx = bigger;
    client->rx_cap = need;
    nxusHeapLogDebug("net rx grow");
    return true;
}

/* Give an enlarged buffer back once the connection has not needed a large frame
   for NXUS_NET_RX_SHRINK_IDLE_NS.  Called only while waiting for the NEXT header,
   so no caller holds a pointer into the buffer that is being replaced (the header
   itself lives on the stack). */
static void clientRxShrinkIfIdle(NxusNetClient *client, u64 now) {
    if (client->rx == NULL || client->rx_cap <= NXUS_NET_RX_IDLE_SIZE) return;
    if (client->rx_big_tick == 0) return;
    const u64 idle_ns = elapsedNs(client->rx_big_tick, now);
    if (idle_ns < NXUS_NET_RX_SHRINK_IDLE_NS) return;

    u8 *smaller = (u8 *)realloc(client->rx, NXUS_NET_RX_IDLE_SIZE);
    if (smaller == NULL) return;   /* keep the larger block: harmless, still bounded */
    NXUS_LOG("recv: fd=%d has had no large frame for %llu ms - shrunk the receive "
             "buffer %u -> %u B",
             nxusNetSlotFd(clientSlot(client)),
             (unsigned long long)(idle_ns / 1000000ull),
             (unsigned)client->rx_cap, (unsigned)NXUS_NET_RX_IDLE_SIZE);
    client->rx = smaller;
    client->rx_cap = NXUS_NET_RX_IDLE_SIZE;
    nxusHeapLogDebug("net rx shrink");
}

/* Receive exactly `length` bytes, but never unconditionally:

   The previous implementation looped on recv() alone (SO_RCVTIMEO -> EAGAIN ->
   retry) while SO_RCVTIMEO kept firing.  A half-open connection (the console
   slept, the PC vanished without a FIN) therefore parked the connection thread
   inside recvAll() forever: the listener was never serviced again, so every
   reconnect was refused or timed out, and only a sysmodule restart helped.

   Every wait now goes through poll() in 200 ms slices.  The accept thread is
   independent, so this function only has to watch its own socket:

     - a reset request or a shutdown returns false immediately;
     - 20 s without a single byte while `got == 0` and 5 s without progress once a
       payload has started are fatal, so dead sockets are always reaped
       (the PC heartbeats every 4 s, so a healthy idle session is never cut);
     - while waiting for the next header (is_header && got == 0) an enlarged
       receive buffer is shrunk back after the idle interval. */
static bool recvExact(NxusNetClient *client, int fd, void *buffer, u32 length, bool is_header) {
    u8 *out = (u8 *)buffer;
    u32 got = 0;
    u64 last_progress = armGetSystemTick();

    while (got < length) {
        if (!nxusNetRunning()) return false;
        if (resetRequested()) {
            NXUS_LOG("recv: reset requested while fd=%d was idle - dropping client", fd);
            return false;
        }

        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        const int pr = poll(&pfd, 1, NXUS_NET_POLL_SLICE_MS);
        if (pr < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            NXUS_LOG("recv: poll(fd=%d) failed errno=%d - dropping client", fd, errno);
            return false;
        }

        if (pr > 0 && (pfd.revents & POLLIN)) {
            const int n = recv(fd, out + got, (int)(length - got), 0);
            if (n > 0) {
                got += (u32)n;
                last_progress = armGetSystemTick();
                /* A byte on the wire is a live PC: the sleep/wake heuristic in
                   main.c must never reset the network while traffic flows. */
                g_LastActivityTick = last_progress;
                client->last_rx_tick = last_progress;
                nxusNetSlotTouch(clientSlot(client), armTicksToNs(last_progress));
            } else if (n == 0) {
                return false;               /* orderly shutdown by the peer */
            } else if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                /* SO_RCVTIMEO expired between poll() and recv(): poll again. */
            } else {
                NXUS_LOG("recv: fd=%d failed errno=%d - dropping client", fd, errno);
                return false;
            }
        } else if (pr > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            NXUS_LOG("recv: fd=%d error/hangup (revents=0x%X)", fd, (unsigned)pfd.revents);
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
            if (is_header) clientRxShrinkIfIdle(client, now);
        } else if (idle_ns > NXUS_NET_PAYLOAD_STALL_NS) {
            NXUS_LOG("recv: fd=%d stalled at %u/%u bytes for %llu ms - dropping client", fd,
                     (unsigned)got, (unsigned)length,
                     (unsigned long long)(idle_ns / 1000000ull));
            return false;
        }
    }
    return true;
}

/* ---- sending ------------------------------------------------------------ */

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

/* Core writer.  The caller must already hold the connection's send lock (or own
   the descriptor exclusively, for the BUSY refusal): that is the same lock the
   teardown takes around close(), so the descriptor cannot be closed (and its
   number recycled into a new client) between the check and the last byte
   written. */
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
           connection down (the owning thread then closes it) instead of returning
           an error that leaves the stream permanently desynced. */
        if (sent_total > 0) shutdown(fd, SHUT_RDWR);
        rc = MAKERESULT(Module_Libnx, LibnxError_ShouldNotHappen);
    } else {
        g_LastActivityTick = armGetSystemTick();
        /* A completed write is I/O activity for the stale watchdog.  Resolving the
         * client from `fd` is cheap (four atomic reads) and covers every caller,
         * including replies sent from worker threads.  A descriptor that is not
         * registered (the BUSY refusal) simply has no slot to stamp. */
        NxusNetClient *client = clientForFd(fd);
        if (client != NULL) nxusNetSlotTouch(clientSlot(client), armTicksToNs(g_LastActivityTick));
    }

    return rc;
}

Result nxusNetSendFd(int fd, u16 type, u16 flags, u32 seq, const void *payload, u32 length) {
    /* Look the descriptor up, then re-check it under the connection's send lock.
       Resolving the fd through nxusNetClientFd() before taking the lock was the
       injection bug: the owner could close the descriptor and the kernel hand the
       very same number to another client in that window, so the event went to a
       session that never asked for it. */
    NxusNetClient *client = clientForFd(fd);
    if (client == NULL) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);

    mutexLock(&client->send_lock);
    Result rc = MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    /* Only a registered connection of the generation this state was claimed for is
       writable; a descriptor a handler kept across a disconnect (or across a force
       release and slot reuse) is stale and must not be reused either. */
    if (nxusNetSlotFd(clientSlot(client)) == fd &&
        nxusNetSlotGeneration(clientSlot(client)) == clientGeneration(client)) {
        rc = sendFrameLocked(fd, type, flags, seq, payload, length);
    }
    mutexUnlock(&client->send_lock);
    return rc;
}

Result nxusNetSend(u16 type, u16 flags, u32 seq, const void *payload, u32 length) {
    /* Broadcast: asynchronous events are not addressed to one session.  Every
       connection is written under its own send lock, so one slow client cannot
       block the replies of the others beyond its own send timeout. */
    if (!atomic_load_explicit(&g_TableReady, memory_order_acquire))
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    bool any = false;
    Result first_error = 0;
    for (int i = 0; i < NXUS_NET_MAX_CLIENTS; i++) {
        NxusNetClient *client = slotClient(i);
        if (client == NULL) continue;
        const int fd = nxusNetSlotFd(clientSlot(client));
        if (fd < 0) continue;

        mutexLock(&client->send_lock);
        if (nxusNetSlotFd(clientSlot(client)) == fd &&
            nxusNetSlotGeneration(clientSlot(client)) == clientGeneration(client)) {
            const Result rc = sendFrameLocked(fd, type, flags, seq, payload, length);
            if (rc == 0) any = true;
            else if (first_error == 0) first_error = rc;
        }
        mutexUnlock(&client->send_lock);
    }
    if (any) return 0;
    return (first_error != 0) ? first_error
                              : MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
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

/* ---- serving one connection --------------------------------------------- */

void nxusNetSetCloseHandler(NxusNetCloseHandler handler, void *user) {
    g_CloseHandler = handler;
    g_CloseUser = user;
}

static void serveClient(NxusNetClient *client, int fd) {
    NXUS_LOG("client connected from %s (fd=%d, slot %d, %d/%d busy)",
             client->peer, fd,
             (int)(clientSlot(client) - &g_Slots[0]),
             nxusNetClientCount(), NXUS_NET_MAX_CLIENTS);
    /* The heap line for the one allocation point a user can trigger repeatedly:
     * a reconnect storm after a Wi-Fi switch is exactly when "free" matters. */
    nxusHeapLog("net client connected");

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

    while (nxusNetRunning() &&
           nxusNetSlotGeneration(clientSlot(client)) == clientGeneration(client) &&
           nxusNetSlotFd(clientSlot(client)) == fd) {
        NxusPacketHeader header;
        if (!recvExact(client, fd, &header, sizeof(header), true)) break;

        if (header.magic != NXUS_MAGIC) {
            NXUS_LOG("bad magic 0x%08X - closing", (unsigned)header.magic);
            break;
        }
        if (header.length > NXUS_NET_BUF_SIZE) {
            NXUS_LOG("payload too large (%u) - closing", (unsigned)header.length);
            break;
        }

        const u32 length = header.length;
        if (length > 0) {
            if (!clientRxEnsure(client, length)) {
                /* The payload cannot be buffered, and it is still queued: refuse
                   the request with the protocol's BAD_LENGTH reason and drop the
                   connection rather than parse the remaining bytes as a header.
                   The connection keeps whatever buffer it has (nxus_net.h). */
                NXUS_LOG("recv: fd=%d payload of %u B does not fit the %u B receive "
                         "buffer (limit %u B) - refusing with BAD_LENGTH",
                         fd, (unsigned)length, (unsigned)client->rx_cap,
                         (unsigned)NXUS_NET_BUF_SIZE);
                s32 payload[2];
                payload[0] = (s32)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
                payload[1] = (s32)NXUS_REASON_BAD_LENGTH;
                mutexLock(&client->send_lock);
                if (nxusNetSlotFd(clientSlot(client)) == fd) {
                    (void)sendFrameLocked(fd, header.type, NXUS_FLAG_ERROR, header.seq,
                                          payload, (u32)sizeof(payload));
                }
                mutexUnlock(&client->send_lock);
                break;
            }
            /* Payload: a started frame must finish, so no listener in the set. */
            if (!recvExact(client, fd, client->rx, length, false)) break;
        }

        if (g_Handler != NULL) {
            g_Handler(fd, &header, client->rx, length, g_HandlerUser);
        }
    }

    NXUS_LOG("client disconnected (fd=%d)", fd);

    /* Unregister FIRST: from here on no sender can reach this descriptor, while
       it is still open, so the number is unique and the close hook can name this
       connection by fd without hitting a recycled descriptor.  After a force-
       release the generation no longer matches, so clientTakeFd() returns -1 and
       neither the close hook nor close() touches a descriptor this thread does not
       own any more. */
    const bool owned = (clientTakeFd(client) == fd);
    if (owned) {
        if (g_CloseHandler != NULL) g_CloseHandler(fd, g_CloseUser);
        close(fd);
    }

    free(client->rx);
    client->rx = NULL;
    client->rx_cap = 0;
    nxusHeapLogDebug("net client close");

    /* Publish the slot state for this generation first (the reaper keys on it),
       then tell the zombie reaper this state object is safe to join. */
    (void)nxusNetSlotFinishGeneration(clientSlot(client), clientGeneration(client));
    clientPublishFinished(client);
}

static void clientThread(void *arg) {
    NxusNetClient *client = (NxusNetClient *)arg;
    const int fd = nxusNetSlotFd(clientSlot(client));
    if (fd >= 0) {
        serveClient(client, fd);
        return;
    }

    /* The exit path unregistered the descriptor before this thread got to run.
       Nothing to serve, nothing to close - just release the buffer and publish
       the slot as done so the reaper can collect the thread. */
    free(client->rx);
    client->rx = NULL;
    client->rx_cap = 0;
    (void)nxusNetSlotFinishGeneration(clientSlot(client), clientGeneration(client));
    clientPublishFinished(client);
}

/* Join and release every slot whose serving thread has finished.  Only the accept
   thread and nxusNetExit() call this, and nxusNetExit() only after the accept
   thread has been joined, so a slot's Thread handle is touched by exactly one
   reaper. */
static void reapFinishedClients(void) {
    for (int i = 0; i < NXUS_NET_MAX_CLIENTS; i++) {
        if (!nxusNetSlotReapable(&g_Slots[i])) continue;
        NxusNetClient *client = slotClient(i);
        if (client == NULL) {
            /* A slot that finished without a published state object: nothing to
               join, just release the claim. */
            nxusNetSlotReaped(&g_Slots[i]);
            NXUS_LOG("client slot %d released (no connection state)", i);
            continue;
        }

        threadWaitForExit(&client->thread);
        threadClose(&client->thread);
        free(client->stack);
        client->stack = NULL;
        /* serveClient()/clientThread() already freed it; defensive only. */
        free(client->rx);
        client->rx = NULL;
        client->rx_cap = 0;

        slotSetClient(i, NULL);
        nxusNetSlotReaped(&g_Slots[i]);
        clientStateRelease(client);
        NXUS_LOG("client slot %d released (thread joined)", i);
        /* The connection's whole resident cost (rx buffer + 24/32 KiB stack) is back
           in the heap now; the close line above is only the buffer half. */
        nxusHeapLogDebug("net slot released");
    }
}

/* Reclaim state objects the stale watchdog detached from their slots.  The
 * serving thread may still have been inside a long handler when the slot was
 * force-released; once it publishes `finished` (its last statement) the Thread can
 * be joined, the leaked stack freed, and the descriptor - which the watchdog took
 * out of the slot and recorded in retired_fd - closed.  Until then everything is
 * left allocated: freeing a stack or a receive buffer under a live thread is the
 * use-after-free this design exists to avoid. */
static void reapRetiredClients(void) {
    for (int i = 0; i < NXUS_NET_CLIENT_STATE_MAX; i++) {
        NxusNetClient *client = &g_ClientStates[i];
        if (!atomic_load_explicit(&client->reserved, memory_order_acquire)) continue;
        if (!atomic_load_explicit(&client->zombie, memory_order_acquire)) continue;
        if (!clientFinished(client)) continue;

        threadWaitForExit(&client->thread);
        threadClose(&client->thread);
        free(client->stack);
        client->stack = NULL;
        free(client->rx);
        client->rx = NULL;
        client->rx_cap = 0;
        if (client->retired_fd >= 0) {
            /* Unregistered by the watchdog and never touched by the old thread
               (it lost the generation race), so this close cannot hit a live
               connection. */
            close(client->retired_fd);
            client->retired_fd = -1;
        }
        const int state = i;
        clientStateRelease(client);
        NXUS_LOG("net: retired connection state %d reclaimed (thread joined)", state);
        nxusHeapLogDebug("net retired state released");
    }
}

/* Wake every connection so its serving thread notices the shutdown/rebuild. */
static void shutdownAllClients(const char *why) {
    for (int i = 0; i < NXUS_NET_MAX_CLIENTS; i++) {
        if (!nxusNetSlotInUse(&g_Slots[i])) continue;
        const int fd = nxusNetSlotFd(&g_Slots[i]);
        if (fd < 0) continue;
        NxusNetClient *client = slotClient(i);
        if (client == NULL) continue;
        NXUS_LOG("dropping client fd=%d (%s)", fd, why);
        clientShutdown(client);
    }
}

/* Detach a still-published connection state from its slot when the slot is being
 * force-released.  The descriptor is taken out of the slot under the same send
 * lock the serving thread uses for its own take/close, so exactly one party owns
 * the close: if the thread won the race, this returns -1 and the thread closes it;
 * otherwise the descriptor is recorded in retired_fd and reapRetiredClients()
 * closes it after the thread has been joined.
 *
 * The state object stays reserved and becomes a zombie: its thread may still be
 * running (parked in a long handler), so neither its stack nor its receive buffer
 * may be freed here. */
static int detachClientState(NxusNetSlot *slot, NxusNetClient *client) {
    if (client == NULL) return -1;

    mutexLock(&client->send_lock);
    int fd = -1;
    if (nxusNetSlotGeneration(slot) == clientGeneration(client)) {
        fd = nxusNetSlotTakeFd(slot, clientGeneration(client));
    }
    client->retired_fd = fd;
    atomic_store_explicit(&client->zombie, true, memory_order_release);
    mutexUnlock(&client->send_lock);
    return fd;
}

/* Force-release one slot whose thread ignored a shutdown() for the whole stale
 * deadline.  The force log is the one line an operator greps for when a Wi-Fi
 * switch left the sysmodule wedged. */
static void forceReleaseStaleSlot(int index, u64 idle_ms) {
    NxusNetSlot *slot = &g_Slots[index];
    NxusNetClient *client = slotClient(index);

    (void)detachClientState(slot, client);
    if (client != NULL) slotSetClient(index, NULL);

    NXUS_LOG(NXUS_NET_LOG_SLOT_STALE_FMT, index, (unsigned long long)idle_ms);
    nxusNetSlotForceReap(slot);
}

/* The accept loop's stale watchdog: shut a slot down when it has completed no I/O
 * for NXUS_NET_SLOT_STALE_NS, wait (bounded) for its thread to leave, and force-
 * release it when it does not.  Runs on the accept thread only, so the slot table
 * cannot change underneath the scan except through a claim from this same thread. */
static void watchStaleSlots(void) {
    const u64 now = ioNowNs();

    for (int i = 0; i < NXUS_NET_MAX_CLIENTS; i++) {
        NxusNetSlot *slot = &g_Slots[i];
        if (!nxusNetSlotIsStale(slot, now)) continue;

        const u64 idle_ms = nxusNetSlotIdleNs(slot, now) / 1000000ull;
        NxusNetClient *client = slotClient(i);

        NXUS_LOG_DEBUG("net: slot %d has had no I/O for %llu ms - shutting it down",
                       i, (unsigned long long)idle_ms);
        if (client != NULL) {
            clientShutdown(client);

            const u64 deadline = armGetSystemTick() +
                                 armNsToTicks((u64)NXUS_NET_SLOT_STALE_WAIT_MS * 1000000ull);
            if (waitClientFinished(client, deadline)) {
                /* The thread left on its own; the normal reaper joins it on the
                 * next pass.  No force release, no leaked state. */
                NXUS_LOG("net: slot %d left after the shutdown - reaping it normally", i);
                continue;
            }
        }

        forceReleaseStaleSlot(i, idle_ms);
    }
}

/* True while any connection slot still owns a serving thread (including a
   finished one that has not been reaped yet; the caller reaps first). */
static bool clientThreadsActive(void) {
    for (int i = 0; i < NXUS_NET_MAX_CLIENTS; i++) {
        if (nxusNetSlotInUse(&g_Slots[i])) return true;
    }
    return false;
}

/* A rebuild replaces the bsd session (socketExit() + socketInitializeDefault()),
 * so every descriptor the old session handed out is invalid afterwards.  The
 * deferred path already waits for the serving threads, which makes this normally a
 * no-op; it is the explicit "the session changed, trust nothing in the slot table"
 * step the rebind requires, and it doubles as a safety net if a slot was claimed
 * between the drain check and here. */
static void clearSlotTableAfterRebuild(void) {
    int cleared = 0;
    for (int i = 0; i < NXUS_NET_MAX_CLIENTS; i++) {
        if (!nxusNetSlotInUse(&g_Slots[i])) continue;
        NxusNetClient *client = slotClient(i);
        if (client != NULL) {
            (void)detachClientState(&g_Slots[i], client);
            slotSetClient(i, NULL);
        }
        nxusNetSlotForceReap(&g_Slots[i]);
        cleared++;
    }
    if (cleared > 0) {
        NXUS_LOG("net: cleared %d slot(s) after the listener rebuild (the old bsd "
                 "session's descriptors are invalid)", cleared);
    }
}

/* Rebuild the listener, but not while a connection thread may still be inside
 * recv()/send()/close(): a full rebuild calls socketExit(), which closes the bsd
 * service session underneath those threads and is undefined behaviour (the old
 * single-threaded server got this for free because the reset was handled after
 * serveClient() had returned).
 *
 * With clients still active the sockets are shut down (so every recv()/poll()
 * wakes and every thread exits at its next slice) and the rebuild is remembered:
 * the accept loop retries it once the last slot has been reaped.  This covers the
 * sleep/wake reset (dead sockets; the 20 s idle deadline has usually expired by
 * the time the console wakes, so the threads leave within one poll slice) and a
 * long handler (a pointer scan), which may take longer but must not have its
 * session pulled from under it. */
static void rebuildOrDefer(bool full_bsd_reset) {
    /* Every old connection belongs to the bsd session that is about to be replaced:
     * wake all of them before the listener is touched, so the deferred path can
     * drain instead of waiting for a 20 s idle deadline. */
    shutdownAllClients("listener rebuild");

    if (clientThreadsActive()) {
        NXUS_LOG("listener: rebuild deferred until the client threads have drained (%s)",
                 full_bsd_reset ? "full bsd reset" : "reopen");
        atomic_store_explicit(&g_RebuildPending, true, memory_order_release);
        return;
    }

    const u64 started = armGetSystemTick();
    rebuildListener(full_bsd_reset);
    if (peekListenFd() < 0) {
        NXUS_LOG("net: bsd session rebuild did not produce a listener - keeping the "
                 "client slots for the next attempt");
        return;
    }

    clearSlotTableAfterRebuild();
    NXUS_LOG("net: rebuilt the bsd session after %llu ms",
             (unsigned long long)(elapsedNs(started, armGetSystemTick()) / 1000000ull));
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

/* Release a slot that was claimed but never got a serving thread, then refuse the
   connection with BUSY.  The slot is released FIRST: while it is still published,
   a broadcast (nxusNetSend) could try to write to the same socket the BUSY frame
   is going to, and the two frames - each header+payload as two sends - would
   interleave on the wire. */
static void rejectClaimedClient(int slot, int fd, const char *peer_text,
                               const char *why, NxusNetClient *client) {
    /* No thread was started for this state object, so releasing it (and the slot)
     * here cannot race a serving thread. */
    slotSetClient(slot, NULL);
    nxusNetSlotReaped(&g_Slots[slot]);
    if (client != NULL) clientStateRelease(client);
    sendBusyAndClose(fd, peer_text, why);
}

/* Claim a slot for `fd`, allocate the thread's stack and receive buffer, and
   start the serving thread.  Every failure path answers the newcomer with BUSY
   and closes it: no slot is left half-claimed. */
static void startClient(int fd, const char *peer_text) {
    const int slot = nxusNetSlotClaim(g_Slots, NXUS_NET_MAX_CLIENTS, fd);
    if (slot < 0) {
        sendBusyAndClose(fd, peer_text, NULL);   /* every slot really is in use */
        return;
    }

    /* A spare state object is what makes a force-released slot reusable while its
     * old thread still exists; refusing BUSY when every object is out is honest
     * (the previous stale threads have not left yet). */
    NxusNetClient *client = clientStateAcquire();
    if (client == NULL) {
        NXUS_LOG("net: no free connection state (every %d object is reserved)",
                 NXUS_NET_CLIENT_STATE_MAX);
        char why[96];
        snprintf(why, sizeof(why), "no free connection state (%d/%d reserved)",
                 NXUS_NET_CLIENT_STATE_MAX, NXUS_NET_CLIENT_STATE_MAX);
        rejectClaimedClient(slot, fd, peer_text, why, NULL);
        return;
    }

    clientSetSlot(client, &g_Slots[slot]);
    clientSetGeneration(client, nxusNetSlotGeneration(clientSlot(client)));
    client->last_rx_tick = armGetSystemTick();
    client->rx_big_tick = 0;
    snprintf(client->peer, sizeof(client->peer), "%s", peer_text);
    /* Accept is I/O: a connection that never sends a byte still gets the full
     * stale window before the watchdog considers it dead. */
    nxusNetSlotTouch(clientSlot(client), ioNowNs());

    /* The stack must be page-aligned for libnx's threadCreate(), hence the
       aligned allocation instead of a plain malloc.  24 KiB is the ship size; the
       historic 32 KiB is retried when the smaller block is refused, so a heap that
       is 8 KiB short still serves the client instead of answering BUSY. */
    u32 stack_size = NXUS_NET_CLIENT_STACK_SIZE;
    u8 *stack = (u8 *)aligned_alloc(0x1000u, stack_size);
    if (stack == NULL) {
        stack_size = NXUS_NET_CLIENT_STACK_FALLBACK_SIZE;
        stack = (u8 *)aligned_alloc(0x1000u, stack_size);
        if (stack != NULL) {
            NXUS_LOG("client: %u KiB thread stack refused - retried with %u KiB "
                     "(free=%u KiB)",
                     (unsigned)(NXUS_NET_CLIENT_STACK_SIZE / 1024u),
                     (unsigned)(stack_size / 1024u), (unsigned)nxusHeapFreeKiB());
        }
    }
    u8 *rx = (u8 *)malloc(NXUS_NET_RX_IDLE_SIZE);
    if (stack == NULL || rx == NULL) {
        /* One greppable line for the symptom this module exists for, then one line
           with the context (peer, which allocation, free heap) from the refusal
           helper.  The newcomer is answered BUSY (NXUS_NET_BUSY_REASON), which every
           shipped client already treats as retryable. */
        NXUS_LOG("net: out of memory for a connection (free=%u KiB)",
                 (unsigned)nxusHeapFreeKiB());
        char why[96];
        snprintf(why, sizeof(why), "no memory for the %u B stack / %u B receive buffer",
                 (unsigned)stack_size, (unsigned)NXUS_NET_RX_IDLE_SIZE);
        free(stack);
        free(rx);
        rejectClaimedClient(slot, fd, peer_text, why, client);
        return;
    }
    nxusHeapLogDebug("net accept");

    Result rc = threadCreate(&client->thread, clientThread, client, stack,
                             stack_size, 0x2C, -2);
    if (R_FAILED(rc)) {
        /* libnx wants -2 (default) or 0..3; anything else is an invalid core id. */
        rc = threadCreate(&client->thread, clientThread, client, stack,
                          stack_size, 0x2C, 3);
    }
    if (R_FAILED(rc)) {
        NXUS_LOG("client: threadCreate failed rc=0x%08X - refusing %s (fd=%d)",
                 (unsigned)rc, peer_text, fd);
        free(stack);
        free(rx);
        rejectClaimedClient(slot, fd, peer_text, "thread creation failed", client);
        return;
    }

    client->stack = stack;
    client->rx = rx;
    client->rx_cap = NXUS_NET_RX_IDLE_SIZE;

    /* Publish the state BEFORE threadStart(): the serving thread may answer its
     * first request immediately, and the send lookup has to find it. */
    slotSetClient(slot, client);

    rc = threadStart(&client->thread);
    if (R_FAILED(rc)) {
        NXUS_LOG("client: threadStart failed rc=0x%08X - refusing %s (fd=%d)",
                 (unsigned)rc, peer_text, fd);
        /* The thread never ran: close the Thread object (it unmaps the stack
           mirror; the backing memory is ours), then the connection. */
        threadClose(&client->thread);
        free(stack);
        client->stack = NULL;
        free(rx);
        client->rx = NULL;
        client->rx_cap = 0;
        rejectClaimedClient(slot, fd, peer_text, "thread start failed", client);
    }
}

static void serverThread(void *arg) {
    (void)arg;
    u64 last_health = armGetSystemTick();

    while (nxusNetRunning()) {
        /* 0. Collect the connections whose serving thread has finished.  Doing it
              here (and not from the serving thread) is what makes the stack free
              safe: the thread has been joined by now. */
        reapFinishedClients();
        reapRetiredClients();

        /* 0b. The stale-slot watchdog.  A Wi-Fi switch can leave a connection
               thread parked in recv()/poll() for ever, owning its slot, so every
               later connection would be refused BUSY.  Runs on every accept-loop
               pass (at most one poll slice apart); see watchStaleSlots(). */
        watchStaleSlots();

        /* 0c. A rebuild that was deferred because a connection thread still used
               the bsd session: run it as soon as the last slot is drained.  Only
               this loop rebuilds the listener, so there is no second caller that
               could slip in between the check and the rebuild. */
        if (atomic_load_explicit(&g_RebuildPending, memory_order_acquire)) {
            if (clientThreadsActive()) {
                svcSleepThread(NXUS_NET_REBUILD_DRAIN_NS);
                continue;
            }
            atomic_store_explicit(&g_RebuildPending, false, memory_order_release);
            NXUS_LOG("listener: client threads drained - rebuilding the bsd session now");
            rebuildOrDefer(true);
            last_health = armGetSystemTick();
            continue;
        }

        /* 1. explicit reset (sleep/wake from main.c, external request).  Every
              connection belongs to the old bsd session, so they are all dropped
              before the listener is rebuilt (or the rebuild is deferred until
              their threads have left - see rebuildOrDefer). */
        if (takeResetRequest()) {
            NXUS_LOG("network reset requested - dropping clients and rebuilding listener");
            rebuildOrDefer(true);
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
            rebuildOrDefer(true);
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
            rebuildOrDefer(true);
            last_health = armGetSystemTick();
            continue;
        }
        if (pfd.revents & (POLLERR | POLLNVAL)) {
            NXUS_LOG("listener: poll reported error (revents=0x%X) - rebuilding",
                     (unsigned)pfd.revents);
            rebuildOrDefer(true);
            last_health = armGetSystemTick();
            continue;
        }
        if (pfd.revents & POLLHUP) {
            NXUS_LOG("listener: poll reported hangup - rebuilding");
            rebuildOrDefer(false);
            last_health = armGetSystemTick();
            continue;
        }

        /* 4. periodic health probe: catches a listener whose kernel object died
              without the socket call itself failing. */
        const u64 now = armGetSystemTick();
        if (elapsedNs(last_health, now) >= NXUS_NET_HEALTH_INTERVAL_NS) {
            last_health = now;
            if (!listenerHealthy()) {
                rebuildOrDefer(true);
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
            rebuildOrDefer(true);
            last_health = armGetSystemTick();
            continue;
        }

        /* A shutdown that raced the accept: the listener is gone and this
           connection was never published anywhere.  Close it here. */
        if (!nxusNetRunning()) {
            close(fd);
            break;
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

        char peer_text[32];
        formatPeer(fd, &peer, peer_text, sizeof(peer_text));

        startClient(fd, peer_text);
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

    /* Boot-time transport measurement point: the listener, the accept thread and
       every later connection allocate from the shared 8 MiB heap (nxus_heap.h). */
    nxusHeapLogDebug("net init");

    mutexInit(&g_ListenMutex);
    for (int i = 0; i < NXUS_NET_MAX_CLIENTS; i++) {
        nxusNetSlotReset(&g_Slots[i]);
        slotSetClient(i, NULL);
    }
    for (int i = 0; i < NXUS_NET_CLIENT_STATE_MAX; i++) {
        NxusNetClient *client = &g_ClientStates[i];
        /* Never NULL: a stale send path may still hold this pointer (see
           clientStateRelease()).  startClient() repoints it to the claimed slot. */
        clientSetSlot(client, &g_Slots[i % NXUS_NET_MAX_CLIENTS]);
        clientSetGeneration(client, 0);
        client->retired_fd = -1;
        client->rx = NULL;
        client->rx_cap = 0;
        client->stack = NULL;
        client->last_rx_tick = 0;
        client->rx_big_tick = 0;
        client->peer[0] = '\0';
        atomic_store_explicit(&client->reserved, false, memory_order_relaxed);
        atomic_store_explicit(&client->zombie, false, memory_order_relaxed);
        atomic_store_explicit(&client->finished, false, memory_order_relaxed);
        mutexInit(&client->send_lock);
    }
    atomic_store_explicit(&g_TableReady, true, memory_order_release);
    /* No rebuild can be pending in a fresh lifetime (the previous Exit joined or
       abandoned the accept thread that would have performed it). */
    atomic_store_explicit(&g_RebuildPending, false, memory_order_release);
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
        atomic_store_explicit(&g_TableReady, false, memory_order_release);
        return rc;
    }
    NXUS_LOG("socketInitializeDefault ok");

    atomic_store_explicit(&g_Running, true, memory_order_release);
    if (!createListenerSocket()) {
        atomic_store_explicit(&g_Running, false, memory_order_release);
        atomic_store_explicit(&g_TableReady, false, memory_order_release);
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
        atomic_store_explicit(&g_TableReady, false, memory_order_release);
        /* No server thread exists yet, so this is a plain claim+close. */
        const int listen_fd = takeListenFd();
        if (listen_fd >= 0) close(listen_fd);
        socketExit();
        return rc;
    }
    threadStart(&g_ServerThread);

    NXUS_LOG("listening on 0.0.0.0:%u (up to %d clients)", (unsigned)g_Port,
             NXUS_NET_MAX_CLIENTS);
    return 0;
}

void nxusNetRequestReset(const char *reason) {
    NXUS_LOG("network reset requested from outside (%s)", (reason != NULL) ? reason : "?");

    if (!atomic_load_explicit(&g_TableReady, memory_order_acquire)) return;

    /* Release store: the accept thread's exchange() is the only consumer, so the
       request is applied exactly once even if it lands mid-poll. */
    atomic_store_explicit(&g_ResetRequested, true, memory_order_release);

    /* Also wake the connection threads if they are blocked in recv(): shutdown()
       makes poll() report the hangup instead of waiting for the next slice.  Each
       connection's thread stays the owner of the close(), so this only shuts the
       sockets down.  The shutdown runs under the connection's send lock, which is
       also the lock every close takes, so the number cannot be closed and recycled
       into a new client while this runs.  Try-lock keeps this non-blocking for
       its callers (HID/UI threads) even while a 1 MiB reply is being written; a
       missed shutdown only costs one 200 ms poll slice, since the atomic flag
       above is what actually drives the reset. */
    for (int i = 0; i < NXUS_NET_MAX_CLIENTS; i++) {
        if (!nxusNetSlotInUse(&g_Slots[i])) continue;
        NxusNetClient *client = slotClient(i);
        if (client == NULL) continue;
        if (!mutexTryLock(&client->send_lock)) continue;
        /* Generation-checked: a state object detached by the stale watchdog must
         * not shut down the descriptor of the connection that reused its slot. */
        if (nxusNetSlotGeneration(clientSlot(client)) == clientGeneration(client)) {
            const int fd = nxusNetSlotFd(clientSlot(client));
            if (fd >= 0) shutdown(fd, SHUT_RDWR);
        }
        mutexUnlock(&client->send_lock);
    }
}

/* Wait (bounded) for serverThread() to raise g_ServerDone.
 *
 * libnx's threadWaitForExit() has no timeout parameter, and a connection thread
 * may sit inside a long handler (ptrscan is ~90 s), so an unconditional join made
 * __appExit() block for minutes.  Polling the done flag in 10 ms steps caps that
 * at the deadline: true means the thread already finished (or is finishing, so
 * threadWaitForExit() returns immediately), false means the deadline expired. */
static bool waitServerThreadDone(u64 deadline) {
    while (!atomic_load_explicit(&g_ServerDone, memory_order_acquire)) {
        if (armGetSystemTick() >= deadline) return false;
        svcSleepThread(NXUS_NET_EXIT_POLL_NS);
    }
    return true;
}

/* Wait (bounded) for one connection's serving thread to publish that it is done.
 * `finished` is the thread's last statement, so a successful wait means the
 * Thread can be joined and its stack freed without racing the handler. */
static bool waitClientDone(NxusNetClient *client, u64 deadline) {
    return waitClientFinished(client, deadline);
}

/* ---- teardown ------------------------------------------------------------
 *
 * nxusNetExit() runs as __appExit() is about to end the process, but it must not
 * block it: a connection thread can be parked inside a long handler (a pointer
 * scan runs ~90 s) and libnx has no timed join, so the wait is a 2 s budget - for
 * the accept thread AND for all connection threads together - and a thread is
 * *abandoned* past that deadline.
 *
 * What is released therefore depends on whether the thread actually stopped
 * (nxusNetExit() implements exactly this table):
 *
 *   object                   thread joined in time      deadline expired
 *   -----------------------  -------------------------  ---------------------------
 *   accept Thread handle     threadClose()              LEFT OPEN - the thread is
 *                                                       still running (process exit
 *                                                       reclaims it)
 *   client Thread handles    threadClose() each         LEFT OPEN (same reason)
 *   client stacks            free()                     LEFT ALLOCATED - the thread
 *                                                       runs on that stack
 *   client rx buffers        freed by the thread        LEFT ALLOCATED - the thread
 *                                                       may still recv() into it
 *   client sockets (fd)      already closed by thread  claim -> close (after the
 *                            or claimed/closed here     phase-1 shutdown)
 *   listener socket (fd)     claim -> close             claim -> close (after the
 *                                                       phase-1 shutdown)
 *   bsd session (socketExit) socketExit()               LEFT OPEN - socketExit() while
 *                                                       a thread is alive is
 *                                                       undefined behaviour (logged)
 *
 * Closing the sockets on the deadline path is safe because all of them were
 * shutdown() first and because every close is taken under the connection's send
 * lock (listener: the listener lock): the exit path and the owning thread can
 * race, but only one of them ever closes a given number, so the close can never
 * land on a socket that recycled it.
 *
 * Reaping a finished connection slot is only done when the accept thread was
 * joined too: while it may still be running it is the one reaper, and joining the
 * same Thread from two threads would free its stack twice.
 *
 * This is a one-way door: after an abandoned exit, nxusNetInit() must not be
 * called while the old threads (and their bsd session) are still alive - it would
 * share g_ServerThread/g_ServerDone and re-initialise a live bsd session.  The
 * single boot-then-exit lifecycle in main.c guarantees that.
 */
void nxusNetExit(void) {
    if (!nxusNetRunning()) return;
    nxusHeapLogDebug("net exit");
    atomic_store_explicit(&g_Running, false, memory_order_release);
    /* No new frame may be queued from here on: nxusNetSend()/SendFd() refuse
       before they touch a slot or take a send lock the teardown is about to
       use. */
    atomic_store_explicit(&g_TableReady, false, memory_order_release);

    const u64 deadline = armGetSystemTick() +
                         armNsToTicks((u64)NXUS_NET_EXIT_WAIT_MS * 1000000ull);

    /* Phase 1 - stop the I/O.  Every descriptor is shut down (never closed) under
       its own lock, which is also the lock every close takes: while it is held the
       number cannot be recycled, so the shutdown hits its own socket and not one
       that replaced it.  This wakes every thread out of poll()/recv()/accept()
       immediately instead of at its next slice, and it is the precondition for
       phase 4 closing the descriptors. */
    for (int i = 0; i < NXUS_NET_MAX_CLIENTS; i++) {
        if (!nxusNetSlotInUse(&g_Slots[i])) continue;
        NxusNetClient *client = slotClient(i);
        if (client != NULL) clientShutdown(client);
    }
    mutexLock(&g_ListenMutex);
    const int listen_fd = peekListenFd();
    if (listen_fd >= 0) shutdown(listen_fd, SHUT_RDWR);
    mutexUnlock(&g_ListenMutex);

    /* Phase 2 - bounded join of the accept thread.  Join it first: it is the
       reaper, so the client slots must not be touched until it is gone. */
    const bool server_joined = waitServerThreadDone(deadline);
    if (server_joined) {
        /* The flag is the thread's last statement, so this cannot block for long. */
        threadWaitForExit(&g_ServerThread);
        threadClose(&g_ServerThread);
    } else {
        NXUS_LOG_ERROR("net exit: accept thread still busy after %u ms - abandoning the join",
                       (unsigned)NXUS_NET_EXIT_WAIT_MS);
    }

    /* Phase 3 - bounded join of every connection thread.  Only after the accept
       thread is gone: it joins finished slots itself, and a second join of the
       same Thread would free its stack twice. */
    bool all_clients_joined = true;
    if (server_joined) {
        for (int i = 0; i < NXUS_NET_MAX_CLIENTS; i++) {
            if (!nxusNetSlotInUse(&g_Slots[i])) continue;
            NxusNetClient *client = slotClient(i);
            if (client == NULL) {
                nxusNetSlotReaped(&g_Slots[i]);
                continue;
            }

            if (!waitClientDone(client, deadline)) {
                all_clients_joined = false;
                NXUS_LOG_ERROR("net exit: client fd=%d still busy - abandoning its thread "
                               "(stack=%p rx=%p left to process exit)",
                               nxusNetSlotFd(clientSlot(client)), (void *)client->stack,
                               (void *)client->rx);
                continue;
            }
            threadWaitForExit(&client->thread);
            threadClose(&client->thread);
            free(client->stack);
            client->stack = NULL;
            /* serveClient()/clientThread() already freed it before `done`. */
            free(client->rx);
            client->rx = NULL;
            client->rx_cap = 0;
            slotSetClient(i, NULL);
            nxusNetSlotReaped(&g_Slots[i]);
            clientStateRelease(client);
        }

        /* Force-released state objects live outside the slot table.  Join the ones
           whose thread has left (and close the descriptor the watchdog took out of
           the slot); a thread that is still running keeps everything - including
           its descriptor - to process exit. */
        for (int i = 0; i < NXUS_NET_CLIENT_STATE_MAX; i++) {
            NxusNetClient *client = &g_ClientStates[i];
            if (!atomic_load_explicit(&client->reserved, memory_order_acquire)) continue;
            if (!atomic_load_explicit(&client->zombie, memory_order_acquire)) continue;

            if (!waitClientDone(client, deadline)) {
                all_clients_joined = false;
                NXUS_LOG_ERROR("net exit: retired connection state %d still busy - "
                               "leaving it (and fd=%d) to process exit",
                               i, client->retired_fd);
                continue;
            }
            threadWaitForExit(&client->thread);
            threadClose(&client->thread);
            free(client->stack);
            client->stack = NULL;
            free(client->rx);
            client->rx = NULL;
            client->rx_cap = 0;
            if (client->retired_fd >= 0) {
                close(client->retired_fd);
                client->retired_fd = -1;
            }
            clientStateRelease(client);
        }
    } else {
        /* The accept thread may still be reaping a slot; leave every client
           resource alone and only shut the sockets down (already done). */
        all_clients_joined = false;
    }

    /* Phase 4 - descriptors, on both paths.  After a joined thread the slot is
       stable and its fd is -1 (the thread closed it); whatever is left belongs to
       an abandoned thread that was shut down in phase 1, so closing it here cannot
       land on a live socket. */
    for (int i = 0; i < NXUS_NET_MAX_CLIENTS; i++) {
        if (!nxusNetSlotInUse(&g_Slots[i])) continue;
        NxusNetClient *client = slotClient(i);
        int fd = -1;
        if (client != NULL) {
            fd = clientTakeFd(client);
        } else {
            fd = nxusNetSlotFd(&g_Slots[i]);
            if (fd >= 0) nxusNetSlotClearFd(&g_Slots[i]);
        }
        if (fd >= 0) close(fd);
    }
    mutexLock(&g_ListenMutex);
    const int claimed_listen = claimListenFd(peekListenFd());
    if (claimed_listen >= 0) close(claimed_listen);
    mutexUnlock(&g_ListenMutex);

    /* Phase 5 - only safe once every thread is really gone (see the table above). */
    if (!server_joined || !all_clients_joined) {
        NXUS_LOG("net exit: bsd session left to process exit (socketExit() would run "
                 "while a thread still uses it); abandoned thread resources and handles "
                 "are left to process exit as well");
        return;
    }

    socketExit();
}

bool nxusNetIsRunning(void) { return nxusNetRunning(); }
