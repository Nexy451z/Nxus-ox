/*
 * Nxus TCP transport.
 *
 * CONNECTION MODEL
 * ----------------
 * The listener is served by one accept thread; every accepted connection gets
 * its OWN thread and its OWN receive buffer, up to NXUS_NET_MAX_CLIENTS (4)
 * concurrent clients.  A fifth connection (or one accepted while no thread can
 * be created) is answered with the BUSY frame nxusNetFillBusyPayload() describes
 * and closed immediately, so the PC clients see a retryable refusal instead of a
 * silent reset.  There is no preemption any more: a live session is never cut by
 * a newcomer, and a newcomer is never refused just because somebody else is
 * connected.
 *
 * Sends are serialised per connection (one mutex per slot) because the reply
 * thread, the watchdog, the debug/cheat workers and the HID thread all write to
 * the sockets.  nxusNetSendFd() writes to the one connection the handler was
 * called for; nxusNetSend()/nxusNetSendEvent() broadcast to every connected
 * client (async events are not addressed to one session).
 *
 * MEMORY
 * ------
 * A receive buffer is allocated when the connection is accepted:
 * NXUS_NET_RX_IDLE_SIZE (32 KiB) up front.  It grows on demand - and only up to
 * the frame being received - to at most NXUS_NET_BUF_SIZE (1 MiB, the protocol's
 * largest allowed payload).  A connection that has not needed a frame larger than
 * the idle size for NXUS_NET_RX_SHRINK_IDLE_NS is shrunk back to 32 KiB again
 * (heartbeats count as activity, but they do not keep a large buffer alive).
 * The transport therefore never holds more
 * than NXUS_NET_MAX_CLIENTS * NXUS_NET_BUF_SIZE = 4 MiB of receive buffers (plus
 * NXUS_NET_MAX_CLIENTS * NXUS_NET_CLIENT_STACK_SIZE = 96 KiB of thread stacks),
 * and normally holds 4 * 32 KiB = 128 KiB.  The idle buffer used to be 128 KiB and
 * the stack 32 KiB - 160 KiB resident per connection against a shared 8 MiB heap
 * (see nxus_heap.h).  Nothing in a session needs a large buffer until a large
 * frame actually arrives, so the idle size is now 32 KiB, and the connection stack
 * is 24 KiB (page aligned, as threadCreate() requires) with the historic 32 KiB
 * kept as the retry when the smaller allocation is refused.
 *
 * A frame whose payload cannot be accommodated (allocation failed, or above
 * NXUS_NET_BUF_SIZE) is refused with BAD_STATE + NXUS_REASON_BAD_LENGTH and the
 * connection is dropped, because the unread payload would desync the stream; the
 * failure is logged with the free heap.  A connection whose stack or receive
 * buffer cannot be allocated at all is answered BUSY (NXUS_REASON_BUSY_STATE) and
 * logged as "net: out of memory for a connection (free=... KiB)" instead of
 * failing silently.  This keeps the shared 8 MiB heap bounded and makes an
 * allocation failure a clean, visible refusal rather than an out-of-memory abort.
 *
 * THREADING CONTRACT FOR THE HANDLER
 * ----------------------------------
 * NxusNetHandler runs on the connection's own thread.  Several handlers may run
 * concurrently (one per client); the dispatcher serialises the mutating commands
 * itself (see switch/include/nxus_server.h).  A handler must only use the `fd`
 * it was given for replies - the session is no longer "the one client".
 *
 * NxusNetCloseHandler runs once per served connection after the handler loop
 * ends, on that connection's thread, after the descriptor has been unregistered
 * (no sender can reach it any more) but before it is closed, so the number is
 * still unique.  It must not block for long: nxusNetExit() waits at most
 * NXUS_NET_EXIT_WAIT_MS for the client threads.
 *
 * SHUTDOWN
 * --------
 * nxusNetExit() stops accepting, shuts every socket down, then joins the accept
 * thread and every client thread within NXUS_NET_EXIT_WAIT_MS in total.  A
 * thread that does not finish in that window (typically one parked in a 90 s
 * pointer scan) is deliberately abandoned: its stack, rx buffer, Thread handle
 * and socket are left to process exit.  That is the same "leak, never UAF" rule
 * the single-session server used, and it is why nxusNetInit() must not be called
 * again while such a thread may still be alive.
 */
#pragma once

#include <stdbool.h>
#include <stdatomic.h>

#ifdef __SWITCH__
#include <switch.h>
#endif
#include "nxus_protocol.h"

#ifndef __SWITCH__
/* Host tests include this header (tests/test_server_logic.c) to pin the
   connection-slot policy against the SHIPPED helpers.  libnx's Result is a u32
   and nothing else here needs the console's <switch.h>; redeclaring an identical
   typedef is legal C11, so a test that also includes the libnx stub header keeps
   compiling. */
typedef u32 Result;
#endif

/* Largest payload a single frame may carry, in either direction.  This is also
   the ceiling a connection's receive buffer may grow to (see MEMORY above). */
#define NXUS_NET_BUF_SIZE (1024u * 1024u)

/* Concurrent connections the server serves.  Slots beyond this are refused with
   BUSY; the count is fixed so the memory ceiling above is a compile-time one. */
#define NXUS_NET_MAX_CLIENTS 4

/* Per-connection thread stack (heap, page-aligned: libnx threadCreate() requires
   page-aligned memory).  24 KiB is enough for the deepest handler (the old single
   connection thread ran on 32 KiB and the per-connection call path did not get
   deeper with multi-client), and it is the first allocation attempted for a new
   connection because it is the one a nearly full heap refuses first. */
#define NXUS_NET_CLIENT_STACK_SIZE (24u * 1024u)

/* Retry size when the 24 KiB stack cannot be allocated.  The historic 32 KiB is
   used then, so a future deeper handler degrades the heap by 8 KiB per connection
   instead of refusing the client outright. */
#define NXUS_NET_CLIENT_STACK_FALLBACK_SIZE (32u * 1024u)

/* Every accepted connection starts with this receive buffer and is shrunk back
   to it once idle; a frame that needs more grows it on demand.  32 KiB instead of
   the previous 128 KiB: the first big frame (a cheat upload, a hit page) grows the
   buffer exactly when it is needed, while four idle clients cost 128 KiB instead
   of 512 KiB of the shared heap. */
#define NXUS_NET_RX_IDLE_SIZE (32u * 1024u)

/* How long a connection may go without needing a frame larger than
   NXUS_NET_RX_IDLE_SIZE before its enlarged receive buffer is shrunk back to the
   idle size.  Long enough not to churn on a client that is merely thinking,
   short enough that four normally-active clients cost 128 KiB, not 4 MiB. */
#define NXUS_NET_RX_SHRINK_IDLE_NS 30000000000ull

/* Reason word appended to the BUSY reply sent to a refused connection.
   core/nxus_protocol.h has no dedicated "all client slots are in use" code (the
   protocol header is the wire single source of truth and is not changed here), so
   reuse BUSY_STATE - the retryable "the session is busy" reason that every
   existing client already understands.  The same reason answers a connection whose
   thread stack / receive buffer cannot be allocated: "busy, retry" is right from
   the client's side in both cases, and the log line names which of the two it was
   (NXUS_NET_LOG_BUSY_FMT for a full server, the "out of memory for a connection"
   line for an allocation failure). */
#define NXUS_NET_BUSY_REASON NXUS_REASON_BUSY_STATE

/* Log wording for a refused connection.  Exposed so the host test can pin the
   exact strings an operator greps for in the console log. */
#define NXUS_NET_LOG_BUSY_FMT \
    "client busy: refused new connection from %s (fd=%d) - all %d client slots are in use"

/* BUSY reply payload: s32 Result followed by one u32 reason, the same shape
   replyErrorReason() in switch/source/nxus_server.c emits.  There is no request
   to correlate with (the connection is refused before its first command), so the
   frame carries NxusCmd_Nop/seq 0; a raw client reads the Result directly, while
   a seq-correlating client (the shipped PC clients) reports the close. */
static inline void nxusNetFillBusyPayload(s32 out[2]) {
    out[0] = (s32)NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
    out[1] = (s32)NXUS_NET_BUSY_REASON;
}

/* ---- connection slots ----------------------------------------------------
 *
 * The slot table is the ONE decision point for "may this connection be served?":
 * the accept thread claims a free slot before it creates the client thread, the
 * serving thread marks the slot finished as its very last action, and the accept
 * thread (or nxusNetExit()) reaps finished slots - joins the thread, frees the
 * stack and only then makes the slot claimable again.
 *
 * A finished slot is therefore NOT free: its Thread handle and stack are still
 * owned until the reaper has joined it.  That is what nxusNetSlotReapable() and
 * the in_use/done split express, and it is the property the host test pins.
 *
 * The helpers are static inline so tests/test_server_logic.c exercises the
 * shipped policy instead of a copy.  They are lock-free atomic because the send
 * path reads `fd` without the table lock and the exit path reads the table while
 * the accept thread may still be running.
 */
typedef struct {
    atomic_int  fd;      /* -1 = free, else the connected client descriptor      */
    atomic_bool in_use;  /* a serving thread owns (or is starting in) this slot  */
    atomic_bool done;    /* the serving thread has finished; reapable once in_use */
} NxusNetSlot;

static inline void nxusNetSlotReset(NxusNetSlot *slot) {
    atomic_store_explicit(&slot->fd, -1, memory_order_relaxed);
    atomic_store_explicit(&slot->in_use, false, memory_order_relaxed);
    atomic_store_explicit(&slot->done, false, memory_order_relaxed);
}

static inline int nxusNetSlotFd(const NxusNetSlot *slot) {
    return atomic_load_explicit(&slot->fd, memory_order_acquire);
}

/* Unregister the descriptor without closing it: every sender that looks the
   connection up afterwards refuses, while the number stays unique (it is not
   closed yet), so the close handler can still name this connection by fd. */
static inline void nxusNetSlotClearFd(NxusNetSlot *slot) {
    atomic_store_explicit(&slot->fd, -1, memory_order_release);
}

/* The serving thread's last action.  fd goes to -1 first (no more sends), then
   done is published: this is the release store the reaper's acquire sees, so
   "done == true" also means "rx buffer already released, thread about to exit". */
static inline void nxusNetSlotFinish(NxusNetSlot *slot) {
    atomic_store_explicit(&slot->fd, -1, memory_order_relaxed);
    atomic_store_explicit(&slot->done, true, memory_order_release);
}

static inline bool nxusNetSlotInUse(const NxusNetSlot *slot) {
    return atomic_load_explicit(&slot->in_use, memory_order_acquire);
}

static inline bool nxusNetSlotDone(const NxusNetSlot *slot) {
    return atomic_load_explicit(&slot->done, memory_order_acquire);
}

/* Finished AND still owned: the reaper may join this slot. */
static inline bool nxusNetSlotReapable(const NxusNetSlot *slot) {
    return nxusNetSlotInUse(slot) && nxusNetSlotDone(slot);
}

/* Claim a free slot for `fd` and return its index, or -1 when every slot is in
 * use (or merely waiting to be reaped).  The CAS on in_use is the claim; the
 * fields are written after it, and a slot is only ever claimable in the clean
 * state nxusNetSlotReset()/nxusNetSlotReaped() leave behind (fd -1, done false). */
static inline int nxusNetSlotClaim(NxusNetSlot *slots, int count, int fd) {
    for (int i = 0; i < count; i++) {
        NxusNetSlot *slot = &slots[i];
        bool expected = false;
        if (!atomic_compare_exchange_strong_explicit(&slot->in_use, &expected, true,
                                                     memory_order_acq_rel,
                                                     memory_order_acquire)) {
            continue;
        }
        atomic_store_explicit(&slot->done, false, memory_order_relaxed);
        atomic_store_explicit(&slot->fd, fd, memory_order_release);
        return i;
    }
    return -1;
}

/* The reaper's last action: release the slot for a later connection.  Only valid
   once the thread has been joined and its stack freed (see nxusNetSlotReapable). */
static inline void nxusNetSlotReaped(NxusNetSlot *slot) {
    atomic_store_explicit(&slot->fd, -1, memory_order_relaxed);
    atomic_store_explicit(&slot->done, false, memory_order_relaxed);
    atomic_store_explicit(&slot->in_use, false, memory_order_release);
}

/* Slots that could accept a new connection right now.  Used for the BUSY log and
   by the host test; a finished-but-unreaped slot does not count as free. */
static inline int nxusNetSlotFreeCount(const NxusNetSlot *slots, int count) {
    int free_count = 0;
    for (int i = 0; i < count; i++) {
        if (!nxusNetSlotInUse(&slots[i])) free_count++;
    }
    return free_count;
}

typedef void (*NxusNetHandler)(int fd, const NxusPacketHeader *header,
                               const u8 *payload, u32 length, void *user);

/* Called once per served connection, on its thread, after its descriptor has
   been unregistered and before it is closed.  Optional. */
typedef void (*NxusNetCloseHandler)(int fd, void *user);

Result nxusNetInit(u16 port, NxusNetHandler handler, void *user);
void   nxusNetExit(void);
bool   nxusNetIsRunning(void);

/* Install the per-connection close hook (nxusNetInit() can be called before or
   after this; the hook is transport state, not connection state). */
void   nxusNetSetCloseHandler(NxusNetCloseHandler handler, void *user);

/* Descriptor of one connected client, or -1 when nobody is connected.  Intended
   for status/logging and the "is any client connected?" loops, NOT as the source
   of a send target: a value read here can be closed and its descriptor number
   recycled into a new client before the write starts.  The send helpers take the
   lock first and read the registered descriptor themselves. */
int    nxusNetClientFd(void);

/* Number of connected clients (0..NXUS_NET_MAX_CLIENTS). */
int    nxusNetClientCount(void);

/* armGetSystemTick() of the last packet byte received or of the last complete
   send.  The main loop uses this to tell a real sleep/wake (no traffic for a long
   time) from a long handler that merely starved the watchdog thread. */
u64    nxusNetLastActivityTick(void);

/* Thread-safe.  Returns an error if no client is connected or the write fails.
   `fd` must be the client the packet handler was called for: it is validated
   against the registered slot under the send lock, so a stale (closed and
   recycled) number is refused instead of being written to another session. */
Result nxusNetSendFd(int fd, u16 type, u16 flags, u32 seq, const void *payload, u32 length);
/* Broadcast: sends to every connected client and succeeds when at least one
   received the frame.  This is the path for asynchronous events. */
Result nxusNetSend(u16 type, u16 flags, u32 seq, const void *payload, u32 length);

/* Convenience: empty success response / error response for a request seq. */
Result nxusNetSendAck(u32 seq);
Result nxusNetSendError(u32 seq, Result rc);

/* Send an asynchronous event (flags = NXUS_FLAG_ASYNC, seq = 0) to every client. */
Result nxusNetSendEvent(u16 type, const void *payload, u32 length);

/* Send a response, splitting large payloads is the caller's problem for now. */
Result nxusNetRespond(u32 seq, const void *payload, u32 length);

/* Ask the server thread to drop every client and rebuild the listener from
 * scratch (sleep/wake, Wi-Fi rejoin, any other stale-bsd situation).  The flag is
 * picked up by the accept thread within one poll slice (~200 ms), so the call is
 * safe from any thread and never blocks.  The bsd session itself is only torn
 * down once every connection thread has left its socket, so a thread parked in a
 * long handler defers the rebuild instead of having its session pulled from under
 * it.  `reason` only shows up in the log. */
void   nxusNetRequestReset(const char *reason);
