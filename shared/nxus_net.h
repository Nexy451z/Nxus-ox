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

/* A connection that has completed no read AND no write for this long is treated
 * as dead.  A healthy PC client heartbeats every 4 s, so this only fires on the
 * situations that used to leave a slot stuck forever: the Wi-Fi link changed
 * under the sysmodule, the peer vanished without a FIN, or a connection thread
 * is parked in recv()/poll() on a descriptor the old bsd session will never
 * signal again.  The value is deliberately short enough that a reconnect after a
 * network switch is served within half a minute, and long enough that an idle
 * client (which still heartbeats) is never touched. */
#define NXUS_NET_SLOT_STALE_NS 30000000000ull

/* After shutdown() of a stale slot, how long the accept loop waits for its
 * serving thread to publish `finished` before force-releasing the slot.  One
 * second is far more than a thread parked in a 200 ms poll() slice needs and
 * still bounds the accept loop's own stall. */
#define NXUS_NET_SLOT_STALE_WAIT_MS 1000u

/* Granularity of that bounded wait.  Matches the exit path's poll interval. */
#define NXUS_NET_SLOT_STALE_POLL_NS 10000000ull

/* Pinned log wording for a slot the watchdog had to force-release.  Exposed so
 * the host test can assert the exact line an operator greps for. */
#define NXUS_NET_LOG_SLOT_STALE_FMT \
    "net: slot %d stale after %llu ms - force-releasing it"

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
 * STALE WATCHDOG
 * --------------
 * A Wi-Fi switch or a half-open link can leave a serving thread parked in
 * recv()/poll() for ever: the thread owns its slot, so every later connection is
 * answered BUSY and the module only recovers with a restart.  Every slot
 * therefore carries the monotonic nanosecond stamp of its last completed I/O
 * (updated on accept, recv and send).  The accept loop treats a slot with no I/O
 * for NXUS_NET_SLOT_STALE_NS as dead, shuts its socket down, waits at most
 * NXUS_NET_SLOT_STALE_WAIT_MS for the thread to leave and otherwise force-releases
 * the slot so a reconnect can be served (see nxusNetSlotForceReap()).
 *
 * A force-released thread may still be alive (parked in a long handler, or not
 * yet scheduled), so its stack, receive buffer, Thread handle and descriptor are
 * deliberately leaked rather than freed under it.  Every claim bumps the slot's
 * 31-bit generation, and finish()/take are CAS operations against the generation
 * the thread was given: a late action from the old thread therefore cannot clear
 * the new owner's descriptor or mark it done.  That is the property that makes
 * "force-release and reuse" safe instead of a use-after-free.
 *
 * The helpers are static inline so tests/test_server_logic.c exercises the
 * shipped policy instead of a copy.  They are lock-free atomic because the send
 * path reads `fd` without the table lock and the exit path reads the table while
 * the accept thread may still be running.
 */
/* All per-slot mutable state lives in one 64-bit token plus two atomics:
 *
 *   bits 63..33  generation (31 bits, bumped by every claim/reap)
 *   bit  32      done flag  (published by the serving thread)
 *   bits 31..0   descriptor, 0xFFFFFFFF when unregistered
 *
 * `in_use` is the claim ownership bit, and `last_io_ns` is the monotonic
 * nanosecond stamp of the last completed read/write (or the accept).  Keeping
 * generation + done + fd in ONE atomic word is what makes a force-release safe:
 * the old serving thread's finish() is a CAS against its own generation, so it
 * either publishes "done" before the slot is reused or fails and leaves the new
 * owner's descriptor alone.  A separate done flag had a window where a late
 * finish from the old generation could mark the new connection finished. */
typedef struct {
    atomic_bool          in_use;
    atomic_uint_fast64_t token;
    atomic_uint_fast64_t last_io_ns;
} NxusNetSlot;

#define NXUS_NET_SLOT_NO_FD          ((u32)0xFFFFFFFFu)
#define NXUS_NET_SLOT_DONE_FLAG      (1ull << 32)
#define NXUS_NET_SLOT_GENERATION_MASK 0x7FFFFFFFu

/* Pack a token.  `done` is cleared by every claim, so the only way it becomes
   true is nxusNetSlotFinishGeneration() for the current generation. */
static inline u64 nxusNetSlotMakeToken(u32 generation, bool done, int fd) {
    return ((u64)(generation & NXUS_NET_SLOT_GENERATION_MASK) << 33) |
           (done ? NXUS_NET_SLOT_DONE_FLAG : 0ull) |
           (u64)(u32)(s32)fd;
}

static inline u64 nxusNetSlotToken(const NxusNetSlot *slot) {
    return atomic_load_explicit(&slot->token, memory_order_acquire);
}

static inline void nxusNetSlotReset(NxusNetSlot *slot) {
    atomic_store_explicit(&slot->in_use, false, memory_order_relaxed);
    atomic_store_explicit(&slot->token, nxusNetSlotMakeToken(0, false, -1),
                          memory_order_relaxed);
    atomic_store_explicit(&slot->last_io_ns, 0, memory_order_relaxed);
}

static inline int nxusNetSlotFd(const NxusNetSlot *slot) {
    return (int)(s32)(u32)(nxusNetSlotToken(slot) & 0xFFFFFFFFull);
}

static inline u32 nxusNetSlotGeneration(const NxusNetSlot *slot) {
    return (u32)(nxusNetSlotToken(slot) >> 33);
}

static inline bool nxusNetSlotDone(const NxusNetSlot *slot) {
    return (nxusNetSlotToken(slot) & NXUS_NET_SLOT_DONE_FLAG) != 0ull;
}

static inline bool nxusNetSlotInUse(const NxusNetSlot *slot) {
    return atomic_load_explicit(&slot->in_use, memory_order_acquire);
}

/* ---- I/O clock / stale policy ------------------------------------------ */

/* Stamp a completed read/write or the accept.  `now_ns` is a monotonic
   nanosecond value (armTicksToNs(armGetSystemTick()) on the console); 0 means
   "not stamped yet" and is never considered stale. */
static inline void nxusNetSlotTouch(NxusNetSlot *slot, u64 now_ns) {
    atomic_store_explicit(&slot->last_io_ns, now_ns, memory_order_relaxed);
}

static inline u64 nxusNetSlotLastIoNs(const NxusNetSlot *slot) {
    return atomic_load_explicit(&slot->last_io_ns, memory_order_acquire);
}

/* Nanoseconds since the last stamped I/O, clamped to 0 for a slot that has no
   stamp yet or for a clock that went backwards. */
static inline u64 nxusNetSlotIdleNs(const NxusNetSlot *slot, u64 now_ns) {
    const u64 last = nxusNetSlotLastIoNs(slot);
    if (last == 0 || now_ns <= last) return 0;
    return now_ns - last;
}

/* A claimed, unfinished slot with no I/O for NXUS_NET_SLOT_STALE_NS (at least;
   the deadline itself counts as stale).  A free slot, a finished slot (waiting
   for its reap) and a freshly claimed slot without a stamp are never stale. */
static inline bool nxusNetSlotIsStale(const NxusNetSlot *slot, u64 now_ns) {
    if (!nxusNetSlotInUse(slot)) return false;
    if (nxusNetSlotDone(slot)) return false;
    if (nxusNetSlotFd(slot) < 0) return false;
    if (nxusNetSlotLastIoNs(slot) == 0) return false;
    return nxusNetSlotIdleNs(slot, now_ns) >= NXUS_NET_SLOT_STALE_NS;
}

/* ---- descriptor ownership ---------------------------------------------- */

/* Unregister the descriptor without closing it, preserving the generation and
   done bit.  Kept for the simple "no more sends" step; the generation-aware
   executor is nxusNetSlotTakeFd() below. */
static inline void nxusNetSlotClearFd(NxusNetSlot *slot) {
    u64 token = nxusNetSlotToken(slot);
    for (;;) {
        const u64 desired = (token & ~0xFFFFFFFFull) | (u64)NXUS_NET_SLOT_NO_FD;
        if (atomic_compare_exchange_strong_explicit(&slot->token, &token, desired,
                                                    memory_order_acq_rel,
                                                    memory_order_acquire)) {
            return;
        }
    }
}

/* Atomically unregister `fd` when this generation still owns it; returns the
 * descriptor the caller now owns (and must close), or -1 when the slot already
 * belongs to another generation (force-released and reused) or is empty. */
static inline int nxusNetSlotTakeFd(NxusNetSlot *slot, u32 generation) {
    u64 token = nxusNetSlotToken(slot);
    for (;;) {
        if ((u32)(token >> 33) != (generation & NXUS_NET_SLOT_GENERATION_MASK))
            return -1;
        const int fd = (int)(s32)(u32)(token & 0xFFFFFFFFull);
        if (fd < 0) return -1;
        const u64 desired = (token & ~0xFFFFFFFFull) | (u64)NXUS_NET_SLOT_NO_FD;
        if (atomic_compare_exchange_strong_explicit(&slot->token, &token, desired,
                                                    memory_order_acq_rel,
                                                    memory_order_acquire)) {
            return fd;
        }
    }
}

/* The serving thread's last published action for its generation: sets done and
 * drops the descriptor in one CAS.  Returns false (and changes nothing) when the
 * slot was already reused for another generation, so an old thread can never
 * clobber the new owner's state after a force-release.
 *
 * The 31-bit wrap is intentional: it is far beyond any connection count a
 * console lifetime reaches, and a wrapped generation is still different from the
 * generation of every thread that can still be alive. */
static inline bool nxusNetSlotFinishGeneration(NxusNetSlot *slot, u32 generation) {
    u64 expected = nxusNetSlotToken(slot);
    if ((u32)(expected >> 33) != (generation & NXUS_NET_SLOT_GENERATION_MASK))
        return false;
    const u64 desired = ((u64)(generation & NXUS_NET_SLOT_GENERATION_MASK) << 33) |
                        NXUS_NET_SLOT_DONE_FLAG |
                        (u64)NXUS_NET_SLOT_NO_FD;
    return atomic_compare_exchange_strong_explicit(&slot->token, &expected, desired,
                                                   memory_order_acq_rel,
                                                   memory_order_acquire);
}

/* Historical helper: publish done for the slot's current generation.  The slot
 * helpers are single-threaded in the host test; production always names the
 * generation it owns (serveClient/clientThread call the variant above). */
static inline void nxusNetSlotFinish(NxusNetSlot *slot) {
    (void)nxusNetSlotFinishGeneration(slot, nxusNetSlotGeneration(slot));
}

/* Finished AND still owned: the reaper may join this slot. */
static inline bool nxusNetSlotReapable(const NxusNetSlot *slot) {
    return nxusNetSlotInUse(slot) && nxusNetSlotDone(slot);
}

/* Claim a free slot for `fd` and return its index, or -1 when every slot is in
 * use (or merely waiting to be reaped).  The CAS on in_use is the claim; the
 * generation is bumped (which also clears done) and the descriptor published
 * after it, and a slot is only ever claimable in the clean state
 * nxusNetSlotReset()/nxusNetSlotReaped() leave behind. */
static inline int nxusNetSlotClaim(NxusNetSlot *slots, int count, int fd) {
    for (int i = 0; i < count; i++) {
        NxusNetSlot *slot = &slots[i];
        bool expected = false;
        if (!atomic_compare_exchange_strong_explicit(&slot->in_use, &expected, true,
                                                     memory_order_acq_rel,
                                                     memory_order_acquire)) {
            continue;
        }
        u32 generation = nxusNetSlotGeneration(slot);
        generation = (generation + 1u) & NXUS_NET_SLOT_GENERATION_MASK;
        atomic_store_explicit(&slot->token,
                              nxusNetSlotMakeToken(generation, false, fd),
                              memory_order_release);
        atomic_store_explicit(&slot->last_io_ns, 0, memory_order_relaxed);
        return i;
    }
    return -1;
}

/* Internal: retire a slot without joining its thread.  The generation is bumped,
 * so a late finish()/take from the previous owner can no longer touch it. */
static inline void nxusNetSlotRetire(NxusNetSlot *slot) {
    const u32 generation = (nxusNetSlotGeneration(slot) + 1u) &
                           NXUS_NET_SLOT_GENERATION_MASK;
    atomic_store_explicit(&slot->token,
                          nxusNetSlotMakeToken(generation, false, -1),
                          memory_order_release);
    atomic_store_explicit(&slot->last_io_ns, 0, memory_order_relaxed);
    atomic_store_explicit(&slot->in_use, false, memory_order_release);
}

/* The reaper's last action: release the slot for a later connection.  Only valid
   once the thread has been joined and its stack freed (see nxusNetSlotReapable). */
static inline void nxusNetSlotReaped(NxusNetSlot *slot) {
    nxusNetSlotRetire(slot);
}

/* The stale watchdog's last action: make the slot claimable again even though its
 * serving thread has not been joined.  The caller keeps the old thread's state
 * (stack/rx buffer/Thread handle/descriptor) on the leak side of the "leak, never
 * UAF" rule; the bumped generation protects the next owner from it. */
static inline void nxusNetSlotForceReap(NxusNetSlot *slot) {
    nxusNetSlotRetire(slot);
}

/* Drop every live slot after a listener rebuild: the bsd session the old
 * descriptors belonged to is gone, so none of them is valid any more.  Returns
 * the number of slots that still had to be cleared (for the log line). */
static inline int nxusNetSlotClearAll(NxusNetSlot *slots, int count) {
    int cleared = 0;
    for (int i = 0; i < count; i++) {
        if (!nxusNetSlotInUse(&slots[i])) continue;
        nxusNetSlotRetire(&slots[i]);
        cleared++;
    }
    return cleared;
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
