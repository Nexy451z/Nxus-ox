/*
 * Nxus TCP transport.
 *
 * One client at a time (dmnt:cht only allows two debug sessions, so Nxus takes
 * exactly one).  Sends are serialised through a mutex because the response
 * thread, the watchdog and (later) the HID thread all write to the same socket.
 *
 * Reconnects are cooperative: a client waiting for the next command watches the
 * listen socket as well, but a new connection preempts the registered client ONLY
 * when that client has been silent for NXUS_NET_PREEMPT_IDLE_NS (8 s = two missed
 * 4 s heartbeats).  A live session (the normal case) keeps its socket; the
 * newcomer is accepted, answered with BUSY and closed, so an auto-reconnect or a
 * second launcher can no longer knock a healthy NCL/GUI session out.  A half-open
 * session (console slept, PC vanished without a FIN) is still released to the new
 * client after that threshold.  After a sleep/wake cycle (or a dropped link) the
 * bsd session itself is rebuilt on the fly, so the port never stays dead and a
 * reconnect succeeds immediately.
 */
#pragma once

#include <stdbool.h>

#ifdef __SWITCH__
#include <switch.h>
#endif
#include "nxus_protocol.h"

#ifndef __SWITCH__
/* Host tests include this header (tests/test_server_logic.c) to pin the pending-
   connection policy against the SHIPPED constant/helpers.  libnx's Result is a
   u32 and nothing else here needs the console's <switch.h>; redeclaring an
   identical typedef is legal C11, so a test that also includes the libnx stub
   header keeps compiling. */
typedef u32 Result;
#endif

/* Big enough to carry a large read in one reply: the PC-side scanner reads the
   target in chunks of (NXUS_NET_BUF_SIZE - header), so this directly divides
   the number of round trips (the heap cost is one malloc of this size). */
#define NXUS_NET_BUF_SIZE (1024u * 1024u)

/* How long the registered client may be silent before a pending connection is
   allowed to take its place.  The PC heartbeat is 4 s, so 8 s is exactly two
   missed heartbeats: a live session is never preempted (the old code cut at ~1 s
   whenever the second client appeared), while a half-open socket is released. */
#ifndef NXUS_NET_PREEMPT_IDLE_NS
#define NXUS_NET_PREEMPT_IDLE_NS 8000000000ull
#endif

/* Reason word appended to the BUSY reply sent to a refused second connection.
   core/nxus_protocol.h has no dedicated "another client owns the session" code
   (the protocol header is the wire single source of truth and is not changed
   here), so reuse BUSY_STATE - the retryable "the session is busy" reason that
   every existing client already understands. */
#define NXUS_NET_BUSY_REASON NXUS_REASON_BUSY_STATE

/* Log wording for the two preemption outcomes.  Exposed so the host test can pin
   the exact strings an operator greps for in the console log. */
#define NXUS_NET_LOG_PREEMPT_FMT \
    "recv: new connection pending while fd=%d was silent for %llu ms - preempting it"
#define NXUS_NET_LOG_BUSY_FMT \
    "client busy: refused new connection from %s (fd=%d) - live fd=%d keeps the session"

typedef enum {
    NxusNetPending_Preempt = 0,   /* old client is stale: close it, serve the new one */
    NxusNetPending_Busy    = 1,   /* old client is alive: refuse the new one with BUSY */
} NxusNetPendingAction;

/* The policy, kept pure so the host test pins it.  `idle_ns` is the time since
   the registered client last had a byte RECEIVED (not since the last send). */
static inline NxusNetPendingAction nxusNetPendingConnectionAction(u64 idle_ns) {
    return idle_ns >= NXUS_NET_PREEMPT_IDLE_NS ? NxusNetPending_Preempt
                                               : NxusNetPending_Busy;
}

/* BUSY reply payload: s32 Result followed by one u32 reason, the same shape
   replyErrorReason() in switch/source/nxus_server.c emits.  There is no request
   to correlate with (the connection is refused before its first command), so the
   frame carries NxusCmd_Nop/seq 0; a raw client reads the Result directly, while
   a seq-correlating client (the shipped PC clients) reports the close. */
static inline void nxusNetFillBusyPayload(s32 out[2]) {
    out[0] = (s32)NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
    out[1] = (s32)NXUS_NET_BUSY_REASON;
}

typedef void (*NxusNetHandler)(int fd, const NxusPacketHeader *header,
                               const u8 *payload, u32 length, void *user);

Result nxusNetInit(u16 port, NxusNetHandler handler, void *user);
void   nxusNetExit(void);
bool   nxusNetIsRunning(void);

/* -1 when no client is connected.  Intended for status/logging and the
   "is this still my session?" loops, NOT as the source of a send target: a value
   read here can be closed and its descriptor number recycled into a new client
   before the write starts.  The send helpers take the lock first and read the
   registered descriptor themselves. */
int    nxusNetClientFd(void);

/* armGetSystemTick() of the last packet byte received or of the last complete
   send.  The main loop uses this to tell a real sleep/wake (no traffic for a long
   time) from a long handler that merely starved the watchdog thread. */
u64    nxusNetLastActivityTick(void);

/* Thread-safe.  Returns an error if no client is connected or the write fails.
   `fd` must be the client the packet handler was called for: it is validated
   against the registered descriptor under the send lock, so a stale (closed and
   recycled) number is refused instead of being written to another session. */
Result nxusNetSendFd(int fd, u16 type, u16 flags, u32 seq, const void *payload, u32 length);
Result nxusNetSend(u16 type, u16 flags, u32 seq, const void *payload, u32 length);

/* Convenience: empty success response / error response for a request seq. */
Result nxusNetSendAck(u32 seq);
Result nxusNetSendError(u32 seq, Result rc);

/* Send an asynchronous event (flags = NXUS_FLAG_ASYNC, seq = 0). */
Result nxusNetSendEvent(u16 type, const void *payload, u32 length);

/* Send a response, splitting large payloads is the caller's problem for now. */
Result nxusNetRespond(u32 seq, const void *payload, u32 length);

/* Ask the server thread to drop the current client and rebuild the listener from
 * scratch (sleep/wake, Wi-Fi rejoin, any other stale-bsd situation).  The flag is
 * picked up by the protocol thread within one poll slice (~200 ms), so the call
 * is safe from any thread and never blocks.  `reason` only shows up in the log. */
void   nxusNetRequestReset(const char *reason);
