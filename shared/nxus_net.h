/*
 * Nxus TCP transport.
 *
 * One client at a time (dmnt:cht only allows two debug sessions, so Nxus takes
 * exactly one).  Sends are serialised through a mutex because the response
 * thread, the watchdog and (later) the HID thread all write to the same socket.
 */
#pragma once

#include <switch.h>
#include "nxus_protocol.h"

/* Big enough to carry a large read in one reply: the PC-side scanner reads the
   target in chunks of (NXUS_NET_BUF_SIZE - header), so this directly divides
   the number of round trips (the heap cost is one malloc of this size). */
#define NXUS_NET_BUF_SIZE (1024u * 1024u)

typedef void (*NxusNetHandler)(int fd, const NxusPacketHeader *header,
                               const u8 *payload, u32 length, void *user);

Result nxusNetInit(u16 port, NxusNetHandler handler, void *user);
void   nxusNetExit(void);
bool   nxusNetIsRunning(void);

/* -1 when no client is connected. */
int    nxusNetClientFd(void);

/* Thread-safe.  Returns an error if no client is connected or the write fails. */
Result nxusNetSendFd(int fd, u16 type, u16 flags, u32 seq, const void *payload, u32 length);
Result nxusNetSend(u16 type, u16 flags, u32 seq, const void *payload, u32 length);

/* Convenience: empty success response / error response for a request seq. */
Result nxusNetSendAck(u32 seq);
Result nxusNetSendError(u32 seq, Result rc);

/* Send an asynchronous event (flags = NXUS_FLAG_ASYNC, seq = 0). */
Result nxusNetSendEvent(u16 type, const void *payload, u32 length);

/* Send a response, splitting large payloads is the caller's problem for now. */
Result nxusNetRespond(u32 seq, const void *payload, u32 length);
