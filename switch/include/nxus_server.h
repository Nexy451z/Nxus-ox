/* Nxus command dispatcher. */
#pragma once

#include <switch.h>

#include "nxus_protocol.h"

#define NXUS_MAX_HITS_PER_BATCH 8192u
#define NXUS_DEBUG_SERVER_MAX_BREAKS  8u
#define NXUS_DEBUG_SERVER_MAX_HITS    32u
#define NXUS_DEBUG_SERVER_MAX_THREADS 32u

void nxusServerInit(void);
void nxusServerHandle(int fd, const NxusPacketHeader *header, const u8 *payload, u32 length, void *user);
/* Called periodically from the main loop: watchdog + deferred work. */
void nxusServerTick(void);
