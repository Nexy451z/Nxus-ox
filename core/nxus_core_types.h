/*
 * Nxus core types - portable across the Switch sysmodule (libnx) and host tests.
 */
#pragma once

#ifdef __SWITCH__
    #include <switch.h>
    #define NXUS_PACKED NX_PACKED
#else
    #include <stdint.h>
    #include <stddef.h>
    #include <stdbool.h>

    typedef uint8_t  u8;
    typedef uint16_t u16;
    typedef uint32_t u32;
    typedef uint64_t u64;
    typedef int8_t   s8;
    typedef int16_t  s16;
    typedef int32_t  s32;
    typedef int64_t  s64;

    #define NXUS_PACKED __attribute__((packed))
#endif

#define NXUS_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
