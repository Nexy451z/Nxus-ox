/*
 * Nxus - Nintendo Switch headless analysis / remote memory editor
 * Wire protocol definitions (v0.1)
 *
 * This header is the SINGLE SOURCE OF TRUTH for the binary protocol.
 * pc/nxus/protocol.py mirrors it; pc/tests/test_protocol_parity.py parses this
 * file and fails if the two ever disagree.
 */
#pragma once

#include "nxus_core_types.h"

#define NXUS_MAGIC            0x4E585553u   /* 'NXUS' */
#define NXUS_PROTO_VERSION    0x0001u
#define NXUS_DEFAULT_PORT     7332u
#define NXUS_MAX_PAYLOAD      (1u << 20)

/* ---- Nxus private result codes (libnx has no module for us) ---- */
#define NXUS_RESULT_MODULE        484u
#define NXUS_ERR_NOT_IMPLEMENTED  1u
#define NXUS_ERR_UNSUPPORTED      2u
#define NXUS_ERR_BUSY             3u
#define NXUS_ERR_NOT_ATTACHED     4u
#define NXUS_ERR_NO_PROCESS       5u
#define NXUS_ERR_BAD_STATE        6u
#define NXUS_ERR_TOO_LARGE        7u
#define NXUS_MAKE_RESULT(desc) \
    ((u32)(0x80000000u | ((NXUS_RESULT_MODULE & 0x1FFu) << 9) | ((u32)(desc) & 0x1FFu)))

/* ---- error-reply reasons ----
   An error reply carries the s32 Result and MAY append one u32 reason code
   saying which validation refused the request.  The tail is optional: older
   servers send only the Result (4 bytes) and older clients read only the first
   4 bytes, so both directions stay wire-compatible.  NXUS_REASON_NONE is never
   sent - a missing tail already means "no detail available". */
#define NXUS_REASON_NONE            0u
#define NXUS_REASON_BAD_LENGTH      1u   /* payload shorter than the request struct */
#define NXUS_REASON_BAD_INDEX       2u   /* index/slot outside the available range */
#define NXUS_REASON_BAD_BLOCK_SIZE  3u   /* snapshots captured with different blocks */
#define NXUS_REASON_BUSY_STATE      4u   /* request arrived mid-scan / mid-pause */
#define NXUS_REASON_NO_MAPPINGS     5u   /* no mapping table yet: attach/scan first */
/* Appended only (the values above are on the wire): clients that do not know a
   code print it as "(reason=N)", so adding here stays compatible. */
#define NXUS_REASON_UNKNOWN_COMMAND 6u   /* command id this build does not implement */
#define NXUS_REASON_BAD_SLOT        7u   /* snapshot / breakpoint slot outside its table */
#define NXUS_REASON_BAD_CONFIG      8u   /* CONFIG payload length matches neither shape */
#define NXUS_REASON_BAD_ARG         9u   /* field value outside its allowed set (width/kind/scope) */

/* ---- packet header flags ---- */
#define NXUS_FLAG_ASYNC       0x0001u  /* Switch-initiated event; seq is not a request id */
#define NXUS_FLAG_ERROR       0x0002u  /* payload is s32 Result [+ optional u32 reason] */
#define NXUS_FLAG_MORE        0x0004u  /* payload continues in the next packet */

typedef struct NXUS_PACKED {
    u32 magic;      /* NXUS_MAGIC */
    u16 type;       /* NxusCmd / NxusEvent */
    u16 flags;      /* NXUS_FLAG_* */
    u32 length;     /* payload length in bytes */
    u32 seq;        /* request/response correlation id (0 for async events) */
} NxusPacketHeader;

NXUS_STATIC_ASSERT(sizeof(NxusPacketHeader) == 16, "NxusPacketHeader must be 16 bytes");

/* ---- commands (PC -> Switch) ---- */
typedef enum {
    NxusCmd_Nop              = 0x0000,

    NxusCmd_Pause            = 0x0001,
    NxusCmd_Resume           = 0x0002,
    NxusCmd_Heartbeat        = 0x0003,
    NxusCmd_GetStatus        = 0x0004,
    NxusCmd_GetMetadata      = 0x0005,
    NxusCmd_ForceOpen        = 0x0006,
    NxusCmd_ForceClose       = 0x0007,
    NxusCmd_GetModules       = 0x0008,
    NxusCmd_GetProcesses     = 0x0009,

    NxusCmd_GetMappingCount  = 0x0010,
    NxusCmd_GetMappings      = 0x0011,
    NxusCmd_Query            = 0x0012,
    NxusCmd_Read             = 0x0013,
    NxusCmd_Write            = 0x0014,

    NxusCmd_ScanBegin        = 0x0020,
    NxusCmd_ScanNext         = 0x0021,
    NxusCmd_ScanStatus       = 0x0022,
    NxusCmd_ScanCancel       = 0x0023,
    NxusCmd_ScanGetHits      = 0x0024,
    NxusCmd_ScanReset        = 0x0025,
    NxusCmd_SnapshotCapture  = 0x0026,
    NxusCmd_SnapshotDiff     = 0x0027,
    NxusCmd_SnapshotChanged  = 0x0028,
    NxusCmd_ScanUndo         = 0x0029,

    /* pointer scan + cheat export */
    NxusCmd_PtrScanBegin     = 0x0030,
    NxusCmd_PtrScanGet       = 0x0031,
    NxusCmd_CheatExport      = 0x0032,

    NxusCmd_FrozenList       = 0x0040,
    NxusCmd_FrozenEnable     = 0x0041,
    NxusCmd_FrozenDisable    = 0x0042,
    NxusCmd_CheatList        = 0x0043,
    NxusCmd_CheatToggle      = 0x0044,

    NxusCmd_DebugAttach      = 0x0050,
    NxusCmd_DebugDetach      = 0x0051,
    NxusCmd_DebugStatus      = 0x0052,
    NxusCmd_BreakSet         = 0x0053,
    NxusCmd_BreakClear       = 0x0054,
    NxusCmd_BreakList        = 0x0055,
    NxusCmd_DebugContinue    = 0x0056,
    NxusCmd_ThreadList       = 0x0057,
    NxusCmd_RegsGet          = 0x0058,
    NxusCmd_RegsSet          = 0x0059,
    NxusCmd_HitGet           = 0x005A,
    NxusCmd_HitClear         = 0x005B,
    /* GDB-style single step.  0x0057..0x005B are ThreadList/RegsGet/RegsSet/
       HitGet/HitClear and NxusCmd_Config starts at 0x0060, so 0x005C is the next
       free id after DebugContinue.  Payload: optional u64 thread_id (absent or 0 =
       the thread the last stop was recorded on). */
    NxusCmd_DebugStep        = 0x005C,

    NxusCmd_Config           = 0x0060,
    NxusCmd_LogGet           = 0x0061,

    NxusCmd_ProbeRun         = 0x0070,
    NxusCmd_ProbeGet         = 0x0071,
} NxusCmd;

/* ---- asynchronous events (Switch -> PC) ---- */
typedef enum {
    NxusEvent_HotkeyPaused   = 0x8001,
    NxusEvent_AutoResume     = 0x8002,
    NxusEvent_BreakHit       = 0x8003,
    NxusEvent_ScanProgress   = 0x8004,
    NxusEvent_ProcessEvent   = 0x8005,
    NxusEvent_Log            = 0x8006,
    NxusEvent_DebugEvent     = 0x8007,
    /* A GDB-style stop was published: payload is NxusDebugStop. */
    NxusEvent_DebugStopped   = 0x8008,
} NxusEvent;

/* ---- status flags ---- */
#define NXUS_ST_PAUSED         0x0001u
#define NXUS_ST_SCANNING       0x0002u
#define NXUS_ST_HAS_PROCESS    0x0004u
#define NXUS_ST_DEBUG_MODE     0x0008u
#define NXUS_ST_DEBUG_ATTACHED 0x0010u
#define NXUS_ST_DEBUG_STOPPED  0x0020u  /* target held at a break/watch stop */

/* ---- run modes ---- */
#define NXUS_MODE_DMNT        0u   /* thin dmnt:cht client (cheat VM coexists) */
#define NXUS_MODE_DEBUG       1u   /* Nxus owns the kernel debug session */

typedef struct NXUS_PACKED {
    u32 proto_version;
    u32 mode;              /* NXUS_MODE_* */
    u32 status_flags;      /* NXUS_ST_* */
    u32 scan_state;
    u64 process_id;
    u64 program_id;
    u64 main_base;
    u64 main_size;
    u32 hit_count;
    u32 progress_permille;
    s32 last_result;
    u32 uptime_ms;
    u32 heap_used;
    u32 heap_total;
    u32 max_read;          /* largest single Read the server accepts (0 = unspecified) */
} NxusStatus;
NXUS_STATIC_ASSERT(sizeof(NxusStatus) == 76, "NxusStatus must be 76 bytes");

/* ---- process metadata (mirrors dmnt CheatProcessMetadata, 0x70) ---- */
typedef struct NXUS_PACKED {
    u64 process_id;
    u64 program_id;
    u64 main_nso_base;
    u64 main_nso_size;
    u64 heap_base;
    u64 heap_size;
    u64 alias_base;
    u64 alias_size;
    u64 aslr_base;
    u64 aslr_size;
    u8  main_nso_build_id[0x20];
} NxusProcessMetadata;
NXUS_STATIC_ASSERT(sizeof(NxusProcessMetadata) == 0x70, "NxusProcessMetadata must be 0x70");

/* ---- memory info (wire layout mirrors svc::MemoryInfo, 0x28) ---- */
typedef struct NXUS_PACKED {
    u64 base_addr;
    u64 size;
    u32 memory_type;
    u32 memory_attribute;
    u32 perm;
    u32 device_refcount;
    u32 ipc_refcount;
    u32 padding;
} NxusMemoryInfo;
NXUS_STATIC_ASSERT(sizeof(NxusMemoryInfo) == 0x28, "NxusMemoryInfo must be 0x28");

#define NXUS_PERM_R 0x1u
#define NXUS_PERM_W 0x2u
#define NXUS_PERM_X 0x4u

/* ---- module table ---- */
#define NXUS_MODULE_NAME_MAX 16
#define NXUS_MAX_MODULES     64

typedef struct NXUS_PACKED {
    u64 base;
    u64 size;
    u8  build_id[0x20];
    char name[NXUS_MODULE_NAME_MAX];
} NxusModuleInfo;
NXUS_STATIC_ASSERT(sizeof(NxusModuleInfo) == 0x40, "NxusModuleInfo must be 0x40");

/* ---- memory read/write ---- */
typedef struct NXUS_PACKED {
    u64 address;
    u32 size;
    u32 reserved;
} NxusReadRequest;

typedef struct NXUS_PACKED {
    u64 address;
    u32 size;
    u32 reserved;
    /* followed by size bytes of data */
} NxusWriteHeader;

typedef struct NXUS_PACKED {
    u64 offset;
    u32 max_count;
    u32 reserved;
} NxusMappingsRequest;
NXUS_STATIC_ASSERT(sizeof(NxusMappingsRequest) == 16, "NxusMappingsRequest must be 16 bytes");

/* ---- scanning ---- */
typedef enum {
    NxusScanState_Idle      = 0,
    NxusScanState_Running   = 1,
    NxusScanState_Done      = 2,
    NxusScanState_Error     = 3,
    NxusScanState_Cancelled = 4,
} NxusScanState;

typedef enum {
    NxusScanKind_First = 0,
    NxusScanKind_Next  = 1,
} NxusScanKind;

typedef enum {
    NxusCmp_Equal          = 0,
    NxusCmp_NotEqual       = 1,
    NxusCmp_Greater        = 2,
    NxusCmp_Less           = 3,
    NxusCmp_Increased      = 4,   /* NEXT only */
    NxusCmp_Decreased      = 5,   /* NEXT only */
    NxusCmp_Unchanged      = 6,   /* NEXT only */
    NxusCmp_Changed        = 7,   /* NEXT only */
    NxusCmp_FuzzyEqual     = 8,   /* float within epsilon (target2 = epsilon bits) */
    NxusCmp_Between        = 9,   /* target <= v <= target2 (inclusive) */
    NxusCmp_Unknown        = 10,  /* first pass only: record every position */
    NxusCmp_GreaterOrEqual = 11,  /* v >= target */
    NxusCmp_LessOrEqual    = 12,  /* v <= target */
    NxusCmp_Different      = 13,  /* NEXT only: |cur - prev| == target */
} NxusCompareMode;

/*
 * What the user is searching for.  Mirrors Cheat Engine's value types so the PC
 * side can present the familiar list.
 */
typedef enum {
    NxusValueType_U8     = 0,   /* "Byte" */
    NxusValueType_U16    = 1,   /* "2 Bytes" */
    NxusValueType_U32    = 2,   /* "4 Bytes" */
    NxusValueType_U64    = 3,   /* "8 Bytes" */
    NxusValueType_F32    = 4,   /* "Float" */
    NxusValueType_F64    = 5,   /* "Double" */
    NxusValueType_String = 6,   /* "String" (ASCII, or UTF-16LE with the flag) */
    NxusValueType_Bytes  = 7,   /* "Array of byte", ?? wildcards allowed */
    NxusValueType_Binary = 8,   /* "Binary" - exact bit pattern == Bytes without wildcards */
    NxusValueType_All    = 9,   /* "All" - try every numeric width at once */
} NxusValueType;

#define NXUS_SCAN_MAX_PATTERN 64

typedef enum {
    NxusScope_All      = 0,
    NxusScope_Main     = 1,
    NxusScope_Heap     = 2,
    NxusScope_Custom   = 3,
    NxusScope_Writable = 4,
    NxusScope_Tls      = 5,
    NxusScope_Ranges   = 6,   /* scan the union of NXUS_SCAN_F_RANGES ranges */
} NxusScanScope;

/* ---- several scan ranges at once (NxusScope_Ranges) ---------------------------
   With NXUS_SCAN_F_RANGES set in NxusScanRequest.flags, the request payload carries
   this table right after the fixed NxusScanRequest, before any NxusScanExt/pattern.
   Overlapping or adjacent entries are fine: a mapping that meets several ranges
   produces one region per intersection, and hits stay mapping-relative. */
#define NXUS_MAX_SCAN_RANGES 16

typedef struct NXUS_PACKED {
    u32 count;
    u32 reserved;
} NxusRangeListHeader;             /* 8 bytes */

typedef struct NXUS_PACKED {
    u64 begin;
    u64 end;                       /* exclusive */
} NxusRangeEntry;                  /* 16 bytes */

NXUS_STATIC_ASSERT(sizeof(NxusRangeListHeader) == 8, "NxusRangeListHeader must be 8");
NXUS_STATIC_ASSERT(sizeof(NxusRangeEntry) == 16, "NxusRangeEntry must be 16");

#define NXUS_SCAN_F_NEW_SESSION 0x0001u
#define NXUS_SCAN_F_FLOAT       0x0002u
#define NXUS_SCAN_F_SIGNED      0x0004u
#define NXUS_SCAN_F_HEX         0x0008u   /* the value was typed as hex (display hint) */
#define NXUS_SCAN_F_CASE_INSENS 0x0010u   /* string compare ignores case */
#define NXUS_SCAN_F_UTF16       0x0020u   /* string is UTF-16LE */
#define NXUS_SCAN_F_WILDCARD    0x0040u   /* byte array contains ?? wildcards */
#define NXUS_SCAN_F_ALIGNED     0x0080u   /* only consider naturally aligned addresses */
#define NXUS_SCAN_F_RANGES      0x0100u   /* a NxusRangeListHeader + entries follows */

typedef struct NXUS_PACKED {
    u32 kind;            /* NxusScanKind */
    u32 value_size;      /* 1,2,4,8 */
    u32 cmp_mode;        /* NxusCompareMode */
    u32 scope;           /* NxusScanScope */
    u64 range_begin;
    u64 range_end;
    u64 target;          /* comparison value */
    u64 target2;         /* second operand (range/epsilon bits) */
    u32 chunk_size;
    u32 flags;           /* NXUS_SCAN_F_* */
} NxusScanRequest;
NXUS_STATIC_ASSERT(sizeof(NxusScanRequest) == 56, "NxusScanRequest must be 56 bytes");

/* Optional tail of NxusScanRequest (older clients simply omit it). */
typedef struct NXUS_PACKED {
    u32 value_type;        /* NxusValueType */
    u32 pattern_len;       /* pattern bytes that follow this struct */
    u32 epsilon_decimals;  /* float compare: decimals to round to (0 = exact) */
    u32 reserved;
} NxusScanExt;
NXUS_STATIC_ASSERT(sizeof(NxusScanExt) == 16, "NxusScanExt must be 16 bytes");

typedef struct NXUS_PACKED {
    u32 session_id;
    u32 count;           /* hits in this batch */
    u32 total;           /* total hits in the session */
    u32 value_size;
    u32 mapping_count;   /* number of u64 bases following the header */
    u32 reserved;        /* NXUS_HITBATCH_* flags (0 on older servers) */
    /* u64 mapping_bases[mapping_count]; NxusHit hits[count]; */
} NxusHitBatchHeader;
NXUS_STATIC_ASSERT(sizeof(NxusHitBatchHeader) == 24, "NxusHitBatchHeader must be 24 bytes");

/* reserved flags: the hit list stopped because it reached max_capacity, so more
   hits exist but were not collected.  Clients that ignore the field keep working
   (older servers always send 0). */
#define NXUS_HITBATCH_TRUNCATED 0x0001u

typedef struct NXUS_PACKED {
    u32 offset;          /* offset from mapping base */
    u16 mapping_idx;
    u16 value_type;      /* NxusValueType of this hit ("All" scans mix types) */
    u64 value;           /* numeric value (right-aligned), or an FNV-1a hash for
                            string / byte-array hits */
} NxusHit;

typedef struct NXUS_PACKED {
    u32 offset;          /* first hit to return */
    u32 count;           /* how many hits to return */
    u32 reserved[2];
} NxusGetHitsRequest;
NXUS_STATIC_ASSERT(sizeof(NxusGetHitsRequest) == 16, "NxusGetHitsRequest must be 16 bytes");

/* ---- snapshots (dump-free diffing) ---- */

typedef struct NXUS_PACKED {
    u32 slot;             /* 0 = A, 1 = B */
    u32 block_size;       /* 0 = default */
    u32 scope;            /* NxusScanScope */
    u32 reserved;
    u64 range_begin;
    u64 range_end;
} NxusSnapshotRequest;
NXUS_STATIC_ASSERT(sizeof(NxusSnapshotRequest) == 32, "NxusSnapshotRequest must be 32 bytes");

typedef struct NXUS_PACKED {
    u32 from_slot;
    u32 to_slot;
    u32 reserved[2];
} NxusSnapshotDiffRequest;
NXUS_STATIC_ASSERT(sizeof(NxusSnapshotDiffRequest) == 16, "NxusSnapshotDiffRequest must be 16 bytes");

typedef struct NXUS_PACKED {
    u32 slot;
    u32 block_count;
    u32 changed_count;
    u32 block_size;
    u32 region_count;
    u32 truncated;
    u32 reserved[2];
} NxusSnapshotSummary;
NXUS_STATIC_ASSERT(sizeof(NxusSnapshotSummary) == 32, "NxusSnapshotSummary must be 32 bytes");

typedef struct NXUS_PACKED {
    u64 address;
    u32 size;
    u32 flags;            /* 0 = changed, 1 = vanished, 2 = appeared */
} NxusChangedBlockWire;
NXUS_STATIC_ASSERT(sizeof(NxusChangedBlockWire) == 16, "NxusChangedBlockWire must be 16 bytes");

#define NXUS_CHANGE_CHANGED  0u
#define NXUS_CHANGE_VANISHED 1u
#define NXUS_CHANGE_APPEARED 2u

/* ---- pointer scan ---- */
#define NXUS_PTRSCAN_MAX_DEPTH 8

typedef struct NXUS_PACKED {
    u64 target_address;
    u64 module_base;
    u32 max_depth;
    u32 max_offset;
    u32 max_results;
    u32 value_width;      /* 4 for 32-bit titles, 8 for 64-bit */
} NxusPtrScanRequest;
NXUS_STATIC_ASSERT(sizeof(NxusPtrScanRequest) == 32, "NxusPtrScanRequest must be 32 bytes");

typedef struct NXUS_PACKED {
    u32 count;
    u32 total;
    u32 truncated;
    u32 reserved;
} NxusPtrChainListHeader;
NXUS_STATIC_ASSERT(sizeof(NxusPtrChainListHeader) == 16, "NxusPtrChainListHeader must be 16 bytes");

typedef struct NXUS_PACKED {
    u32 root_offset;      /* relative to the module base (M=0 in cheat codes) */
    u32 final_offset;
    u32 step_count;
    u32 reserved;
    u32 steps[NXUS_PTRSCAN_MAX_DEPTH];
} NxusPtrChainWire;
NXUS_STATIC_ASSERT(sizeof(NxusPtrChainWire) == 48, "NxusPtrChainWire must be 48 bytes");

typedef struct NXUS_PACKED {
    u32 index;
    u32 value_width;
    u32 flags;            /* bit0 = 32-bit title (use 4-byte loads) */
    u32 reserved;
    u64 value;
} NxusCheatExportRequest;
NXUS_STATIC_ASSERT(sizeof(NxusCheatExportRequest) == 24, "NxusCheatExportRequest must be 24 bytes");

#define NXUS_CHEAT_F_32BIT 0x0001u
NXUS_STATIC_ASSERT(sizeof(NxusHit) == 16, "NxusHit must be 16 bytes");

/* ---- freeze / cheat ---- */
typedef struct NXUS_PACKED {
    u64 address;
    u64 value;
    u32 width;
    u32 reserved;
} NxusFrozenEntry;

typedef struct NXUS_PACKED {
    u64 address;
    u32 width;
    u32 reserved;
} NxusFrozenRequest;
NXUS_STATIC_ASSERT(sizeof(NxusFrozenRequest) == 16, "NxusFrozenRequest must be 16 bytes");

/* ---- debug mode ---- */
typedef enum {
    NxusBp_Execute = 0,
    NxusBp_Write   = 1,
    NxusBp_Read    = 2,
    NxusBp_Access  = 3,
} NxusBreakKind;

typedef struct NXUS_PACKED {
    u32 slot;        /* 0..5 hardware breakpoint, 0x10..0x13 watchpoint */
    u32 kind;        /* NxusBreakKind */
    u32 size;        /* watch size: 1,2,4,8 */
    u32 ctrl;        /* 0 = compute automatically, else raw ctrl word */
    u64 address;
} NxusBreakRequest;

typedef struct NXUS_PACKED {
    u32 slot;
    u32 kind;
    u32 size;
    u32 enabled;
    u64 address;
    u64 ctrl;
} NxusBreakEntry;

typedef struct NXUS_PACKED {
    u32 index;
    u32 kind;
    u32 slot;
    u32 thread_id_low;
    u64 address;      /* trapped data address (watchpoints) */
    u64 pc;
    u64 lr;
    u64 sp;
    u32 cpsr;
    u32 r[13];        /* r0..r12 */
    u64 tick;
} NxusBreakHit;
NXUS_STATIC_ASSERT(sizeof(NxusBreakHit) == 112, "NxusBreakHit must be 112 bytes");

/* Payload of NxusEvent_DebugStopped: the stop the switch just published.  With
   auto_continue == 0 a hit holds the target (GDB-style) until the PC sends
   DebugContinue or DebugStep, and this event tells it which thread trapped and
   from where.  kind/slot are 0xFFFFFFFF for a manual break (Pause). */
typedef struct NXUS_PACKED {
    u64 thread_id;    /* thread that took the exception (0 = no single owner) */
    u64 pc;           /* PC at the trap */
    u64 address;      /* trapped data address (watchpoints), 0 for exec/manual */
    u32 kind;         /* NxusBreakKind, or 0xFFFFFFFF for a manual break */
    u32 slot;         /* hardware slot, 0xFFFFFFFF when unknown */
} NxusDebugStop;
NXUS_STATIC_ASSERT(sizeof(NxusDebugStop) == 32, "NxusDebugStop must be 32 bytes");

typedef struct NXUS_PACKED {
    u64 thread_id;
    u32 state;
    u32 priority;
    u32 core;
    u32 reserved;
} NxusThreadEntry;

/* Thread context in the wire format: 64-bit view plus the AArch32 alias, so the
   same structure serves 32-bit titles (MHXX) and 64-bit ones. */
typedef struct NXUS_PACKED {
    u64 thread_id;
    u64 pc;
    u64 lr;
    u64 sp;
    u64 fp;
    u32 cpsr;
    u32 r[13];        /* r0..r12 / x0..x12 low halves */
    u32 reserved;     /* NXUS_THREADCTX_FLAG_* */
    u64 x[29];        /* x0..x28 full 64-bit general-purpose registers */
} NxusThreadContext;
NXUS_STATIC_ASSERT(sizeof(NxusThreadContext) == 332, "NxusThreadContext must be 332 bytes");

/* NxusThreadContext.reserved flags.  The field is a bit set, not padding.
   The two directions use different bits: bit 0 is a REQUEST flag ("x[0..28] is
   authoritative", both PC encoders already send it as 1) and bit 1 is a REPLY
   flag (an AArch32 context).

   An AArch32 title reports zeros in the sp/lr/fp header fields; the live SP, LR
   and FP are cpu_gprs[13], cpu_gprs[14] and cpu_gprs[11], which
   nxusDebugGetRegs() mirrors into x[13]/x[14]/x[11] as well (the r[] alias only
   covers r0..r12).  Clients should trust bit 1 rather than guessing from
   sp==lr==0, because a genuine 32-bit fault frame may have SP == 0. */
#define NXUS_THREADCTX_FLAG_X_AUTHORITATIVE 0x0001u   /* request (RegsSet) */
#define NXUS_THREADCTX_FLAG_AARCH32         0x0002u   /* reply (GetRegs) */

typedef struct NXUS_PACKED {
    u32 attached;         /* 0/1 */
    u32 watch_style;      /* which hardware-watchpoint encoding is in use */
    u32 break_count;
    u32 hit_count;
    u32 thread_count;
    s32 last_result;
    u32 auto_continue;
    /* Low 32 bits of the thread the current stop belongs to (0 = not stopped).
       The full id is in the NxusEvent_DebugStopped payload.  The field used to be
       `reserved`; the size and offsets are unchanged. */
    u32 stopped_thread_low;
} NxusDebugStatus;
NXUS_STATIC_ASSERT(sizeof(NxusDebugStatus) == 32, "NxusDebugStatus must be 32 bytes");

typedef struct NXUS_PACKED {
    u32 style;            /* NxusWatchStyle */
    u32 auto_continue;    /* 0 = GDB-style: a hit stops the target (default),
                             1 = resume automatically after each hit */
    u32 reserved[2];
} NxusDebugConfig;
NXUS_STATIC_ASSERT(sizeof(NxusDebugConfig) == 16, "NxusDebugConfig must be 16 bytes");

/* Watchpoint encodings tried against the kernel (the probe reports which one
   this console accepts). */
#define NXUS_WATCH_STYLE_PLAIN     0u   /* no linked context-id breakpoint      */
#define NXUS_WATCH_STYLE_LINK5     1u   /* context-id bp in slot 5, LINK=5      */
#define NXUS_WATCH_STYLE_LINK6     2u   /* second link slot: bp in 4, LINK=4    */
#define NXUS_WATCH_STYLE_DEFAULT   NXUS_WATCH_STYLE_LINK5

/* ---- diagnostics ---- */
#define NXUS_PROBE_MAX 32
#define NXUS_PROBE_NAME_MAX 48

typedef struct NXUS_PACKED {
    u32 id;
    s32 result;
    u64 detail0;
    u64 detail1;
    char name[NXUS_PROBE_NAME_MAX];
} NxusProbeEntry;
NXUS_STATIC_ASSERT(sizeof(NxusProbeEntry) == 72, "NxusProbeEntry must be 72 bytes");

typedef enum {
    NxusProbe_DmntInitialize     = 1,
    NxusProbe_DmntHasProcess     = 2,
    NxusProbe_ForceOpen          = 3,
    NxusProbe_GetMetadata        = 4,
    NxusProbe_MappingCount       = 5,
    NxusProbe_ModuleScan         = 6,
    NxusProbe_ReadMain           = 7,
    NxusProbe_ForceClose         = 8,
    NxusProbe_DebugActiveProcess = 9,
    NxusProbe_DebugAttachResult  = 10,
    NxusProbe_HwbpSetExecute     = 11,
    NxusProbe_HwbpSetWatch       = 12,
    NxusProbe_HwbpEvent          = 13,
    NxusProbe_ReadCores          = 14,
    NxusProbe_FrozenEnable       = 15,
    NxusProbe_FrozenDisable      = 16,
    NxusProbe_ThreadContext      = 17,
    NxusProbe_HidInit            = 18,
    NxusProbe_SdWrite            = 19,
    NxusProbe_Done               = 20,
} NxusProbeId;

typedef struct NXUS_PACKED {
    u64 hotkey_mask;
    u32 hotkey_hold_ms;
    u32 hotkey_enabled;
    u32 chunk_size;
    u32 watchdog_timeout_ms;
    u32 heartbeat_interval_ms;
    u32 log_level;
} NxusConfig;
NXUS_STATIC_ASSERT(sizeof(NxusConfig) == 32, "NxusConfig must be 32 bytes");

static inline void nxusHeaderInit(NxusPacketHeader *h, u16 type, u16 flags, u32 length, u32 seq) {
    h->magic  = NXUS_MAGIC;
    h->type   = type;
    h->flags  = flags;
    h->length = length;
    h->seq    = seq;
}
