"""Nxus wire protocol - Python mirror of core/nxus_protocol.h.

The C header is the single source of truth.  pc/tests/test_protocol_parity.py
parses that header and fails if anything here drifts out of sync.
"""
from __future__ import annotations

import struct

MAGIC = 0x4E585553
PROTO_VERSION = 0x0001
DEFAULT_PORT = 7332
MAX_PAYLOAD = 1 << 20

FLAG_ASYNC = 0x0001
FLAG_ERROR = 0x0002
FLAG_MORE = 0x0004

HEADER = struct.Struct('<IHHII')
HEADER_SIZE = HEADER.size

# proto, mode, flags, scan_state, pid, title, main_base, main_size,
# hits, progress, last_result, uptime, heap_used, heap_total, max_read
STATUS = struct.Struct('<IIIIQQQQIIiIIII')
PROCESS_METADATA = struct.Struct('<QQQQQQQQQQ32s')
MEMORY_INFO = struct.Struct('<QQIIIIII')
MODULE_INFO = struct.Struct('<QQ32s16s')
READ_REQUEST = struct.Struct('<QII')
WRITE_HEADER = struct.Struct('<QII')
MAPPINGS_REQUEST = struct.Struct('<QII')
GET_HITS_REQUEST = struct.Struct('<IIII')
SCAN_REQUEST = struct.Struct('<IIIIQQQQII')
# Optional tail of NxusScanRequest (value type + pattern for string / byte scans)
SCAN_EXT = struct.Struct('<IIII')
HIT_BATCH_HEADER = struct.Struct('<IIIIII')

# NxusHitBatchHeader.reserved flags - mirrors NXUS_HITBATCH_* in core/nxus_protocol.h.
HITBATCH_TRUNCATED = 0x0001   # the console filled its hit list; results may be cut off
HIT = struct.Struct('<IHHQ')   # offset, mapping_idx, value_type, value
FROZEN_ENTRY = struct.Struct('<QQII')
FROZEN_REQUEST = struct.Struct('<QII')
BREAK_REQUEST = struct.Struct('<IIIIQ')
BREAK_ENTRY = struct.Struct('<IIIIQQ')
BREAK_HIT = struct.Struct('<IIIIQQQQI13IQ')
THREAD_ENTRY = struct.Struct('<QIIII')
PROBE_ENTRY = struct.Struct('<IiQQ48s')
CONFIG = struct.Struct('<QIIIIII')
SNAPSHOT_REQUEST = struct.Struct('<IIIIQQ')
SNAPSHOT_DIFF_REQUEST = struct.Struct('<IIII')
SNAPSHOT_SUMMARY = struct.Struct('<IIIIIIII')
CHANGED_BLOCK = struct.Struct('<QII')

# ---- value types / scan types (Cheat Engine style) ----
VT_U8, VT_U16, VT_U32, VT_U64 = 0, 1, 2, 3
VT_F32, VT_F64, VT_STRING, VT_BYTES, VT_BINARY, VT_ALL = 4, 5, 6, 7, 8, 9

VALUE_TYPE_NAMES = {
    VT_U8: 'Byte', VT_U16: '2 Bytes', VT_U32: '4 Bytes', VT_U64: '8 Bytes',
    VT_F32: 'Float', VT_F64: 'Double', VT_STRING: 'String',
    VT_BYTES: 'Array of byte', VT_BINARY: 'Binary', VT_ALL: 'All',
}
VALUE_TYPE_SIZES = {VT_U8: 1, VT_U16: 2, VT_U32: 4, VT_U64: 8, VT_F32: 4, VT_F64: 8}

CMP_EQUAL, CMP_NOT_EQUAL, CMP_GREATER, CMP_LESS = 0, 1, 2, 3
CMP_INCREASED, CMP_DECREASED, CMP_UNCHANGED, CMP_CHANGED, CMP_FUZZY = 4, 5, 6, 7, 8
CMP_BETWEEN, CMP_UNKNOWN = 9, 10
CMP_GREATER_OR_EQUAL, CMP_LESS_OR_EQUAL, CMP_DIFFERENT = 11, 12, 13

SCAN_F_HEX, SCAN_F_CASE_INSENS, SCAN_F_UTF16 = 0x0008, 0x0010, 0x0020
SCAN_F_WILDCARD, SCAN_F_ALIGNED = 0x0040, 0x0080
SCAN_F_FLOAT, SCAN_F_SIGNED = 0x0002, 0x0004
SCAN_F_RANGES = 0x0100
RANGE_LIST_HEADER = struct.Struct('<II')
RANGE_ENTRY = struct.Struct('<QQ')
MAX_SCAN_RANGES = 16
SCAN_MAX_PATTERN = 64

CHANGE_CHANGED = 0
CHANGE_VANISHED = 1
CHANGE_APPEARED = 2
SNAPSHOT_DEFAULT_BLOCK_SIZE = 16384
PTRSCAN_REQUEST = struct.Struct('<QQIIII')
PTR_CHAIN_LIST_HEADER = struct.Struct('<IIII')
PTR_CHAIN = struct.Struct('<IIII8I')
CHEAT_EXPORT_REQUEST = struct.Struct('<IIIIQ')
THREAD_CONTEXT = struct.Struct('<QQQQQ I 13I I 29Q')
# attached, watch_style, break_count, hit_count, thread_count, last_result,
# auto_continue, stopped_thread_low (C: stopped_thread_low, 0 = nothing held)
DEBUG_STATUS = struct.Struct('<IIIIIiII')
DEBUG_CONFIG = struct.Struct('<IIII')
# NxusEvent_DebugStopped payload: thread_id, pc, address, kind, slot (32 bytes)
DEBUG_STOP = struct.Struct('<QQQII')

WATCH_STYLE_PLAIN = 0
WATCH_STYLE_LINK5 = 1
WATCH_STYLE_LINK6 = 2

NXUS_PTRSCAN_MAX_DEPTH = 8
CHEAT_F_32BIT = 0x0001

STRUCTS = {
    'NxusPacketHeader': HEADER,
    'NxusStatus': STATUS,
    'NxusProcessMetadata': PROCESS_METADATA,
    'NxusMemoryInfo': MEMORY_INFO,
    'NxusModuleInfo': MODULE_INFO,
    'NxusReadRequest': READ_REQUEST,
    'NxusWriteHeader': WRITE_HEADER,
    'NxusMappingsRequest': MAPPINGS_REQUEST,
    'NxusGetHitsRequest': GET_HITS_REQUEST,
    'NxusScanRequest': SCAN_REQUEST,
    'NxusScanExt': SCAN_EXT,
    'NxusRangeListHeader': RANGE_LIST_HEADER,
    'NxusRangeEntry': RANGE_ENTRY,
    'NxusHitBatchHeader': HIT_BATCH_HEADER,
    'NxusHit': HIT,
    'NxusFrozenEntry': FROZEN_ENTRY,
    'NxusFrozenRequest': FROZEN_REQUEST,
    'NxusBreakRequest': BREAK_REQUEST,
    'NxusBreakEntry': BREAK_ENTRY,
    'NxusBreakHit': BREAK_HIT,
    'NxusThreadEntry': THREAD_ENTRY,
    'NxusProbeEntry': PROBE_ENTRY,
    'NxusConfig': CONFIG,
    'NxusSnapshotRequest': SNAPSHOT_REQUEST,
    'NxusSnapshotDiffRequest': SNAPSHOT_DIFF_REQUEST,
    'NxusSnapshotSummary': SNAPSHOT_SUMMARY,
    'NxusChangedBlockWire': CHANGED_BLOCK,
    'NxusPtrScanRequest': PTRSCAN_REQUEST,
    'NxusPtrChainListHeader': PTR_CHAIN_LIST_HEADER,
    'NxusPtrChainWire': PTR_CHAIN,
    'NxusCheatExportRequest': CHEAT_EXPORT_REQUEST,
    'NxusThreadContext': THREAD_CONTEXT,
    'NxusDebugStatus': DEBUG_STATUS,
    'NxusDebugConfig': DEBUG_CONFIG,
    'NxusDebugStop': DEBUG_STOP,
}

CMD = {
    'Nop': 0x0000,
    'Pause': 0x0001,
    'Resume': 0x0002,
    'Heartbeat': 0x0003,
    'GetStatus': 0x0004,
    'GetMetadata': 0x0005,
    'ForceOpen': 0x0006,
    'ForceClose': 0x0007,
    'GetModules': 0x0008,
    'GetProcesses': 0x0009,
    'GetMappingCount': 0x0010,
    'GetMappings': 0x0011,
    'Query': 0x0012,
    'Read': 0x0013,
    'Write': 0x0014,
    'ScanBegin': 0x0020,
    'ScanNext': 0x0021,
    'ScanStatus': 0x0022,
    'ScanCancel': 0x0023,
    'ScanGetHits': 0x0024,
    'ScanReset': 0x0025,
    'SnapshotCapture': 0x0026,
    'SnapshotDiff': 0x0027,
    'SnapshotChanged': 0x0028,
    'ScanUndo': 0x0029,
    'PtrScanBegin': 0x0030,
    'PtrScanGet': 0x0031,
    'CheatExport': 0x0032,
    'FrozenList': 0x0040,
    'FrozenEnable': 0x0041,
    'FrozenDisable': 0x0042,
    'CheatList': 0x0043,
    'CheatToggle': 0x0044,
    'DebugAttach': 0x0050,
    'DebugDetach': 0x0051,
    'DebugStatus': 0x0052,
    'BreakSet': 0x0053,
    'BreakClear': 0x0054,
    'BreakList': 0x0055,
    'DebugContinue': 0x0056,
    'ThreadList': 0x0057,
    'RegsGet': 0x0058,
    'RegsSet': 0x0059,
    'HitGet': 0x005A,
    'HitClear': 0x005B,
    'DebugStep': 0x005C,
    'Config': 0x0060,
    'LogGet': 0x0061,
    'ProbeRun': 0x0070,
    'ProbeGet': 0x0071,
}

EVT = {
    'HotkeyPaused': 0x8001,
    'AutoResume': 0x8002,
    'BreakHit': 0x8003,
    'ScanProgress': 0x8004,
    'ProcessEvent': 0x8005,
    'Log': 0x8006,
    'DebugEvent': 0x8007,
    'DebugStopped': 0x8008,
}

ST = {
    'NXUS_ST_PAUSED': 0x0001,
    'NXUS_ST_SCANNING': 0x0002,
    'NXUS_ST_HAS_PROCESS': 0x0004,
    'NXUS_ST_DEBUG_MODE': 0x0008,
    'NXUS_ST_DEBUG_ATTACHED': 0x0010,
    'NXUS_ST_DEBUG_STOPPED': 0x0020,
}

MODE = {'NXUS_MODE_DMNT': 0, 'NXUS_MODE_DEBUG': 1}

CMP = {
    'NxusCmp_Equal': 0,
    'NxusCmp_NotEqual': 1,
    'NxusCmp_Greater': 2,
    'NxusCmp_Less': 3,
    'NxusCmp_Increased': 4,
    'NxusCmp_Decreased': 5,
    'NxusCmp_Unchanged': 6,
    'NxusCmp_Changed': 7,
    'NxusCmp_FuzzyEqual': 8,
    'NxusCmp_Between': 9,
    'NxusCmp_Unknown': 10,
    'NxusCmp_GreaterOrEqual': 11,
    'NxusCmp_LessOrEqual': 12,
    'NxusCmp_Different': 13,
}

SCOPE = {
    'NxusScope_All': 0,
    'NxusScope_Main': 1,
    'NxusScope_Heap': 2,
    'NxusScope_Custom': 3,
    'NxusScope_Writable': 4,
    'NxusScope_Tls': 5,
    'NxusScope_Ranges': 6,
}

SCAN_STATE = {
    'NxusScanState_Idle': 0,
    'NxusScanState_Running': 1,
    'NxusScanState_Done': 2,
    'NxusScanState_Error': 3,
    'NxusScanState_Cancelled': 4,
}

SCAN_KIND = {'NxusScanKind_First': 0, 'NxusScanKind_Next': 1}

SCAN_F = {
    'NXUS_SCAN_F_NEW_SESSION': 0x0001,
    'NXUS_SCAN_F_FLOAT': 0x0002,
    'NXUS_SCAN_F_SIGNED': 0x0004,
}

PERM = {'NXUS_PERM_R': 0x1, 'NXUS_PERM_W': 0x2, 'NXUS_PERM_X': 0x4}

BREAK_KIND = {
    'NxusBp_Execute': 0,
    'NxusBp_Write': 1,
    'NxusBp_Read': 2,
    'NxusBp_Access': 3,
}

PROBE = {
    'NxusProbe_DmntInitialize': 1,
    'NxusProbe_DmntHasProcess': 2,
    'NxusProbe_ForceOpen': 3,
    'NxusProbe_GetMetadata': 4,
    'NxusProbe_MappingCount': 5,
    'NxusProbe_ModuleScan': 6,
    'NxusProbe_ReadMain': 7,
    'NxusProbe_ForceClose': 8,
    'NxusProbe_DebugActiveProcess': 9,
    'NxusProbe_DebugAttachResult': 10,
    'NxusProbe_HwbpSetExecute': 11,
    'NxusProbe_HwbpSetWatch': 12,
    'NxusProbe_HwbpEvent': 13,
    'NxusProbe_ReadCores': 14,
    'NxusProbe_FrozenEnable': 15,
    'NxusProbe_FrozenDisable': 16,
    'NxusProbe_ThreadContext': 17,
    'NxusProbe_HidInit': 18,
    'NxusProbe_SdWrite': 19,
    'NxusProbe_Done': 20,
}

RESULT_MODULE = 484
ERR_NOT_IMPLEMENTED = 1
ERR_UNSUPPORTED = 2
ERR_BUSY = 3
ERR_NOT_ATTACHED = 4
ERR_NO_PROCESS = 5
ERR_BAD_STATE = 6
ERR_TOO_LARGE = 7


def make_result(desc: int) -> int:
    return (0x80000000 | ((RESULT_MODULE & 0x1FF) << 9) | (desc & 0x1FF)) & 0xFFFFFFFF


NXUS_MODULE_NAME_MAX = 16
NXUS_MAX_MODULES = 64
NXUS_PROBE_MAX = 32
NXUS_PROBE_NAME_MAX = 48


def pack_header(msg_type: int, flags: int = 0, length: int = 0, seq: int = 0) -> bytes:
    return HEADER.pack(MAGIC, msg_type, flags, length, seq)


def unpack_header(data: bytes):
    """Returns (magic, type, flags, length, seq)."""
    return HEADER.unpack_from(data, 0)


def is_event(msg_type: int, flags: int) -> bool:
    return bool(flags & FLAG_ASYNC) or msg_type >= 0x8000
