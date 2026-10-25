//! Nxus wire protocol - the Rust mirror of core/nxus_protocol.h.
//!
//! Every structure is little-endian and packed exactly like the C side, so the
//! three implementations (sysmodule C, Python reference, this client) agree.

pub const MAGIC: u32 = 0x4E58_5553; // 'NXUS'
pub const PROTO_VERSION: u32 = 0x0001;
pub const DEFAULT_PORT: u16 = 7332;

pub const FLAG_ASYNC: u16 = 0x0001;
pub const FLAG_ERROR: u16 = 0x0002;

pub const HEADER_SIZE: usize = 16;

// ---- commands ----
pub mod cmd {
    pub const NOP: u16 = 0x0000;
    pub const PAUSE: u16 = 0x0001;
    pub const RESUME: u16 = 0x0002;
    pub const HEARTBEAT: u16 = 0x0003;
    pub const GET_STATUS: u16 = 0x0004;
    pub const GET_METADATA: u16 = 0x0005;
    pub const FORCE_OPEN: u16 = 0x0006;
    pub const FORCE_CLOSE: u16 = 0x0007;
    pub const GET_MODULES: u16 = 0x0008;
    pub const GET_PROCESSES: u16 = 0x0009;

    pub const GET_MAPPING_COUNT: u16 = 0x0010;
    pub const GET_MAPPINGS: u16 = 0x0011;
    pub const QUERY: u16 = 0x0012;
    pub const READ: u16 = 0x0013;
    pub const WRITE: u16 = 0x0014;

    pub const SCAN_BEGIN: u16 = 0x0020;
    pub const SCAN_NEXT: u16 = 0x0021;
    pub const SCAN_STATUS: u16 = 0x0022;
    pub const SCAN_CANCEL: u16 = 0x0023;
    pub const SCAN_GET_HITS: u16 = 0x0024;
    pub const SCAN_RESET: u16 = 0x0025;
    pub const SNAPSHOT_CAPTURE: u16 = 0x0026;
    pub const SNAPSHOT_DIFF: u16 = 0x0027;
    pub const SNAPSHOT_CHANGED: u16 = 0x0028;
    pub const SCAN_UNDO: u16 = 0x0029;

    pub const PTRSCAN_BEGIN: u16 = 0x0030;
    pub const PTRSCAN_GET: u16 = 0x0031;
    pub const CHEAT_EXPORT: u16 = 0x0032;

    pub const FROZEN_LIST: u16 = 0x0040;
    pub const FROZEN_ENABLE: u16 = 0x0041;
    pub const FROZEN_DISABLE: u16 = 0x0042;

    // Intentionally undefined here (not an oversight):
    //
    //   NxusCmd_CheatList   = 0x0043
    //   NxusCmd_CheatToggle = 0x0044
    //   NxusCmd_ProbeRun    = 0x0070
    //   NxusCmd_ProbeGet    = 0x0071
    //
    // Those ids exist in core/nxus_protocol.h, but the C server
    // (switch/source/nxus_server.c) has no `case` for any of them: they fall
    // through to `default:` and answer NXUS_ERR_UNSUPPORTED.  Mirroring them as
    // constants would only invite client calls the console must reject, so they
    // stay out until the console implements them.

    pub const DEBUG_ATTACH: u16 = 0x0050;
    pub const DEBUG_DETACH: u16 = 0x0051;
    pub const DEBUG_STATUS: u16 = 0x0052;
    pub const BREAK_SET: u16 = 0x0053;
    pub const BREAK_CLEAR: u16 = 0x0054;
    pub const BREAK_LIST: u16 = 0x0055;
    pub const DEBUG_CONTINUE: u16 = 0x0056;
    pub const THREAD_LIST: u16 = 0x0057;
    pub const REGS_GET: u16 = 0x0058;
    pub const REGS_SET: u16 = 0x0059;
    pub const HIT_GET: u16 = 0x005A;
    pub const HIT_CLEAR: u16 = 0x005B;
    pub const DEBUG_STEP: u16 = 0x005C;

    pub const CONFIG: u16 = 0x0060;
    pub const LOG_GET: u16 = 0x0061;
}

pub mod event {
    pub const HOTKEY_PAUSED: u16 = 0x8001;
    pub const AUTO_RESUME: u16 = 0x8002;
    pub const BREAK_HIT: u16 = 0x8003;
    pub const SCAN_PROGRESS: u16 = 0x8004;
    pub const PROCESS_EVENT: u16 = 0x8005;
    pub const LOG: u16 = 0x8006;
    pub const DEBUG_EVENT: u16 = 0x8007;
    /// The target stopped on a breakpoint and is held (auto_continue == 0).
    pub const DEBUG_STOPPED: u16 = 0x8008;
}

// ---- status flags (NXUS_ST_*) ----
pub const ST_PAUSED: u32 = 0x0001;
pub const ST_SCANNING: u32 = 0x0002;
pub const ST_HAS_PROCESS: u32 = 0x0004;
pub const ST_DEBUG_MODE: u32 = 0x0008;
pub const ST_DEBUG_ATTACHED: u32 = 0x0010;
/// A debug breakpoint hit is holding the target (see NxusEvent_DebugStopped).
pub const ST_DEBUG_STOPPED: u32 = 0x0020;

// ---- enums ----
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Compare {
    Equal = 0,
    NotEqual = 1,
    Greater = 2,
    Less = 3,
    Increased = 4,
    Decreased = 5,
    Unchanged = 6,
    Changed = 7,
    FuzzyEqual = 8,
    Between = 9,
    Unknown = 10,
    GreaterOrEqual = 11,
    LessOrEqual = 12,
    Different = 13,
}

impl Compare {
    pub fn parse(text: &str) -> Option<Compare> {
        match text.to_ascii_lowercase().as_str() {
            "equal" | "eq" | "=" => Some(Compare::Equal),
            "not-equal" | "ne" | "!=" => Some(Compare::NotEqual),
            "greater" | "gt" | ">" => Some(Compare::Greater),
            "less" | "lt" | "<" => Some(Compare::Less),
            "greater-equal" | "greater-or-equal" | "ge" | "gte" | ">=" => Some(Compare::GreaterOrEqual),
            "less-equal" | "less-or-equal" | "le" | "lte" | "<=" => Some(Compare::LessOrEqual),
            "increased" | "inc" | "+" => Some(Compare::Increased),
            "decreased" | "dec" | "-" => Some(Compare::Decreased),
            "unchanged" | "same" => Some(Compare::Unchanged),
            "changed" | "diff" => Some(Compare::Changed),
            "different" | "changed-by" | "delta" => Some(Compare::Different),
            "fuzzy" => Some(Compare::FuzzyEqual),
            "between" | "range" => Some(Compare::Between),
            "unknown" | "unknown-initial" => Some(Compare::Unknown),
            _ => None,
        }
    }
}

/// Cheat Engine style value types (mirrors NxusValueType in nxus_protocol.h).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ValueType {
    U8 = 0,
    U16 = 1,
    U32 = 2,
    U64 = 3,
    F32 = 4,
    F64 = 5,
    Str = 6,
    Bytes = 7,
    Binary = 8,
    All = 9,
}

pub const VALUE_TYPE_NAMES: [(&str, ValueType); 10] = [
    ("Byte", ValueType::U8),
    ("2 Bytes", ValueType::U16),
    ("4 Bytes", ValueType::U32),
    ("8 Bytes", ValueType::U64),
    ("Float", ValueType::F32),
    ("Double", ValueType::F64),
    ("String", ValueType::Str),
    ("Array of byte", ValueType::Bytes),
    ("Binary", ValueType::Binary),
    ("All", ValueType::All),
];

impl ValueType {
    pub fn size(self) -> u32 {
        match self {
            ValueType::U8 => 1,
            ValueType::U16 => 2,
            ValueType::U32 | ValueType::F32 => 4,
            ValueType::U64 | ValueType::F64 => 8,
            _ => 4,             // pattern types carry their own length
        }
    }

    pub fn is_pattern(self) -> bool {
        matches!(self, ValueType::Str | ValueType::Bytes | ValueType::Binary)
    }

    pub fn is_float(self) -> bool {
        matches!(self, ValueType::F32 | ValueType::F64)
    }

    pub fn name(self) -> &'static str {
        VALUE_TYPE_NAMES.iter().find(|(_, t)| *t == self).map(|(n, _)| *n).unwrap_or("?")
    }

    pub fn parse(text: &str) -> Option<ValueType> {
        match text.to_ascii_lowercase().as_str() {
            "u8" | "byte" | "1" => Some(ValueType::U8),
            "u16" | "2bytes" | "2" => Some(ValueType::U16),
            "u32" | "4bytes" | "4" | "int" => Some(ValueType::U32),
            "u64" | "8bytes" | "8" => Some(ValueType::U64),
            "f32" | "float" => Some(ValueType::F32),
            "f64" | "double" => Some(ValueType::F64),
            "str" | "string" => Some(ValueType::Str),
            "bytes" | "array" | "aob" => Some(ValueType::Bytes),
            "binary" | "bits" => Some(ValueType::Binary),
            "all" => Some(ValueType::All),
            _ => None,
        }
    }
}

// NXUS_SCAN_F_*
pub const SCAN_F_HEX: u32 = 0x0008;
pub const SCAN_F_CASE_INSENS: u32 = 0x0010;
pub const SCAN_F_UTF16: u32 = 0x0020;
pub const SCAN_F_WILDCARD: u32 = 0x0040;
pub const SCAN_F_ALIGNED: u32 = 0x0080;
/// C: NXUS_SCAN_F_RANGES - a range list follows the request (ScanSpec::ranges).
pub const SCAN_F_RANGES: u32 = 0x0100;
/// Wire sizes of the range list that NXUS_SCAN_F_RANGES introduces.
pub const RANGE_LIST_HEADER_SIZE: usize = 8;
pub const RANGE_ENTRY_SIZE: usize = 16;
pub const MAX_SCAN_RANGES: usize = 16;
/// C: NXUS_SCAN_F_NEW_SESSION (0x0001). Numeric scans always walk absolute
/// multiples of the value size, so ALIGNED cannot change their result.
pub const SCAN_F_NEW_SESSION: u32 = 0x0001;
pub const SCAN_F_FLOAT: u32 = 0x0002;
pub const SCAN_F_SIGNED: u32 = 0x0004;
pub const SCAN_MAX_PATTERN: usize = 64;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Scope {
    All = 0,
    Main = 1,
    Heap = 2,
    Custom = 3,
    Writable = 4,
    Tls = 5,
    /// Scan the union of ScanSpec::ranges (server-side region list).
    Ranges = 6,
}

impl Scope {
    pub fn parse(text: &str) -> Option<Scope> {
        match text.to_ascii_lowercase().as_str() {
            "all" => Some(Scope::All),
            "main" => Some(Scope::Main),
            "heap" => Some(Scope::Heap),
            "custom" => Some(Scope::Custom),
            "writable" | "rw" => Some(Scope::Writable),
            "tls" | "thread-local" => Some(Scope::Tls),
            "ranges" | "list" | "multi" => Some(Scope::Ranges),
            _ => None,
        }
    }
}

pub mod scan_state {
    pub const IDLE: u32 = 0;
    pub const RUNNING: u32 = 1;
    pub const DONE: u32 = 2;
    pub const ERROR: u32 = 3;
    pub const CANCELLED: u32 = 4;

    pub fn name(state: u32) -> &'static str {
        match state {
            IDLE => "idle",
            RUNNING => "running",
            DONE => "done",
            ERROR => "error",
            CANCELLED => "cancelled",
            _ => "unknown",
        }
    }
}

pub mod break_kind {
    pub const EXECUTE: u32 = 0;
    pub const WRITE: u32 = 1;
    pub const READ: u32 = 2;
    pub const ACCESS: u32 = 3;

    pub fn parse(text: &str) -> Option<u32> {
        match text.to_ascii_lowercase().as_str() {
            "exec" | "execute" | "x" => Some(EXECUTE),
            "write" | "w" => Some(WRITE),
            "read" | "r" => Some(READ),
            "access" | "rw" | "a" => Some(ACCESS),
            _ => None,
        }
    }

    pub fn name(kind: u32) -> &'static str {
        match kind {
            EXECUTE => "exec",
            WRITE => "write",
            READ => "read",
            ACCESS => "access",
            _ => "?",
        }
    }
}

pub const PERM_R: u32 = 0x1;
pub const PERM_W: u32 = 0x2;
pub const PERM_X: u32 = 0x4;
pub const MEMTYPE_HEAP: u32 = 5;
pub const MEMTYPE_TLS: u32 = 0x0C;

pub const WATCH_STYLE_PLAIN: u32 = 0;
pub const WATCH_STYLE_LINK5: u32 = 1;
pub const WATCH_STYLE_LINK6: u32 = 2;
pub const CHEAT_F_32BIT: u32 = 0x0001;

pub const SNAPSHOT_DEFAULT_BLOCK_SIZE: u32 = 16384;
pub const CHANGE_CHANGED: u32 = 0;
pub const CHANGE_VANISHED: u32 = 1;
pub const CHANGE_APPEARED: u32 = 2;

// ---- small LE helpers ----
pub fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}
pub fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
pub fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Copy `N` little-endian bytes at `off`, or `None` when they are not all there.
fn read_le<const N: usize>(data: &[u8], off: usize) -> Option<[u8; N]> {
    // `checked_add` first: a caller-supplied offset near `usize::MAX` must not
    // wrap around into a valid-looking (and in-bounds) range.
    let end = off.checked_add(N)?;
    let slice = data.get(off..end)?;
    let mut buf = [0u8; N];
    buf.copy_from_slice(slice);
    Some(buf)
}

/// Bounds-checked little-endian readers.
///
/// Every payload decoded in this file comes from the console - or from whatever
/// else happens to answer on that port - and a truncated reply used to index
/// past the end of the slice.  That panic kills a GUI worker thread, which then
/// never reports back, leaving the GUI on "busy" forever, so a missing tail is
/// decoded as zeroes instead.
///
/// `rd_u16` / `rd_u32` / `rd_u64` keep their signatures: callers that want to
/// distinguish a short payload test `data.len()` before the call.
pub fn rd_u16(data: &[u8], off: usize) -> u16 {
    read_le::<2>(data, off).map(u16::from_le_bytes).unwrap_or(0)
}
pub fn rd_u32(data: &[u8], off: usize) -> u32 {
    read_le::<4>(data, off).map(u32::from_le_bytes).unwrap_or(0)
}
pub fn rd_u64(data: &[u8], off: usize) -> u64 {
    read_le::<8>(data, off).map(u64::from_le_bytes).unwrap_or(0)
}
/// `Some(value)` only when all four bytes are present.
pub fn rd_u32_checked(data: &[u8], off: usize) -> Option<u32> {
    read_le::<4>(data, off).map(u32::from_le_bytes)
}
/// `Some(value)` only when all eight bytes are present.
pub fn rd_u64_checked(data: &[u8], off: usize) -> Option<u64> {
    read_le::<8>(data, off).map(u64::from_le_bytes)
}

// ---- decoded structures ----

#[derive(Debug, Clone, Default)]
pub struct Status {
    pub proto_version: u32,
    pub mode: u32,
    pub status_flags: u32,
    pub scan_state: u32,
    pub process_id: u64,
    pub program_id: u64,
    pub main_base: u64,
    pub main_size: u64,
    pub hit_count: u32,
    pub progress_permille: u32,
    pub last_result: i32,
    pub uptime_ms: u32,
    pub heap_used: u32,
    pub heap_total: u32,
    /// Largest single Read the server accepts (0 = unspecified: use the default).
    pub max_read: u32,
}

impl Status {
    pub const SIZE: usize = 76;
    pub fn parse(data: &[u8]) -> Status {
        Status {
            proto_version: rd_u32(data, 0),
            mode: rd_u32(data, 4),
            status_flags: rd_u32(data, 8),
            scan_state: rd_u32(data, 12),
            process_id: rd_u64(data, 16),
            program_id: rd_u64(data, 24),
            main_base: rd_u64(data, 32),
            main_size: rd_u64(data, 40),
            hit_count: rd_u32(data, 48),
            progress_permille: rd_u32(data, 52),
            last_result: rd_u32(data, 56) as i32,
            uptime_ms: rd_u32(data, 60),
            heap_used: rd_u32(data, 64),
            heap_total: rd_u32(data, 68),
            max_read: rd_u32(data, 72),
        }
    }
    pub fn paused(&self) -> bool {
        self.status_flags & ST_PAUSED != 0
    }
    pub fn scanning(&self) -> bool {
        self.status_flags & ST_SCANNING != 0
    }
    pub fn has_process(&self) -> bool {
        self.status_flags & ST_HAS_PROCESS != 0
    }
    pub fn debug_mode(&self) -> bool {
        self.status_flags & ST_DEBUG_MODE != 0
    }
    pub fn debug_attached(&self) -> bool {
        self.status_flags & ST_DEBUG_ATTACHED != 0
    }
    /// A breakpoint hit is holding the target (the thread itself is reported by
    /// NxusDebugStatus.stopped_thread_low, which `Client::debug_stopped_thread`
    /// reads).
    pub fn debug_stopped(&self) -> bool {
        self.status_flags & ST_DEBUG_STOPPED != 0
    }
}

#[derive(Debug, Clone, Default)]
pub struct Metadata {
    pub process_id: u64,
    pub program_id: u64,
    pub main_base: u64,
    pub main_size: u64,
    pub heap_base: u64,
    pub heap_size: u64,
    pub alias_base: u64,
    pub alias_size: u64,
    pub aslr_base: u64,
    pub aslr_size: u64,
    pub build_id: [u8; 0x20],
}

impl Metadata {
    pub const SIZE: usize = 0x70;
    /// A short reply decodes with zeroes for the missing tail; `NxusClient::metadata`
    /// rejects anything under `SIZE` before it gets here.
    pub fn parse(data: &[u8]) -> Metadata {
        let mut build_id = [0u8; 0x20];
        if let Some(src) = data.get(0x50..0x70) {
            build_id.copy_from_slice(src);
        }
        Metadata {
            process_id: rd_u64(data, 0),
            program_id: rd_u64(data, 8),
            main_base: rd_u64(data, 16),
            main_size: rd_u64(data, 24),
            heap_base: rd_u64(data, 32),
            heap_size: rd_u64(data, 40),
            alias_base: rd_u64(data, 48),
            alias_size: rd_u64(data, 56),
            aslr_base: rd_u64(data, 64),
            aslr_size: rd_u64(data, 72),
            build_id,
        }
    }
    pub fn build_id_hex(&self) -> String {
        self.build_id.iter().take(8).map(|b| format!("{:02x}", b)).collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct MemoryInfo {
    pub base: u64,
    pub size: u64,
    pub memory_type: u32,
    pub attr: u32,
    pub perm: u32,
}

impl MemoryInfo {
    pub const SIZE: usize = 0x28;
    pub fn parse(data: &[u8]) -> MemoryInfo {
        MemoryInfo {
            base: rd_u64(data, 0),
            size: rd_u64(data, 8),
            memory_type: rd_u32(data, 16),
            attr: rd_u32(data, 20),
            perm: rd_u32(data, 24),
        }
    }
    pub fn perms(&self) -> String {
        let mut s = String::new();
        s.push(if self.perm & PERM_R != 0 { 'r' } else { '-' });
        s.push(if self.perm & PERM_W != 0 { 'w' } else { '-' });
        s.push(if self.perm & PERM_X != 0 { 'x' } else { '-' });
        s
    }
}

#[derive(Debug, Clone)]
pub struct Hit {
    pub address: u64,
    pub mapping_idx: u16,
    /// NxusValueType of this hit ("All" scans mix types).
    pub value_type: u16,
    pub value: u64,
}

impl Hit {
    /// Renders the value the way the value type implies.
    pub fn display_value(&self, fallback_size: u32) -> String {
        let kind = VALUE_TYPE_NAMES.iter().find(|(_, t)| *t as u16 == self.value_type).map(|(_, t)| *t);
        match kind {
            Some(ValueType::F32) => format!("{}", f32::from_bits(self.value as u32)),
            Some(ValueType::F64) => format!("{}", f64::from_bits(self.value)),
            Some(ValueType::Str) | Some(ValueType::Bytes) | Some(ValueType::Binary) => {
                format!("{:016X}", self.value)      // FNV-1a of the matched bytes
            }
            Some(ValueType::U8) => format!("{}", self.value as u8),
            Some(ValueType::U16) => format!("{}", self.value as u16),
            Some(ValueType::U32) => format!("{}", self.value as u32),
            Some(ValueType::U64) => format!("{}", self.value),
            _ => match fallback_size {
                1 => format!("{}", self.value as u8),
                2 => format!("{}", self.value as u16),
                8 => format!("{}", self.value),
                _ => format!("{}", self.value as u32),
            },
        }
    }
}

/// `NxusHitBatchHeader.reserved` bit 0: the console filled its hit list, so the
/// reply may not contain every match.  Mirrors NXUS_HITBATCH_TRUNCATED in
/// core/nxus_protocol.h.
pub const NXUS_HITBATCH_TRUNCATED: u32 = 0x0001;

#[derive(Debug, Clone)]
pub struct HitBatch {
    pub session_id: u32,
    pub total: u32,
    pub value_size: u32,
    /// The console hit its hit-list capacity, so the list may be incomplete.
    pub truncated: bool,
    pub hits: Vec<Hit>,
}

impl HitBatch {
    /// Fixed header of a `NxusHitBatch` reply: session, count, total, value size,
    /// mapping count, reserved.
    pub const HEADER_SIZE: usize = 24;
    /// Wire size of one `NxusHit` record (offset, mapping index, value type, value).
    pub const HIT_SIZE: usize = 16;

    pub fn empty() -> HitBatch {
        HitBatch { session_id: 0, total: 0, value_size: 0, truncated: false, hits: Vec::new() }
    }

    /// Decode a `SCAN_GET_HITS` reply.
    ///
    /// Never panics and never trusts the counts blindly: the mapping table and
    /// the hit records are limited to the bytes actually present (so a corrupt
    /// or hostile `count` cannot turn into a multi-gigabyte `Vec::with_capacity`),
    /// and a mapping index outside the table decodes as base 0.  A reply shorter
    /// than the header yields an empty batch.
    pub fn parse(data: &[u8]) -> HitBatch {
        if data.len() < Self::HEADER_SIZE {
            return HitBatch::empty();
        }
        let session_id = rd_u32(data, 0);
        let total = rd_u32(data, 8);
        let value_size = rd_u32(data, 12);
        // Bit 0 marks "the console filled its hit list, results may be cut off".
        let truncated = (rd_u32(data, 20) & NXUS_HITBATCH_TRUNCATED) != 0;
        let mut pos = Self::HEADER_SIZE;

        let mapping_count = (rd_u32(data, 16) as usize).min((data.len() - pos) / 8);
        let mut bases = Vec::with_capacity(mapping_count);
        for _ in 0..mapping_count {
            bases.push(rd_u64(data, pos));
            pos += 8;
        }

        let count = (rd_u32(data, 4) as usize).min((data.len() - pos) / Self::HIT_SIZE);
        let mut hits = Vec::with_capacity(count);
        for _ in 0..count {
            let off = rd_u32(data, pos);
            let mapping_idx = rd_u16(data, pos + 4);
            let value_type = rd_u16(data, pos + 6);
            let value = rd_u64(data, pos + 8);
            pos += Self::HIT_SIZE;
            let base = bases.get(mapping_idx as usize).copied().unwrap_or(0);
            hits.push(Hit {
                address: base.wrapping_add(off as u64),
                mapping_idx,
                value_type,
                value,
            });
        }
        HitBatch { session_id, total, value_size, truncated, hits }
    }
}

#[derive(Debug, Clone)]
pub struct PtrChain {
    pub root_offset: u32,
    pub final_offset: u32,
    pub steps: Vec<u32>,
}

/// One entry of a `FROZEN_LIST` reply (C: `NxusFrozenEntry`).
///
/// `core/nxus_protocol.h` declares it as
/// `typedef struct NXUS_PACKED { u64 address; u64 value; u32 width; u32 reserved; }`,
/// so one record is 24 bytes on the wire (`pc/nxus/protocol.py` agrees:
/// `struct.Struct('<QQII')`).  The trailing `reserved` word has no field here -
/// it only pads the stride and is always zero from the server - but it must be
/// counted in [`FrozenEntry::SIZE`] or every entry after the first decodes
/// shifted by 4 bytes.
#[derive(Debug, Clone, Default)]
pub struct FrozenEntry {
    pub address: u64,
    /// Value the console is holding the address at (the frozen value).
    pub value: u64,
    /// Frozen width in bytes (1/2/4/8), the same field `FrozenEnable` takes.
    pub width: u32,
}

impl FrozenEntry {
    /// Wire stride = `sizeof(NxusFrozenEntry)` = address + value + width + reserved.
    pub const SIZE: usize = 24;

    pub fn parse(data: &[u8]) -> FrozenEntry {
        FrozenEntry {
            address: rd_u64(data, 0),
            value: rd_u64(data, 8),
            width: rd_u32(data, 16),
            // data[20..24] is the reserved word: skipped on purpose.
        }
    }
}

/// Decode a `FROZEN_LIST` reply.
///
/// The C server (`NxusCmd_FrozenList` in switch/source/nxus_server.c) answers
/// with a plain `NxusFrozenEntry[]` whose length is `count * sizeof(NxusFrozenEntry)`;
/// there is no count field in the reply, so the entry count is the payload
/// length divided by the stride.  `chunks_exact` drops a trailing partial
/// record: a cut-off reply yields the complete entries it does contain instead
/// of a half-decoded last one.
pub fn parse_frozen_list(data: &[u8]) -> Vec<FrozenEntry> {
    data.chunks_exact(FrozenEntry::SIZE).map(FrozenEntry::parse).collect()
}

#[derive(Debug, Clone, Default)]
pub struct DebugStatus {
    pub attached: bool,
    pub watch_style: u32,
    pub break_count: u32,
    pub hit_count: u32,
    pub thread_count: u32,
    pub last_result: i32,
    pub auto_continue: u32,
    /// Low 32 bits of the thread held at a breakpoint (0 = nothing held).  The
    /// C header calls this `stopped_thread_low`; the thread id is a u64, so the
    /// wire status only carries the half that fits.
    pub stopped_thread_low: u32,
}

impl DebugStatus {
    pub const SIZE: usize = 32;
    pub fn parse(data: &[u8]) -> DebugStatus {
        let mut status = DebugStatus {
            attached: rd_u32(data, 0) != 0,
            watch_style: rd_u32(data, 4),
            break_count: rd_u32(data, 8),
            hit_count: rd_u32(data, 12),
            thread_count: rd_u32(data, 16),
            ..Default::default()
        };
        if data.len() >= 24 {
            status.last_result = rd_u32(data, 20) as i32;
        }
        if data.len() >= 28 {
            status.auto_continue = rd_u32(data, 24);
        }
        if data.len() >= Self::SIZE {
            status.stopped_thread_low = rd_u32(data, 28);
        }
        status
    }

    /// Thread currently held at a breakpoint, or None when the target runs.
    pub fn stopped_thread(&self) -> Option<u64> {
        match self.stopped_thread_low {
            0 => None,
            low => Some(low as u64),
        }
    }
}

/// NxusEvent_DebugStopped payload (C: `NxusDebugStop`, 32 bytes): the console
/// holds the target after a breakpoint hit, and this says which thread stopped
/// and where.
#[derive(Debug, Clone, Default)]
pub struct DebugStop {
    pub thread_id: u64,
    pub pc: u64,
    /// Trapped data address (watchpoints); 0 for an execute breakpoint.
    pub address: u64,
    pub kind: u32,
    pub slot: u32,
}

impl DebugStop {
    pub const SIZE: usize = 32;
    pub fn parse(data: &[u8]) -> DebugStop {
        DebugStop {
            thread_id: rd_u64(data, 0),
            pc: rd_u64(data, 8),
            address: rd_u64(data, 16),
            kind: rd_u32(data, 24),
            slot: rd_u32(data, 28),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BreakEntry {
    pub slot: u32,
    pub kind: u32,
    pub size: u32,
    pub enabled: bool,
    pub address: u64,
    pub ctrl: u64,
}

impl BreakEntry {
    pub const SIZE: usize = 32;
    pub fn parse(data: &[u8]) -> BreakEntry {
        BreakEntry {
            slot: rd_u32(data, 0),
            kind: rd_u32(data, 4),
            size: rd_u32(data, 8),
            enabled: rd_u32(data, 12) != 0,
            address: rd_u64(data, 16),
            ctrl: rd_u64(data, 24),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BreakHit {
    pub index: u32,
    pub kind: u32,
    pub slot: u32,
    pub thread_id_low: u32,
    pub address: u64,
    pub pc: u64,
    pub lr: u64,
    pub sp: u64,
    pub cpsr: u32,
    pub regs: [u32; 13],
    pub tick: u64,
}

impl BreakHit {
    pub const SIZE: usize = 112;
    pub fn parse(data: &[u8]) -> BreakHit {
        let mut regs = [0u32; 13];
        for (i, slot) in regs.iter_mut().enumerate() {
            *slot = rd_u32(data, 52 + i * 4);
        }
        BreakHit {
            index: rd_u32(data, 0),
            kind: rd_u32(data, 4),
            slot: rd_u32(data, 8),
            thread_id_low: rd_u32(data, 12),
            address: rd_u64(data, 16),
            pc: rd_u64(data, 24),
            lr: rd_u64(data, 32),
            sp: rd_u64(data, 40),
            cpsr: rd_u32(data, 48),
            regs,
            tick: rd_u64(data, 104),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ThreadEntry {
    pub thread_id: u64,
    pub state: u32,
    pub priority: u32,
    pub core: u32,
}

impl ThreadEntry {
    pub const SIZE: usize = 24;
    pub fn parse(data: &[u8]) -> ThreadEntry {
        ThreadEntry {
            thread_id: rd_u64(data, 0),
            state: rd_u32(data, 8),
            priority: rd_u32(data, 12),
            core: rd_u32(data, 16),
        }
    }
}

// NXUS_THREADCTX_FLAG_* - bits of `NxusThreadContext.reserved`.  The word is a
// bit set, not padding, and the two directions reuse it:
//
//   * RegsSet (PC -> console) understands bit 0 only: "x[0..28] is
//     authoritative", i.e. [ThreadContext::encode] sent the 64-bit view rather
//     than the r[] alias.  Both PC encoders hard-code it.
//   * GetRegs (console -> PC) sets bit 1 for an AArch32 context.  Bit 0 already
//     means the request thing, so AArch32 had to take the next bit - a 32-bit
//     title therefore reports a reply with bit 1 set and bit 0 clear.
//
// A 32-bit reply leaves the sp/lr/fp header fields zeroed; the live values are
// cpu_gprs[13] / cpu_gprs[14] / cpu_gprs[11], which nxusDebugGetRegs() mirrors
// into x[13] / x[14] / x[11] (r13/r14/r11 in AArch32 terms).
pub const NXUS_THREADCTX_FLAG_X_AUTHORITATIVE: u32 = 0x0001;
pub const NXUS_THREADCTX_FLAG_AARCH32: u32 = 0x0002;

#[derive(Debug, Clone)]
pub struct ThreadContext {
    pub thread_id: u64,
    pub pc: u64,
    pub lr: u64,
    pub sp: u64,
    pub fp: u64,
    pub cpsr: u32,
    pub r: [u32; 13],
    /// `NxusThreadContext.reserved`: NXUS_THREADCTX_FLAG_* bits.
    pub flags: u32,
    pub x: [u64; 29],
}

impl Default for ThreadContext {
    fn default() -> Self {
        ThreadContext {
            thread_id: 0,
            pc: 0,
            lr: 0,
            sp: 0,
            fp: 0,
            cpsr: 0,
            r: [0u32; 13],
            flags: 0,
            x: [0u64; 29],
        }
    }
}

impl ThreadContext {
    pub const SIZE: usize = 332;
    /// Offset of `reserved` (the flag word): after cpsr + the 13 r[] words.
    pub const FLAGS_OFFSET: usize = 96;

    pub fn parse(data: &[u8]) -> ThreadContext {
        let mut r = [0u32; 13];
        for (i, slot) in r.iter_mut().enumerate() {
            *slot = rd_u32(data, 44 + i * 4);
        }
        let mut x = [0u64; 29];
        if data.len() >= Self::SIZE {
            for (i, slot) in x.iter_mut().enumerate() {
                *slot = rd_u64(data, 100 + i * 8);
            }
        } else {
            for i in 0..13 {
                x[i] = r[i] as u64;
            }
        }
        ThreadContext {
            thread_id: rd_u64(data, 0),
            pc: rd_u64(data, 8),
            lr: rd_u64(data, 16),
            sp: rd_u64(data, 24),
            fp: rd_u64(data, 32),
            cpsr: rd_u32(data, 40),
            r,
            // Short replies (down to the 96 bytes regs_get accepts) decode as 0,
            // which is "no flags" - i.e. never a made-up AArch32 context.
            flags: rd_u32(data, Self::FLAGS_OFFSET),
            x,
        }
    }

    /// Did GetRegs report an AArch32 (32-bit) context?
    ///
    /// When true the sp/lr/fp header fields are zero on purpose and the live
    /// values live in [`ThreadContext::x`] at 13/14/11 (r13/r14/r11).
    pub fn is_aarch32(&self) -> bool {
        self.flags & NXUS_THREADCTX_FLAG_AARCH32 != 0
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SIZE);
        put_u64(&mut out, self.thread_id);
        put_u64(&mut out, self.pc);
        put_u64(&mut out, self.lr);
        put_u64(&mut out, self.sp);
        put_u64(&mut out, self.fp);
        put_u32(&mut out, self.cpsr);
        for i in 0..13 {
            put_u32(&mut out, (self.x[i] & 0xFFFF_FFFF) as u32);
        }
        // RegsSet direction: x[0..28] is authoritative.  NXUS_THREADCTX_FLAG_AARCH32
        // is a reply-only bit, so it is not echoed back here.
        put_u32(&mut out, NXUS_THREADCTX_FLAG_X_AUTHORITATIVE);
        for &val in &self.x {
            put_u64(&mut out, val);
        }
        out
    }
}

// =========================================================================
// Disassembler (AArch64 / AArch32 / Thumb-16 / Thumb-2)
// -------------------------------------------------------------------------
// Decodes the shapes that show up around a breakpoint or watchpoint hit: data
// processing, loads/stores, branches, stack traffic and system instructions.
// The goal is GDB-like text, not complete architectural coverage; anything that
// is not recognised comes out as `.word 0x...` (`.short 0x...` for Thumb-16) so
// a wrong decode is always obvious.
// =========================================================================

/// ARM (AArch32) condition suffixes, indexed by the 4-bit condition field.
/// 0xE means "always" and therefore prints no suffix at all.
const ARM_COND: [&str; 16] = [
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "", "nv",
];

/// AArch64 condition suffixes (hs/lo instead of cs/cc, al instead of none).
const ARM64_COND: [&str; 16] = [
    "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
];

const ARM_REGS: [&str; 13] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
];

fn arm_reg(n: u32) -> &'static str {
    match n {
        0..=12 => ARM_REGS[n as usize],
        13 => "sp",
        14 => "lr",
        _ => "pc",
    }
}

/// Sign-extend the low `bits` bits of `v` to 64 bits.
fn sext(v: u32, bits: u32) -> i64 {
    let sh = 64 - bits;
    (((v as u64) << sh) as i64) >> sh
}

/// Render an offset the way objdump/GDB do (`#0x4`, `#-0x4`).
fn fmt_off(v: i64) -> String {
    if v < 0 {
        format!("#-{:#x}", -v)
    } else {
        format!("#{:#x}", v)
    }
}

/// Render `[Rn]`, `[Rn, off]`, `[Rn, off]!` or `[Rn], off` (P/W addressing).
fn arm_mem(p: bool, w: bool, rn: u32, off: Option<&str>) -> String {
    let base = arm_reg(rn);
    match off {
        None => format!("[{}]", base),
        Some(o) => {
            if p {
                if w {
                    format!("[{}, {}]!", base, o)
                } else {
                    format!("[{}, {}]", base, o)
                }
            } else {
                format!("[{}], {}", base, o)
            }
        }
    }
}

/// Operand-2 of a data-processing instruction.  The same bit layout carries the
/// (shifted) register offset of LDR/STR, so both share this helper.
fn arm_shift_operand(word: u32) -> String {
    let rm = word & 0xF;
    let st = (word >> 5) & 3;
    let imm5 = (word >> 7) & 0x1F;
    let by_reg = ((word >> 4) & 1) != 0;
    if by_reg {
        let rs = (word >> 8) & 0xF;
        let name = match st {
            0 => "lsl",
            1 => "lsr",
            2 => "asr",
            _ => "ror",
        };
        return format!("{}, {} {}", arm_reg(rm), name, arm_reg(rs));
    }
    match st {
        0 => {
            if imm5 == 0 {
                arm_reg(rm).to_string()
            } else {
                format!("{}, lsl #{}", arm_reg(rm), imm5)
            }
        }
        1 => {
            let amt = if imm5 == 0 { 32 } else { imm5 };
            format!("{}, lsr #{}", arm_reg(rm), amt)
        }
        2 => {
            let amt = if imm5 == 0 { 32 } else { imm5 };
            format!("{}, asr #{}", arm_reg(rm), amt)
        }
        _ => {
            if imm5 == 0 {
                format!("{}, rrx", arm_reg(rm))
            } else {
                format!("{}, ror #{}", arm_reg(rm), imm5)
            }
        }
    }
}

fn arm_operand2(word: u32) -> String {
    if ((word >> 25) & 1) != 0 {
        // rotated 8-bit immediate: imm8 ROR (rot * 2)
        let imm8 = word & 0xFF;
        let rot = ((word >> 8) & 0xF) * 2;
        return fmt_off(imm8.rotate_right(rot) as i64);
    }
    arm_shift_operand(word)
}

fn arm_reg_list(mask: u32) -> String {
    let mut parts: Vec<&'static str> = Vec::new();
    for i in 0..16u32 {
        if (mask >> i) & 1 != 0 {
            parts.push(arm_reg(i));
        }
    }
    format!("{{{}}}", parts.join(", "))
}

// -------------------------------------------------------------------------
// AArch32
// -------------------------------------------------------------------------

fn disasm_aarch32(pc: u64, word: u32) -> String {
    let cond = word >> 28;
    // Unconditional encodings (cond == 0b1111) share this space.
    if cond == 0xF {
        // BLX (immediate): 1111 101H imm24
        if (word & 0x0E00_0000) == 0x0A00_0000 && (word & 0x0100_0000) != 0 {
            let h = ((word >> 24) & 1) as i64;
            let off = (sext(word & 0x00FF_FFFF, 24) << 2) | (h << 1);
            let target = pc.wrapping_add(8).wrapping_add(off as u64);
            return format!("blx {:#x}", target);
        }
        return format!(".word 0x{:08X}", word);
    }
    let cs = if cond == 0xE { "" } else { ARM_COND[cond as usize] };

    // Well-known spellings that carry no operands worth decoding.
    if word == 0xE320F000 || word == 0xE1A00000 {
        return "nop".to_string();
    }

    // ---- SVC ------------------------------------------------------------
    if (word & 0x0F00_0000) == 0x0F00_0000 {
        return format!("svc{} {}", cs, fmt_off((word & 0x00FF_FFFF) as i64));
    }

    // ---- B / BL ---------------------------------------------------------
    if (word & 0x0E00_0000) == 0x0A00_0000 {
        let link = (word & 0x0100_0000) != 0;
        let off = sext(word & 0x00FF_FFFF, 24) << 2;
        let target = pc.wrapping_add(8).wrapping_add(off as u64);
        return format!("{}{} {:#x}", if link { "bl" } else { "b" }, cs, target);
    }

    // ---- BX / BLX (register) -------------------------------------------
    if (word & 0x0FFF_FFF0) == 0x012F_FF10 {
        return format!("bx{} {}", cs, arm_reg(word & 0xF));
    }
    if (word & 0x0FFF_FFF0) == 0x012F_FF30 {
        return format!("blx{} {}", cs, arm_reg(word & 0xF));
    }

    // ---- MOVW / MOVT ----------------------------------------------------
    let wide = word & 0x0FF0_0000;
    if wide == 0x0300_0000 || wide == 0x0340_0000 {
        let movt = wide == 0x0340_0000;
        let imm16 = (word & 0xFFF) | (((word >> 16) & 0xF) << 12);
        let rd = (word >> 12) & 0xF;
        return format!(
            "{}{} {}, {}",
            if movt { "movt" } else { "movw" },
            cs,
            arm_reg(rd),
            fmt_off(imm16 as i64)
        );
    }

    // ---- MUL / MLA / MLS ------------------------------------------------
    if (word & 0x0F00_00F0) == 0x0000_0090 && (word & 0x60) == 0 {
        let op = (word >> 21) & 0x7;
        let sets_flags = ((word >> 20) & 1) != 0;
        let ss = if sets_flags { "s" } else { "" };
        let rd = (word >> 16) & 0xF;
        let rs = (word >> 8) & 0xF;
        let rm = word & 0xF;
        match op {
            0 if ((word >> 12) & 0xF) == 0 => {
                return format!("mul{}{} {}, {}, {}", ss, cs, arm_reg(rd), arm_reg(rm), arm_reg(rs));
            }
            1 => {
                let rn = (word >> 12) & 0xF;
                return format!(
                    "mla{}{} {}, {}, {}, {}",
                    ss, cs, arm_reg(rd), arm_reg(rm), arm_reg(rs), arm_reg(rn)
                );
            }
            3 if !sets_flags => {
                let ra = (word >> 12) & 0xF;
                return format!(
                    "mls{} {}, {}, {}, {}",
                    cs, arm_reg(rd), arm_reg(rm), arm_reg(rs), arm_reg(ra)
                );
            }
            _ => {}
        }
    }

    // ---- UDF ------------------------------------------------------------
    // cond 0111 1111 imm12 1111 imm4  (the 12-bit immediate sits at bits 19-8)
    if (word & 0x0FF0_00F0) == 0x07F0_00F0 {
        let imm = (((word >> 8) & 0xFFF) << 4) | (word & 0xF);
        return format!("udf{} {}", cs, fmt_off(imm as i64));
    }

    // ---- extra load/store: halfword, signed byte, doubleword -----------
    if (word & 0x0E00_0090) == 0x0000_0090 && (word & 0x60) != 0 {
        let p = ((word >> 24) & 1) != 0;
        let u = ((word >> 23) & 1) != 0;
        let i = ((word >> 22) & 1) != 0;
        let w = ((word >> 21) & 1) != 0;
        let l = ((word >> 20) & 1) != 0;
        let rn = (word >> 16) & 0xF;
        let rt = (word >> 12) & 0xF;
        let sh = (word >> 5) & 3;
        let mnem = match (sh, l) {
            (1, false) => Some("strh"),
            (1, true) => Some("ldrh"),
            (2, false) => Some("ldrd"),
            (2, true) => Some("ldrsb"),
            (3, false) => Some("strd"),
            (3, true) => Some("ldrsh"),
            _ => None,
        };
        if let Some(mnem) = mnem {
            let off = if i {
                let imm = (((word >> 8) & 0xF) << 4) | (word & 0xF);
                if imm == 0 {
                    None
                } else {
                    Some(fmt_off(if u { imm as i64 } else { -(imm as i64) }))
                }
            } else {
                let mut t = arm_reg(word & 0xF).to_string();
                if !u {
                    t = format!("-{}", t);
                }
                Some(t)
            };
            let addr = arm_mem(p, w, rn, off.as_deref());
            if mnem.ends_with('d') {
                return format!("{}{} {}, {}, {}", mnem, cs, arm_reg(rt), arm_reg(rt + 1), addr);
            }
            return format!("{}{} {}, {}", mnem, cs, arm_reg(rt), addr);
        }
    }

    // ---- LDM / STM (and the PUSH / POP aliases) -------------------------
    if (word & 0x0E00_0000) == 0x0800_0000 {
        let p = ((word >> 24) & 1) != 0;
        let u = ((word >> 23) & 1) != 0;
        let s = ((word >> 22) & 1) != 0;
        let w = ((word >> 21) & 1) != 0;
        let l = ((word >> 20) & 1) != 0;
        let rn = (word >> 16) & 0xF;
        let regs = arm_reg_list(word & 0xFFFF);
        if !s && w && p && !u && !l && rn == 13 {
            return format!("push{} {}", cs, regs);
        }
        if !s && w && !p && u && l && rn == 13 {
            return format!("pop{} {}", cs, regs);
        }
        let mnem = match (l, p, u) {
            (true, false, true) => "ldmia",
            (true, true, true) => "ldmib",
            (true, false, false) => "ldmda",
            (true, true, false) => "ldmdb",
            (false, false, true) => "stmia",
            (false, true, true) => "stmib",
            (false, false, false) => "stmda",
            (false, true, false) => "stmdb",
        };
        let bang = if w { "!" } else { "" };
        return format!("{}{} {}{}, {}", mnem, cs, arm_reg(rn), bang, regs);
    }

    // ---- LDR / STR / LDRB / STRB ---------------------------------------
    if (word & 0x0C00_0000) == 0x0400_0000 {
        let i = ((word >> 25) & 1) != 0;
        let p = ((word >> 24) & 1) != 0;
        let u = ((word >> 23) & 1) != 0;
        let b = ((word >> 22) & 1) != 0;
        let w = ((word >> 21) & 1) != 0;
        let l = ((word >> 20) & 1) != 0;
        let rn = (word >> 16) & 0xF;
        let rt = (word >> 12) & 0xF;
        let mnem = match (l, b) {
            (false, false) => "str",
            (false, true) => "strb",
            (true, false) => "ldr",
            (true, true) => "ldrb",
        };
        let off = if i {
            let mut t = arm_shift_operand(word);
            if !u {
                t = format!("-{}", t);
            }
            Some(t)
        } else {
            let imm = word & 0xFFF;
            if imm == 0 {
                None
            } else {
                Some(fmt_off(if u { imm as i64 } else { -(imm as i64) }))
            }
        };
        let addr = arm_mem(p, w, rn, off.as_deref());
        return format!("{}{} {}, {}", mnem, cs, arm_reg(rt), addr);
    }

    // ---- data processing -----------------------------------------------
    if (word & 0x0C00_0000) == 0 {
        let names = [
            "and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc",
            "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn",
        ];
        let opcode = (word >> 21) & 0xF;
        let sets_flags = ((word >> 20) & 1) != 0;
        let rn = (word >> 16) & 0xF;
        let rd = (word >> 12) & 0xF;
        let op2 = arm_operand2(word);
        let name = names[opcode as usize];
        // TST/TEQ/CMP/CMN always compare: the S bit is implied, not written.
        if (8..=11).contains(&opcode) {
            return format!("{}{} {}, {}", name, cs, arm_reg(rn), op2);
        }
        let ss = if sets_flags { "s" } else { "" };
        if opcode == 13 || opcode == 15 {
            return format!("{}{}{} {}, {}", name, ss, cs, arm_reg(rd), op2);
        }
        return format!("{}{}{} {}, {}, {}", name, ss, cs, arm_reg(rd), arm_reg(rn), op2);
    }

    format!(".word 0x{:08X}", word)
}

// -------------------------------------------------------------------------
// AArch64
// -------------------------------------------------------------------------

fn a64_gpr(sf: bool, reg: u32, sp_is_31: bool) -> String {
    if reg == 31 {
        if sp_is_31 {
            if sf { "sp".into() } else { "wsp".into() }
        } else if sf {
            "xzr".into()
        } else {
            "wzr".into()
        }
    } else if sf {
        format!("x{}", reg)
    } else {
        format!("w{}", reg)
    }
}

fn a64_shift(shift: u32, amount: u32) -> String {
    if shift == 0 && amount == 0 {
        return String::new();
    }
    let name = match shift {
        0 => "lsl",
        1 => "lsr",
        2 => "asr",
        _ => "ror",
    };
    format!(", {} #{}", name, amount)
}

fn disasm_aarch64(pc: u64, word: u32) -> String {
    if word == 0xD503_201F {
        return "nop".to_string();
    }
    if (word & 0xFFFF_FC1F) == 0xD65F_0000 {
        let rn = (word >> 5) & 0x1F;
        return if rn == 30 { "ret".to_string() } else { format!("ret x{}", rn) };
    }
    // Unconditional B / BL
    if (word & 0x7C00_0000) == 0x1400_0000 {
        let bl = (word >> 31) != 0;
        let imm26 = (((word & 0x03FF_FFFF) as i32) << 6) >> 4;
        let target = pc.wrapping_add(imm26 as i64 as u64);
        return format!("{} {:#x}", if bl { "bl" } else { "b" }, target);
    }
    // B.<cond>
    if (word & 0xFF00_0010) == 0x5400_0000 {
        let cond = word & 0xF;
        let off = sext((word >> 5) & 0x7FFFF, 19) << 2;
        let target = pc.wrapping_add(off as u64);
        return format!("b.{} {:#x}", ARM64_COND[cond as usize], target);
    }
    // CBZ / CBNZ
    if (word & 0x7E00_0000) == 0x3400_0000 {
        let sf = (word >> 31) != 0;
        let n = ((word >> 24) & 1) != 0;
        let imm19 = ((((word >> 5) & 0x7FFFF) as i32) << 13) >> 11;
        let rt = word & 0x1F;
        let target = pc.wrapping_add(imm19 as i64 as u64);
        return format!("{} {}, {:#x}", if n { "cbnz" } else { "cbz" }, a64_gpr(sf, rt, false), target);
    }
    // TBZ / TBNZ
    if (word & 0x7E00_0000) == 0x3600_0000 {
        let sf = (word >> 31) != 0;
        let nz = ((word >> 24) & 1) != 0;
        let b40 = (word >> 19) & 0x1F;
        let pos = if sf { 0x20 | b40 } else { b40 };
        let off = sext((word >> 5) & 0x3FFF, 14) << 2;
        let target = pc.wrapping_add(off as u64);
        let rt = word & 0x1F;
        return format!(
            "{} {}, #{:#x}, {:#x}",
            if nz { "tbnz" } else { "tbz" },
            a64_gpr(sf, rt, false),
            pos,
            target
        );
    }
    // ADD / SUB (immediate), with the CMP / CMN aliases
    if (word & 0x1F00_0000) == 0x1100_0000 {
        let sf = (word >> 31) != 0;
        let sub = ((word >> 30) & 1) != 0;
        let sets_flags = ((word >> 29) & 1) != 0;
        let sh = ((word >> 22) & 1) != 0;
        let imm12 = ((word >> 10) & 0xFFF) << (if sh { 12 } else { 0 });
        let rn = (word >> 5) & 0x1F;
        let rd = word & 0x1F;
        if sets_flags && rd == 31 {
            return format!(
                "{} {}, #{:#x}",
                if sub { "cmp" } else { "cmn" },
                a64_gpr(sf, rn, true),
                imm12
            );
        }
        return format!(
            "{}{} {}, {}, #{:#x}",
            if sub { "sub" } else { "add" },
            if sets_flags { "s" } else { "" },
            a64_gpr(sf, rd, true),
            a64_gpr(sf, rn, true),
            imm12
        );
    }
    // ADR / ADRP
    if (word & 0x1F00_0000) == 0x1000_0000 {
        let page = (word >> 31) != 0;
        let immlo = (word >> 29) & 3;
        let immhi = (word >> 5) & 0x7FFFF;
        let imm = sext((immhi << 2) | immlo, 21);
        if page {
            let target = (pc & !0xFFF).wrapping_add((imm << 12) as u64);
            return format!("adrp {:#x}", target);
        }
        return format!("adr {:#x}", pc.wrapping_add(imm as u64));
    }
    // MOVZ / MOVN / MOVK
    if (word & 0x1F80_0000) == 0x1280_0000 {
        let sf = (word >> 31) != 0;
        let opc = (word >> 29) & 3;
        let hw = ((word >> 21) & 3) * 16;
        let imm16 = (word >> 5) & 0xFFFF;
        let rd = word & 0x1F;
        let mnem = match opc {
            0 => "movn",
            2 => "movz",
            3 => "movk",
            _ => "mov?",
        };
        if hw == 0 {
            return format!("{} {}, #{:#x}", mnem, a64_gpr(sf, rd, false), imm16);
        } else {
            return format!("{} {}, #{:#x}, lsl #{}", mnem, a64_gpr(sf, rd, false), imm16, hw);
        }
    }
    // LDR / STR (unsigned immediate)
    if (word & 0x3B00_0000) == 0x3900_0000 && ((word >> 26) & 1) == 0 {
        let size = (word >> 30) & 3;
        let opc = (word >> 22) & 3;
        let imm12 = ((word >> 10) & 0xFFF) << size;
        let rn = (word >> 5) & 0x1F;
        let rt = word & 0x1F;
        let (mnem, sf) = match (size, opc) {
            (0, 0) => ("strb", false),
            (0, 1) => ("ldrb", false),
            (1, 0) => ("strh", false),
            (1, 1) => ("ldrh", false),
            (2, 0) => ("str", false),
            (2, 1) => ("ldr", false),
            (3, 0) => ("str", true),
            (3, 1) => ("ldr", true),
            _ => ("mem", size == 3),
        };
        if imm12 == 0 {
            return format!("{} {}, [{}]", mnem, a64_gpr(sf, rt, false), a64_gpr(true, rn, true));
        } else {
            return format!(
                "{} {}, [{}, #{:#x}]",
                mnem,
                a64_gpr(sf, rt, false),
                a64_gpr(true, rn, true),
                imm12
            );
        }
    }
    // STP / LDP (signed offset, pre-index, post-index)
    let pair_kind = match word & 0xFFC0_0000 {
        0xA900_0000 => Some((true, 0u8, false)),
        0xA940_0000 => Some((true, 0, true)),
        0xA980_0000 => Some((true, 1, false)),
        0xA9C0_0000 => Some((true, 1, true)),
        0xA880_0000 => Some((true, 2, false)),
        0xA8C0_0000 => Some((true, 2, true)),
        0x2900_0000 => Some((false, 0, false)),
        0x2940_0000 => Some((false, 0, true)),
        0x2980_0000 => Some((false, 1, false)),
        0x29C0_0000 => Some((false, 1, true)),
        0x2880_0000 => Some((false, 2, false)),
        0x28C0_0000 => Some((false, 2, true)),
        _ => None,
    };
    if let Some((sf, mode, load)) = pair_kind {
        let imm7 = sext((word >> 15) & 0x7F, 7);
        let imm = imm7 * if sf { 8 } else { 4 };
        let rt2 = (word >> 10) & 0x1F;
        let rn = (word >> 5) & 0x1F;
        let rt = word & 0x1F;
        let mnem = if load { "ldp" } else { "stp" };
        let regs = format!("{}, {}", a64_gpr(sf, rt, false), a64_gpr(sf, rt2, false));
        let base = a64_gpr(true, rn, true);
        return match mode {
            0 => {
                if imm == 0 {
                    format!("{} {}, [{}]", mnem, regs, base)
                } else {
                    format!("{} {}, [{}, {}]", mnem, regs, base, fmt_off(imm))
                }
            }
            1 => format!("{} {}, [{}, {}]!", mnem, regs, base, fmt_off(imm)),
            _ => format!("{} {}, [{}], {}", mnem, regs, base, fmt_off(imm)),
        };
    }
    // LDUR / STUR (unscaled immediate)
    if (word & 0x3F00_0C00) == 0x3800_0000 {
        let size = (word >> 30) & 3;
        let opc = (word >> 22) & 3;
        if (size == 2 || size == 3) && (opc == 0 || opc == 1) {
            let sf = size == 3;
            let load = opc == 1;
            let imm9 = sext((word >> 12) & 0x1FF, 9);
            let rn = (word >> 5) & 0x1F;
            let rt = word & 0x1F;
            let mnem = if load { "ldur" } else { "stur" };
            let base = a64_gpr(true, rn, true);
            if imm9 == 0 {
                return format!("{} {}, [{}]", mnem, a64_gpr(sf, rt, false), base);
            }
            return format!("{} {}, [{}, {}]", mnem, a64_gpr(sf, rt, false), base, fmt_off(imm9));
        }
    }
    // ADD / SUB (shifted register), with the CMP / CMN aliases
    if (word & 0x1F20_0000) == 0x0B00_0000 {
        let sf = (word >> 31) != 0;
        let sub = ((word >> 30) & 1) != 0;
        let sets_flags = ((word >> 29) & 1) != 0;
        let shift = (word >> 22) & 3;
        let amt = (word >> 10) & 0x3F;
        let rm = (word >> 16) & 0x1F;
        let rn = (word >> 5) & 0x1F;
        let rd = word & 0x1F;
        let sh = a64_shift(shift, amt);
        if sets_flags && rd == 31 {
            return format!(
                "{} {}, {}{}",
                if sub { "cmp" } else { "cmn" },
                a64_gpr(sf, rn, true),
                a64_gpr(sf, rm, false),
                sh
            );
        }
        return format!(
            "{}{} {}, {}, {}{}",
            if sub { "sub" } else { "add" },
            if sets_flags { "s" } else { "" },
            a64_gpr(sf, rd, !sets_flags),
            a64_gpr(sf, rn, !sets_flags),
            a64_gpr(sf, rm, false),
            sh
        );
    }
    // AND / ORR / EOR / ANDS (shifted register), with the MOV / TST aliases
    if (word & 0x1F20_0000) == 0x0A00_0000 {
        let sf = (word >> 31) != 0;
        let opc = (word >> 29) & 3;
        let shift = (word >> 22) & 3;
        let amt = (word >> 10) & 0x3F;
        let rm = (word >> 16) & 0x1F;
        let rn = (word >> 5) & 0x1F;
        let rd = word & 0x1F;
        let sh = a64_shift(shift, amt);
        if opc == 1 && rn == 31 {
            return format!("mov {}, {}{}", a64_gpr(sf, rd, false), a64_gpr(sf, rm, false), sh);
        }
        if opc == 3 && rd == 31 {
            return format!("tst {}, {}{}", a64_gpr(sf, rn, false), a64_gpr(sf, rm, false), sh);
        }
        let mnem = match opc {
            0 => "and",
            1 => "orr",
            2 => "eor",
            _ => "ands",
        };
        return format!(
            "{} {}, {}, {}{}",
            mnem,
            a64_gpr(sf, rd, false),
            a64_gpr(sf, rn, false),
            a64_gpr(sf, rm, false),
            sh
        );
    }
    // BR / BLR
    if (word & 0xFFFF_FC1F) == 0xD61F_0000 {
        return format!("br x{}", (word >> 5) & 0x1F);
    }
    if (word & 0xFFFF_FC1F) == 0xD63F_0000 {
        return format!("blr x{}", (word >> 5) & 0x1F);
    }
    // SVC
    if (word & 0xFFE0_001F) == 0xD400_0001 {
        return format!("svc #{:#x}", (word >> 5) & 0xFFFF);
    }
    format!(".word 0x{:08X}", word)
}

/// Instruction-set selector used by [`disasm_stream`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisasmArch {
    AArch64,
    Arm32,
    Thumb,
}

/// One decoded instruction: its address, byte length, raw bytes and text.
#[derive(Debug, Clone)]
pub struct DisasmInsn {
    pub address: u64,
    pub size: usize,
    pub raw_hex: String,
    pub text: String,
}

fn raw_hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02X}", b));
    }
    out
}

/// Disassemble a byte range.
///
/// AArch64 and AArch32 are fixed-width (4 bytes).  Thumb is variable: a halfword
/// of 0xE800 or more introduces a 32-bit Thumb-2 instruction, anything else is
/// a 16-bit instruction.  `max_insns` of 0 means "no limit".
pub fn disasm_stream(base_addr: u64, data: &[u8], arch: DisasmArch, max_insns: usize) -> Vec<DisasmInsn> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < data.len() {
        if max_insns > 0 && out.len() >= max_insns {
            break;
        }
        match arch {
            DisasmArch::AArch64 | DisasmArch::Arm32 => {
                if off + 4 > data.len() {
                    break;
                }
                let bytes = &data[off..off + 4];
                let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                let address = base_addr.wrapping_add(off as u64);
                out.push(DisasmInsn {
                    address,
                    size: 4,
                    raw_hex: raw_hex_bytes(bytes),
                    text: disasm_arm(address, word, arch == DisasmArch::Arm32),
                });
                off += 4;
            }
            DisasmArch::Thumb => {
                if off + 2 > data.len() {
                    break;
                }
                let hw1 = u16::from_le_bytes([data[off], data[off + 1]]);
                let address = base_addr.wrapping_add(off as u64);
                if hw1 >= 0xE800 {
                    if off + 4 > data.len() {
                        break;
                    }
                    let hw2 = u16::from_le_bytes([data[off + 2], data[off + 3]]);
                    let bytes = &data[off..off + 4];
                    out.push(DisasmInsn {
                        address,
                        size: 4,
                        raw_hex: raw_hex_bytes(bytes),
                        text: disasm_thumb32(address, hw1, hw2),
                    });
                    off += 4;
                } else {
                    out.push(DisasmInsn {
                        address,
                        size: 2,
                        raw_hex: raw_hex_bytes(&data[off..off + 2]),
                        text: disasm_thumb16(address, hw1),
                    });
                    off += 2;
                }
            }
        }
    }
    out
}

// -------------------------------------------------------------------------
// Thumb-16
// -------------------------------------------------------------------------

pub fn disasm_thumb16(pc: u64, hw: u16) -> String {
    let w = hw as u32;

    // ---- ADD/SUB (register) and (3-bit immediate) ----------------------
    if (w & 0xFC00) == 0x1800 {
        let sub = ((w >> 9) & 1) != 0;
        let rm = (w >> 6) & 7;
        let rn = (w >> 3) & 7;
        let rd = w & 7;
        return format!(
            "{} {}, {}, {}",
            if sub { "subs" } else { "adds" },
            arm_reg(rd),
            arm_reg(rn),
            arm_reg(rm)
        );
    }
    if (w & 0xFC00) == 0x1C00 {
        let sub = ((w >> 9) & 1) != 0;
        let imm3 = (w >> 6) & 7;
        let rn = (w >> 3) & 7;
        let rd = w & 7;
        return format!(
            "{} {}, {}, {}",
            if sub { "subs" } else { "adds" },
            arm_reg(rd),
            arm_reg(rn),
            fmt_off(imm3 as i64)
        );
    }

    // ---- shifts by immediate -------------------------------------------
    if (w & 0xE000) == 0x0000 {
        let op = (w >> 11) & 3;
        let imm5 = (w >> 6) & 0x1F;
        let rm = (w >> 3) & 7;
        let rd = w & 7;
        match op {
            0 => {
                if imm5 == 0 {
                    return format!("movs {}, {}", arm_reg(rd), arm_reg(rm));
                }
                return format!("lsls {}, {}, {}", arm_reg(rd), arm_reg(rm), fmt_off(imm5 as i64));
            }
            1 => {
                let amt = if imm5 == 0 { 32 } else { imm5 };
                return format!("lsrs {}, {}, {}", arm_reg(rd), arm_reg(rm), fmt_off(amt as i64));
            }
            2 => {
                let amt = if imm5 == 0 { 32 } else { imm5 };
                return format!("asrs {}, {}, {}", arm_reg(rd), arm_reg(rm), fmt_off(amt as i64));
            }
            _ => {}
        }
    }

    // ---- MOVS / CMP / ADDS / SUBS (immediate 8) ------------------------
    if (w & 0xE000) == 0x2000 {
        let op = (w >> 11) & 3;
        let rd = (w >> 8) & 7;
        let imm = w & 0xFF;
        let mnem = match op {
            0 => "movs",
            1 => "cmp",
            2 => "adds",
            _ => "subs",
        };
        return format!("{} {}, {}", mnem, arm_reg(rd), fmt_off(imm as i64));
    }

    // ---- data processing (register) ------------------------------------
    if (w & 0xFC00) == 0x4000 {
        let names = [
            "ands", "eors", "lsls", "lsrs", "asrs", "adcs", "sbcs", "rors",
            "tst", "rsbs", "cmp", "cmn", "orrs", "muls", "bics", "mvns",
        ];
        let op = (w >> 6) & 0xF;
        let rm = (w >> 3) & 7;
        let rdn = w & 7;
        let mnem = names[op as usize];
        return match op {
            9 => format!("rsbs {}, {}, #0x0", arm_reg(rdn), arm_reg(rm)),
            13 => format!("muls {}, {}, {}", arm_reg(rdn), arm_reg(rm), arm_reg(rdn)),
            _ => format!("{} {}, {}", mnem, arm_reg(rdn), arm_reg(rm)),
        };
    }

    // ---- BX / BLX (register) -------------------------------------------
    if (w & 0xFF07) == 0x4700 {
        let link = ((w >> 7) & 1) != 0;
        let rm = (w >> 3) & 0xF;
        return format!("{} {}", if link { "blx" } else { "bx" }, arm_reg(rm));
    }

    // ---- LDR (literal) --------------------------------------------------
    if (w & 0xF800) == 0x4800 {
        let rt = (w >> 8) & 7;
        let imm = (w & 0xFF) * 4;
        let addr = if imm == 0 {
            "[pc]".to_string()
        } else {
            format!("[pc, {}]", fmt_off(imm as i64))
        };
        return format!("ldr {}, {}", arm_reg(rt), addr);
    }

    // ---- LDR/STR (register offset) -------------------------------------
    if (w & 0xF000) == 0x5000 {
        let ops = ["str", "strh", "strb", "ldrsb", "ldr", "ldrh", "ldrb", "ldrsh"];
        let op = (w >> 9) & 7;
        let rm = (w >> 6) & 7;
        let rn = (w >> 3) & 7;
        let rt = w & 7;
        return format!("{} {}, [{}, {}]", ops[op as usize], arm_reg(rt), arm_reg(rn), arm_reg(rm));
    }

    // ---- LDR/STR/LDRB/STRB (immediate 5) -------------------------------
    if (w & 0xE000) == 0x6000 {
        let b = ((w >> 12) & 1) != 0;
        let l = ((w >> 11) & 1) != 0;
        let imm5 = (w >> 6) & 0x1F;
        let rn = (w >> 3) & 7;
        let rt = w & 7;
        let imm = if b { imm5 } else { imm5 * 4 };
        let mnem = match (l, b) {
            (false, false) => "str",
            (false, true) => "strb",
            (true, false) => "ldr",
            (true, true) => "ldrb",
        };
        let addr = if imm == 0 {
            format!("[{}]", arm_reg(rn))
        } else {
            format!("[{}, {}]", arm_reg(rn), fmt_off(imm as i64))
        };
        return format!("{} {}, {}", mnem, arm_reg(rt), addr);
    }

    // ---- LDR/STR (SP relative) -----------------------------------------
    if (w & 0xF000) == 0x9000 {
        let l = ((w >> 11) & 1) != 0;
        let rt = (w >> 8) & 7;
        let imm = (w & 0xFF) * 4;
        let addr = if imm == 0 {
            "[sp]".to_string()
        } else {
            format!("[sp, {}]", fmt_off(imm as i64))
        };
        return format!("{} {}, {}", if l { "ldr" } else { "str" }, arm_reg(rt), addr);
    }

    // ---- ADD/SUB SP, #imm ---------------------------------------------
    if (w & 0xFF80) == 0xB000 {
        let sub = ((w >> 7) & 1) != 0;
        let imm = (w & 0x7F) * 4;
        return format!("{} sp, {}", if sub { "sub" } else { "add" }, fmt_off(imm as i64));
    }

    // ---- PUSH / POP ----------------------------------------------------
    if (w & 0xFE00) == 0xB400 || (w & 0xFE00) == 0xBC00 {
        let pop = ((w >> 11) & 1) != 0;
        let bit8 = (w >> 8) & 1;
        let extra = if pop { bit8 << 15 } else { bit8 << 14 };
        let mask = (w & 0xFF) | extra;
        return format!("{} {}", if pop { "pop" } else { "push" }, arm_reg_list(mask));
    }

    // ---- CBZ / CBNZ ----------------------------------------------------
    if (w & 0xF500) == 0xB100 {
        let nz = ((w >> 11) & 1) != 0;
        let i = (w >> 9) & 1;
        let imm5 = (w >> 3) & 0x1F;
        let off = ((i << 5) | imm5) << 1;
        let rn = w & 7;
        let target = pc.wrapping_add(4).wrapping_add(off as u64);
        return format!("{} {}, {:#x}", if nz { "cbnz" } else { "cbz" }, arm_reg(rn), target);
    }

    // ---- B<cond> / UDF / SVC -------------------------------------------
    if (w & 0xF000) == 0xD000 {
        let cond = (w >> 8) & 0xF;
        let imm8 = w & 0xFF;
        if cond == 0xE {
            return format!("udf {}", fmt_off(imm8 as i64));
        }
        if cond == 0xF {
            return format!("svc {}", fmt_off(imm8 as i64));
        }
        let off = sext(imm8, 8) << 1;
        let target = pc.wrapping_add(4).wrapping_add(off as u64);
        return format!("b{} {:#x}", ARM_COND[cond as usize], target);
    }

    // ---- B (unconditional) ---------------------------------------------
    if (w & 0xF800) == 0xE000 {
        let off = sext(w & 0x7FF, 11) << 1;
        let target = pc.wrapping_add(4).wrapping_add(off as u64);
        return format!("b {:#x}", target);
    }

    // ---- hints / BKPT ---------------------------------------------------
    if hw == 0xBF00 {
        return "nop".to_string();
    }
    if (w & 0xFF00) == 0xBE00 {
        return format!("bkpt {}", fmt_off((w & 0xFF) as i64));
    }
    if (w & 0xFF00) == 0xBF00 {
        return format!("hint {}", fmt_off((w & 0xFF) as i64));
    }

    format!(".short 0x{:04X}", hw)
}

// -------------------------------------------------------------------------
// Thumb-2 (32-bit)
// -------------------------------------------------------------------------

pub fn disasm_thumb32(pc: u64, hw1: u16, hw2: u16) -> String {
    let w1 = hw1 as u32;
    let w2 = hw2 as u32;

    // ---- BL / B.W / B<cond>.W ------------------------------------------
    if (w1 & 0xF800) == 0xF000 {
        let s = (w1 >> 10) & 1;
        let kind = w2 & 0xD000;
        if kind == 0xD000 || kind == 0x9000 {
            let j1 = (w2 >> 13) & 1;
            let j2 = (w2 >> 11) & 1;
            let i1 = 1 - (j1 ^ s);
            let i2 = 1 - (j2 ^ s);
            let imm = ((s as i64) << 24)
                | ((i1 as i64) << 23)
                | ((i2 as i64) << 22)
                | (((w1 & 0x3FF) as i64) << 12)
                | (((w2 & 0x7FF) as i64) << 1);
            let imm = (imm << 7) >> 7;
            let target = pc.wrapping_add(4).wrapping_add(imm as u64);
            return format!("{} {:#x}", if kind == 0xD000 { "bl" } else { "b.w" }, target);
        }
        if kind == 0x8000 {
            let cond = (w1 >> 6) & 0xF;
            let j1 = (w2 >> 13) & 1;
            let j2 = (w2 >> 11) & 1;
            let i1 = 1 - (j1 ^ s);
            let i2 = 1 - (j2 ^ s);
            let imm = ((s as i64) << 20)
                | ((i1 as i64) << 19)
                | ((i2 as i64) << 18)
                | (((w1 & 0x3F) as i64) << 12)
                | (((w2 & 0x7FF) as i64) << 1);
            let imm = (imm << 11) >> 11;
            let target = pc.wrapping_add(4).wrapping_add(imm as u64);
            return format!("b{}.w {:#x}", ARM_COND[cond as usize], target);
        }
    }

    // ---- LDR / STR (immediate 12) --------------------------------------
    let ls_key = w1 & 0xFFF0;
    let ls = match ls_key {
        0xF8C0 => Some(("str", 4u32)),
        0xF8D0 => Some(("ldr", 4)),
        0xF880 => Some(("strb", 1)),
        0xF890 => Some(("ldrb", 1)),
        0xF8A0 => Some(("strh", 2)),
        0xF8B0 => Some(("ldrh", 2)),
        0xF990 => Some(("ldrsb", 1)),
        0xF9B0 => Some(("ldrsh", 2)),
        _ => None,
    };
    if let Some((mnem, scale)) = ls {
        let rn = w1 & 0xF;
        let rt = (w2 >> 12) & 0xF;
        let imm = (w2 & 0xFFF) * scale;
        let addr = if imm == 0 {
            format!("[{}]", arm_reg(rn))
        } else {
            format!("[{}, {}]", arm_reg(rn), fmt_off(imm as i64))
        };
        return format!("{}.w {}, {}", mnem, arm_reg(rt), addr);
    }

    // ---- PUSH.W / POP.W -------------------------------------------------
    if w1 == 0xE92D {
        return format!("push.w {}", arm_reg_list(w2));
    }
    if w1 == 0xE8BD {
        return format!("pop.w {}", arm_reg_list(w2));
    }

    // ---- ADD.W / SUB.W (immediate) -------------------------------------
    let imm_key = w1 & 0xFBF0;
    if imm_key == 0xF200 || imm_key == 0xF2A0 {
        let sub = imm_key == 0xF2A0;
        let i = (w1 >> 10) & 1;
        let imm3 = (w2 >> 12) & 7;
        let rd = (w2 >> 8) & 0xF;
        let rn = w1 & 0xF;
        let imm = (i << 11) | (imm3 << 8) | (w2 & 0xFF);
        if rd == 15 {
            return format!("cmp.w {}, {}", arm_reg(rn), fmt_off(imm as i64));
        }
        return format!(
            "{}.w {}, {}, {}",
            if sub { "sub" } else { "add" },
            arm_reg(rd),
            arm_reg(rn),
            fmt_off(imm as i64)
        );
    }
    // ---- MOV.W (immediate) ---------------------------------------------
    if imm_key == 0xF040 {
        let i = (w1 >> 10) & 1;
        let imm3 = (w2 >> 12) & 7;
        let rd = (w2 >> 8) & 0xF;
        let imm = (i << 11) | (imm3 << 8) | (w2 & 0xFF);
        return format!("mov.w {}, {}", arm_reg(rd), fmt_off(imm as i64));
    }
    // ---- CMP.W (immediate) ---------------------------------------------
    if imm_key == 0xF1B0 {
        let i = (w1 >> 10) & 1;
        let imm3 = (w2 >> 12) & 7;
        let rn = w1 & 0xF;
        let imm = (i << 11) | (imm3 << 8) | (w2 & 0xFF);
        return format!("cmp.w {}, {}", arm_reg(rn), fmt_off(imm as i64));
    }

    // ---- ADD.W / SUB.W / CMP.W (register) ------------------------------
    let reg_key = w1 & 0xFFF0;
    if reg_key == 0xEB00 || reg_key == 0xEBA0 || reg_key == 0xEBB0 {
        let rn = w1 & 0xF;
        let rd = (w2 >> 8) & 0xF;
        let rm = w2 & 0xF;
        if reg_key == 0xEBB0 || rd == 15 {
            return format!("cmp.w {}, {}", arm_reg(rn), arm_reg(rm));
        }
        return format!(
            "{}.w {}, {}, {}",
            if reg_key == 0xEBA0 { "sub" } else { "add" },
            arm_reg(rd),
            arm_reg(rn),
            arm_reg(rm)
        );
    }
    // ---- MOV.W (register) ----------------------------------------------
    if w1 == 0xEA4F {
        let rd = (w2 >> 8) & 0xF;
        let rm = w2 & 0xF;
        return format!("mov.w {}, {}", arm_reg(rd), arm_reg(rm));
    }

    format!(".short 0x{:04X}, 0x{:04X}", hw1, hw2)
}

/// Disassemble one 32-bit instruction word.
///
/// `aarch32` selects the ARM (32-bit) form; otherwise the AArch64 form is used.
pub fn disasm_arm(pc: u64, word: u32, aarch32: bool) -> String {
    if aarch32 {
        disasm_aarch32(pc, word)
    } else {
        disasm_aarch64(pc, word)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SnapshotSummary {
    pub slot: u32,
    pub block_count: u32,
    pub changed_count: u32,
    pub block_size: u32,
    pub region_count: u32,
    pub truncated: bool,
}

impl SnapshotSummary {
    pub const SIZE: usize = 32;
    pub fn parse(data: &[u8]) -> SnapshotSummary {
        SnapshotSummary {
            slot: rd_u32(data, 0),
            block_count: rd_u32(data, 4),
            changed_count: rd_u32(data, 8),
            block_size: rd_u32(data, 12),
            region_count: rd_u32(data, 16),
            truncated: rd_u32(data, 20) != 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChangedBlock {
    pub address: u64,
    pub size: u32,
    pub flags: u32,
}

impl ChangedBlock {
    pub const SIZE: usize = 16;
    pub fn parse(data: &[u8]) -> ChangedBlock {
        ChangedBlock {
            address: rd_u64(data, 0),
            size: rd_u32(data, 8),
            flags: rd_u32(data, 12),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub base: u64,
    pub size: u64,
    pub build_id: String,
}

impl ModuleInfo {
    pub const SIZE: usize = 0x40;
    pub fn parse(data: &[u8]) -> ModuleInfo {
        ModuleInfo {
            base: rd_u64(data, 0),
            size: rd_u64(data, 8),
            // `chunks_exact(SIZE)` normally guarantees the range, but the helper
            // is public: fall back to zeroes rather than slicing out of bounds.
            build_id: data
                .get(16..24)
                .map(|id| id.iter().map(|b| format!("{:02x}", b)).collect())
                .unwrap_or_default(),
        }
    }
}


/// Evaluate an address / offset expression (jnoexs ExpressionEvaluator parity).
///
/// Supports:
/// - `main`, `heap` symbolic bases
/// - `0x` hex, decimal, or bare hex tokens (e.g. `42CA1DC4`)
/// - parentheses `(...)`
/// - unary `+`, `-`, `~`
/// - binary `*`, `/`, `%`, `+`, `-`, `<<`, `>>`, `&`, `^`, `|`
pub fn eval_expr(text: &str, main_base: u64, heap_base: u64) -> Option<u64> {
    struct Parser<'a> {
        bytes: &'a [u8],
        pos: usize,
        main_base: u64,
        heap_base: u64,
    }

    impl<'a> Parser<'a> {
        fn skip_ws(&mut self) {
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
                self.pos += 1;
            }
        }

        fn parse_or(&mut self) -> Option<u64> {
            let mut v = self.parse_xor()?;
            loop {
                self.skip_ws();
                if self.pos < self.bytes.len() && self.bytes[self.pos] == b'|' {
                    self.pos += 1;
                    v |= self.parse_xor()?;
                } else {
                    break;
                }
            }
            Some(v)
        }

        fn parse_xor(&mut self) -> Option<u64> {
            let mut v = self.parse_and()?;
            loop {
                self.skip_ws();
                if self.pos < self.bytes.len() && self.bytes[self.pos] == b'^' {
                    self.pos += 1;
                    v ^= self.parse_and()?;
                } else {
                    break;
                }
            }
            Some(v)
        }

        fn parse_and(&mut self) -> Option<u64> {
            let mut v = self.parse_shift()?;
            loop {
                self.skip_ws();
                if self.pos < self.bytes.len() && self.bytes[self.pos] == b'&' {
                    self.pos += 1;
                    v &= self.parse_shift()?;
                } else {
                    break;
                }
            }
            Some(v)
        }

        fn parse_shift(&mut self) -> Option<u64> {
            let mut v = self.parse_add()?;
            loop {
                self.skip_ws();
                if self.pos + 1 < self.bytes.len()
                    && self.bytes[self.pos] == b'<'
                    && self.bytes[self.pos + 1] == b'<'
                {
                    self.pos += 2;
                    let rhs = self.parse_add()?;
                    v = v.wrapping_shl(rhs as u32);
                } else if self.pos + 1 < self.bytes.len()
                    && self.bytes[self.pos] == b'>'
                    && self.bytes[self.pos + 1] == b'>'
                {
                    self.pos += 2;
                    let rhs = self.parse_add()?;
                    v = v.wrapping_shr(rhs as u32);
                } else {
                    break;
                }
            }
            Some(v)
        }

        fn parse_add(&mut self) -> Option<u64> {
            let mut v = self.parse_mul()?;
            loop {
                self.skip_ws();
                if self.pos < self.bytes.len() && self.bytes[self.pos] == b'+' {
                    self.pos += 1;
                    v = v.wrapping_add(self.parse_mul()?);
                } else if self.pos < self.bytes.len() && self.bytes[self.pos] == b'-' {
                    self.pos += 1;
                    v = v.wrapping_sub(self.parse_mul()?);
                } else {
                    break;
                }
            }
            Some(v)
        }

        fn parse_mul(&mut self) -> Option<u64> {
            let mut v = self.parse_unary()?;
            loop {
                self.skip_ws();
                if self.pos < self.bytes.len() && self.bytes[self.pos] == b'*' {
                    self.pos += 1;
                    v = v.wrapping_mul(self.parse_unary()?);
                } else if self.pos < self.bytes.len() && self.bytes[self.pos] == b'/' {
                    self.pos += 1;
                    let rhs = self.parse_unary()?;
                    if rhs == 0 {
                        return None;
                    }
                    v /= rhs;
                } else if self.pos < self.bytes.len() && self.bytes[self.pos] == b'%' {
                    self.pos += 1;
                    let rhs = self.parse_unary()?;
                    if rhs == 0 {
                        return None;
                    }
                    v %= rhs;
                } else {
                    break;
                }
            }
            Some(v)
        }

        fn parse_unary(&mut self) -> Option<u64> {
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                return None;
            }
            match self.bytes[self.pos] {
                b'+' => {
                    self.pos += 1;
                    self.parse_unary()
                }
                b'-' => {
                    self.pos += 1;
                    Some(0u64.wrapping_sub(self.parse_unary()?))
                }
                b'~' => {
                    self.pos += 1;
                    Some(!self.parse_unary()?)
                }
                _ => self.parse_primary(),
            }
        }

        fn parse_primary(&mut self) -> Option<u64> {
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                return None;
            }
            if self.bytes[self.pos] == b'(' {
                self.pos += 1;
                let v = self.parse_or()?;
                self.skip_ws();
                if self.pos >= self.bytes.len() || self.bytes[self.pos] != b')' {
                    return None;
                }
                self.pos += 1;
                return Some(v);
            }
            let start = self.pos;
            while self.pos < self.bytes.len() {
                let c = self.bytes[self.pos];
                if c.is_ascii_alphanumeric() || c == b'_' {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            if self.pos == start {
                return None;
            }
            let tok = std::str::from_utf8(&self.bytes[start..self.pos]).ok()?;
            if tok.eq_ignore_ascii_case("main") {
                return Some(self.main_base);
            }
            if tok.eq_ignore_ascii_case("heap") {
                return Some(self.heap_base);
            }
            let clean = tok.replace('_', "");
            if let Some(hex) = clean.strip_prefix("0x").or_else(|| clean.strip_prefix("0X")) {
                return u64::from_str_radix(hex, 16).ok();
            }
            if let Ok(dec) = clean.parse::<u64>() {
                return Some(dec);
            }
            if clean.chars().all(|c| c.is_ascii_hexdigit()) {
                return u64::from_str_radix(&clean, 16).ok();
            }
            None
        }
    }

    let mut p = Parser {
        bytes: text.as_bytes(),
        pos: 0,
        main_base,
        heap_base,
    };
    let val = p.parse_or()?;
    p.skip_ws();
    if p.pos == p.bytes.len() {
        Some(val)
    } else {
        None
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // ---- parity with the C header (the single source of truth) -----------
    // Read at compile time: drifting either side stops the test from passing.
    const HEADER: &str = include_str!("../../../core/nxus_protocol.h");

    fn header_size(text: &str, what: &str) -> Option<u32> {
        let needle = format!("NXUS_STATIC_ASSERT(sizeof({}) == ", what);
        let start = text.find(&needle)? + needle.len();
        let rest = text[start..].trim_start().trim_start_matches('(');
        let end = rest.find(|c: char| !(c.is_ascii_hexdigit() || c == 'x' || c == 'X'))?;
        let raw = rest[..end].trim_end_matches(['u', 'U']);
        match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
            Some(hex) => u32::from_str_radix(hex, 16).ok(),
            None => raw.parse().ok(),
        }
    }

    fn header_enum(text: &str, enum_name: &str, variant: &str) -> Option<u32> {
        let close = text.find(&format!("}} {};", enum_name))?;
        let head = text[..close].rfind("typedef enum {")?;
        let body = &text[head + "typedef enum {".len()..close];

        let mut value: u32 = 0;
        for raw in body.lines() {
            let line = raw.split("/*").next().unwrap_or("")
                .split("//").next().unwrap_or("")
                .trim().trim_end_matches(',').trim();
            if line.is_empty() {
                continue;
            }
            let (name, this) = match line.split_once('=') {
                Some((n, v)) => {
                    let v = v.trim().trim_end_matches('u').trim();
                    let parsed = match v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
                        Some(hex) => u32::from_str_radix(hex, 16).unwrap_or(value),
                        None => v.parse().unwrap_or(value),
                    };
                    (n.trim(), parsed)
                }
                None => (line, value),
            };
            if name == variant {
                return Some(this);
            }
            value = this + 1;
        }
        None
    }

    fn header_define(text: &str, name: &str) -> Option<u32> {
        let needle = format!("#define {} ", name);
        let start = text.find(&needle)? + needle.len();
        let rest = text[start..].trim_start().trim_start_matches('(');
        let end = rest.find(|c: char| !(c.is_ascii_hexdigit() || c == 'x' || c == 'X'))?;
        let raw = rest[..end].trim_end_matches(['u', 'U']);
        raw.strip_prefix("0x").and_then(|h| u32::from_str_radix(h, 16).ok())
    }

    #[test]
    fn sizes_match_the_c_header() {
        assert_eq!(header_size(HEADER, "NxusStatus"), Some(Status::SIZE as u32));
        assert_eq!(header_size(HEADER, "NxusHit"), Some(16));
        assert_eq!(header_size(HEADER, "NxusModuleInfo"), Some(ModuleInfo::SIZE as u32));
        assert_eq!(header_size(HEADER, "NxusThreadContext"), Some(ThreadContext::SIZE as u32));
        // the range list that NXUS_SCAN_F_RANGES introduces
        assert_eq!(header_size(HEADER, "NxusRangeListHeader"), Some(RANGE_LIST_HEADER_SIZE as u32));
        assert_eq!(header_size(HEADER, "NxusRangeEntry"), Some(RANGE_ENTRY_SIZE as u32));
        // NxusFrozenEntry has no NXUS_STATIC_ASSERT in the header (unlike its
        // NxusFrozenRequest sibling): its fields are {u64 address; u64 value;
        // u32 width; u32 reserved}, i.e. 24 packed bytes, matching protocol.py's
        // '<QQII'.  Pin the stride here so either side drifting fails the test.
        assert_eq!(FrozenEntry::SIZE, 24);
    }

    #[test]
    fn threadctx_flags_match_the_c_header() {
        // Bit 0 is the RegsSet request flag, bit 1 the GetRegs AArch32 marker: a
        // drift here would make is_aarch32() answer for the wrong bit.
        assert_eq!(header_define(HEADER, "NXUS_THREADCTX_FLAG_X_AUTHORITATIVE"), Some(NXUS_THREADCTX_FLAG_X_AUTHORITATIVE));
        assert_eq!(header_define(HEADER, "NXUS_THREADCTX_FLAG_AARCH32"), Some(NXUS_THREADCTX_FLAG_AARCH32));
    }

    #[test]
    fn aarch32_reply_is_detected_from_the_reserved_word() {
        // A 32-bit reply: header sp/lr/fp stay zero, the live values sit in
        // x[13]/x[14]/x[11], and reserved carries bit 1.
        let mut data = vec![0u8; ThreadContext::SIZE];
        data[40..44].copy_from_slice(&0x6000_0000u32.to_le_bytes());   // cpsr
        data[ThreadContext::FLAGS_OFFSET..ThreadContext::FLAGS_OFFSET + 4]
            .copy_from_slice(&NXUS_THREADCTX_FLAG_AARCH32.to_le_bytes());
        for (i, reg) in [(13usize, 0x3600_F000u64), (14, 0x1B00_4001), (11, 0x3600_0FF0)] {
            let off = 100 + i * 8;
            data[off..off + 8].copy_from_slice(&reg.to_le_bytes());
        }
        let ctx = ThreadContext::parse(&data);
        assert!(ctx.is_aarch32());
        assert_eq!(ctx.cpsr, 0x6000_0000);
        assert_eq!((ctx.x[13], ctx.x[14], ctx.x[11]), (0x3600_F000, 0x1B00_4001, 0x3600_0FF0));
        // A 64-bit reply (bit 0 from an echo, or nothing at all) is not AArch32.
        let mut data64 = data.clone();
        data64[ThreadContext::FLAGS_OFFSET..ThreadContext::FLAGS_OFFSET + 4]
            .copy_from_slice(&NXUS_THREADCTX_FLAG_X_AUTHORITATIVE.to_le_bytes());
        assert!(!ThreadContext::parse(&data64).is_aarch32());
        assert!(!ThreadContext::parse(&[]).is_aarch32());
    }

    #[test]
    fn command_ids_match_the_c_header() {
        // NxusCmd is an enum, so the values come from header_enum (header_define is
        // only for #define lines - asserting with the wrong helper silently returned
        // None and "passed" nothing).
        assert_eq!(header_enum(HEADER, "NxusCmd", "NxusCmd_GetProcesses"),
                   Some(cmd::GET_PROCESSES as u32));
        assert_eq!(header_enum(HEADER, "NxusCmd", "NxusCmd_ScanUndo"),
                   Some(cmd::SCAN_UNDO as u32));
        assert_eq!(header_enum(HEADER, "NxusCmd", "NxusCmd_DebugAttach"),
                   Some(cmd::DEBUG_ATTACH as u32));
        assert_eq!(header_enum(HEADER, "NxusCmd", "NxusCmd_ScanBegin"),
                   Some(cmd::SCAN_BEGIN as u32));
    }

    #[test]
    fn debug_step_stop_and_flags_match_the_c_header() {
        assert_eq!(header_enum(HEADER, "NxusCmd", "NxusCmd_DebugStep"),
                   Some(cmd::DEBUG_STEP as u32));
        assert_eq!(header_enum(HEADER, "NxusEvent", "NxusEvent_DebugStopped"),
                   Some(event::DEBUG_STOPPED as u32));
        assert_eq!(header_define(HEADER, "NXUS_ST_DEBUG_STOPPED"), Some(ST_DEBUG_STOPPED));
        // reserved-flag on the hit batch (added in Round 4/5): a drift here would
        // silently turn a truncated result back into a "complete" one.
        assert_eq!(header_define(HEADER, "NXUS_HITBATCH_TRUNCATED"),
                   Some(NXUS_HITBATCH_TRUNCATED));
        assert_eq!(header_size(HEADER, "NxusDebugStop"), Some(DebugStop::SIZE as u32));
        assert_eq!(header_size(HEADER, "NxusDebugStatus"), Some(DebugStatus::SIZE as u32));
    }

    #[test]
    fn debug_status_decodes_the_stopped_thread_at_offset_28() {
        let mut data = vec![0u8; DebugStatus::SIZE];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());          // attached
        data[24..28].copy_from_slice(&0u32.to_le_bytes());        // auto_continue
        data[28..32].copy_from_slice(&0x1001u32.to_le_bytes());   // stopped_thread_low
        let status = DebugStatus::parse(&data);
        assert!(status.attached);
        assert_eq!(status.auto_continue, 0);
        assert_eq!(status.stopped_thread(), Some(0x1001));
        // a running target reports 0 there, and a short reply must not panic
        assert_eq!(DebugStatus::parse(&vec![0u8; DebugStatus::SIZE]).stopped_thread(), None);
        assert_eq!(DebugStatus::parse(&[0u8; 20]).stopped_thread(), None);
    }

    #[test]
    fn debug_stop_payload_decodes_at_the_header_offsets() {
        let mut data = vec![0u8; DebugStop::SIZE];
        data[0..8].copy_from_slice(&0x1001u64.to_le_bytes());
        data[8..16].copy_from_slice(&0x00712345u64.to_le_bytes());
        data[16..24].copy_from_slice(&0x42CA1DC4u64.to_le_bytes());
        data[24..28].copy_from_slice(&1u32.to_le_bytes());
        data[28..32].copy_from_slice(&0x10u32.to_le_bytes());
        let stop = DebugStop::parse(&data);
        assert_eq!((stop.thread_id, stop.pc, stop.address, stop.kind, stop.slot),
                   (0x1001, 0x00712345, 0x42CA1DC4, 1, 0x10));
    }

    #[test]
    fn enums_match_the_c_header() {
        assert_eq!(header_enum(HEADER, "NxusCompareMode", "NxusCmp_Between"),
                   Some(Compare::Between as u32));
        assert_eq!(header_enum(HEADER, "NxusCompareMode", "NxusCmp_Unknown"),
                   Some(Compare::Unknown as u32));
        assert_eq!(header_enum(HEADER, "NxusCompareMode", "NxusCmp_GreaterOrEqual"),
                   Some(Compare::GreaterOrEqual as u32));
        assert_eq!(header_enum(HEADER, "NxusCompareMode", "NxusCmp_LessOrEqual"),
                   Some(Compare::LessOrEqual as u32));
        assert_eq!(header_enum(HEADER, "NxusCompareMode", "NxusCmp_Different"),
                   Some(Compare::Different as u32));
        assert_eq!(header_enum(HEADER, "NxusScanScope", "NxusScope_Ranges"),
                   Some(Scope::Ranges as u32));
        assert_eq!(header_enum(HEADER, "NxusValueType", "NxusValueType_All"),
                   Some(ValueType::All as u32));
        assert_eq!(header_enum(HEADER, "NxusValueType", "NxusValueType_String"),
                   Some(ValueType::Str as u32));
        assert_eq!(header_enum(HEADER, "NxusScanScope", "NxusScope_Tls"),
                   Some(Scope::Tls as u32));
    }

    #[test]
    fn scan_flags_match_the_c_header() {
        assert_eq!(header_define(HEADER, "NXUS_SCAN_F_WILDCARD"), Some(SCAN_F_WILDCARD));
        assert_eq!(header_define(HEADER, "NXUS_SCAN_F_UTF16"), Some(SCAN_F_UTF16));
        assert_eq!(header_define(HEADER, "NXUS_SCAN_F_ALIGNED"), Some(SCAN_F_ALIGNED));
        assert_eq!(header_define(HEADER, "NXUS_SCAN_F_FLOAT"), Some(SCAN_F_FLOAT));
        assert_eq!(header_define(HEADER, "NXUS_SCAN_F_NEW_SESSION"), Some(SCAN_F_NEW_SESSION));
        assert_eq!(header_define(HEADER, "NXUS_SCAN_F_SIGNED"), Some(SCAN_F_SIGNED));
        assert_eq!(header_define(HEADER, "NXUS_SCAN_F_HEX"), Some(SCAN_F_HEX));
        assert_eq!(header_define(HEADER, "NXUS_SCAN_F_CASE_INSENS"), Some(SCAN_F_CASE_INSENS));
    }

    #[test]
    fn expression_evaluator_handles_arithmetic_and_symbols() {
        let main = 0x7100000000;
        let heap = 0x42CA0000;
        assert_eq!(eval_expr("main+0x80000+0x1000", main, heap), Some(main + 0x81000));
        assert_eq!(eval_expr("(heap + 0x1DC0) + 4", main, heap), Some(0x42CA1DC4));
        assert_eq!(eval_expr("main + (2 * 0x40000) - 0x10", main, heap), Some(main + 0x80000 - 0x10));
        assert_eq!(eval_expr("(0x100 << 4) | 0xF", main, heap), Some(0x100F));
        assert_eq!(eval_expr("42CA1DC4", main, heap), Some(0x42CA1DC4));
        assert_eq!(eval_expr("100 / 0", main, heap), None);
        assert_eq!(disasm_arm(0x7100001000, 0xD503_201F, false), "nop");
        assert_eq!(disasm_arm(0x7100001000, 0xD65F_03C0, false), "ret");
        assert_eq!(disasm_arm(0x7100001000, 0xB900_0401, false), "str w1, [x0, #0x4]");
        assert_eq!(disasm_arm(0x00701000, 0xE580_1004, true), "str r1, [r0, #0x4]");
    }

    #[test]
    fn status_fields_decode_at_the_header_offsets() {
        let mut data = vec![0u8; Status::SIZE];
        data[72..76].copy_from_slice(&524288u32.to_le_bytes());
        assert_eq!(Status::parse(&data).max_read, 524288);
        let data = vec![9u8; Status::SIZE];
        assert_eq!(Status::parse(&data).proto_version, 0x09090909);
    }

    // ---- disassembler ----------------------------------------------------

    #[test]
    fn disasm_aarch32_common_instructions() {
        // data processing: immediate and register forms, with condition codes
        assert_eq!(disasm_arm(0x0010_0000, 0xE241_1004, true), "sub r1, r1, #0x4");
        assert_eq!(disasm_arm(0x0010_0000, 0xE281_0008, true), "add r0, r1, #0x8");
        assert_eq!(disasm_arm(0x0010_0000, 0xE351_0000, true), "cmp r1, #0x0");
        assert_eq!(disasm_arm(0x0010_0000, 0x1281_0008, true), "addne r0, r1, #0x8");
        assert_eq!(disasm_arm(0x0010_0000, 0xE1A0_2001, true), "mov r2, r1");
        assert_eq!(disasm_arm(0x0010_0000, 0xE3A0_2001, true), "mov r2, #0x1");
        assert_eq!(disasm_arm(0x0010_0000, 0xE290_0001, true), "adds r0, r0, #0x1");

        // push / pop (the stmdb sp! / ldmia sp! aliases)
        assert_eq!(disasm_arm(0x0010_0000, 0xE92D_4FF0, true),
                   "push {r4, r5, r6, r7, r8, r9, r10, r11, lr}");
        assert_eq!(disasm_arm(0x0010_0000, 0xE8BD_8FF0, true),
                   "pop {r4, r5, r6, r7, r8, r9, r10, r11, pc}");

        // branches: target = pc + 8 + (sign_extend(imm24) << 2)
        assert_eq!(disasm_arm(0x0010_0000, 0xEAFF_FFFE, true), "b 0x100000");
        assert_eq!(disasm_arm(0x0010_0000, 0xEB00_0000, true), "bl 0x100008");
        assert_eq!(disasm_arm(0x0010_0000, 0x0A00_0000, true), "beq 0x100008");

        // loads / stores
        assert_eq!(disasm_arm(0x0010_0000, 0xE591_0004, true), "ldr r0, [r1, #0x4]");
        assert_eq!(disasm_arm(0x0010_0000, 0xE511_0004, true), "ldr r0, [r1, #-0x4]");
        assert_eq!(disasm_arm(0x0010_0000, 0xE5D1_0003, true), "ldrb r0, [r1, #0x3]");
        assert_eq!(disasm_arm(0x0010_0000, 0xE791_0002, true), "ldr r0, [r1, r2]");
        assert_eq!(disasm_arm(0x0010_0000, 0xE1D1_00B4, true), "ldrh r0, [r1, #0x4]");

        // wide immediates, multiply, system instructions
        assert_eq!(disasm_arm(0x0010_0000, 0xE301_0234, true), "movw r0, #0x1234");
        assert_eq!(disasm_arm(0x0010_0000, 0xE341_0234, true), "movt r0, #0x1234");
        assert_eq!(disasm_arm(0x0010_0000, 0xE000_0291, true), "mul r0, r1, r2");
        assert_eq!(disasm_arm(0x0010_0000, 0xEF00_0001, true), "svc #0x1");
        assert_eq!(disasm_arm(0x0010_0000, 0xE7F0_00F0, true), "udf #0x0");
        assert_eq!(disasm_arm(0x0010_0000, 0xE12F_FF1E, true), "bx lr");
    }

    #[test]
    fn disasm_thumb16_instructions() {
        assert_eq!(disasm_thumb16(0x1000, 0xBF00), "nop");
        assert_eq!(disasm_thumb16(0x1000, 0x2001), "movs r0, #0x1");
        assert_eq!(disasm_thumb16(0x1000, 0x2803), "cmp r0, #0x3");
        assert_eq!(disasm_thumb16(0x1000, 0x0088), "lsls r0, r1, #0x2");
        assert_eq!(disasm_thumb16(0x1000, 0x1888), "adds r0, r1, r2");
        assert_eq!(disasm_thumb16(0x1000, 0x4770), "bx lr");
        assert_eq!(disasm_thumb16(0x1000, 0xB510), "push {r4, lr}");
        assert_eq!(disasm_thumb16(0x1000, 0x4804), "ldr r0, [pc, #0x10]");
        assert_eq!(disasm_thumb16(0x1000, 0x6051), "str r1, [r2, #0x4]");
        assert_eq!(disasm_thumb16(0x1000, 0xB004), "add sp, #0x10");
        assert_eq!(disasm_thumb16(0x1000, 0xD0FE), "beq 0x1000");
        assert_eq!(disasm_thumb16(0x1000, 0xE7FE), "b 0x1000");
        assert_eq!(disasm_thumb16(0x1000, 0xB108), "cbz r0, 0x1006");
        assert_eq!(disasm_thumb16(0x1000, 0xDF01), "svc #0x1");
        assert_eq!(disasm_thumb16(0x1000, 0xBE00), "bkpt #0x0");
        // Thumb-2 halfwords must not be decoded as Thumb-16
        assert_eq!(disasm_thumb16(0x1000, 0xF8D1), ".short 0xF8D1");
    }

    #[test]
    fn disasm_thumb32_instructions() {
        assert_eq!(disasm_thumb32(0x1000, 0xF000, 0xF800), "bl 0x1004");
        assert_eq!(disasm_thumb32(0x1000, 0xF000, 0xB800), "b.w 0x1004");
        assert_eq!(disasm_thumb32(0x1000, 0xF000, 0xA800), "beq.w 0x1004");
        assert_eq!(disasm_thumb32(0x1000, 0xF8D1, 0x0001), "ldr.w r0, [r1, #0x4]");
        assert_eq!(disasm_thumb32(0x1000, 0xF8C2, 0x0001), "str.w r0, [r2, #0x4]");
        assert_eq!(disasm_thumb32(0x1000, 0xE92D, 0x4010), "push.w {r4, lr}");
        assert_eq!(disasm_thumb32(0x1000, 0xE8BD, 0x8010), "pop.w {r4, pc}");
        assert_eq!(disasm_thumb32(0x1000, 0xF201, 0x0002), "add.w r0, r1, #0x2");
        assert_eq!(disasm_thumb32(0x1000, 0xF2A1, 0x0002), "sub.w r0, r1, #0x2");
        assert_eq!(disasm_thumb32(0x1000, 0xF04F, 0x0001), "mov.w r0, #0x1");
        assert_eq!(disasm_thumb32(0x1000, 0xF1B0, 0x0F01), "cmp.w r0, #0x1");
        assert_eq!(disasm_thumb32(0x1000, 0xEB01, 0x0002), "add.w r0, r1, r2");
        assert_eq!(disasm_thumb32(0x1000, 0xEBA1, 0x0002), "sub.w r0, r1, r2");
        assert_eq!(disasm_thumb32(0x1000, 0xEA4F, 0x0001), "mov.w r0, r1");
        assert_eq!(disasm_thumb32(0x1000, 0xF123, 0x4567), ".short 0xF123, 0x4567");
    }

    #[test]
    fn disasm_stream_walks_fixed_and_variable_width_code() {
        // Thumb-16: two halfwords
        let thumb = [0x00, 0xBF, 0x01, 0x20];
        let insns = disasm_stream(0x1000, &thumb, DisasmArch::Thumb, 8);
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].address, 0x1000);
        assert_eq!(insns[0].size, 2);
        assert_eq!(insns[0].raw_hex, "00BF");
        assert_eq!(insns[0].text, "nop");
        assert_eq!(insns[1].address, 0x1002);
        assert_eq!(insns[1].raw_hex, "0120");
        assert_eq!(insns[1].text, "movs r0, #0x1");

        // Thumb-2: a halfword >= 0xE800 makes the instruction four bytes long
        let thumb2 = [0x00, 0xF0, 0x00, 0xF8];
        let insns = disasm_stream(0x1000, &thumb2, DisasmArch::Thumb, 8);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].size, 4);
        assert_eq!(insns[0].raw_hex, "00F000F8");
        assert_eq!(insns[0].text, "bl 0x1004");

        // AArch64: fixed four-byte steps
        let a64 = [0x1F, 0x20, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6];
        let insns = disasm_stream(0x7100, &a64, DisasmArch::AArch64, 0);
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].text, "nop");
        assert_eq!(insns[0].raw_hex, "1F2003D5");
        assert_eq!(insns[1].address, 0x7104);
        assert_eq!(insns[1].text, "ret");

        // AArch32 at an arbitrary base
        let arm = [0xF0, 0x4F, 0x2D, 0xE9];
        let insns = disasm_stream(0x0010_0000, &arm, DisasmArch::Arm32, 8);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].text, "push {r4, r5, r6, r7, r8, r9, r10, r11, lr}");

        // a limit is honoured, and a truncated tail is not decoded
        let insns = disasm_stream(0x1000, &a64, DisasmArch::AArch64, 1);
        assert_eq!(insns.len(), 1);
        assert_eq!(disasm_stream(0x1000, &a64[..3], DisasmArch::AArch64, 8).len(), 0);
    }

    #[test]
    fn disasm_aarch64_extended_instructions() {
        assert_eq!(disasm_arm(0x1000, 0x9100_0401, false), "add x1, x0, #0x1");
        assert_eq!(disasm_arm(0x1000, 0xF940_0401, false), "ldr x1, [x0, #0x8]");
        assert_eq!(disasm_arm(0x1000, 0x5400_0020, false), "b.eq 0x1004");
        assert_eq!(disasm_arm(0x1000, 0x3640_0020, false), "tbz w0, #0x8, 0x1004");
        assert_eq!(disasm_arm(0x1000, 0x8B02_0001, false), "add x1, x0, x2");
        assert_eq!(disasm_arm(0x1000, 0xAA01_03E0, false), "mov x0, x1");
        assert_eq!(disasm_arm(0x1000, 0xA901_0801, false), "stp x1, x2, [x0, #0x10]");
        assert_eq!(disasm_arm(0x1000, 0xA941_0801, false), "ldp x1, x2, [x0, #0x10]");
        assert_eq!(disasm_arm(0x1000, 0xA9C1_0801, false), "ldp x1, x2, [x0, #0x10]!");
        assert_eq!(disasm_arm(0x1000, 0xA8C1_0801, false), "ldp x1, x2, [x0], #0x10");
        assert_eq!(disasm_arm(0x1000, 0xF840_0001, false), "ldur x1, [x0]");
        assert_eq!(disasm_arm(0x1000, 0xF81F_8001, false), "stur x1, [x0, #-0x8]");
        assert_eq!(disasm_arm(0x1000, 0xD61F_0000, false), "br x0");
        assert_eq!(disasm_arm(0x1000, 0xD63F_0020, false), "blr x1");
        assert_eq!(disasm_arm(0x1000, 0xD400_0001, false), "svc #0x0");
    }

    #[test]
    fn hit_batch_reports_truncation_and_skips_unknown_bits() {
        // 24-byte header (session, count, total, value_size, mapping_count,
        // reserved) + one u64 base + one 16-byte hit, as nxus_server.c sends it.
        let mut data = Vec::new();
        data.extend_from_slice(&7u32.to_le_bytes());      // session
        data.extend_from_slice(&1u32.to_le_bytes());      // count
        data.extend_from_slice(&9u32.to_le_bytes());      // total
        data.extend_from_slice(&4u32.to_le_bytes());      // value_size
        data.extend_from_slice(&1u32.to_le_bytes());      // mapping_count
        data.extend_from_slice(&NXUS_HITBATCH_TRUNCATED.to_le_bytes()); // reserved
        data.extend_from_slice(&0x1000_0000u64.to_le_bytes());          // base[0]
        data.extend_from_slice(&0x24u32.to_le_bytes());   // hit.offset
        data.extend_from_slice(&0u16.to_le_bytes());      // hit.mapping_idx
        data.extend_from_slice(&2u16.to_le_bytes());      // hit.value_type (U32)
        data.extend_from_slice(&0xDEAD_BEEFu64.to_le_bytes()); // hit.value

        let batch = HitBatch::parse(&data);
        assert_eq!(batch.session_id, 7);
        assert_eq!(batch.total, 9);
        assert!(batch.truncated, "reserved bit 0 must surface as truncated");
        assert_eq!(batch.hits.len(), 1);
        assert_eq!(batch.hits[0].address, 0x1000_0024);

        // Older servers always send 0: nothing may be reported as truncated then.
        let mut clean = data.clone();
        clean[20..24].copy_from_slice(&0u32.to_le_bytes());
        assert!(!HitBatch::parse(&clean).truncated);
        // Unknown reserved bits are ignored rather than misread.
        clean[20..24].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        assert!(!HitBatch::parse(&clean).truncated);
    }
}
