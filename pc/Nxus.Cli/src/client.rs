//! Nxus TCP client: seq-correlated requests plus an asynchronous event queue.
//!
//! Works against the real sysmodule and against pc/nxus/mock_switch.py, so the
//! whole protocol can be exercised without a console.

use std::collections::HashMap;
use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::protocol::*;

/// One entry of the target's memory map, under the name this module's
/// pointer-width rule speaks of (`mappings`).
pub use crate::protocol::MemoryInfo as Mapping;
pub use crate::protocol::ValueType;

#[derive(Debug, Clone)]
pub struct NxusError {
    pub message: String,
    pub result: Option<u32>,
}

impl fmt::Display for NxusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.result {
            Some(rc) => write!(f, "{} (result=0x{:08X})", self.message, rc),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for NxusError {}

pub type Result<T> = std::result::Result<T, NxusError>;

/// End of the 32-bit address space: the highest address a 4-byte pointer can
/// describe.
///
/// A mapping that ends exactly here still holds only 32-bit-addressable bytes, so
/// it does not by itself prove 8-byte pointers (the console compares the same way
/// in `nxusPtrScanAutoWidthFor()`).
pub const WIDTH_LIMIT: u64 = 0x1_0000_0000;

// Why [`pointer_width_with_reason`] answered what it answered.  One constant per
// branch, not one per step: "the process address space" can decide either way,
// and an operator reading 4 vs 8 needs to know which evidence won.
//
// They are worded to complete "assumed {N}-bit from ...", which is exactly what
// the GUI prints ("width: auto (assumed 64-bit from the process address space,
// which is wider than 4 GiB)").  The branches correspond one to one with the
// console's NXUS_PTRSCAN_WIDTH_REASON_* (core/nxus_ptrscan.h), whose own strings
// are console-log terse ("process is 64-bit", "mapping ends").
pub const WIDTH_REASON_PROCESS_64: &str = "the process address space, which is wider than 4 GiB";
pub const WIDTH_REASON_PROCESS_32: &str = "the process address space, which fits in 4 GiB";
pub const WIDTH_REASON_MAPPINGS_64: &str = "the mapping table, whose highest end is above 4 GiB";
pub const WIDTH_REASON_MAPPINGS_32: &str = "the mapping table, whose every end is within 4 GiB";
pub const WIDTH_REASON_MAIN_BASE_64: &str = "the main module base, at or above 4 GiB";
pub const WIDTH_REASON_MAIN_BASE_32: &str = "the main module base, below 4 GiB";
pub const WIDTH_REASON_DEFAULT: &str = "the AArch64 default, because nothing is known";

/// The title's pointer width in bytes (4 or 8) *and the evidence for it* - the
/// ONE width rule on the PC.
///
/// Nothing here is ever sent to the console: a pointer scan request carries
/// `value_width = 0` ("automatic") and the console decides.  This mirrors the
/// console's `nxusPtrScanAutoWidthFor()` (core/nxus_ptrscan.c) so the PC can
/// *explain* that decision and pick the matching parts: the address format in
/// the GUI, the pointer width a PC-side dump walk uses, and the 540F/580F pointer
/// load plus the 640F/680F value write of a cheat export.
///
/// It exists because the PC used to answer this in three places with three
/// different rules (the GUI said 4 for an unknown base, a dump walk said 8, and
/// the CLI decided from the mapping table), so a display, a PC-side scan and an
/// exported cheat could disagree about the very same title.
///
/// The rule, in the console's order - the order is what makes the two agree:
///
/// 1. **The process's own address space** (`Metadata::address_space_arch()`,
///    from dmnt's `aslr_base`/`aslr_size`).  This outranks every observation of
///    where the memory happens to sit this run: AArch64 ASLR routinely places a
///    64-bit title's main module at 0x00700000 and its heap around 0x36000000,
///    i.e. *every mapping ends below 4 GiB*, and the old mapping-only rule then
///    walked that title with 4-byte loads - the server said 8, the PC said 4, and
///    the GUI happily generated 540F/640F code for a 64-bit game.  A 32-bit
///    process can never hold a pointer above 4 GiB, so AArch32 is equally
///    authoritative - but only when the metadata really says so: "no answer"
///    (0 size: an old console or dmnt closed) must not be read as AArch32.
/// 2. **The mappings.**  `mappings` is the target's memory map.  An entry whose
///    end lies above 4 GiB proves a 64-bit address space; when every entry ends
///    at or below 4 GiB, 4-byte pointers cover the whole map.  Entries the console
///    could not walk (size 0, not readable) are ignored exactly like
///    `buildPtrRegions()` ignores them.
/// 3. **The main module base.**  Without a usable mapping table this is the only
///    evidence left: `0` means "unknown" and falls through to 8, a base at or
///    above 4 GiB is already outside the 32-bit address space, everything else 4.
/// 4. **8**: nothing known at all.  AArch64 is the common case, and a wide load
///    on a 32-bit title only costs a failed scan while a narrow load on a 64-bit
///    title silently loses every chain.
pub fn pointer_width_with_reason(
    metadata: &Metadata,
    mappings: Option<&[Mapping]>,
) -> (u32, &'static str) {
    // 1. The process itself.  `Unknown` (old firmware, dmnt closed, inconsistent
    //    region) falls through instead of guessing.
    match metadata.address_space_arch() {
        AddressSpaceArch::Aarch64 => return (8, WIDTH_REASON_PROCESS_64),
        AddressSpaceArch::Aarch32 => return (4, WIDTH_REASON_PROCESS_32),
        AddressSpaceArch::Unknown => {}
    }

    // 2. The mappings the walk is about to traverse.
    let mut have_mapping = false;
    let mut wide = false;
    for mapping in mappings.unwrap_or(&[]) {
        if mapping.size == 0 || mapping.perm & PERM_R == 0 {
            continue;
        }
        have_mapping = true;
        // A wrapping base+size covers the top of the address space, which no
        // 32-bit pointer reaches: saturating at u64::MAX is the right answer,
        // not a wrapped (small) end.
        if mapping.base.saturating_add(mapping.size) > WIDTH_LIMIT {
            wide = true;
        }
    }
    if have_mapping {
        return if wide {
            (8, WIDTH_REASON_MAPPINGS_64)
        } else {
            (4, WIDTH_REASON_MAPPINGS_32)
        };
    }

    // 3. The main module base, then 4. the wide default.
    match metadata.main_base {
        0 => (8, WIDTH_REASON_DEFAULT),
        base if base >= WIDTH_LIMIT => (8, WIDTH_REASON_MAIN_BASE_64),
        _ => (4, WIDTH_REASON_MAIN_BASE_32),
    }
}

/// The width alone, for callers that only need the number.
///
/// Kept as the narrow signature the CLI, the dump walker and the EdiZon export
/// already call; [`pointer_width_with_reason`] is the same decision plus the
/// evidence, and the GUI shows that evidence.
pub fn pointer_width_for(metadata: &Metadata, mappings: Option<&[Mapping]>) -> u32 {
    pointer_width_with_reason(metadata, mappings).0
}

/// `sizeof(NxusDebugConfig)` on the wire.  A CONFIG payload of exactly this
/// length means "apply the debug block, leave the hotkey/watchdog settings
/// alone"; the full `NxusConfig` (32 bytes, +16 with a debug tail) rewrites them.
pub const DEBUG_CONFIG_LEN: usize = 16;

/// `NXUS_MAKE_RESULT(NXUS_ERR_BUSY)` (core/nxus_protocol.h).  PtrScanGet answers
/// with it while the console's pointer-scan worker is still walking.
pub const RESULT_BUSY: u32 = 0x8003_C803;

/// `NXUS_RESULT_PTRSCAN_STARTED` (switch/include/nxus_server.h): PtrScanBegin
/// accepted the walk and handed it to a worker thread.  The chain list is then
/// collected by polling PtrScanGet until it stops answering [`RESULT_BUSY`].
pub const RESULT_PTRSCAN_STARTED: u32 = 0x8003_C808;

/// PtrScanGet poll period while the console walks.  Short enough that the poll
/// loop itself keeps the console's pause watchdog fed (any traffic does), long
/// enough not to spin a core in the console's single connection thread.
const PTRSCAN_POLL: Duration = Duration::from_millis(250);

/// `NXUS_REASON_RETRY_LATER` (core/nxus_protocol.h): the console has not
/// finished releasing the previous debug session yet.  It answers a short
/// debug command (Attach / Detach / Continue / Step) with BUSY + this reason
/// for a moment right after a detach, and the same command works again once
/// the release completes.
pub const REASON_RETRY_LATER: u32 = 13;

/// Delay between the automatic retries of a [`REASON_RETRY_LATER`] answer.
const RETRY_LATER_DELAY: Duration = Duration::from_millis(250);

/// How many times such a command is retried: 6 x 250 ms = 1.5 s, which covers
/// the console's release window without making the UI look stuck.
const RETRY_LATER_RETRIES: u32 = 6;

/// One-shot text for the GUI (which has no stderr) and the CLI log: the retry
/// is announced exactly once per process, not once per attempt.
static RETRY_LATER_NOTICE: Mutex<Option<String>> = Mutex::new(None);

/// Set once [`note_retry_later`] has reported the retry.
static RETRY_LATER_LOGGED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn note_retry_later() {
    if RETRY_LATER_LOGGED.swap(true, Ordering::Relaxed) {
        return;
    }
    let message = "retrying after the previous session was released".to_string();
    eprintln!("{}", message);
    // The GUI polls this (see `take_retry_later_notice`): stderr is invisible
    // there, and a silent one-second stall would look like a hang.
    *lock(&RETRY_LATER_NOTICE) = Some(message);
}

/// Take the "retrying after the previous session was released" line, if a
/// retry happened in this process.  Returns `Some` exactly once.
pub fn take_retry_later_notice() -> Option<String> {
    lock(&RETRY_LATER_NOTICE).take()
}

/// How often a `scan_wait*` run may hand its polled progress to a `report`
/// callback.
///
/// The status poll itself runs every 20 ms (see `scan_wait_cancellable`), which
/// is the right rate for noticing "done", but a UI cannot absorb 50 progress
/// updates per second: `progress_permille` only moves as fast as the walk does,
/// so a fifth of a second is plenty and keeps the GUI's event channel quiet.
const SCAN_PROGRESS_REPORT: Duration = Duration::from_millis(200);

#[derive(Debug, Clone)]
pub struct Event {
    pub kind: u16,
    pub payload: Vec<u8>,
}

/// Everything a scan needs.  `pattern` holds the raw bytes for string /
/// byte-array / binary searches; `mask` is the wildcard mask (1 = compare).
#[derive(Debug, Clone)]
pub struct ScanSpec {
    pub value: u64,
    /// Second operand: the high bound for Between, or the epsilon bits for a
    /// fuzzy float compare.
    pub target2: u64,
    pub value_size: u32,
    pub value_type: ValueType,
    pub compare: Compare,
    pub scope: Scope,
    pub range_begin: u64,
    pub range_end: u64,
    /// Several disjoint ranges at once (scope = Ranges).  Each entry is [begin, end).
    pub ranges: Vec<(u64, u64)>,
    pub flags: u32,
    pub pattern: Vec<u8>,
    pub mask: Vec<u8>,
    pub epsilon_decimals: u32,
}

impl ScanSpec {
    pub fn new(value_type: ValueType, compare: Compare) -> ScanSpec {
        ScanSpec {
            ranges: Vec::new(),
            value: 0,
            target2: 0,
            value_size: value_type.size(),
            value_type,
            compare,
            scope: Scope::All,
            range_begin: 0,
            range_end: 0,
            flags: if value_type.is_float() {
                SCAN_F_FLOAT
            } else {
                0
            },
            pattern: Vec::new(),
            mask: Vec::new(),
            epsilon_decimals: 0,
        }
    }

    pub fn with_value(mut self, value: u64) -> ScanSpec {
        self.value = value;
        self
    }

    pub fn with_pattern(mut self, pattern: Vec<u8>) -> ScanSpec {
        self.pattern = pattern;
        self
    }
}

#[allow(non_snake_case)]
fn buildScanPayload(spec: &ScanSpec, kind: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        56 + 16 + spec.pattern.len() * 2 + spec.ranges.len() * crate::protocol::RANGE_ENTRY_SIZE,
    );
    put_u32(&mut payload, kind);
    put_u32(&mut payload, spec.value_size);
    put_u32(&mut payload, spec.compare as u32);
    put_u32(&mut payload, spec.scope as u32);
    put_u64(&mut payload, spec.range_begin);
    put_u64(&mut payload, spec.range_end);
    put_u64(&mut payload, spec.value);
    put_u64(&mut payload, spec.target2);
    put_u32(&mut payload, 0); // chunk size (server default)
                              // The range list travels right after the request, so the flag has to be set
                              // before the fixed header is written.
    let mut flags = spec.flags;
    let use_ranges = spec.scope == crate::protocol::Scope::Ranges && !spec.ranges.is_empty();
    if use_ranges {
        flags |= crate::protocol::SCAN_F_RANGES;
    }
    put_u32(&mut payload, flags);

    if use_ranges {
        let count = spec.ranges.len().min(crate::protocol::MAX_SCAN_RANGES);
        put_u32(&mut payload, count as u32);
        put_u32(&mut payload, 0); // reserved
        for (begin, end) in spec.ranges.iter().take(count) {
            put_u64(&mut payload, *begin);
            put_u64(&mut payload, *end);
        }
    }

    put_u32(&mut payload, spec.value_type as u32);
    put_u32(&mut payload, spec.pattern.len() as u32);
    put_u32(&mut payload, spec.epsilon_decimals);
    put_u32(&mut payload, 0);
    payload.extend_from_slice(&spec.pattern);
    if spec.flags & SCAN_F_WILDCARD != 0 {
        payload.extend_from_slice(&spec.mask);
    }
    payload
}

type Response = Option<(u16, u16, Vec<u8>)>;

/// One in-flight request: where its reply goes and when it gives up.
///
/// `deadline` exists for the reader, not for the waiter.  A `ScanBegin` reply
/// legitimately takes minutes, so "no bytes for 20 s" must not kill the link
/// while such a request is outstanding; the reader waits until the latest
/// pending deadline before it calls the link dead.
struct Pending {
    tx: Sender<Response>,
    deadline: Instant,
    /// Whether this deadline may drive the reader's "silence means dead" rule.
    ///
    /// A keepalive `Heartbeat` is excluded: missing one is not a disconnect, the
    /// next one retries.  If it counted, a single lost reply would kill the link
    /// at the heartbeat's 3 s deadline and the "two misses in a row" tolerance
    /// below would never get a chance.
    guards_idle: bool,
}

/// Conservative default until the server tells us its real limit.
pub const DEFAULT_MAX_READ: u32 = 64 * 1024;

/// Maximum number of hits the console admits to one `ScanGetHits` window.
///
/// Mirrors `NXUS_MAX_HITS_PER_BATCH` in `switch/include/nxus_server.h` (8192).
/// Asking for more is clamped by the server, but clamping locally keeps the
/// client's notion of the requested window identical to the server's - the page
/// walk advances the server index by exactly that many slots.
pub const NXUS_MAX_HITS_PER_BATCH: u32 = 8192;

/// Largest payload this client will accept from the console.
///
/// `shared/nxus_net.h` caps a single reply at `NXUS_NET_BUF_SIZE` (1 MiB); this
/// leaves headroom for the header and for a future bump, while still rejecting a
/// garbage length outright instead of trying to allocate it.
pub const MAX_PAYLOAD: u32 = 8 * 1024 * 1024;

/// Deadline for the TCP handshake.
///
/// `TcpStream::connect` has no deadline of its own: an unreachable console (wrong
/// IP, powered off, on another subnet) leaves it inside the OS retry loop for
/// 20-30 s, and the GUI's worker thread cannot answer anything meanwhile, so the
/// whole window looks hung.  Five seconds is well beyond a LAN handshake and
/// still short enough to report "unreachable" promptly.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Deadline for turning the host name into addresses.
///
/// [`std::net::ToSocketAddrs`] has no deadline of its own: a DNS server that stops
/// answering keeps the call inside the resolver for tens of seconds (or forever on
/// some stacks), and the GUI's worker thread cannot report anything meanwhile.  The
/// lookup therefore runs on its own (detached) thread and this is how long the
/// caller waits for the answer before giving up.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);

/// Deadline for a plain [`NxusClient::request`] (status, metadata, freeze, ...).
///
/// 30 s was far too long for a command that a healthy LAN console answers in
/// milliseconds: one NCL operation issues dozens of requests, so a console that
/// stopped answering turned into "30 s x N" - the window looked hung.  Ten
/// seconds still leaves room for a slow console and a busy `dmnt`, while long
/// operations (scan, snapshot, pointer scan) pass their own, longer deadline.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Deadline for one cheat-VM memory access.
///
/// A cheat instruction reads/writes several times, and a block is tens of
/// instructions: the 10 s default (let alone the old 30 s) turns a block into
/// minutes.  Three seconds is "a live console always answers within it"; when
/// the console is really gone, the link's `dead` flag makes the *next* access
/// fail immediately instead of waiting again.
pub const CHEAT_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------------------
// コンソール側チート VM（`NxusCmd_Cheat*` / `NxusEvent_CheatFault`）
// ---------------------------------------------------------------------------

// コマンド id を `protocol::cmd` に足さないのは、あの表が
// `core/nxus_protocol.h` との対応を固定するパリティ検査（`protocol.rs` の
// `header_define` 系テストと Python 側の test_protocol_parity）に載っている
// 「プロトコル定義そのもの」だから。ここに置くのは、この 5 つを使うのが
// 下の薄いラッパだけであり、定義表を動かさずに済むため。
/// `NxusCmd_CheatUpload`（`NxusCheatProgramHeader` + ブロック + 命令）。
pub const CMD_CHEAT_UPLOAD: u16 = 0x0080;
/// `NxusCmd_CheatEnable`（`NxusCheatEnable`）。
pub const CMD_CHEAT_ENABLE: u16 = 0x0081;
/// `NxusCmd_CheatStatus` -> `NxusCheatStatus`。
pub const CMD_CHEAT_STATUS: u16 = 0x0082;
/// `NxusCmd_CheatPanicOff` -> `NxusCheatRestore`。
pub const CMD_CHEAT_PANIC_OFF: u16 = 0x0083;
/// `NxusCmd_CheatClear`（書き戻さずにプログラムを捨てる）。
pub const CMD_CHEAT_CLEAR: u16 = 0x0084;

/// `NxusEvent_CheatFault`: コンソールのチートワーカーが自分から全ブロックを
/// 止めた（対象消滅 / 復元表が満杯 / 書き込み失敗）。
pub const EVENT_CHEAT_FAULT: u16 = 0x800A;

/// CheatUpload の締切（10 秒）。
///
/// プログラムは最大 48 KiB あり、コンソールは受け取ったバイト列をリンク・
/// 検証してから答える。他のチート命令と同じ 3 秒では、遅い Wi-Fi や大きめの
/// チートファイルで正当な応答を取りこぼす。
pub const CHEAT_UPLOAD_TIMEOUT: Duration = Duration::from_secs(10);

/// CheatEnable / CheatStatus / CheatPanicOff / CheatClear の締切（3 秒）。
///
/// どれも「押したらすぐ返る」対話操作で、長い締切はそのまま UI の固まりに
/// なる。チート 1 命令と同じ [`CHEAT_REQUEST_TIMEOUT`] に合わせてある。
pub const CHEAT_COMMAND_TIMEOUT: Duration = Duration::from_secs(3);

/// `NxusCheatStatus`（48 バイト）: `NxusCmd_CheatStatus` の応答。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CheatStatus {
    /// 0 のときは何もアップロードされていない。
    pub program_valid: u32,
    pub block_count: u32,
    pub enabled_count: u32,
    pub insn_count: u32,
    /// アップロード以後に実行した 16 ms ティック数。
    pub tick_count: u32,
    /// いま書き換えたバイトを保持しているアドレス数。
    pub journal_count: u32,
    /// 最後に失敗したブロックの `NXUS_CHEATVM_ERR_*`（0 = 無し）。
    pub last_error: u32,
    pub last_error_pc: u32,
    /// ワーカーが自分からプログラムを止めた回数。
    pub fault_count: u32,
    pub running: u32,
    /// エンジンが使っている生の HID マスク。
    pub keys_held: u64,
}

impl CheatStatus {
    pub const SIZE: usize = 48;

    /// 短い応答も 0 埋めで受ける（古いコンソールは末尾のフィールドを
    /// 送ってこない。足りない分を 0 として読むのが、`NxusStatus` と同じ扱い）。
    pub fn parse(body: &[u8]) -> CheatStatus {
        let word = |offset: usize| -> u32 {
            if body.len() >= offset + 4 {
                rd_u32(body, offset)
            } else {
                0
            }
        };
        CheatStatus {
            program_valid: word(0),
            block_count: word(4),
            enabled_count: word(8),
            insn_count: word(12),
            tick_count: word(16),
            journal_count: word(20),
            last_error: word(24),
            last_error_pc: word(28),
            fault_count: word(32),
            running: word(36),
            keys_held: if body.len() >= 48 { rd_u64(body, 40) } else { 0 },
        }
    }

    /// 最後の失敗を 1 行にする（0 なら `None`）。
    pub fn last_error_text(&self) -> Option<String> {
        if self.last_error == 0 {
            return None;
        }
        let name = cheat_error_name(self.last_error)
            .map(|name| name.to_string())
            .unwrap_or_else(|| format!("code {}", self.last_error));
        Some(format!("{name} at instruction {}", self.last_error_pc))
    }
}

/// `NxusCheatRestore`（16 バイト）: `NxusCmd_CheatPanicOff` の応答。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CheatRestore {
    /// 書き戻せたアドレス数。
    pub restored: u32,
    /// 書き戻せなかったアドレス数（対象が消えた）。
    pub failed: u32,
    pub blocks_stopped: u32,
    pub reserved: u32,
}

impl CheatRestore {
    pub const SIZE: usize = 16;

    pub fn parse(body: &[u8]) -> CheatRestore {
        let word = |offset: usize| -> u32 {
            if body.len() >= offset + 4 {
                rd_u32(body, offset)
            } else {
                0
            }
        };
        CheatRestore {
            restored: word(0),
            failed: word(4),
            blocks_stopped: word(8),
            reserved: word(12),
        }
    }

    /// 全部戻せたか。1 バイトでも戻せていないなら「完了」ではない。
    pub fn is_complete(&self) -> bool {
        self.failed == 0
    }
}

/// `NxusCheatUploadReply`（16 バイト）: `NxusCmd_CheatUpload` の応答。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CheatUploadReply {
    pub accepted_blocks: u32,
    pub accepted_insns: u32,
    /// 0、または拒否理由（`NXUS_CHEATVM_ERR_*` を正の値で）。
    pub rejected_reason: u32,
    pub reserved: u32,
}

impl CheatUploadReply {
    pub const SIZE: usize = 16;

    pub fn parse(body: &[u8]) -> CheatUploadReply {
        let word = |offset: usize| -> u32 {
            if body.len() >= offset + 4 {
                rd_u32(body, offset)
            } else {
                0
            }
        };
        CheatUploadReply {
            accepted_blocks: word(0),
            accepted_insns: word(4),
            rejected_reason: word(8),
            reserved: word(12),
        }
    }

    /// コンソールが拒否した理由（受理されたなら `None`）。
    pub fn rejected_text(&self) -> Option<String> {
        if self.rejected_reason == 0 {
            return None;
        }
        let name = cheat_error_name(self.rejected_reason)
            .map(|name| name.to_string())
            .unwrap_or_else(|| format!("code {}", self.rejected_reason));
        Some(name)
    }
}

/// `NxusCheatFault`（16 バイト）: `NxusEvent_CheatFault` のペイロード。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CheatFault {
    /// `NXUS_CHEATVM_ERR_*` または `NXUS_CHEAT_FAULT_*`。
    pub reason: u32,
    /// ブロック番号。特定のブロックでないときは 0xFFFFFFFF。
    pub block: u32,
    /// そのブロック内の命令番号。
    pub pc: u32,
    /// 止まるまでに書き戻せたアドレス数。
    pub restored: u32,
}

impl CheatFault {
    pub const SIZE: usize = 16;

    /// `NXUS_CHEAT_FAULT_TARGET_GONE`: タイトルが終了 / 再起動した。
    pub const TARGET_GONE: u32 = 100;
    /// `NXUS_CHEAT_FAULT_JOURNAL_FULL`: 復元表（`NXUS_CHEATVM_MAX_JOURNAL`）が満杯。
    pub const JOURNAL_FULL: u32 = 101;

    pub fn parse(body: &[u8]) -> Option<CheatFault> {
        if body.len() < CheatFault::SIZE {
            return None;
        }
        Some(CheatFault {
            reason: rd_u32(body, 0),
            block: rd_u32(body, 4),
            pc: rd_u32(body, 8),
            restored: rd_u32(body, 12),
        })
    }

    /// 利用者にそのまま出す理由。
    ///
    /// 「全ブロックが勝手に止まった」だけでは何をすればよいか分からないので、
    /// 原因ごとに次の行動が分かる文にする。
    pub fn reason_text(&self) -> String {
        let block = if self.block == u32::MAX {
            "all blocks".to_string()
        } else {
            format!("block {}", self.block)
        };
        let text = match self.reason {
            CheatFault::TARGET_GONE => "the title was closed or restarted".to_string(),
            CheatFault::JOURNAL_FULL => {
                "the restore table is full: turn some cheats off and try again".to_string()
            }
            other => cheat_error_name(other)
                .map(|name| name.to_string())
                .unwrap_or_else(|| format!("reason {other}")),
        };
        format!("{text} ({block}, {} address(es) restored)", self.restored)
    }
}

/// `NXUS_CHEATVM_ERR_*` の名前。
///
/// 2 つの載り方がある: `NxusCheatStatus.last_error` は s32 の負値をそのまま
/// u32 に載せ、`NxusCheatUploadReply.rejected_reason` は「正の値」で返す
/// （`core/nxus_protocol.h` のコメント）。どちらの経路でも同じ名前を出せる
/// ように両方を受ける。
fn cheat_error_name(code: u32) -> Option<&'static str> {
    let negative = code >= 0xFFFF_FF00; // s32 の -256..-1
    let small = if negative {
        0u32.wrapping_sub(code)
    } else {
        code
    };
    match small {
        1 => Some("bad program"),
        2 => Some("bad block"),
        3 => Some("a branch target is outside the program"),
        4 => Some("step limit reached"),
        5 => Some("target read failed"),
        6 => Some("target write failed"),
        7 => Some("bad register"),
        8 => Some("bad opcode"),
        _ => None,
    }
}

/// 受信イベントのうち、このビルドが構造化して扱うもの。
///
/// [`Event`] は生フレーム（kind + payload）のまま保持する。既知のイベントを
/// ここで型付きに開くことで、GUI/CLI がペイロードのレイアウトを知らずに
/// 済み、知らないイベントは [`IncomingEvent::Other`] として素通りする
/// （新しいイベントを足しても既存の呼び出し側が壊れない）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncomingEvent {
    /// `NxusEvent_CheatFault`: コンソールのチートワーカーが自分から全部止めた。
    CheatFault {
        reason: u32,
        block: u32,
        pc: u32,
        restored: u32,
    },
    /// このビルドが解釈しないイベント（生データは [`Event`] 側にある）。
    Other,
}

impl Event {
    /// 生フレームを型付きイベントに開く。
    pub fn decode(&self) -> IncomingEvent {
        match self.cheat_fault() {
            Some(fault) => IncomingEvent::CheatFault {
                reason: fault.reason,
                block: fault.block,
                pc: fault.pc,
                restored: fault.restored,
            },
            None => IncomingEvent::Other,
        }
    }

    /// `NxusEvent_CheatFault` なら中身を返す（[`Self::decode`] の近道）。
    pub fn cheat_fault(&self) -> Option<CheatFault> {
        if self.kind != EVENT_CHEAT_FAULT {
            return None;
        }
        CheatFault::parse(&self.payload)
    }
}

/// コンソールがこのコマンドを知らない（旧ビルド）ことを示す応答か。
///
/// 新しいコマンドを送ると、実装していないコンソールは
/// `NXUS_MAKE_RESULT(NXUS_ERR_NOT_IMPLEMENTED)`（0x8003C801）または
/// `NXUS_ERR_UNSUPPORTED`（0x8003C802）を返し、たいてい
/// `NXUS_REASON_UNKNOWN_COMMAND`（6）を添える。判定をここ 1 か所にまとめて
/// おくことで、GUI と NCL のフォールバック条件がずれない。
pub fn is_unsupported_command(error: &NxusError) -> bool {
    match error.result {
        Some(0x8003_C801) | Some(0x8003_C802) => true,
        // Result だけ返す古いコンソールでも、理由コードが読めたなら分かる。
        _ => error.message.contains("(reason=6)"),
    }
}

/// How long the reader tolerates hearing nothing while no request is waiting.
///
/// The keepalive below sends a `Heartbeat` every few seconds, so a *live* link
/// never stays quiet for 20 s.  While a long command is outstanding (one
/// `ScanBegin` reply can take 600 s) the reader waits for that request's own
/// deadline instead, so this value only applies to a link that should be idle.
const LINK_IDLE_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the link may be silent before the keepalive sends a `Heartbeat`.
///
/// The console's own watchdog is 15 s (`watchdog_timeout_ms = 15000` in
/// `switch/source/nxus_server.c`) and it resumes a paused target when it hears
/// nothing, so an idle PC has to keep talking - the GUI already heartbeats every
/// 4 s for exactly that reason.  Five seconds also keeps the reader's 20 s
/// "silence means dead" rule honest, with room for one lost reply.
const LINK_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// How long one keepalive `Heartbeat` waits for its reply.
const LINK_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(3);

/// Retry delay after a heartbeat went unanswered (the link may just be slow).
const LINK_KEEPALIVE_RETRY: Duration = Duration::from_secs(2);

/// Consecutive unanswered heartbeats before the link is declared dead.
const LINK_KEEPALIVE_MISSES: u32 = 2;

/// How often the keepalive thread re-reads the link state.
const LINK_KEEPALIVE_TICK: Duration = Duration::from_millis(500);

/// Reader/keepalive timings, injectable so tests do not have to wait 20 s.
///
/// Production uses [`LinkTiming::default`].  The tests build the same client
/// with milliseconds instead, which is the only way to exercise the "silent
/// peer" and "keepalive" paths without making the suite take half a minute.
#[derive(Clone, Copy)]
struct LinkTiming {
    /// How long the reader tolerates silence while nothing is pending.
    idle_timeout: Duration,
    /// How long the link may be quiet before a heartbeat is sent.
    keepalive_interval: Duration,
    /// Deadline for one heartbeat reply.
    keepalive_timeout: Duration,
    /// Retry delay after an unanswered heartbeat.
    keepalive_retry: Duration,
    /// Unanswered heartbeats in a row before the link is declared dead.
    keepalive_misses: u32,
}

impl Default for LinkTiming {
    fn default() -> Self {
        Self {
            idle_timeout: LINK_IDLE_TIMEOUT,
            keepalive_interval: LINK_KEEPALIVE_INTERVAL,
            keepalive_timeout: LINK_KEEPALIVE_TIMEOUT,
            keepalive_retry: LINK_KEEPALIVE_RETRY,
            keepalive_misses: LINK_KEEPALIVE_MISSES,
        }
    }
}

/// Lock a mutex, ignoring poisoning.
///
/// A worker thread that panicked while holding one of these locks must not turn
/// every later call into another panic: the data behind the lock is plain
/// bookkeeping that stays usable, and a panicking worker is exactly the
/// "GUI stuck on busy forever" failure this module tries to avoid.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Resolve `host` with a deadline ([`RESOLVE_TIMEOUT`]).
///
/// An IP literal is answered without touching the resolver at all: the address is
/// already known, and a DNS server that hangs would otherwise delay even
/// `127.0.0.1` by the full timeout.  Everything else is looked up on a detached
/// thread (its `JoinHandle` is deliberately dropped: the call cannot be cancelled,
/// and the caller only waits for the channel).
fn resolve_host(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    use std::net::ToSocketAddrs;

    let bare = host.trim();
    let bare = bare
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(bare);
    if let Ok(ip) = IpAddr::from_str(bare) {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let (tx, rx) = mpsc::channel::<std::io::Result<Vec<SocketAddr>>>();
    let name = bare.to_string();
    thread::spawn(move || {
        let resolved = (name.as_str(), port)
            .to_socket_addrs()
            .map(|addrs| addrs.collect::<Vec<_>>());
        let _ = tx.send(resolved);
    });

    match rx.recv_timeout(RESOLVE_TIMEOUT) {
        Ok(Ok(addrs)) => Ok(addrs),
        Ok(Err(e)) => Err(NxusError {
            message: format!("cannot resolve {}:{} - {}", host, port, net_error_text(&e)),
            result: None,
        }),
        Err(RecvTimeoutError::Timeout) => Err(NxusError {
            message: format!(
                "cannot resolve {}:{} - the host name lookup did not answer within {} s",
                host,
                port,
                RESOLVE_TIMEOUT.as_secs()
            ),
            result: None,
        }),
        Err(RecvTimeoutError::Disconnected) => Err(NxusError {
            message: format!(
                "cannot resolve {}:{} - the host name lookup failed",
                host, port
            ),
            result: None,
        }),
    }
}

/// Protocol-version mismatch text waiting to be shown by the GUI.
///
/// `NxusClient::status` is the only place that sees the console's version, but it
/// runs on the worker thread and the GUI has no stderr, so the message is parked
/// here instead of only printed.  It is written once per process (the `swap` guard
/// in `status`) and cleared by [`take_protocol_warning`].
static PROTOCOL_WARNING: Mutex<Option<String>> = Mutex::new(None);

/// Take the protocol-version warning, if one was recorded.
///
/// Returns `Some` exactly once: the slot is empty afterwards, so a GUI that polls
/// every frame logs the line a single time.
pub fn take_protocol_warning() -> Option<String> {
    lock(&PROTOCOL_WARNING).take()
}

/// Connect with the overall [`CONNECT_TIMEOUT`] split across the resolved
/// addresses (a host name can resolve to both IPv4 and IPv6).
fn connect_with_timeout(host: &str, port: u16) -> Result<TcpStream> {
    let addrs = resolve_host(host, port)?;

    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut last_error: Option<std::io::Error> = None;
    let mut had_address = false;

    for addr in addrs {
        had_address = true;
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        // connect_timeout rejects a zero duration outright.
        if left.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&addr, left) {
            Ok(stream) => return Ok(stream),
            Err(e) => last_error = Some(e),
        }
    }

    let reason = match last_error {
        Some(e) => net_error_text(&e),
        None if !had_address => "the host name has no address".to_string(),
        None => format!("no answer within {} s", CONNECT_TIMEOUT.as_secs()),
    };
    Err(NxusError {
        message: format!(
            "cannot connect to {}:{} - {}. Is the console running Nxus and is this the console's IP?",
            host, port, reason
        ),
        result: None,
    })
}

pub struct NxusClient {
    max_read: std::sync::atomic::AtomicU32,
    /// Set when a hit batch reports NXUS_HITBATCH_TRUNCATED (see scan_all_hits).
    truncated: std::sync::atomic::AtomicBool,
    /// Set when a hit batch reports NXUS_HITBATCH_DROPPED: the console dropped
    /// hits whose mapping is gone, so the collected list is lossy (see
    /// scan_all_hits).
    dropped: std::sync::atomic::AtomicBool,
    /// Shared (`Arc`) with the keepalive thread: both write whole frames, and a
    /// single mutex is what keeps a heartbeat from landing between a request's
    /// header and its payload.
    stream: Arc<Mutex<TcpStream>>,
    pending: Arc<Mutex<HashMap<u32, Pending>>>,
    events: Mutex<Receiver<Event>>,
    /// Shared with the keepalive thread: one sequence space for every frame that
    /// expects an answer.  A separate counter would eventually hand a caller's
    /// reply to a heartbeat (or the other way round).
    seq: Arc<Mutex<u32>>,
    /// Shared with the reader thread; an `AtomicBool` (not a `Mutex<bool>`) so `Drop`
    /// can flag it without ever blocking behind a busy lock.
    running: Arc<std::sync::atomic::AtomicBool>,
    /// Set the moment the link is known to be gone: EOF, a protocol violation, a
    /// read deadline that expired, or a failed send.  Every later request fails
    /// with "connection lost" instead of spending its own timeout first.
    dead: Arc<std::sync::atomic::AtomicBool>,
    /// When the last frame was written (request or keepalive).  The keepalive
    /// thread reads it to decide whether the link has been quiet for too long.
    last_tx: Arc<Mutex<Instant>>,
    /// Addresses the previous `frozen_list()` reported.  Kept so a later reply can
    /// be compared against it; see [`NxusClient::frozen_list_diff`].
    last_frozen: Mutex<Vec<u64>>,
    /// Addresses that were in `last_frozen` and are missing from the newest
    /// `frozen_list()` reply - the console (or another dmnt user) released them.
    released_frozen: Mutex<Vec<u64>>,
    /// Full thread id of the newest `NxusEvent_DebugStopped` this client has seen
    /// through [`NxusClient::poll_event`], or None when that event was not observed
    /// (or the target has been resumed since).  The event carries the complete 64-bit
    /// id, so it recovers the id an old console could only report truncated in
    /// `NxusDebugStatus.stopped_thread_low`; the low half is compared before it is
    /// trusted (see [`select_stopped_thread`]).
    last_stop: Mutex<Option<u64>>,
}

/// Text for an I/O error that is safe to show in the GUI.
///
/// Known socket errors get a plain English description first; the localised OS message
/// is kept as-is behind it (the GUI now bundles a Japanese font, so it renders).
pub fn net_error_text(e: &std::io::Error) -> String {
    if let Some(code) = e.raw_os_error() {
        let known = match code {
            10061 => Some("connection refused (nothing is listening there)"),
            10060 => Some("timed out (wrong IP, or the console is off/unreachable)"),
            10065 => Some("no route to host"),
            10051 => Some("network unreachable"),
            10013 => Some("permission denied (firewall?)"),
            10048 => Some("address already in use"),
            10049 => Some("cannot assign the requested address"),
            _ => None,
        };
        if let Some(text) = known {
            return format!("{} (os error {})", text, code);
        }
    }
    let raw = e.to_string();
    let cleaned = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.is_empty() {
        format!("io error (os error {:?})", e.raw_os_error())
    } else {
        cleaned
    }
}

/// Human-readable text for the optional reason word of an error reply.
///
/// Mirror of `NXUS_REASON_*` in core/nxus_protocol.h: a current console appends
/// one u32 reason after the Result, older ones send only the Result (no tail,
/// so no text).  A number this build does not know is still reported by value
/// rather than dropped, which keeps a newer console's codes visible.
fn error_reason_text(reason: u32) -> Option<&'static str> {
    match reason {
        1 => Some("payload too short for this command"),
        2 => Some("index or slot out of range"),
        3 => Some("snapshot block sizes differ"),
        4 => Some("busy: a scan or pause/resume is in progress"),
        5 => Some("no mappings yet: attach to the process and scan first"),
        6 => Some("unknown command: this console does not implement it"),
        7 => Some("slot number out of range"),
        8 => Some("bad config payload (expected 16 or 32+ bytes)"),
        9 => Some("argument outside the accepted range"),
        10 => Some("8 MiB heap budget: release the snapshots (or reset) and retry"),
        11 => Some("the console holds a debug session: detach before freezing"),
        12 => {
            Some("a fixed table is full (breakpoint slots or pinned views): clear something first")
        }
        13 => Some("the previous session is still being released: retry in a moment"),
        14 => Some(
            "the console's cheat restore table is full: run Panic Restore All (or reboot the \
             console) before enabling more cheats",
        ),
        _ => None,
    }
}

/// Is `e` the "the previous session is still being released" answer?
///
/// The console reports it as BUSY (`NXUS_MAKE_RESULT(NXUS_ERR_BUSY)`) plus the
/// [`REASON_RETRY_LATER`] word; [`error_from_reply`] folds the reason into the
/// message, so that suffix is what identifies it here.
fn is_retry_later(e: &NxusError) -> bool {
    e.result == Some(RESULT_BUSY)
        && e.message
            .ends_with(&format!("(reason={})", REASON_RETRY_LATER))
}

/// Build the client error for a `FLAG_ERROR` reply.
///
/// The payload is the s32 Result, optionally followed by one u32 reason code
/// (see [`error_reason_text`]).  A short or reason-less payload keeps the old
/// message exactly ("command 0x.... failed"), so a console that predates the
/// reason word still produces the familiar text.
/// Human hint for a result code, whatever module produced it.
///
/// Two encodings arrive here:
/// * our own codes, `0x80000000 | (NXUS_RESULT_MODULE << 9) | description`;
/// * libnx's `MAKERESULT`, which is **small and bit-31 clear** (`(module) |
///   (description << 9)`, module 345 = Module_Libnx).  Printing `0x00001759`
///   told the user nothing, even though it is just "bad input".
const RESULT_MODULE_NXUS: u32 = 484; // core/nxus_protocol.h NXUS_RESULT_MODULE

fn result_text(rc: u32) -> Option<&'static str> {
    // Two different layouts: libnx packs (module | description << 9) with bit 31
    // clear, while our own codes are 0x80000000 | (module << 9) | description.
    let (module, desc) = if rc & 0x8000_0000 != 0 {
        ((rc >> 9) & 0x1FF, rc & 0x1FF)
    } else {
        (rc & 0x1FF, (rc >> 9) & 0x1FFF)
    };
    if module == RESULT_MODULE_NXUS {
        return match desc {
            1 => Some("the console does not implement this command"),
            2 => Some("the console does not support this"),
            3 => Some("the console is busy - retry"),
            4 => Some("nothing is attached"),
            5 => Some("no process is running"),
            6 => Some("the console is in the wrong state for this"),
            7 => Some("the request is too large"),
            8 => Some("a pointer scan is already running"),
            _ => None,
        };
    }
    if module == 345 {
        // Module_Libnx: LibnxError_BadInput is 11 (the usual "nothing to refine").
        return match desc {
            11 => Some("libnx rejected the input (nothing to refine?)"),
            _ => None,
        };
    }
    None
}

fn error_from_reply(cmd: u16, body: &[u8]) -> NxusError {
    let rc = if body.len() >= 4 { rd_u32(body, 0) } else { 0 };
    let mut message = format!("command 0x{:04X} failed", cmd);
    if let Some(text) = result_text(rc) {
        message.push_str(&format!(" - {}", text));
    }
    if body.len() >= 8 {
        let reason = rd_u32(body, 4);
        match error_reason_text(reason) {
            Some(text) => message.push_str(&format!(" - {} (reason={})", text, reason)),
            None => message.push_str(&format!(" (reason={})", reason)),
        }
    }
    NxusError {
        message,
        result: Some(rc),
    }
}

/// Thread id to use for `regs_get` on a held target.
///
/// Three sources, best first:
/// 1. `event` - the full 64-bit id from the `NxusEvent_DebugStopped` this client
///    observed.  It is only trusted when its low 32 bits match the status reply:
///    a client that has not drained events since the previous hit still holds an
///    older id, and that must never be handed to `regs_get` for the current stop.
/// 2. `status.stopped_thread` - the id appended to `NxusDebugStatus`, present from
///    Round 15 consoles on (the same full id, without needing the event).
/// 3. `status.stopped_thread_low` - the legacy half; correct only for ids below
///    4 GiB, which is all an old console can express.
///
/// None means the target is running and there is nothing to read registers from.
fn select_stopped_thread(status: &DebugStatus, event: Option<u64>) -> Option<u64> {
    let low = status.stopped_thread_low;
    if let Some(id) = event {
        // `id == 0` never reaches here (an all-zero event clears the cache), and
        // requiring the low half to match keeps a stale event out of the answer:
        // a console that moved on to another thread reports a different half.
        if low != 0 && (id as u32) == low {
            return Some(id);
        }
    }
    // The status reply is authoritative for "is anything held": a stop appended
    // id (new firmware) wins over the legacy half, and when neither is set the
    // target runs - a cached event must not resurrect an old hit.
    if status.stopped_thread != 0 {
        return Some(status.stopped_thread);
    }
    match low {
        0 => None,
        low => Some(low as u64),
    }
}

/// A cheat instruction's time budget.
///
/// One cheat instruction is not one request: a pointer walk plus a read plus a
/// compare is several round trips, and a block of tens of instructions multiplies
/// all of them.  The VM therefore gets to say "this instruction has N ms" and the
/// client clamps *every* chunk of it to what is left, so the block's worst case is
/// `instructions x budget` instead of `instructions x requests x request-timeout`.
///
/// An exhausted budget is *not* a dead link: it only means the console is slower
/// than this instruction was allowed to be, and the next instruction may still
/// work.  Link death is decided elsewhere (EOF, a protocol violation, a read
/// deadline, a failed send, unanswered heartbeats), never by a budget alone.
pub struct InstructionBudget {
    deadline: Instant,
}

impl InstructionBudget {
    /// Start a budget of `per_instruction` from now.
    pub fn new(per_instruction: Duration) -> Self {
        let deadline = Instant::now()
            .checked_add(per_instruction)
            // An absurd duration must not panic; a day is "effectively no limit".
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400));
        Self { deadline }
    }

    /// What is left of the budget (zero once it is used up).
    pub fn remaining(&self) -> Duration {
        self.deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default()
    }

    /// True once the whole instruction budget has been spent.
    pub fn expired(&self) -> bool {
        self.remaining().is_zero()
    }

    /// Deadline to hand to one request inside this budget.
    fn request_timeout(&self) -> Option<Duration> {
        let left = self.remaining();
        if left.is_zero() {
            None
        } else {
            Some(left)
        }
    }
}

/// Error for a request that never ran because its instruction budget was gone.
fn budget_exhausted() -> NxusError {
    NxusError {
        message: "instruction budget exhausted".into(),
        result: None,
    }
}

impl NxusClient {
    pub fn connect(host: &str, port: u16) -> Result<NxusClient> {
        Self::connect_with_timing(host, port, LinkTiming::default())
    }

    /// Connect with test timings (see [`LinkTiming`]).  Not part of the API: a
    /// caller never wants a sub-second idle deadline, only the tests do.
    #[cfg(test)]
    fn connect_for_test(host: &str, port: u16, timing: LinkTiming) -> Result<NxusClient> {
        Self::connect_with_timing(host, port, timing)
    }

    fn connect_with_timing(host: &str, port: u16, timing: LinkTiming) -> Result<NxusClient> {
        let stream = connect_with_timeout(host, port)?;
        stream.set_nodelay(true).ok();
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .map_err(|e| NxusError {
                message: e.to_string(),
                result: None,
            })?;
        // Without a write deadline a dead link makes `write_all` block for
        // minutes: the TCP stack keeps retrying and the request never fails, so
        // the GUI would look frozen instead of noticing the console went away.
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| NxusError {
                message: e.to_string(),
                result: None,
            })?;
        let reader_stream = stream.try_clone().map_err(|e| NxusError {
            message: e.to_string(),
            result: None,
        })?;

        let pending: Arc<Mutex<HashMap<u32, Pending>>> = Arc::new(Mutex::new(HashMap::new()));
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let dead = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let last_tx = Arc::new(Mutex::new(Instant::now()));
        let seq = Arc::new(Mutex::new(0u32));
        let stream = Arc::new(Mutex::new(stream));
        let (event_tx, event_rx) = mpsc::channel::<Event>();

        {
            let pending = Arc::clone(&pending);
            let running = Arc::clone(&running);
            let dead = Arc::clone(&dead);
            // A named thread makes a debugger dump say what stalled.
            if let Err(e) = thread::Builder::new()
                .name("nxus-reader".into())
                .spawn(move || reader_loop(reader_stream, pending, event_tx, running, dead, timing))
            {
                return Err(NxusError {
                    message: format!("cannot start the reader thread: {}", e),
                    result: None,
                });
            }
        }
        {
            let stream = Arc::clone(&stream);
            let pending = Arc::clone(&pending);
            let seq = Arc::clone(&seq);
            let last_tx = Arc::clone(&last_tx);
            let running = Arc::clone(&running);
            let dead = Arc::clone(&dead);
            if let Err(e) = thread::Builder::new()
                .name("nxus-keepalive".into())
                .spawn(move || {
                    keepalive_loop(stream, pending, seq, last_tx, running, dead, timing)
                })
            {
                return Err(NxusError {
                    message: format!("cannot start the keepalive thread: {}", e),
                    result: None,
                });
            }
        }

        Ok(NxusClient {
            max_read: std::sync::atomic::AtomicU32::new(DEFAULT_MAX_READ),
            truncated: std::sync::atomic::AtomicBool::new(false),
            dropped: std::sync::atomic::AtomicBool::new(false),
            stream,
            pending,
            events: Mutex::new(event_rx),
            seq,
            running,
            dead,
            last_tx,
            last_frozen: Mutex::new(Vec::new()),
            released_frozen: Mutex::new(Vec::new()),
            last_stop: Mutex::new(None),
        })
    }

    /// True once the link is known to be gone.
    ///
    /// Every request after this fails with "connection lost" without touching the
    /// socket, so a GUI/CLI can show "disconnected" instead of waiting out a
    /// request timeout per button press.  Reconnecting means building a new
    /// [`NxusClient`]: a dead link is never revived.
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    pub fn request(&self, cmd: u16, payload: &[u8]) -> Result<(u16, Vec<u8>)> {
        self.request_timeout(cmd, payload, DEFAULT_REQUEST_TIMEOUT)
    }

    pub fn request_timeout(
        &self,
        cmd: u16,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<(u16, Vec<u8>)> {
        // 死んだ接続に書いても読んでも意味は無い。ここで即座に返すことで、
        // 1 命令ごとに read/write するチート VM が「10 秒 × 命令数」待つのを防ぐ。
        if self.dead.load(Ordering::SeqCst) {
            return Err(connection_lost());
        }
        request_on(
            &self.stream,
            &self.pending,
            &self.seq,
            &self.last_tx,
            &self.dead,
            cmd,
            payload,
            timeout,
        )
    }

    /// Send a short command, retrying it while the console is still releasing
    /// the previous debug session (BUSY + [`REASON_RETRY_LATER`]).
    ///
    /// Only short commands use this: Attach, Detach, Continue, Step and
    /// Pause/Resume.  Scans and pointer scans never do - a scan can run for
    /// minutes, and a pointer scan has its own RESULT_BUSY polling contract
    /// (see [`ptrscan_begin`](Self::ptrscan_begin)).
    fn request_when_released(
        &self,
        cmd: u16,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<(u16, Vec<u8>)> {
        let mut attempt = 0;
        loop {
            match self.request_timeout(cmd, payload, timeout) {
                Ok(reply) => return Ok(reply),
                Err(e) if attempt < RETRY_LATER_RETRIES && is_retry_later(&e) => {
                    if attempt == 0 {
                        note_retry_later();
                    }
                    attempt += 1;
                    thread::sleep(RETRY_LATER_DELAY);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Wait for the next asynchronous event (Switch-initiated).
    ///
    /// A `NxusEvent_DebugStopped` is remembered on the way through: its payload
    /// carries the full 64-bit thread id, which an old console's DebugStatus reply
    /// can only report truncated.
    pub fn poll_event(&self, timeout: Duration) -> Option<Event> {
        let event = lock(&self.events).recv_timeout(timeout).ok()?;
        if event.kind == event::DEBUG_STOPPED && event.payload.len() >= 8 {
            let thread_id = rd_u64(&event.payload, 0);
            *lock(&self.last_stop) = if thread_id != 0 {
                Some(thread_id)
            } else {
                None
            };
        }
        Some(event)
    }

    // ---- session ----

    pub fn status(&self) -> Result<Status> {
        let (_, body) = self.request(cmd::GET_STATUS, &[])?;
        let status = Status::parse(&body);
        if status.proto_version != PROTO_VERSION {
            // A console that speaks another version still answers the fields we
            // know, so this is a warning, not a disconnect.  `swap` makes it fire
            // once per process even though the GUI polls status constantly.
            static PROTO_WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !PROTO_WARNED.swap(true, Ordering::Relaxed) {
                let message = format!(
                    "console protocol version {} (this client expects {}); \
                     continuing, replies may decode incorrectly",
                    status.proto_version, PROTO_VERSION
                );
                eprintln!("warning: {}", message);
                // The GUI has no stderr, so park the text for it to pick up (see
                // `take_protocol_warning`); taking it clears the slot.
                *lock(&PROTOCOL_WARNING) = Some(message);
            }
        }
        if status.max_read > 0 {
            self.max_read.store(status.max_read, Ordering::Relaxed);
        }
        Ok(status)
    }

    pub fn metadata(&self) -> Result<Metadata> {
        let (_, body) = self.request(cmd::GET_METADATA, &[])?;
        if body.len() < Metadata::SIZE {
            return Err(NxusError {
                message: "short metadata reply".into(),
                result: None,
            });
        }
        Ok(Metadata::parse(&body))
    }

    pub fn pause(&self) -> Result<()> {
        self.request_when_released(cmd::PAUSE, &[], Duration::from_secs(30))
            .map(|_| ())
    }

    pub fn resume(&self) -> Result<()> {
        self.request_when_released(cmd::RESUME, &[], Duration::from_secs(30))
            .map(|_| ())
    }

    pub fn heartbeat(&self) -> Result<()> {
        self.request(cmd::HEARTBEAT, &[]).map(|_| ())
    }

    /// Heartbeat with a caller-chosen deadline.
    ///
    /// The GUI's idle keep-alive uses this: the default 30 s of `request` would
    /// keep a sleeping console looking connected for half a minute, while a
    /// console that is awake answers in milliseconds.
    pub fn heartbeat_timeout(&self, timeout: Duration) -> Result<()> {
        self.request_timeout(cmd::HEARTBEAT, &[], timeout)
            .map(|_| ())
    }

    pub fn force_open(&self) -> Result<()> {
        self.request(cmd::FORCE_OPEN, &[]).map(|_| ())
    }

    pub fn log(&self) -> Result<String> {
        let (_, body) = self.request(cmd::LOG_GET, &[])?;
        Ok(String::from_utf8_lossy(&body).to_string())
    }

    // ---- memory ----

    pub fn mapping_count(&self) -> Result<u64> {
        let (_, body) = self.request(cmd::GET_MAPPING_COUNT, &[])?;
        if body.len() < 8 {
            return Err(NxusError {
                message: "short mapping count reply".into(),
                result: None,
            });
        }
        Ok(rd_u64(&body, 0))
    }

    pub fn mappings(&self, offset: u64, count: u32) -> Result<Vec<MemoryInfo>> {
        let mut payload = Vec::new();
        put_u64(&mut payload, offset);
        put_u32(&mut payload, count);
        put_u32(&mut payload, 0);
        let (_, body) = self.request(cmd::GET_MAPPINGS, &payload)?;
        Ok(body
            .chunks_exact(MemoryInfo::SIZE)
            .map(MemoryInfo::parse)
            .collect())
    }

    /// Largest read the server will answer.  Updated from every status reply so
    /// the console, not the PC, decides the limit.
    pub fn max_read(&self) -> u32 {
        match self.max_read.load(Ordering::Relaxed) {
            0 => DEFAULT_MAX_READ,
            value => value,
        }
    }

    pub fn read(&self, address: u64, size: u32) -> Result<Vec<u8>> {
        self.read_timeout(address, size, Duration::from_secs(30))
    }

    /// [`read`](Self::read) with an explicit deadline per request.
    ///
    /// A cheat VM tick must not block for 30 seconds on an unresponsive console;
    /// callers that poll target memory use a short timeout here.  The chunking
    /// and short-reply handling are identical to `read`.
    pub fn read_timeout(&self, address: u64, size: u32, timeout: Duration) -> Result<Vec<u8>> {
        self.read_chunks(address, size, || Ok(timeout))
    }

    /// Cheat-VM read: [`CHEAT_REQUEST_TIMEOUT`] instead of `read`'s 30 s.
    ///
    /// チートは 1 命令で何度も read するので、ここを 3 秒にしておかないと
    /// 数十命令のブロックが数分かかる。無音のコンソールでは 2 命令目以降は
    /// `dead` フラグで即エラーになる（[`NxusClient::is_dead`]）。
    pub fn read_for_cheat(&self, address: u64, size: u32) -> Result<Vec<u8>> {
        self.read_timeout(address, size, CHEAT_REQUEST_TIMEOUT)
    }

    /// Read under a whole-instruction budget (see [`InstructionBudget`]).
    ///
    /// Every chunk gets "whatever is left of the budget" as its own deadline, so
    /// a multi-chunk read cannot spend more than the instruction was granted.
    /// An exhausted budget is reported as a plain error and does *not* mark the
    /// link dead: the console may simply be slow, and the next instruction can
    /// still work.
    pub fn read_with_budget(
        &self,
        address: u64,
        size: u32,
        budget: &InstructionBudget,
    ) -> Result<Vec<u8>> {
        self.read_chunks(address, size, || {
            budget.request_timeout().ok_or_else(budget_exhausted)
        })
    }

    /// [`read_timeout`](Self::read_timeout)'s body: the per-chunk deadline comes
    /// from `timeout_for`, which lets the budget variant shrink it as it is spent.
    fn read_chunks<F>(&self, address: u64, size: u32, mut timeout_for: F) -> Result<Vec<u8>>
    where
        F: FnMut() -> Result<Duration>,
    {
        // Never ask for more than the server can put in one reply: an oversized
        // request is rejected outright and the caller would see "unreadable".
        const MIN_READ: u32 = 4096;
        let cap = self.max_read();
        let mut want_cap = cap;
        let mut got = Vec::with_capacity(size.min(cap) as usize);
        let mut offset = 0u64;

        while (got.len() as u32) < size {
            let want = (size - got.len() as u32).min(want_cap);
            let Some(chunk_address) = address.checked_add(offset) else {
                break; // would wrap: stop
            };
            let timeout = timeout_for()?;
            let mut payload = Vec::new();
            put_u64(&mut payload, chunk_address);
            put_u32(&mut payload, want);
            put_u32(&mut payload, 0);
            let (_, body) = self.request_timeout(cmd::READ, &payload, timeout)?;
            if body.is_empty() {
                break; // nothing readable here
            }
            offset += body.len() as u64;
            got.extend_from_slice(&body);
            if body.len() < want as usize {
                // The console halves a read dmnt refuses, so a short reply means
                // "not that much at once", not "end of region": ask for the rest
                // in smaller pieces instead of handing back partial data.
                let smaller = (body.len() as u32).max(MIN_READ);
                if smaller >= want {
                    break; // no smaller step possible
                }
                want_cap = smaller;
            }
        }
        Ok(got)
    }

    pub fn read_u32(&self, address: u64) -> Result<u32> {
        let data = self.read(address, 4)?;
        if data.len() < 4 {
            return Err(NxusError {
                message: "short read reply".into(),
                result: None,
            });
        }
        Ok(rd_u32(&data, 0))
    }

    pub fn write(&self, address: u64, data: &[u8]) -> Result<()> {
        self.write_timeout(address, data, Duration::from_secs(30))
    }

    /// [`write`](Self::write) with an explicit deadline.
    pub fn write_timeout(&self, address: u64, data: &[u8], timeout: Duration) -> Result<()> {
        self.write_with_flags_timeout(address, data, 0, timeout)
    }

    /// Write with `NxusWriteHeader.reserved` flags (see [`WRITE_FLAG_ALLOW_RX`]).
    pub fn write_with_flags(&self, address: u64, data: &[u8], flags: u32) -> Result<()> {
        self.write_with_flags_timeout(address, data, flags, Duration::from_secs(30))
    }

    pub fn write_with_flags_timeout(
        &self,
        address: u64,
        data: &[u8],
        flags: u32,
        timeout: Duration,
    ) -> Result<()> {
        let payload = encode_write_flags(address, data, flags);
        self.request_timeout(cmd::WRITE, &payload, timeout)
            .map(|_| ())
    }

    /// Cheat-VM write: [`CHEAT_REQUEST_TIMEOUT`] instead of `write`'s 30 s.
    ///
    /// RX フラグは付けない（データ書き込み用）。コードパッチは
    /// [`write_code_for_cheat`](Self::write_code_for_cheat) を使う。
    pub fn write_for_cheat(&self, address: u64, data: &[u8]) -> Result<()> {
        self.write_with_flags_timeout(address, data, 0, CHEAT_REQUEST_TIMEOUT)
    }

    /// Cheat-VM code patch (Read-Execute target) with the short deadline.
    pub fn write_code_for_cheat(&self, address: u64, data: &[u8]) -> Result<()> {
        self.write_with_flags_timeout(address, data, WRITE_FLAG_ALLOW_RX, CHEAT_REQUEST_TIMEOUT)
    }

    /// Write under a whole-instruction budget (see [`InstructionBudget`]).
    pub fn write_with_budget(
        &self,
        address: u64,
        data: &[u8],
        budget: &InstructionBudget,
    ) -> Result<()> {
        self.write_with_flags_budget(address, data, 0, budget)
    }

    /// [`write_with_budget`](Self::write_with_budget) with explicit write flags.
    pub fn write_with_flags_budget(
        &self,
        address: u64,
        data: &[u8],
        flags: u32,
        budget: &InstructionBudget,
    ) -> Result<()> {
        // 予算切れは「送る前に諦める」。0 秒で送ると pending を汚すだけ。
        let timeout = budget.request_timeout().ok_or_else(budget_exhausted)?;
        self.write_with_flags_timeout(address, data, flags, timeout)
    }

    /// Write a cheat/ASM patch that may target Read-Execute `.text`.
    ///
    /// The console only accepts a non-writable mapping when the Write header
    /// carries `NXUS_WRITE_FLAG_ALLOW_RX`, so this is the method a PC-side cheat
    /// VM must use for code patches.  Data writes should keep using
    /// [`write`](Self::write).
    pub fn write_code(&mut self, address: u64, data: &[u8]) -> std::result::Result<(), String> {
        self.write_with_flags(address, data, WRITE_FLAG_ALLOW_RX)
            .map_err(|e| e.to_string())
    }

    pub fn modules(&self) -> Result<Vec<ModuleInfo>> {
        let (_, body) = self.request(cmd::GET_MODULES, &[])?;
        Ok(body
            .chunks_exact(ModuleInfo::SIZE)
            .map(ModuleInfo::parse)
            .collect())
    }

    // ---- scanning ----

    pub fn scan_begin(
        &self,
        value: u64,
        value_size: u32,
        compare: Compare,
        scope: Scope,
        range_begin: u64,
        range_end: u64,
    ) -> Result<Status> {
        let spec = ScanSpec {
            value,
            target2: 0,
            value_size,
            value_type: ValueType::U32,
            compare,
            scope,
            range_begin,
            range_end,
            ranges: Vec::new(),
            flags: 0,
            pattern: Vec::new(),
            mask: Vec::new(),
            epsilon_decimals: 0,
        };
        self.scan_begin_spec(&spec)
    }

    pub fn scan_next(&self, value: u64, compare: Compare) -> Result<Status> {
        let spec = ScanSpec {
            value,
            target2: 0,
            value_size: 4,
            value_type: ValueType::U32,
            compare,
            scope: Scope::All,
            range_begin: 0,
            range_end: 0,
            ranges: Vec::new(),
            flags: 0,
            pattern: Vec::new(),
            mask: Vec::new(),
            epsilon_decimals: 0,
        };
        self.scan_next_spec(&spec)
    }

    /// Full Cheat-Engine-style scan: value type, pattern (string / byte array),
    /// wildcards, range compare and alignment all go through here.
    pub fn scan_begin_spec(&self, spec: &ScanSpec) -> Result<Status> {
        let payload = buildScanPayload(spec, 0);
        let (_, body) =
            self.request_timeout(cmd::SCAN_BEGIN, &payload, Duration::from_secs(600))?;
        if body.len() < Status::LEGACY_SIZE {
            return Err(NxusError {
                message: "short status reply".into(),
                result: None,
            });
        }
        Ok(Status::parse(&body))
    }

    pub fn scan_next_spec(&self, spec: &ScanSpec) -> Result<Status> {
        let payload = buildScanPayload(spec, 1);
        let (_, body) = self.request_timeout(cmd::SCAN_NEXT, &payload, Duration::from_secs(600))?;
        if body.len() < Status::LEGACY_SIZE {
            return Err(NxusError {
                message: "short status reply".into(),
                result: None,
            });
        }
        Ok(Status::parse(&body))
    }

    pub fn scan_status(&self) -> Result<Status> {
        let (_, body) = self.request(cmd::SCAN_STATUS, &[])?;
        // A truncated reply would otherwise decode as scan_state 0 (idle) and
        // make `scan_wait` spin until its own timeout instead of reporting
        // "the console sent something broken".
        if body.len() < Status::LEGACY_SIZE {
            return Err(NxusError {
                message: "short status reply".into(),
                result: None,
            });
        }
        Ok(Status::parse(&body))
    }

    /// Like scan_wait(), but stops early when the UI asks to cancel: the worker
    /// thread is single threaded, so the cancel button can only be honoured from
    /// inside the wait itself.
    pub fn scan_wait_cancellable(
        &self,
        timeout: Duration,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<Status> {
        self.scan_wait_cancellable_reporting(timeout, cancel, |_| {})
    }

    /// [`NxusClient::scan_wait_cancellable`] plus live progress.
    ///
    /// The console never pushes `NxusEvent_ScanProgress`: nothing on the Switch
    /// side posts that event (`event::SCAN_PROGRESS` is only decoded, never
    /// sent), so the *polled* status is the only source of `progress_permille`,
    /// `hit_count` and `scan_state` while a walk runs.  A caller that throws the
    /// polled reply away - as the GUI's progress bar did - shows a bar stuck at
    /// 0 for the whole scan and a hit counter frozen at whatever the previous
    /// scan left behind.
    ///
    /// `report` is therefore called with the first reply, then whenever one of
    /// those three values changes, throttled to [`SCAN_PROGRESS_REPORT`], and
    /// once more with the final status (also when the scan was cancelled) so the
    /// caller never has to guess how the walk ended.
    pub fn scan_wait_cancellable_reporting<F>(
        &self,
        timeout: Duration,
        cancel: &std::sync::atomic::AtomicBool,
        mut report: F,
    ) -> Result<Status>
    where
        F: FnMut(&Status),
    {
        let start = Instant::now();
        let mut last_heartbeat = Instant::now();
        let mut last_report: Option<Instant> = None;
        let mut last_seen: Option<(u32, u32, u32)> = None;
        loop {
            if cancel.load(Ordering::Relaxed) {
                cancel.store(false, Ordering::Relaxed);
                let _ = self.request(cmd::SCAN_CANCEL, &[]);
                let _ = self.heartbeat();
                let status = self.scan_status()?;
                report(&status);
                return Ok(status);
            }
            if last_heartbeat.elapsed() >= Duration::from_secs(4) {
                last_heartbeat = Instant::now();
                let _ = self.heartbeat();
            }
            let status = self.scan_status()?;
            let finished = matches!(
                status.scan_state,
                scan_state::DONE | scan_state::ERROR | scan_state::CANCELLED
            );
            let seen = (
                status.scan_state,
                status.hit_count,
                status.progress_permille,
            );
            if finished {
                // The final state always reaches the caller, even when it lands
                // inside the throttle window: that is the value the UI ends on.
                report(&status);
                return Ok(status);
            }
            let due = match last_report {
                Some(at) => at.elapsed() >= SCAN_PROGRESS_REPORT,
                None => true,
            };
            if due && last_seen != Some(seen) {
                last_seen = Some(seen);
                last_report = Some(Instant::now());
                report(&status);
            }
            if start.elapsed() > timeout {
                return Err(NxusError {
                    message: "scan did not finish".into(),
                    result: None,
                });
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn scan_wait(&self, timeout: Duration) -> Result<Status> {
        let start = Instant::now();
        let mut last_heartbeat = Instant::now();
        loop {
            // A scan can run for minutes; without this the console's watchdog
            // would resume a paused target in the middle of it.
            if last_heartbeat.elapsed() >= Duration::from_secs(4) {
                last_heartbeat = Instant::now();
                let _ = self.heartbeat();
            }
            let status = self.scan_status()?;
            match status.scan_state {
                scan_state::DONE | scan_state::ERROR | scan_state::CANCELLED => return Ok(status),
                _ => {}
            }
            if start.elapsed() > timeout {
                return Err(NxusError {
                    message: "scan did not finish".into(),
                    result: None,
                });
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn scan_hits(&self, offset: u32, count: u32) -> Result<HitBatch> {
        let mut payload = Vec::new();
        put_u32(&mut payload, offset);
        put_u32(&mut payload, count);
        put_u32(&mut payload, 0);
        put_u32(&mut payload, 0);
        let (_, body) = self.request(cmd::SCAN_GET_HITS, &payload)?;
        if body.len() < HitBatch::HEADER_SIZE {
            return Err(NxusError {
                message: "short hit batch".into(),
                result: None,
            });
        }
        Ok(HitBatch::parse(&body))
    }

    /// Upper bound on the pre-allocation [`NxusClient::scan_all_hits`] derives from
    /// the total the console reports in its first reply.
    ///
    /// Even this is only a cap on what a corrupt or hostile `total` may make the
    /// client reserve up front; the vector still grows normally if the console
    /// really has more hits.
    pub const MAX_ALL_HITS: usize = crate::pcscan::DEFAULT_MAX_HITS;

    /// Sane upper bound on the *initial* allocation of [`NxusClient::scan_all_hits`].
    ///
    /// The total in the first reply is untrusted.  The console's own hit list is
    /// far below this (around 150 k in normal builds), so 1 Mi entries is already
    /// generous; reserving `MAX_ALL_HITS` (8 M, ~192 MB) up front from a corrupt
    /// `total` is not.
    pub const MAX_ALL_HITS_PREALLOC: usize = 1_048_576;

    /// True when the last `scan_all_hits()` reply reported a full hit list on the
    /// console, i.e. the returned set may be missing matches.
    pub fn last_scan_truncated(&self) -> bool {
        self.truncated.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn set_last_scan_truncated(&self, value: bool) {
        self.truncated
            .store(value, std::sync::atomic::Ordering::Relaxed);
    }

    /// True when the last `scan_all_hits()` walk saw a batch that had dropped hits
    /// whose mapping is gone (`NXUS_HITBATCH_DROPPED`), i.e. the returned set is
    /// missing matches the console could no longer resolve.
    ///
    /// This is a different failure mode from [`NxusClient::last_scan_truncated`]:
    /// truncation means "the list hit its cap", dropping means "a page lost
    /// records the PC could never address".
    pub fn last_scan_dropped(&self) -> bool {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn set_last_scan_dropped(&self, value: bool) {
        self.dropped
            .store(value, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn scan_all_hits(&self, page: u32) -> Result<Vec<Hit>> {
        let (all, truncated, dropped) =
            walk_all_hits(page, |offset, count| self.scan_hits(offset, count))?;
        self.set_last_scan_truncated(truncated);
        self.set_last_scan_dropped(dropped);
        Ok(all)
    }

    pub fn scan_reset(&self) -> Result<()> {
        self.request(cmd::SCAN_RESET, &[]).map(|_| ())
    }

    pub fn scan_undo(&self) -> Result<Status> {
        let (_, body) = self.request(cmd::SCAN_UNDO, &[])?;
        if body.len() < Status::LEGACY_SIZE {
            return Err(NxusError {
                message: "short status reply".into(),
                result: None,
            });
        }
        Ok(Status::parse(&body))
    }

    // ---- snapshots ----

    pub fn snapshot_capture(
        &self,
        slot: u32,
        scope: Scope,
        block_size: u32,
    ) -> Result<SnapshotSummary> {
        let mut payload = Vec::new();
        put_u32(&mut payload, slot);
        put_u32(&mut payload, block_size);
        put_u32(&mut payload, scope as u32);
        put_u32(&mut payload, 0);
        put_u64(&mut payload, 0);
        put_u64(&mut payload, 0);
        let (_, body) =
            self.request_timeout(cmd::SNAPSHOT_CAPTURE, &payload, Duration::from_secs(300))?;
        Ok(SnapshotSummary::parse(&body))
    }

    pub fn snapshot_diff(&self, from_slot: u32, to_slot: u32) -> Result<SnapshotSummary> {
        let mut payload = Vec::new();
        put_u32(&mut payload, from_slot);
        put_u32(&mut payload, to_slot);
        put_u32(&mut payload, 0);
        put_u32(&mut payload, 0);
        let (_, body) =
            self.request_timeout(cmd::SNAPSHOT_DIFF, &payload, Duration::from_secs(300))?;
        Ok(SnapshotSummary::parse(&body))
    }

    pub fn snapshot_changed(&self, offset: u32, count: u32) -> Result<Vec<ChangedBlock>> {
        let mut payload = Vec::new();
        put_u32(&mut payload, offset);
        put_u32(&mut payload, count);
        put_u32(&mut payload, 0);
        put_u32(&mut payload, 0);
        let (_, body) = self.request(cmd::SNAPSHOT_CHANGED, &payload)?;
        Ok(body
            .chunks_exact(ChangedBlock::SIZE)
            .map(ChangedBlock::parse)
            .collect())
    }

    pub fn snapshot_changed_all(&self, page: u32) -> Result<Vec<ChangedBlock>> {
        let mut all = Vec::new();
        loop {
            let batch = self.snapshot_changed(all.len() as u32, page)?;
            if batch.is_empty() {
                return Ok(all);
            }
            all.extend(batch);
        }
    }

    // ---- pointer scan / cheat export ----

    pub fn ptrscan_begin(
        &self,
        target: u64,
        module_base: u64,
        max_depth: u32,
        max_offset: u32,
        max_results: u32,
        value_width: u32,
    ) -> Result<(Vec<PtrChain>, bool)> {
        let mut payload = Vec::new();
        put_u64(&mut payload, target);
        put_u64(&mut payload, module_base);
        put_u32(&mut payload, max_depth);
        put_u32(&mut payload, max_offset);
        put_u32(&mut payload, max_results);
        put_u32(&mut payload, value_width);
        // The console walks the chain graph on a worker thread, so the command
        // answers at once: either with the chain list (a build that still walks
        // inside the command) or with NXUS_RESULT_PTRSCAN_STARTED, and then the
        // results come from polling PtrScanGet (see the loop below).
        //
        // The console aborts its own pointer scan after 90 s and answers with
        // whatever it has (NXUS_PTRSCAN_TIME_BUDGET_MS in nxus_server.c), so the
        // deadline has to sit clearly above that: 150 s leaves room for the reply
        // to travel and for a slow tick on the console side.  It still applies to
        // the synchronous shape, and it is the total budget for the poll loop too.
        match self.request_timeout(cmd::PTRSCAN_BEGIN, &payload, Duration::from_secs(150)) {
            Ok((_, body)) => return Ok(parse_chains(&body)),
            Err(e) if e.result == Some(RESULT_PTRSCAN_STARTED) => { /* poll below */ }
            Err(e) => return Err(e),
        }

        let deadline = Instant::now() + Duration::from_secs(150);
        loop {
            match self.request_timeout(cmd::PTRSCAN_GET, &[], Duration::from_secs(30)) {
                Ok((_, body)) => return Ok(parse_chains(&body)),
                // Still walking: the console owns the chain array, so an empty
                // answer here would falsely read as "no chains found".
                Err(e) if e.result == Some(RESULT_BUSY) => {
                    if Instant::now() >= deadline {
                        return Err(NxusError {
                            message: "pointer scan did not finish on the console".into(),
                            result: None,
                        });
                    }
                    thread::sleep(PTRSCAN_POLL);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// The last chain list the console published.
    ///
    /// Answers [`RESULT_BUSY`] while a `ptrscan_begin` walk is still running;
    /// [`ptrscan_begin`](Self::ptrscan_begin) already polls around that, so this
    /// is the direct accessor (and the way to fetch a list a previous session
    /// left behind).
    pub fn ptrscan_get(&self) -> Result<(Vec<PtrChain>, bool)> {
        let (_, body) = self.request(cmd::PTRSCAN_GET, &[])?;
        Ok(parse_chains(&body))
    }

    pub fn cheat_export(
        &self,
        index: u32,
        value: u64,
        value_width: u32,
        is_32bit: bool,
    ) -> Result<String> {
        let mut payload = Vec::new();
        put_u32(&mut payload, index);
        put_u32(&mut payload, value_width);
        put_u32(&mut payload, if is_32bit { CHEAT_F_32BIT } else { 0 });
        put_u32(&mut payload, 0);
        put_u64(&mut payload, value);
        let (_, body) = self.request(cmd::CHEAT_EXPORT, &payload)?;
        Ok(String::from_utf8_lossy(&body).to_string())
    }

    // ---- on-console cheat engine ----

    /// リンク済みプログラム全体をコンソールへ載せる（`NxusCmd_CheatUpload`）。
    ///
    /// コンソールはブロック単位のアップロードを受け付けない: 先に
    /// [`crate::cheat::ir::build_program`] の出力（最大 48 KiB）を送り、その
    /// あと [`cheat_enable`](Self::cheat_enable) でブロックを個別に ON にする。
    /// だから「1 ブロック ON」でも毎回プログラム全体が要る。
    pub fn cheat_upload(&self, program: &[u8]) -> Result<CheatUploadReply> {
        if program.is_empty() {
            return Err(NxusError {
                message: "cannot upload an empty cheat program".into(),
                result: None,
            });
        }
        let (_, body) =
            self.request_timeout(CMD_CHEAT_UPLOAD, program, CHEAT_UPLOAD_TIMEOUT)?;
        Ok(CheatUploadReply::parse(&body))
    }

    /// 1 ブロックを ON/OFF する（`NxusCmd_CheatEnable`）。
    ///
    /// ON にした Patch ブロックはコンソールのワーカーがその場で 1 回実行し、
    /// Loop ブロックは 16 ms ごとに回る。OFF にするとコンソールが自分で
    /// ジャーナルから原本を書き戻す（この PC 側のバックアップは使わない）。
    pub fn cheat_enable(&self, index: u32, enabled: bool) -> Result<()> {
        let mut payload = Vec::with_capacity(8);
        put_u32(&mut payload, index);
        put_u32(&mut payload, u32::from(enabled));
        self.request_timeout(CMD_CHEAT_ENABLE, &payload, CHEAT_COMMAND_TIMEOUT)
            .map(|_| ())
    }

    /// コンソールのチートワーカーの状態（`NxusCmd_CheatStatus`）。
    pub fn cheat_status(&self) -> Result<CheatStatus> {
        let (_, body) = self.request_timeout(CMD_CHEAT_STATUS, &[], CHEAT_COMMAND_TIMEOUT)?;
        Ok(CheatStatus::parse(&body))
    }

    /// 全ブロックを止めて原本を書き戻す（`NxusCmd_CheatPanicOff`）。
    ///
    /// PC 側のジャーナル復元と違い、書き戻しはコンソールが自分のジャーナルで
    /// 行い、対象がもう居なければ `failed` に数えて返す。この PC はその数字を
    /// 表示するだけ。
    pub fn cheat_panic_off(&self) -> Result<CheatRestore> {
        let (_, body) =
            self.request_timeout(CMD_CHEAT_PANIC_OFF, &[], CHEAT_COMMAND_TIMEOUT)?;
        Ok(CheatRestore::parse(&body))
    }

    /// プログラムを捨てる（書き戻さない。`NxusCmd_CheatClear`）。
    pub fn cheat_clear(&self) -> Result<()> {
        self.request_timeout(CMD_CHEAT_CLEAR, &[], CHEAT_COMMAND_TIMEOUT)
            .map(|_| ())
    }

    // ---- freeze ----

    /// Current frozen entries (`FROZEN_LIST`, i.e. `NxusCmd_FrozenList`).
    ///
    /// The console answers with a bare `NxusFrozenEntry[]`; the count is implied
    /// by the payload length, so [`parse_frozen_list`] derives it.  An empty
    /// payload is a valid answer ("nothing is frozen").  The server also pages
    /// the list when the request carries a `NxusMappingsRequest`
    /// (offset u64, max_count u32), but dmnt's table is capped at 0x80 entries
    /// and the default page already covers it, so the empty request asks for the
    /// first page with the server's default count.
    ///
    /// Every reply is also remembered as the new baseline for
    /// [`NxusClient::frozen_list_diff`]: the console releases frozen addresses
    /// itself once the client has been gone for a while and has no way to tell
    /// the PC, so a shrinking list is the only signal there is.
    pub fn frozen_list(&self) -> Result<Vec<FrozenEntry>> {
        let (_, body) = self.request(cmd::FROZEN_LIST, &[])?;
        let entries = parse_frozen_list(&body);
        self.record_frozen_addresses(&entries);
        Ok(entries)
    }

    /// Remember the addresses a previous run saw.
    ///
    /// The CLI is one process per command, so it has no earlier reply of its own
    /// to compare against; it loads the addresses of the last run from its small
    /// state file and seeds them here, which keeps the release detection working
    /// across a disconnect/reconnect.
    pub fn seed_frozen_baseline(&self, addresses: Vec<u64>) {
        *lock(&self.last_frozen) = addresses;
        lock(&self.released_frozen).clear();
    }

    /// Addresses reported by the last [`NxusClient::frozen_list`] (empty until
    /// the first one).
    pub fn frozen_addresses(&self) -> Vec<u64> {
        lock(&self.last_frozen).clone()
    }

    /// Addresses that were frozen the previous time [`NxusClient::frozen_list`]
    /// ran and are gone from the newest reply (sorted, unique).
    ///
    /// An empty list means either "nothing vanished" or "no previous reply".  A
    /// non-empty one after a reconnect is the console's `releaseOwnedFrozen()`
    /// at work: it disables the addresses it enabled 30 s after the last client
    /// disappeared (`NXUS_FROZEN_RELEASE_AFTER_MS` in switch/source/nxus_server.c)
    /// and only logs that to its own ring/SD file, never on the wire.
    pub fn frozen_list_diff(&self) -> Vec<u64> {
        lock(&self.released_frozen).clone()
    }

    fn record_frozen_addresses(&self, entries: &[FrozenEntry]) {
        let current: Vec<u64> = entries.iter().map(|entry| entry.address).collect();
        let released = released_addresses(&lock(&self.last_frozen), &current);
        *lock(&self.released_frozen) = released;
        *lock(&self.last_frozen) = current;
    }

    pub fn frozen_enable(&self, address: u64, width: u32) -> Result<u64> {
        let mut payload = Vec::new();
        put_u64(&mut payload, address);
        put_u32(&mut payload, width);
        put_u32(&mut payload, 0);
        let (_, body) = self.request(cmd::FROZEN_ENABLE, &payload)?;
        if body.len() < 8 {
            return Err(NxusError {
                message: "short frozen handle reply".into(),
                result: None,
            });
        }
        // A freeze the PC asked for is not a release when lists are compared
        // later; keep the baseline in step with it (and with `frozen_disable`).
        lock(&self.released_frozen).retain(|frozen| *frozen != address);
        {
            let mut last = lock(&self.last_frozen);
            if !last.contains(&address) {
                last.push(address);
            }
        }
        Ok(rd_u64(&body, 0))
    }

    pub fn frozen_disable(&self, address: u64) -> Result<()> {
        let mut payload = Vec::new();
        put_u64(&mut payload, address);
        self.request(cmd::FROZEN_DISABLE, &payload).map(|_| ())?;
        // An explicit unfreeze must not surface as "the console released it".
        lock(&self.released_frozen).retain(|frozen| *frozen != address);
        lock(&self.last_frozen).retain(|frozen| *frozen != address);
        Ok(())
    }

    /// Record addresses the console said it released
    /// (`NxusEvent_FrozenReleased`, see [`FrozenReleased`]).
    ///
    /// Once the console reports the release on the wire, the PC's own
    /// "list shrank" difference (see [`NxusClient::frozen_list_diff`]) must not
    /// report the same addresses a second time: they are dropped from the
    /// baseline so the next `FROZEN_LIST` reply looks consistent.
    pub fn note_frozen_released(&self, addresses: &[u64]) {
        if addresses.is_empty() {
            return;
        }
        lock(&self.released_frozen).retain(|frozen| !addresses.contains(frozen));
        lock(&self.last_frozen).retain(|frozen| !addresses.contains(frozen));
    }

    // ---- debug mode ----

    pub fn processes(&self) -> Result<Vec<u64>> {
        let (_, body) = self.request(cmd::GET_PROCESSES, &[])?;
        Ok(body.chunks_exact(8).map(|c| rd_u64(c, 0)).collect())
    }

    pub fn debug_attach(&self) -> Result<DebugStatus> {
        self.debug_attach_pid(0)
    }

    pub fn debug_attach_pid(&self, pid: u64) -> Result<DebugStatus> {
        let mut payload = Vec::new();
        if pid != 0 {
            put_u64(&mut payload, pid);
        }
        let (_, body) =
            self.request_when_released(cmd::DEBUG_ATTACH, &payload, Duration::from_secs(60))?;
        Ok(DebugStatus::parse(&body))
    }

    pub fn debug_detach(&self) -> Result<()> {
        *lock(&self.last_stop) = None;
        self.request_when_released(cmd::DEBUG_DETACH, &[], Duration::from_secs(60))
            .map(|_| ())
    }

    pub fn debug_status(&self) -> Result<DebugStatus> {
        let (_, body) = self.request(cmd::DEBUG_STATUS, &[])?;
        Ok(DebugStatus::parse(&body))
    }

    /// Resume a target the console is holding at a breakpoint.
    pub fn debug_continue(&self) -> Result<()> {
        // The remembered stop belongs to the hit just acknowledged: dropping it
        // keeps it from naming a thread after the target is running again.
        *lock(&self.last_stop) = None;
        self.request_when_released(cmd::DEBUG_CONTINUE, &[], Duration::from_secs(60))
            .map(|_| ())
    }

    /// Single-step the stopped thread (0 = whichever thread the console holds).
    pub fn debug_step(&self, thread_id: u64) -> Result<()> {
        let mut payload = Vec::new();
        put_u64(&mut payload, thread_id);
        self.request_when_released(cmd::DEBUG_STEP, &payload, Duration::from_secs(60))
            .map(|_| ())
    }

    /// Thread the console is holding at a breakpoint (None = the target runs).
    ///
    /// This is the id to hand to [`NxusClient::regs_get`]: the full 64-bit value,
    /// never the truncated low half.  It comes from the `DebugStopped` event seen
    /// through [`NxusClient::poll_event`] when that event described this stop,
    /// else from the field the console appended to `NxusDebugStatus`, else (an old
    /// console whose event was never polled) from the legacy 32-bit field.
    pub fn debug_stopped_thread(&self) -> Result<Option<u64>> {
        let status = self.debug_status()?;
        let event = *lock(&self.last_stop);
        Ok(select_stopped_thread(&status, event))
    }

    /// Push ONLY the debug block (a bare `NxusDebugConfig`, 16 bytes): the
    /// watchpoint encoding plus the auto-continue policy (`auto_continue == 0`
    /// makes a hit hold the target until `debug_continue`).
    ///
    /// The console reads a CONFIG payload of exactly `DEBUG_CONFIG_LEN` bytes as
    /// "debug settings only" and keeps the rest of its configuration.  That
    /// matters: the full request ([`set_config`], 32+ bytes) rewrites every
    /// field, so a `watch`/`break` run used to zero the controller hotkey the
    /// user had applied from the Settings window (and a GUI arm did the same).
    pub fn set_debug_auto_continue(&self, style: u32, auto_continue: u32) -> Result<()> {
        let mut payload = Vec::with_capacity(DEBUG_CONFIG_LEN);
        put_u32(&mut payload, style);
        put_u32(&mut payload, auto_continue);
        put_u32(&mut payload, 0);
        put_u32(&mut payload, 0);
        debug_assert_eq!(
            payload.len(),
            DEBUG_CONFIG_LEN,
            "NxusDebugConfig is 16 bytes"
        );
        self.request(cmd::CONFIG, &payload).map(|_| ())
    }

    pub fn break_set(
        &self,
        address: u64,
        kind: u32,
        size: u32,
        slot: u32,
        ctrl: u64,
    ) -> Result<Vec<BreakEntry>> {
        let mut payload = Vec::new();
        put_u32(&mut payload, slot);
        put_u32(&mut payload, kind);
        put_u32(&mut payload, size);
        put_u32(&mut payload, 0);
        put_u64(&mut payload, address);
        let _ = ctrl;
        let (_, body) = self.request_timeout(cmd::BREAK_SET, &payload, Duration::from_secs(60))?;
        Ok(body
            .chunks_exact(BreakEntry::SIZE)
            .map(BreakEntry::parse)
            .collect())
    }

    pub fn break_clear(&self, slot: u32) -> Result<()> {
        let mut payload = Vec::new();
        put_u32(&mut payload, slot);
        self.request(cmd::BREAK_CLEAR, &payload).map(|_| ())
    }

    pub fn break_list(&self) -> Result<Vec<BreakEntry>> {
        let (_, body) = self.request(cmd::BREAK_LIST, &[])?;
        Ok(body
            .chunks_exact(BreakEntry::SIZE)
            .map(BreakEntry::parse)
            .collect())
    }

    pub fn thread_list(&self) -> Result<Vec<ThreadEntry>> {
        let (_, body) = self.request(cmd::THREAD_LIST, &[])?;
        Ok(body
            .chunks_exact(ThreadEntry::SIZE)
            .map(ThreadEntry::parse)
            .collect())
    }

    pub fn regs_get(&self, thread_id: u64) -> Result<ThreadContext> {
        let mut payload = Vec::new();
        put_u64(&mut payload, thread_id);
        let (_, body) = self.request(cmd::REGS_GET, &payload)?;
        // 96 bytes is the minimum that fills the whole `r` array (the ARM32 half
        // of the legacy 100-byte layout); `ThreadContext::parse` zero-fills the
        // rest, so anything shorter would silently show made-up registers.
        if body.len() < 96 {
            return Err(NxusError {
                message: "short thread context reply".into(),
                result: None,
            });
        }
        Ok(ThreadContext::parse(&body))
    }

    pub fn regs_set(&self, ctx: &ThreadContext) -> Result<()> {
        let payload = ctx.encode();
        self.request(cmd::REGS_SET, &payload).map(|_| ())
    }

    pub fn hit_get(&self, count: u32) -> Result<Vec<BreakHit>> {
        let mut payload = Vec::new();
        put_u32(&mut payload, 0);
        put_u32(&mut payload, count);
        put_u32(&mut payload, 0);
        put_u32(&mut payload, 0);
        let (_, body) = self.request(cmd::HIT_GET, &payload)?;
        Ok(body
            .chunks_exact(BreakHit::SIZE)
            .map(BreakHit::parse)
            .collect())
    }

    pub fn hit_clear(&self) -> Result<()> {
        self.request(cmd::HIT_CLEAR, &[]).map(|_| ())
    }

    // ---- configuration ----

    /// The FULL configuration request (`NxusConfig` = 32 bytes, plus the optional
    /// 16-byte `NxusDebugConfig` tail).  This is what the Settings window sends
    /// when the user applies their settings: it rewrites every field, so it must
    /// NOT be used to flip a single debug flag behind the user's back - see
    /// [`set_debug_auto_continue`], which sends the 16-byte debug-only form.
    pub fn set_config(
        &self,
        hotkey_mask: u64,
        hotkey_hold_ms: u32,
        hotkey_enabled: u32,
        chunk_size: u32,
        watchdog_ms: u32,
        heartbeat_ms: u32,
        log_level: u32,
        debug: Option<(u32, u32)>,
    ) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        put_u64(&mut payload, hotkey_mask);
        put_u32(&mut payload, hotkey_hold_ms);
        put_u32(&mut payload, hotkey_enabled);
        put_u32(&mut payload, chunk_size);
        put_u32(&mut payload, watchdog_ms);
        put_u32(&mut payload, heartbeat_ms);
        put_u32(&mut payload, log_level);
        debug_assert_eq!(payload.len(), 32, "NxusConfig is 32 bytes");
        if let Some((style, auto_continue)) = debug {
            put_u32(&mut payload, style);
            put_u32(&mut payload, auto_continue);
            put_u32(&mut payload, 0);
            put_u32(&mut payload, 0);
        }
        let (_, body) = self.request(cmd::CONFIG, &payload)?;
        Ok(body)
    }
}

/// Addresses in `previous` that are missing from `current`, sorted and unique.
///
/// The console never tells the PC that it dropped a frozen address: 30 s after
/// the last client disappears `releaseOwnedFrozen()` (switch/source/nxus_server.c)
/// disables every address Nxus itself froze and writes the line to its own log
/// ring/SD file only.  Comparing two `FROZEN_LIST` replies is therefore the only
/// material the PC has, and this is that comparison.  Addresses that appear in
/// `current` but not in `previous` are new freezes, not releases, so they are
/// deliberately not reported.
fn released_addresses(previous: &[u64], current: &[u64]) -> Vec<u64> {
    let mut gone: Vec<u64> = previous
        .iter()
        .copied()
        .filter(|address| !current.contains(address))
        .collect();
    gone.sort_unstable();
    gone.dedup();
    gone
}

impl Drop for NxusClient {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        // A graceful shutdown sends the FIN immediately, so the console drops the
        // session and the reader thread's blocking read wakes up in milliseconds
        // instead of after the next read timeout.  This is what lets the GUI open
        // a fresh connection right after dropping the old one.  `lock` (not
        // `unwrap`) so a panicking worker cannot make `drop` itself panic.
        let s = lock(&self.stream);
        let _ = s.shutdown(std::net::Shutdown::Both);
    }
}

/// Returns the chains and whether the console hit its own cap (the header's
/// truncated flag: count == 64 is NOT the same thing).
/// Pointer width the console actually walked (0 when the console predates the
/// field).  parse_chains() records it here so callers can render/verify it without
/// changing the (chains, truncated) tuple they already use.
static LAST_CHAIN_WIDTH: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

pub fn last_chain_pointer_width() -> u32 {
    LAST_CHAIN_WIDTH.load(std::sync::atomic::Ordering::Relaxed)
}

fn parse_chains(body: &[u8]) -> (Vec<PtrChain>, bool) {
    if body.len() < 16 {
        return (Vec::new(), false);
    }
    let truncated = rd_u32(body, 8) != 0;

    // A corrupt count must not become a multi-gigabyte allocation: only as many
    // chains as the body can actually hold are ever decoded.
    // A 20-byte header appends the walked pointer width; 16 bytes is an older
    // console.  The length decides, because guessing wrong shifts every record by
    // four bytes and yields plausible garbage instead of an error.
    let count_guess = rd_u32(body, 0) as usize;
    let wide = body.len() == 20 + count_guess * 48;
    let header = if wide { 20usize } else { 16usize };
    let parsed_width = if wide { rd_u32(body, 16) } else { 0 };
    let count = count_guess.min(body.len().saturating_sub(header) / 48);
    LAST_CHAIN_WIDTH.store(parsed_width, std::sync::atomic::Ordering::Relaxed);
    let mut chains = Vec::with_capacity(count);
    let mut pos = header;
    for _ in 0..count {
        if pos + 48 > body.len() {
            break;
        }
        let root_offset = rd_u32(body, pos);
        let final_offset = rd_u32(body, pos + 4);
        let step_count = rd_u32(body, pos + 8) as usize;
        let mut steps = Vec::new();
        for i in 0..step_count.min(8) {
            steps.push(rd_u32(body, pos + 16 + i * 4));
        }
        pos += 48;
        chains.push(PtrChain {
            root_offset,
            final_offset,
            steps,
        });
    }
    (chains, truncated)
}

/// 接続死を確定する。
///
/// 1. `dead` を立てる: 以後の `request_timeout` は入口で即 "connection lost"。
/// 2. 待機中の要求すべてに `None` を流して起こす（`request_timeout` は
///    "connection closed" で戻る）。reader が終了するときの後始末と同じ経路で、
///    これが無いと待っている側は自分の締切まで気づけない。
///
/// `dead` は「この接続ではもう通信できない」の意味で、一度立ったら戻さない。
/// 復帰は [`NxusClient`] を作り直す（GUI の再接続）だけ。
fn mark_dead(
    dead: &std::sync::atomic::AtomicBool,
    pending: &Mutex<HashMap<u32, Pending>>,
) {
    dead.store(true, Ordering::SeqCst);
    for (_, entry) in lock(pending).drain() {
        let _ = entry.tx.send(None);
    }
}

/// 死んだ接続に対する共通のエラー。
fn connection_lost() -> NxusError {
    NxusError {
        message: "connection lost".into(),
        result: None,
    }
}

fn next_seq(seq: &Mutex<u32>) -> u32 {
    let mut seq = lock(seq);
    *seq = seq.wrapping_add(1);
    *seq
}

/// 待機中の要求のうち、いちばん遅い締切。
///
/// reader はこれを見て「無音をどこまで許すか」を決める。長いコマンド
/// （`ScanBegin` の応答は 600 秒かかりうる）の返事待ちの間は、サーバが
/// 何も送ってこないのが正常なので、ここが無いと健全な接続を殺してしまう。
/// keepalive の Heartbeat は [`Pending::guards_idle`] で除外する。
fn pending_deadline(pending: &Mutex<HashMap<u32, Pending>>) -> Option<Instant> {
    lock(pending)
        .values()
        .filter(|entry| entry.guards_idle)
        .map(|entry| entry.deadline)
        .max()
}

/// 1 コマンドぶんの送受信（[`NxusClient::request_timeout`] と keepalive の共通部）。
///
/// `dead` を受け取るのは、送信に失敗した時点で「この接続はもう使えない」を
/// 確定させるため: 送れなかった要求の後始末だけして黙って返すと、次の要求が
/// また自分の締切まで待ってしまう。
#[allow(clippy::too_many_arguments)]
fn request_on(
    stream: &Mutex<TcpStream>,
    pending: &Mutex<HashMap<u32, Pending>>,
    seq_counter: &Mutex<u32>,
    last_tx: &Mutex<Instant>,
    dead: &std::sync::atomic::AtomicBool,
    cmd: u16,
    payload: &[u8],
    timeout: Duration,
) -> Result<(u16, Vec<u8>)> {
    let seq = next_seq(seq_counter);
    let (tx, rx) = mpsc::channel::<Response>();
    // reader が「この要求のための無音」をこの時刻まで許す。
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400));
    // Heartbeat は生存確認そのものなので、その短い締切で reader の無音判定を
    // 縮めない（1 回の取りこぼしで即・接続死にしないため）。
    let guards_idle = cmd != cmd::HEARTBEAT;
    lock(pending).insert(
        seq,
        Pending {
            tx,
            deadline,
            guards_idle,
        },
    );

    let mut header = Vec::with_capacity(HEADER_SIZE);
    put_u32(&mut header, MAGIC);
    put_u16(&mut header, cmd);
    put_u16(&mut header, 0);
    put_u32(&mut header, payload.len() as u32);
    put_u32(&mut header, seq);

    // ヘッダと payload は同じロックの中で書く: keepalive の Heartbeat が
    // この 2 つの間に割り込むと、フレームが壊れて以後すべてデシンクする。
    let sent = {
        let mut stream = lock(stream);
        stream
            .write_all(&header)
            .and_then(|_| stream.write_all(payload))
            .and_then(|_| stream.flush())
    };
    if let Err(e) = sent {
        // 送信できない = 相手はいない。ここで死を確定しないと、次の要求が
        // また 10 秒待ってから同じ失敗を繰り返す。
        mark_dead(dead, pending);
        return Err(NxusError {
            message: format!("send failed: {}", e),
            result: None,
        });
    }
    *lock(last_tx) = Instant::now();

    match rx.recv_timeout(timeout) {
        Ok(Some((_kind, flags, body))) => {
            if flags & FLAG_ERROR != 0 {
                return Err(error_from_reply(cmd, &body));
            }
            Ok((cmd, body))
        }
        Ok(None) => Err(NxusError {
            message: "connection closed".into(),
            result: None,
        }),
        // 締切超過は「このコマンドが返らなかった」であって、接続死の判定は
        // reader に任せる: 長いスキャンの返事待ちを、そのコマンド自身の
        // タイムアウトで「死」にしてはいけない。
        Err(RecvTimeoutError::Timeout) => {
            lock(pending).remove(&seq);
            Err(NxusError {
                message: format!("no reply for command 0x{:04X}", cmd),
                result: None,
            })
        }
        Err(RecvTimeoutError::Disconnected) => Err(NxusError {
            message: "connection closed".into(),
            result: None,
        }),
    }
}

/// 無音の接続に `Heartbeat` を送り、返事が来なければ接続死を確定する。
///
/// OS の SO_KEEPALIVE は Windows の既定で 2 時間 idle なので検出には使えない。
/// プロトコル自身の Heartbeat（サーバは `NxusCmd_Heartbeat` を実装済み）なら
/// 数秒で分かるうえ、コンソール側 watchdog（15 秒）も同時に満たせる。
///
/// 長いコマンドの返事待ちの間は Heartbeat を積まない: サーバの接続スレッドは
/// 1 本で、スキャン中はコマンドを読めないため、積むと自分の Heartbeat が
/// タイムアウトして健全な接続を殺してしまう。
fn keepalive_loop(
    stream: Arc<Mutex<TcpStream>>,
    pending: Arc<Mutex<HashMap<u32, Pending>>>,
    seq: Arc<Mutex<u32>>,
    last_tx: Arc<Mutex<Instant>>,
    running: Arc<std::sync::atomic::AtomicBool>,
    dead: Arc<std::sync::atomic::AtomicBool>,
    timing: LinkTiming,
) {
    let mut misses = 0u32;
    // 見回りは Heartbeat 間隔より細かくする。本番は 500 ms で十分だが、
    // テストは 200 ms 間隔なので、固定値のままだと「次に送るまで」が
    // 間隔より長くなってタイミングの検証ができない。
    let tick = timing
        .keepalive_interval
        .min(LINK_KEEPALIVE_TICK)
        .max(Duration::from_millis(20));
    loop {
        thread::sleep(tick);
        if !running.load(Ordering::SeqCst) || dead.load(Ordering::SeqCst) {
            break;
        }
        // 1 回目の失敗のあとは短い間隔で再試行する（一時的な取りこぼしと
        // 本当の切断を、2 回目の成否で分ける）。
        let wait = if misses == 0 {
            timing.keepalive_interval
        } else {
            timing.keepalive_retry
        };
        if lock(&last_tx).elapsed() < wait {
            continue;
        }
        if !lock(&pending).is_empty() {
            continue;
        }
        match request_on(
            &stream,
            &pending,
            &seq,
            &last_tx,
            &dead,
            cmd::HEARTBEAT,
            &[],
            timing.keepalive_timeout,
        ) {
            Ok(_) => misses = 0,
            // エラー応答でも「返事が来た」= 相手は生きている。プロトコルを
            // 実装していない古いコンソールを誤って切断しないための判定。
            Err(e) if e.result.is_some() => misses = 0,
            Err(_) => {
                misses += 1;
                if misses >= timing.keepalive_misses {
                    mark_dead(&dead, &pending);
                    break;
                }
            }
        }
    }
}

fn reader_loop(
    mut stream: TcpStream,
    pending: Arc<Mutex<HashMap<u32, Pending>>>,
    events: Sender<Event>,
    running: Arc<std::sync::atomic::AtomicBool>,
    dead: Arc<std::sync::atomic::AtomicBool>,
    timing: LinkTiming,
) {
    let mut header = [0u8; HEADER_SIZE];
    loop {
        if !running.load(Ordering::SeqCst) {
            break;
        }
        if read_frame(
            &mut stream,
            &mut header,
            &pending,
            &running,
            timing.idle_timeout,
        )
        .is_err()
        {
            break;
        }
        let magic = rd_u32(&header, 0);
        if magic != MAGIC {
            break;
        }
        let kind = rd_u16(&header, 4);
        let flags = rd_u16(&header, 6);
        let length = rd_u32(&header, 8);
        let seq = rd_u32(&header, 12);

        // The header is attacker-controlled on a hostile or broken peer: a length
        // of 0xFFFFFFFF used to become a 4 GiB `vec![0u8; ...]` and abort the
        // process (the GUI then stayed "busy" forever).  The console never sends
        // more than one net buffer, so anything larger is a framing error.
        if length > MAX_PAYLOAD {
            break;
        }
        let mut payload = vec![0u8; length as usize];
        if length > 0
            && read_frame(
                &mut stream,
                &mut payload,
                &pending,
                &running,
                timing.idle_timeout,
            )
            .is_err()
        {
            break;
        }

        if flags & FLAG_ASYNC != 0 || kind >= 0x8000 {
            let _ = events.send(Event { kind, payload });
        } else {
            let sender = lock(&pending).remove(&seq);
            if let Some(entry) = sender {
                let _ = entry.tx.send(Some((kind, flags, payload)));
            }
        }
    }
    // ここに来た = EOF・プロトコル違反・締切超過・実行中断のいずれか。
    // どれも「この接続ではもうフレームを組み立てられない」なので、待って
    // いる全員を起こして以後の要求を即エラーにする。
    mark_dead(&dead, &pending);
}

/// フレーム 1 つぶんの受信（ヘッダでも payload でも同じ規則）。
///
/// - 待機中の要求が無いとき: [`LINK_IDLE_TIMEOUT`] の無音で接続死。
///   （keepalive が数秒ごとに Heartbeat を送るので、生きていれば無音にならない）
/// - 長いコマンドの返事待ちのとき: その要求自身の締切まで待つ。
/// - 途中で長い要求が登録された場合: 締切を延ばして待ち直す。接続直後の
///   idle 待ちの最中にスキャンを始めると、これが無いと 20 秒で誤判定する。
fn read_frame(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    pending: &Mutex<HashMap<u32, Pending>>,
    running: &std::sync::atomic::AtomicBool,
    idle_timeout: Duration,
) -> std::io::Result<()> {
    loop {
        let deadline = match pending_deadline(pending) {
            Some(deadline) if deadline > Instant::now() => deadline,
            _ => Instant::now() + idle_timeout,
        };
        match read_exact(stream, buffer, deadline, running) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == ErrorKind::TimedOut => {
                if pending_deadline(pending).is_some_and(|d| d > Instant::now()) {
                    continue;
                }
                return Err(e);
            }
            Err(e) => return Err(e),
        }
    }
}

/// バッファが埋まるまで読む。タイムアウトは **締切まで** 再試行する。
///
/// 以前は `WouldBlock` / `TimedOut` を `continue` で捨てていたため、フレームの
/// 途中でピアが黙ると reader スレッドが永久に回り続けた（200 ms の
/// `set_read_timeout` が「無通信の検出」にまったく寄与していなかった）。
/// 締切を持たせることで、無音のピアは必ず [`read_frame`] の「接続断」判定に
/// 落ち、`running` が false になったら [`ErrorKind::Interrupted`] で即座に
/// 抜ける（GUI の再接続が古い reader を引きずらない）。
///
/// 途中まで読めたバイトは `buffer` にそのまま残す（呼び出し側のバッファへ
/// 直接書く）。部分フレームは復元できないので、呼び出し側は失敗後に
/// そのバッファを捨てる前提。
fn read_exact(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
    running: &std::sync::atomic::AtomicBool,
) -> std::io::Result<()> {
    let mut got = 0;
    while got < buffer.len() {
        if !running.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(
                ErrorKind::Interrupted,
                "the client is shutting down",
            ));
        }
        match stream.read(&mut buffer[got..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "the peer closed the connection",
                ))
            }
            Ok(n) => got += n,
            // set_read_timeout(200ms) で戻ってくるだけ。捨てずに締切を
            // 確かめるのが要点で、締切が無いと永久に回り続ける。
            Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        ErrorKind::TimedOut,
                        "no byte from the peer before the deadline",
                    ));
                }
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Walk the console's hit list one page at a time.
///
/// `fetch(offset, count)` stands in for `SCAN_GET_HITS`, which makes the walk
/// testable without a socket.  The crucial rule is that `offset` is a
/// *server-side index*, not the number of records collected: a page whose hits
/// were dropped (`NXUS_HITBATCH_DROPPED`) still consumed its whole request
/// window, and the next request must start after that window.  Advancing by
/// `hits.len()` instead re-examines indices, yields duplicates and can miss the
/// tail of the list.
///
/// Returns the collected hits plus the aggregated truncated/dropped flags.
fn walk_all_hits<F>(page: u32, mut fetch: F) -> Result<(Vec<Hit>, bool, bool)>
where
    F: FnMut(u32, u32) -> Result<HitBatch>,
{
    let page = page.clamp(1, NXUS_MAX_HITS_PER_BATCH);
    // Collected hits are only ever appended; reserve once from the first total
    // (bounded, because `total` comes from the wire and may be corrupt).
    let mut all: Vec<Hit> = Vec::new();
    let mut sized = false;
    let mut truncated = false;
    let mut dropped = false;
    let mut server_offset: u32 = 0;
    let mut total: Option<u32> = None;
    let mut session_id: Option<u32> = None;

    loop {
        // Once the total is known, never ask beyond the list.  `server_offset`
        // is what the console indexes; `all.len()` may be smaller after drops.
        let req_count = match total {
            Some(total) => {
                if server_offset >= total {
                    break;
                }
                page.min(total - server_offset)
            }
            None => page,
        };
        if req_count == 0 {
            break;
        }

        let batch = fetch(server_offset, req_count)?;
        // A non-zero session id identifies the scan.  A different one mid-walk
        // means the console started another scan and these pages do not belong
        // to the same hit list.
        if batch.session_id != 0 {
            match session_id {
                Some(expected) if expected != batch.session_id => {
                    return Err(NxusError {
                        message: format!(
                            "scan session changed during the hit walk ({} -> {})",
                            expected, batch.session_id
                        ),
                        result: None,
                    });
                }
                None => session_id = Some(batch.session_id),
                _ => {}
            }
        }

        if total.is_none() {
            total = Some(batch.total);
        }
        if !sized {
            sized = true;
            let want = (batch.total as usize).min(NxusClient::MAX_ALL_HITS_PREALLOC);
            if want > all.capacity() {
                all.reserve_exact(want - all.capacity());
            }
        }

        // The flags describe the whole walk, not just the last page.
        truncated |= batch.truncated;
        dropped |= batch.dropped;
        let batch_total = batch.total;
        let hit_count = batch.hits.len() as u32;
        all.extend(batch.hits);

        if batch.dropped {
            // The server examined this whole request window and omitted the
            // dropped records.  Consume the window, not the written records.
            let spanned = req_count.min(batch_total.saturating_sub(server_offset));
            if spanned == 0 {
                break;
            }
            server_offset = server_offset.saturating_add(spanned);
        } else {
            // No drops: every returned record occupies one server slot.  An
            // empty page without the drop flag is the genuine end of the list.
            if hit_count == 0 {
                break;
            }
            server_offset = server_offset.saturating_add(hit_count);
        }

        if server_offset >= batch_total {
            break;
        }
    }

    Ok((all, truncated, dropped))
}

#[cfg(test)]
mod tests {
    use super::{
        error_from_reply, error_reason_text, is_retry_later, is_unsupported_command,
        pointer_width_for, pointer_width_with_reason, read_exact, released_addresses, result_text,
        select_stopped_thread, walk_all_hits, CheatFault, CheatRestore, CheatStatus,
        CheatUploadReply, Event, Hit, HitBatch, IncomingEvent, LinkTiming, Mapping, Metadata,
        NxusClient, NxusError, CHEAT_COMMAND_TIMEOUT, CHEAT_REQUEST_TIMEOUT, CHEAT_UPLOAD_TIMEOUT,
        CMD_CHEAT_CLEAR, CMD_CHEAT_ENABLE, CMD_CHEAT_PANIC_OFF, CMD_CHEAT_STATUS, CMD_CHEAT_UPLOAD,
        EVENT_CHEAT_FAULT, PERM_R, RESULT_BUSY, WIDTH_REASON_DEFAULT, WIDTH_REASON_MAIN_BASE_32,
        WIDTH_REASON_MAIN_BASE_64, WIDTH_REASON_MAPPINGS_32, WIDTH_REASON_MAPPINGS_64,
        WIDTH_REASON_PROCESS_32, WIDTH_REASON_PROCESS_64,
    };
    use crate::protocol::{
        cmd, put_u16, put_u32, rd_u16, rd_u32, DebugStatus, HEADER_SIZE, MAGIC, WRITE_FLAG_ALLOW_RX,
    };
    use std::time::{Duration, Instant};

    fn error_body(rc: u32, reason: Option<u32>) -> Vec<u8> {
        let mut body = Vec::new();
        put_u32(&mut body, rc);
        if let Some(reason) = reason {
            put_u32(&mut body, reason);
        }
        body
    }

    fn mapping(base: u64, size: u64, perm: u32) -> Mapping {
        Mapping {
            base,
            size,
            memory_type: 5,
            attr: 0,
            perm,
        }
    }

    fn metadata(main_base: u64) -> Metadata {
        Metadata {
            main_base,
            ..Default::default()
        }
    }

    fn page_hit(index: u32) -> Hit {
        Hit {
            address: index as u64,
            mapping_idx: 0,
            value_type: 0,
            value: index as u64,
        }
    }

    /// A wire-faithful `SCAN_GET_HITS` server: `dropped` indices are counted in
    /// the window but omitted from `hits`, exactly like `sendHits()` on the
    /// console.
    fn serve_hit_page(
        total: u32,
        dropped_indices: &[u32],
        requests: &mut Vec<(u32, u32)>,
        offset: u32,
        count: u32,
    ) -> HitBatch {
        requests.push((offset, count));
        let start = offset.min(total);
        let end = offset.saturating_add(count).min(total);
        let mut hits = Vec::new();
        let mut dropped = false;
        for index in start..end {
            if dropped_indices.contains(&index) {
                dropped = true;
            } else {
                hits.push(page_hit(index));
            }
        }
        HitBatch {
            session_id: 7,
            total,
            value_size: 4,
            truncated: false,
            dropped,
            hits,
        }
    }

    fn addresses(hits: &[Hit]) -> Vec<u32> {
        hits.iter().map(|hit| hit.address as u32).collect()
    }

    /// The cheat path must set `NXUS_WRITE_FLAG_ALLOW_RX`, while an ordinary
    /// write keeps the reserved word zero (an old console relies on that
    /// strictness).  Read the actual frames off a local socket, so this pins the
    /// wire encoding rather than only the helper functions.
    #[test]
    fn write_code_sets_allow_rx_but_write_does_not() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut flags = Vec::new();
            for _ in 0..2 {
                let mut head = [0u8; HEADER_SIZE];
                socket.read_exact(&mut head).expect("frame header");
                let length = rd_u32(&head, 8) as usize;
                let seq = rd_u32(&head, 12);
                let mut payload = vec![0u8; length];
                socket.read_exact(&mut payload).expect("frame payload");
                flags.push(rd_u32(&payload, 12)); // NxusWriteHeader.reserved
                let mut reply = Vec::new();
                put_u32(&mut reply, MAGIC);
                reply.extend_from_slice(&cmd::WRITE.to_le_bytes());
                reply.extend_from_slice(&0u16.to_le_bytes());
                put_u32(&mut reply, 0); // no payload, no error
                put_u32(&mut reply, seq);
                socket.write_all(&reply).expect("reply");
            }
            flags
        });

        let mut client = NxusClient::connect("127.0.0.1", port).expect("connect");
        client
            .write(0x0070_0000, &[1, 2, 3, 4])
            .expect("normal write");
        client
            .write_code(0x0070_0000, &[5, 6, 7, 8])
            .expect("code write");
        let flags = server.join().expect("server");
        assert_eq!(flags, vec![0, WRITE_FLAG_ALLOW_RX]);
    }

    /// A partial drop makes the written records shorter than the request window.
    /// The next offset must be the end of the *window*, never `all.len()`, or the
    /// walk re-reads indices and loses the tail.
    #[test]
    fn a_partially_dropped_page_advances_by_the_server_window() {
        let mut requests = Vec::new();
        let (hits, truncated, dropped) = walk_all_hits(4, |offset, count| {
            Ok(serve_hit_page(10, &[1], &mut requests, offset, count))
        })
        .expect("page walk");

        assert_eq!(
            requests,
            vec![(0, 4), (4, 4), (8, 2)],
            "the next request must start after the whole examined window"
        );
        assert_eq!(
            addresses(&hits),
            vec![0, 2, 3, 4, 5, 6, 7, 8, 9],
            "index 1 is dropped, all other records appear exactly once"
        );
        assert!(dropped);
        assert!(!truncated);
        let mut unique = hits.iter().map(|hit| hit.address).collect::<Vec<_>>();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), hits.len(), "the walk produced duplicate hits");
    }

    /// A page can consist entirely of dropped records.  It is not the end of the
    /// list: the window was still consumed, so the next page must be requested
    /// and its valid hits returned (the old code retried the same page 3 times
    /// and gave up).
    #[test]
    fn an_all_dropped_first_page_advances_to_the_next_page() {
        let mut requests = Vec::new();
        let (hits, truncated, dropped) = walk_all_hits(4, |offset, count| {
            Ok(serve_hit_page(
                10,
                &[0, 1, 2, 3],
                &mut requests,
                offset,
                count,
            ))
        })
        .expect("page walk");

        assert_eq!(
            requests,
            vec![(0, 4), (4, 4), (8, 2)],
            "an empty dropped page must still advance the server index"
        );
        assert_eq!(
            addresses(&hits),
            vec![4, 5, 6, 7, 8, 9],
            "the valid later pages must not be abandoned"
        );
        assert!(dropped, "the drop flag must survive the whole walk");
        assert!(!truncated);
    }

    /// No drop flag + no hits is the only genuine end-of-list signal.
    #[test]
    fn an_empty_page_without_the_drop_flag_ends_the_walk() {
        let mut requests = Vec::new();
        let (hits, _truncated, dropped) = walk_all_hits(4, |offset, count| {
            requests.push((offset, count));
            Ok(HitBatch {
                session_id: 7,
                total: 10,
                value_size: 4,
                truncated: false,
                dropped: false,
                hits: Vec::new(),
            })
        })
        .expect("page walk");

        assert!(hits.is_empty());
        assert!(!dropped);
        assert_eq!(
            requests,
            vec![(0, 4)],
            "an empty non-dropped page ends the walk"
        );
    }

    /// The mapping table decides: any traversable mapping ending above 4 GiB
    /// means 8-byte pointers, an end at or below it does not.
    #[test]
    fn pointer_width_follows_the_console_auto_rule() {
        let low = 0x0070_0000u64; // MockSwitch's main module base
                                  // A 32-bit title: every mapping ends below 4 GiB.
        assert_eq!(
            pointer_width_for(
                &metadata(low),
                Some(&[
                    mapping(0x0070_0000, 0x80000, PERM_R),
                    mapping(0x42CA_0000, 0x3000, PERM_R)
                ])
            ),
            4
        );
        // A 64-bit title whose main module ASLR'd below 4 GiB: the high mapping
        // is the evidence that the address space is wide.
        assert_eq!(
            pointer_width_for(
                &metadata(low),
                Some(&[
                    mapping(low, 0x80000, PERM_R),
                    mapping(0x7F_0000_0000, 0x1000, PERM_R)
                ])
            ),
            8
        );
        // An end exactly at 4 GiB still addresses only 32-bit-reachable bytes.
        assert_eq!(
            pointer_width_for(
                &metadata(low),
                Some(&[mapping(0xFFFF_F000, 0x1000, PERM_R)])
            ),
            4
        );
        // A mapping that wraps past the top is 64-bit evidence, not a small end.
        assert_eq!(
            pointer_width_for(
                &metadata(low),
                Some(&[mapping(u64::MAX - 0xFFF, 0x2000, PERM_R)])
            ),
            8
        );
    }

    /// Without a mapping table the main module base decides, and 0 is "unknown"
    /// (the console's AArch64 default), not a 32-bit hint.
    #[test]
    fn without_mappings_an_unknown_base_is_64bit() {
        assert_eq!(pointer_width_for(&metadata(0), None), 8);
        assert_eq!(pointer_width_for(&metadata(0), Some(&[])), 8);
        assert_eq!(pointer_width_for(&metadata(0x0780_4000), None), 4);
        assert_eq!(pointer_width_for(&metadata(0x1_0000_0000), None), 8);
        // Entries the console would not walk are not evidence either.
        let unusable = [
            mapping(0x7F_0000_0000, 0x1000, 0),
            mapping(0x0070_0000, 0, PERM_R),
        ];
        assert_eq!(
            pointer_width_for(&metadata(0x0070_0000), Some(&unusable)),
            4,
            "unreadable / empty mappings fall back to the main base"
        );
        assert_eq!(pointer_width_for(&metadata(0), Some(&unusable)), 8);
    }

    /// The High-severity bug this rule fixes: a 64-bit title whose main module
    /// and heap both ASLR'd below 4 GiB.  Every mapping ends below 4 GiB, so the
    /// mapping-only rule said 4 while the console - which also looks at the
    /// process's own address space - said 8; the GUI then generated 540F/640F
    /// code for a 64-bit game.
    #[test]
    fn the_process_address_space_outranks_the_mappings() {
        let low = 0x0070_0000u64;
        let low_maps = [
            mapping(low, 0x80000, PERM_R),
            mapping(0x3600_0000, 0x10_0000, PERM_R),
        ];
        // dmnt's AArch64 pair: 0x8000000 + 0x7FF8000000 (512 GiB).
        let wide = Metadata {
            main_base: low,
            aslr_base: 0x0800_0000,
            aslr_size: 0x7FF8_0000_00,
            ..Default::default()
        };
        assert_eq!(
            pointer_width_with_reason(&wide, Some(&low_maps)),
            (8, WIDTH_REASON_PROCESS_64),
            "a low mapping table must not drag a 64-bit process down to 4"
        );

        // dmnt's AArch32 pair: 0x200000 + 0xFFE00000 (ends exactly at 4 GiB).
        let narrow = Metadata {
            main_base: low,
            aslr_base: 0x0020_0000,
            aslr_size: 0xFFE0_0000,
            ..Default::default()
        };
        assert_eq!(
            pointer_width_with_reason(&narrow, Some(&low_maps)),
            (4, WIDTH_REASON_PROCESS_32)
        );
        // AArch32 stays authoritative even next to a mapping the PC cannot place
        // (a 32-bit title can never hold a pointer above 4 GiB).
        assert_eq!(
            pointer_width_with_reason(&narrow, Some(&[mapping(0x7F_0000_0000, 0x1000, PERM_R)])),
            (4, WIDTH_REASON_PROCESS_32)
        );
        // No metadata answer (old console / dmnt closed): the mappings decide.
        assert_eq!(
            pointer_width_with_reason(&metadata(low), Some(&low_maps)),
            (4, WIDTH_REASON_MAPPINGS_32)
        );
        // ... and a high mapping still proves the wide space on its own.
        assert_eq!(
            pointer_width_with_reason(
                &metadata(low),
                Some(&[mapping(0x7F_0000_0000, 0x1000, PERM_R)])
            ),
            (8, WIDTH_REASON_MAPPINGS_64)
        );
    }

    /// Every branch names its evidence, and the words line up with the value:
    /// the UI prints "{width}-bit from {reason}", so a mismatched pair would be
    /// worse than no explanation at all.
    #[test]
    fn every_width_names_its_evidence() {
        let low = 0x0070_0000u64;
        let cases: [(Metadata, Option<&[Mapping]>, u32, &str); 5] = [
            (
                Metadata {
                    aslr_base: 0x0800_0000,
                    aslr_size: 0x7FF8_0000_00,
                    ..Default::default()
                },
                None,
                8,
                WIDTH_REASON_PROCESS_64,
            ),
            (
                Metadata {
                    aslr_base: 0x0020_0000,
                    aslr_size: 0xFFE0_0000,
                    ..Default::default()
                },
                None,
                4,
                WIDTH_REASON_PROCESS_32,
            ),
            (metadata(low), None, 4, WIDTH_REASON_MAIN_BASE_32),
            (metadata(0x1_0000_0000), None, 8, WIDTH_REASON_MAIN_BASE_64),
            (metadata(0), None, 8, WIDTH_REASON_DEFAULT),
        ];
        for (md, maps, width, reason) in cases {
            let (got_width, got_reason) = pointer_width_with_reason(&md, maps);
            assert_eq!((got_width, got_reason), (width, reason));
            assert_eq!(
                pointer_width_for(&md, maps),
                width,
                "the narrow wrapper must not disagree with the decision"
            );
        }
        // The two mapping branches too, with a table each.
        let wide_maps = [mapping(0x7F_0000_0000, 0x1000, PERM_R)];
        assert_eq!(
            pointer_width_with_reason(&metadata(low), Some(&wide_maps)).1,
            WIDTH_REASON_MAPPINGS_64
        );
        let narrow_maps = [mapping(low, 0x80000, PERM_R)];
        assert_eq!(
            pointer_width_with_reason(&metadata(low), Some(&narrow_maps)).1,
            WIDTH_REASON_MAPPINGS_32
        );
        // No reason is empty or shared with a different width.
        let all = [
            WIDTH_REASON_PROCESS_64,
            WIDTH_REASON_PROCESS_32,
            WIDTH_REASON_MAPPINGS_64,
            WIDTH_REASON_MAPPINGS_32,
            WIDTH_REASON_MAIN_BASE_64,
            WIDTH_REASON_MAIN_BASE_32,
            WIDTH_REASON_DEFAULT,
        ];
        for (i, a) in all.iter().enumerate() {
            assert!(!a.is_empty());
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b, "two branches share a reason");
            }
        }
    }

    /// Trans-language parity with the console's own rule.
    ///
    /// The expectations below were produced by BUILDING AND RUNNING
    /// `core/nxus_ptrscan.c` on the host - a throwaway harness that calls
    /// `nxusPtrScanArchFromAddressSpace()` and `nxusPtrScanAutoWidthFor()` with
    /// exactly these inputs - not by reading the C by hand.  A future edit on
    /// either side that changes a decision therefore fails here.
    ///
    /// The inputs model what the console really passes: `ptrScanProcessArch()`'s
    /// two dmnt aslr pairs (0x8000000 + 0x7FF8000000 for AArch64, 0x200000 +
    /// 0xFFE00000 for AArch32) and `buildPtrRegions()`'s region list (readable,
    /// non-empty mappings only).
    ///
    /// One deliberate difference, and only for an input the console cannot
    /// produce: `buildPtrRegions()` filters `!(reserved & NXUS_PERM_R)` out, so
    /// the C rule never sees an unreadable mapping, while the PC's tables (the
    /// GUI's mapping list, dump files) contain them and this rule ignores them.
    /// That can only turn "a high but unreadable region" into "no mapping
    /// evidence", which then falls through to the main base - the C would have
    /// counted its end.  See `without_mappings_an_unknown_base_is_64bit`.
    #[test]
    fn matches_the_console_pointer_width_rule() {
        const A64: (u64, u64) = (0x0800_0000, 0x7FF8_0000_00); // 512 GiB
        const A32: (u64, u64) = (0x0020_0000, 0xFFE0_0000); // ends exactly at 4 GiB
        let low = [
            mapping(0x0070_0000, 0x80000, PERM_R),
            mapping(0x3600_0000, 0x10_0000, PERM_R),
        ];
        let high = [mapping(0x7F_0000_0000, 0x1000, PERM_R)];
        let at_4gib = [mapping(0xFFFF_F000, 0x1000, PERM_R)];
        let wrapping = [mapping(u64::MAX - 0xFFF, 0x2000, PERM_R)];
        let empty_size = [mapping(0x7F_0000_0000, 0, PERM_R)];

        let with_aslr = |pair: (u64, u64), main_base: u64| Metadata {
            main_base,
            aslr_base: pair.0,
            aslr_size: pair.1,
            ..Default::default()
        };

        // (C harness output) -> (our width, our reason)
        let cases: [(Metadata, Option<&[Mapping]>, u32, &str); 13] = [
            // A64 pair + low maps: arch=2 width=8 "process is 64-bit" (max_end 0x36100000)
            (
                with_aslr(A64, 0x0070_0000),
                Some(&low),
                8,
                WIDTH_REASON_PROCESS_64,
            ),
            // A64 pair + no regions: arch=2 width=8
            (
                with_aslr(A64, 0x0070_0000),
                None,
                8,
                WIDTH_REASON_PROCESS_64,
            ),
            // A32 pair + low maps: arch=1 width=4 "process is AArch32"
            (
                with_aslr(A32, 0x0780_4000),
                Some(&low),
                4,
                WIDTH_REASON_PROCESS_32,
            ),
            // A32 pair + high map: arch=1 width=4 (the process outranks the mapping)
            (
                with_aslr(A32, 0x0070_0000),
                Some(&high),
                4,
                WIDTH_REASON_PROCESS_32,
            ),
            // straddling pair + low maps: arch=0 width=4 "mapping ends"
            (
                with_aslr((0x8000_0000, 0x9000_0000), 0x0070_0000),
                Some(&low),
                4,
                WIDTH_REASON_MAPPINGS_32,
            ),
            // overflowing pair: arch=0 width=4
            (
                with_aslr((0xFFFF_FFFF_FFFF_0000, 0x1000), 0),
                Some(&low),
                4,
                WIDTH_REASON_MAPPINGS_32,
            ),
            // no answer + low maps: arch=0 width=4
            (
                metadata(0x0070_0000),
                Some(&low),
                4,
                WIDTH_REASON_MAPPINGS_32,
            ),
            // no answer + high map: width=8
            (
                metadata(0x0070_0000),
                Some(&high),
                8,
                WIDTH_REASON_MAPPINGS_64,
            ),
            // no answer + an end exactly at 4 GiB: width=4 (max_end 0x100000000)
            (
                metadata(0x0070_0000),
                Some(&at_4gib),
                4,
                WIDTH_REASON_MAPPINGS_32,
            ),
            // no answer + wrapping region: width=8 (max_end 0xFFFFFFFFFFFFFFFF)
            (
                metadata(0x0070_0000),
                Some(&wrapping),
                8,
                WIDTH_REASON_MAPPINGS_64,
            ),
            // no answer + only zero-size regions: width=4 (they are skipped)
            (
                metadata(0x0070_0000),
                Some(&empty_size),
                4,
                WIDTH_REASON_MAIN_BASE_32,
            ),
            // no answer + no regions, base 0: width=8 (the AArch64 default)
            (metadata(0), None, 8, WIDTH_REASON_DEFAULT),
            // no answer + no regions, base 4 GiB: width=8
            (metadata(0x1_0000_0000), None, 8, WIDTH_REASON_MAIN_BASE_64),
        ];
        for (metadata, mappings, width, reason) in cases {
            assert_eq!(
                pointer_width_with_reason(&metadata, mappings),
                (width, reason),
                "diverged from core/nxus_ptrscan.c for aslr={:#x}+{:#x} main={:#x}: \
                        the console's host-run rule answers {}",
                metadata.aslr_base,
                metadata.aslr_size,
                metadata.main_base,
                width
            );
        }
    }

    #[test]
    fn error_without_reason_reads_like_before() {
        let e = error_from_reply(0x0013, &error_body(0x8000_0186, None));
        assert_eq!(e.message, "command 0x0013 failed");
        assert_eq!(e.result, Some(0x8000_0186));
    }

    #[test]
    fn error_with_reason_names_the_validation() {
        let e = error_from_reply(0x0032, &error_body(0x8000_0186, Some(2)));
        assert_eq!(
            e.message,
            "command 0x0032 failed - index or slot out of range (reason=2)"
        );
        assert_eq!(e.result, Some(0x8000_0186));
    }

    #[test]
    fn unknown_reason_is_still_printed() {
        let e = error_from_reply(0x0011, &error_body(0x8000_0186, Some(99)));
        assert!(e.message.ends_with("(reason=99)"), "{}", e.message);
        assert_eq!(error_reason_text(99), None);
    }

    #[test]
    fn short_error_reply_decodes_as_zero_result() {
        let e = error_from_reply(0x0003, &[]);
        assert_eq!(e.result, Some(0));
        assert_eq!(e.message, "command 0x0003 failed");
    }

    #[test]
    fn every_documented_reason_has_text() {
        for reason in 1..=13 {
            assert!(
                error_reason_text(reason).is_some(),
                "reason {} has no text",
                reason
            );
        }
        assert_eq!(
            error_reason_text(0),
            None,
            "0 means 'no detail', never sent"
        );
    }

    #[test]
    fn busy_reasons_name_the_blocking_condition() {
        // 11/12/13 were previously printed as a bare "(reason=N)", which told
        // the operator nothing about what to do.
        assert_eq!(
            error_from_reply(0x0020, &error_body(0x8000_0186, Some(11))).message,
            "command 0x0020 failed - the console holds a debug session: detach before freezing (reason=11)"
        );
        assert_eq!(
            error_reason_text(12),
            Some("a fixed table is full (breakpoint slots or pinned views): clear something first")
        );
        assert_eq!(
            error_reason_text(13),
            Some("the previous session is still being released: retry in a moment")
        );
    }

    #[test]
    fn only_busy_with_reason_13_is_retried() {
        let busy_later = NxusError {
            message: "command 0x0013 failed - the previous session is still being released: retry in a moment (reason=13)".into(),
            result: Some(RESULT_BUSY),
        };
        assert!(is_retry_later(&busy_later));

        // Reason 4 (scan in progress) is a real busy state, not a release window.
        let busy_scan = NxusError {
            message:
                "command 0x0013 failed - busy: a scan or pause/resume is in progress (reason=4)"
                    .into(),
            result: Some(RESULT_BUSY),
        };
        assert!(!is_retry_later(&busy_scan));

        // A failing command with a reason 13 but no BUSY result is not retried.
        let not_busy = NxusError {
            message: "command 0x0013 failed - the previous session is still being released: retry in a moment (reason=13)".into(),
            result: Some(0x8000_0186),
        };
        assert!(!is_retry_later(&not_busy));
    }

    #[test]
    fn frozen_diff_is_empty_without_a_previous_list() {
        assert!(released_addresses(&[], &[0x1000, 0x2000]).is_empty());
        assert!(released_addresses(&[], &[]).is_empty());
    }

    #[test]
    fn frozen_diff_reports_the_address_the_console_released() {
        assert_eq!(
            released_addresses(&[0x1FA1234, 0x1FA1238], &[0x1FA1238]),
            vec![0x1FA1234]
        );
    }

    #[test]
    fn frozen_diff_of_a_cleared_list_is_the_old_list_in_order() {
        // releaseOwnedFrozen() drops everything at once: the warning has to name
        // every address, sorted so the output is stable.
        assert_eq!(
            released_addresses(&[0x3000, 0x1000, 0x2000], &[]),
            vec![0x1000, 0x2000, 0x3000]
        );
    }

    #[test]
    fn frozen_diff_ignores_new_freezes_and_repeats() {
        // a new address is not a release, and a duplicate must not print twice
        assert!(released_addresses(&[0x1000], &[0x1000, 0x5000]).is_empty());
        assert_eq!(released_addresses(&[0x1000, 0x1000], &[]), vec![0x1000]);
    }

    fn stopped(low: u32, full: u64) -> DebugStatus {
        DebugStatus {
            stopped_thread_low: low,
            stopped_thread: full,
            ..Default::default()
        }
    }

    #[test]
    fn the_event_id_wins_when_it_describes_the_current_stop() {
        // Old console: only the low half is in the status, the event has the whole
        // id.  This is the case the truncation bug was about.
        let full = 0x1_0000_2A3Bu64;
        let status = stopped(full as u32, 0);
        assert_eq!(select_stopped_thread(&status, Some(full)), Some(full));
    }

    #[test]
    fn a_stale_event_is_never_handed_to_regs_get() {
        // The client did not drain events since an older hit on another thread.
        let status = stopped(0x2A3B, 0);
        assert_eq!(
            select_stopped_thread(&status, Some(0x1_0000_1F00)),
            Some(0x2A3B),
            "the truncated half beats the wrong thread"
        );
        // A new-firmware status names the real thread even with a stale event.
        let status = stopped(0x2A3B, 0x1_0000_2A3B);
        assert_eq!(
            select_stopped_thread(&status, Some(0x1_0000_1F00)),
            Some(0x1_0000_2A3B)
        );
    }

    #[test]
    fn the_appended_status_field_works_without_any_event() {
        let full = 0x1_0000_2A3Bu64;
        assert_eq!(
            select_stopped_thread(&stopped(full as u32, full), None),
            Some(full)
        );
    }

    #[test]
    fn a_running_target_is_none_even_with_a_cached_event() {
        assert_eq!(select_stopped_thread(&stopped(0, 0), Some(0x1001)), None);
    }

    #[test]
    fn without_the_new_field_the_truncated_half_is_the_last_resort() {
        // Old console whose event was never polled: still the legacy behaviour.
        assert_eq!(
            select_stopped_thread(&stopped(0x1001, 0), None),
            Some(0x1001)
        );
    }

    #[test]
    fn result_text_labels_both_encodings() {
        // libnx MAKERESULT(Module_Libnx, LibnxError_BadInput): bit 31 clear, tiny.
        assert_eq!(
            result_text(0x0000_1759),
            Some("libnx rejected the input (nothing to refine?)")
        );
        // Our own BAD_STATE: 0x80000000 | (484 << 9) | 6.
        assert_eq!(
            result_text(0x8003_C806),
            Some("the console is in the wrong state for this")
        );
        assert_eq!(
            result_text(0x8003_C801),
            Some("the console does not implement this command")
        );
        assert_eq!(result_text(0), None, "0 is never an error");
        assert_eq!(
            result_text(0x1234_5678),
            None,
            "unknown module stays unlabelled"
        );
    }

    // ---- link liveness / deadlines -------------------------------------
    //
    // 本番の締切（idle 20 秒 / heartbeat 5 秒）をそのまま待つと 1 本 20 秒
    // かかってしまい、テストが実質「実行しない」ものになる。同じコードを
    // ミリ秒のタイミングで組み立てて、判定そのものを固定する。

    fn fast_timing() -> LinkTiming {
        LinkTiming {
            idle_timeout: Duration::from_millis(800),
            keepalive_interval: Duration::from_millis(200),
            keepalive_timeout: Duration::from_millis(150),
            keepalive_retry: Duration::from_millis(100),
            keepalive_misses: 2,
        }
    }

    /// ローカルの TCP 対（戻り値の 2 番目がサーバ役）。
    fn socket_pair(read_timeout: Duration) -> (std::net::TcpStream, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("local addr");
        let accept = std::thread::spawn(move || listener.accept().expect("accept").0);
        let client = std::net::TcpStream::connect(address).expect("connect");
        client
            .set_read_timeout(Some(read_timeout))
            .expect("read timeout");
        let server = accept.join().expect("accept thread");
        (client, server)
    }

    /// サーバが返す 1 フレームを組み立てる。
    fn frame_bytes(kind: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(HEADER_SIZE + body.len());
        put_u32(&mut frame, MAGIC);
        put_u16(&mut frame, kind);
        put_u16(&mut frame, flags);
        put_u32(&mut frame, body.len() as u32);
        put_u32(&mut frame, seq);
        frame.extend_from_slice(body);
        frame
    }

    /// サーバ役として 1 フレーム読む。
    fn read_frame_from(stream: &mut std::net::TcpStream) -> Option<(u16, u16, u32, Vec<u8>)> {
        use std::io::Read;

        let mut header = [0u8; HEADER_SIZE];
        stream.read_exact(&mut header).ok()?;
        let kind = rd_u16(&header, 4);
        let flags = rd_u16(&header, 6);
        let length = rd_u32(&header, 8) as usize;
        let seq = rd_u32(&header, 12);
        let mut body = vec![0u8; length];
        if length > 0 {
            stream.read_exact(&mut body).ok()?;
        }
        Some((kind, flags, seq, body))
    }

    /// 接続死に気づくまで待つ（テスト用タイミングなら 1 秒前後）。
    fn wait_until_dead(client: &NxusClient) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !client.is_dead() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(client.is_dead(), "the client never noticed the dead link");
    }

    /// 締切の無い `read_exact` は無音のピアで永久に回っていた（200 ms の
    /// read timeout を `continue` で捨てていた）。締切で必ず戻ることを固定する。
    #[test]
    fn read_exact_gives_up_at_its_deadline_instead_of_spinning_forever() {
        use std::sync::atomic::AtomicBool;

        let (mut stream, _server) = socket_pair(Duration::from_millis(20));
        let running = AtomicBool::new(true);
        let started = Instant::now();

        let error = read_exact(
            &mut stream,
            &mut [0u8; HEADER_SIZE],
            started + Duration::from_millis(150),
            &running,
        )
        .expect_err("a silent peer must not satisfy read_exact");

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() >= Duration::from_millis(140),
            "gave up before the deadline: {:?}",
            started.elapsed()
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "a 150 ms deadline took {:?}",
            started.elapsed()
        );
    }

    /// 途中まで読めたバイトは呼び出し側のバッファに残す（部分フレームは
    /// 復元できないので、呼び出し側は失敗後に捨てる）。`running == false` は
    /// 締切より優先して即座に Interrupted。
    #[test]
    fn read_exact_keeps_the_partial_frame_and_stops_when_asked_to_quit() {
        use std::io::Write;
        use std::sync::atomic::{AtomicBool, Ordering};

        let (mut stream, mut server) = socket_pair(Duration::from_millis(20));
        server.write_all(&[0xAA, 0xBB, 0xCC]).expect("partial frame");
        server.flush().expect("flush");

        let running = AtomicBool::new(true);
        let mut buffer = [0u8; 8];
        let error = read_exact(
            &mut stream,
            &mut buffer,
            Instant::now() + Duration::from_millis(120),
            &running,
        )
        .expect_err("a 3-byte frame cannot complete an 8-byte read");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(&buffer[..3], &[0xAA, 0xBB, 0xCC], "partial bytes kept");
        assert_eq!(buffer[3], 0, "nothing past the received bytes");

        running.store(false, Ordering::SeqCst);
        let started = Instant::now();
        let error = read_exact(
            &mut stream,
            &mut buffer,
            started + Duration::from_secs(30),
            &running,
        )
        .expect_err("a shutdown interrupts the read");
        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "the shutdown check must not wait for the deadline: {:?}",
            started.elapsed()
        );
    }

    /// 何も返さないピア（スリープ / Wi-Fi 断 / 本体ハング）。以前は全要求が
    /// 自分の締切まで待ち、次の要求もまた待った。いまは接続死が立ち、2 回目
    /// 以降は 1 バイトも書かずに即エラーになる。
    #[test]
    fn a_silent_peer_is_declared_dead_and_later_requests_fail_fast() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let server = std::thread::spawn(move || {
            let (_socket, _) = listener.accept().expect("accept");
            // 接続は保持したまま黙る。
            std::thread::sleep(Duration::from_millis(1500));
        });

        let client =
            NxusClient::connect_for_test("127.0.0.1", port, fast_timing()).expect("connect");
        let started = Instant::now();
        let _ = client.request_timeout(cmd::GET_STATUS, &[], Duration::from_millis(500));
        wait_until_dead(&client);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "took {:?} to notice a silent peer",
            started.elapsed()
        );

        let fast = Instant::now();
        let error = client.request(cmd::GET_STATUS, &[]).expect_err("dead link");
        assert_eq!(error.message, "connection lost");
        assert!(
            fast.elapsed() < Duration::from_millis(100),
            "a dead link still waited {:?}",
            fast.elapsed()
        );

        drop(client);
        let _ = server.join();
    }

    /// 途中で切るピア: ヘッダだけ送って FIN。部分フレームは復元できないので、
    /// その場で接続死にして以後の要求を即エラーにする。
    #[test]
    fn a_peer_that_closes_mid_frame_kills_the_link() {
        use std::io::Write;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            // 「64 バイトの payload が来る」と宣言するヘッダだけ送って閉じる。
            let mut header = Vec::new();
            put_u32(&mut header, MAGIC);
            put_u16(&mut header, cmd::HEARTBEAT);
            put_u16(&mut header, 0);
            put_u32(&mut header, 64);
            put_u32(&mut header, 1);
            socket.write_all(&header).expect("partial frame");
            socket.flush().expect("flush");
            // drop(socket) が FIN になる。
        });

        let client =
            NxusClient::connect_for_test("127.0.0.1", port, fast_timing()).expect("connect");
        wait_until_dead(&client);

        let fast = Instant::now();
        let error = client.request(cmd::GET_STATUS, &[]).expect_err("dead link");
        assert_eq!(error.message, "connection lost");
        assert!(
            fast.elapsed() < Duration::from_millis(100),
            "a dead link still waited {:?}",
            fast.elapsed()
        );

        drop(client);
        let _ = server.join();
    }

    /// 長い要求（スキャン等）の返事待ちを無音判定で殺さない。
    ///
    /// サーバの接続スレッドは 1 本で、`ScanBegin` は処理し終えるまで何も
    /// 送ってこない。要求自身の締切までは待つ、という規則が無いと、健全な
    /// スキャンが 20 秒（テストでは 800 ms）で「接続死」になる。
    #[test]
    fn a_long_request_is_not_killed_by_the_idle_rule() {
        use std::io::Write;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let (kind, _flags, seq, _body) =
                read_frame_from(&mut socket).expect("the request frame");
            // idle_timeout(800 ms) より長く黙ってから返す: 遅いスキャンの代役。
            std::thread::sleep(Duration::from_millis(1200));
            socket
                .write_all(&frame_bytes(kind, 0, seq, &[]))
                .expect("late reply");
            // 返信直後に閉じると、クライアントは（正しく）EOF を接続死として
            // 拾う。このテストが見たいのは「遅い返事」だけなので、判定が
            // 終わるまで接続を保持する。
            std::thread::sleep(Duration::from_millis(500));
        });

        let client =
            NxusClient::connect_for_test("127.0.0.1", port, fast_timing()).expect("connect");
        let (_, body) = client
            .request_timeout(cmd::GET_STATUS, &[], Duration::from_secs(3))
            .expect("a long request must wait for its own deadline");
        assert!(body.is_empty());
        assert!(
            !client.is_dead(),
            "waiting for a slow reply is not a dead link"
        );

        drop(client);
        let _ = server.join();
    }

    /// 無音でも健全な接続は殺さない: keepalive が Heartbeat を送り、応答が
    /// 返る限り reader の無音判定（本番 20 秒）は発火しない。
    /// 同時に「送信が止まった接続に Heartbeat が実際に出る」ことも固定する。
    #[test]
    fn the_keepalive_keeps_a_quiet_but_healthy_link_alive() {
        use std::io::Write;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let (frame_tx, frame_rx) = std::sync::mpsc::channel::<u16>();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout");
            while let Some((kind, _flags, seq, _body)) = read_frame_from(&mut socket) {
                let _ = frame_tx.send(kind);
                if kind != cmd::HEARTBEAT {
                    continue;
                }
                // コンソールと同じく、Heartbeat には空の応答を返す。
                if socket.write_all(&frame_bytes(kind, 0, seq, &[])).is_err() {
                    break;
                }
            }
        });

        let client =
            NxusClient::connect_for_test("127.0.0.1", port, fast_timing()).expect("connect");
        let first = frame_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("the keepalive must send a Heartbeat on a quiet link");
        assert_eq!(first, cmd::HEARTBEAT);

        // 応答が返り続けている限り、無音を「接続死」にしない。
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            !client.is_dead(),
            "an answered heartbeat must keep the link alive"
        );
        let mut more = 0;
        while frame_rx.try_recv().is_ok() {
            more += 1;
        }
        assert!(
            more >= 1,
            "the keepalive must repeat while the link stays quiet"
        );

        drop(client);
        let _ = server.join();
    }

    // ---- コンソール側チート VM ------------------------------------------

    /// チートの締切は「アップロードだけ 10 秒、それ以外は 3 秒」。
    ///
    /// アップロードは最大 48 KiB をリンクさせるので長く、ON/OFF と状態取得は
    /// 対話操作なので短い。値をピンしておかないと、片方だけ直して
    /// 「UI が数秒固まる」再発になる。
    #[test]
    fn cheat_deadlines_are_ten_seconds_for_upload_and_three_for_the_rest() {
        assert_eq!(CHEAT_UPLOAD_TIMEOUT, Duration::from_secs(10));
        assert_eq!(CHEAT_COMMAND_TIMEOUT, Duration::from_secs(3));
        assert_eq!(CHEAT_COMMAND_TIMEOUT, CHEAT_REQUEST_TIMEOUT);
        // コマンド id は core/nxus_protocol.h の NxusCmd_Cheat* と一致する。
        assert_eq!(CMD_CHEAT_UPLOAD, 0x0080);
        assert_eq!(CMD_CHEAT_ENABLE, 0x0081);
        assert_eq!(CMD_CHEAT_STATUS, 0x0082);
        assert_eq!(CMD_CHEAT_PANIC_OFF, 0x0083);
        assert_eq!(CMD_CHEAT_CLEAR, 0x0084);
        assert_eq!(EVENT_CHEAT_FAULT, 0x800A);
        // ワイヤ構造体のサイズ（static_assert と同じ値）。
        assert_eq!(CheatStatus::SIZE, 48);
        assert_eq!(CheatRestore::SIZE, 16);
        assert_eq!(CheatUploadReply::SIZE, 16);
        assert_eq!(CheatFault::SIZE, 16);
    }

    /// アップロードは `build_program` の出力を 1 バイトも変えずに送り、
    /// 応答を `NxusCheatUploadReply` として読む。
    ///
    /// 「PC が組み立てたプログラム」と「実際に線を流れたバイト」が同じことを
    /// 固定しないと、リンカの変更が静かに壊れた状態で通ってしまう。
    #[test]
    fn cheat_upload_sends_the_linked_program_verbatim() {
        use crate::cheat::{ir, CheatDocument};

        let document = CheatDocument::parse(
            "[Money]\n04000000 42CA1DC4 0098967F\n",
            "9D4C86E6EF74504A",
        );
        let program = ir::build_program(
            &document,
            0x9D4C_86E6_EF74_504A,
            0x0100_C380_0049_C000,
            &std::collections::BTreeSet::new(),
        )
        .expect("the program links");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let server = std::thread::spawn(move || {
            use std::io::Write;

            let (mut socket, _) = listener.accept().expect("accept");
            let mut seen: Option<Vec<u8>> = None;
            while let Some((kind, _flags, seq, body)) = read_frame_from(&mut socket) {
                if kind == CMD_CHEAT_UPLOAD {
                    seen = Some(body);
                    let mut reply = Vec::new();
                    put_u32(&mut reply, 1); // accepted_blocks
                    put_u32(&mut reply, 1); // accepted_insns
                    put_u32(&mut reply, 0); // rejected_reason
                    put_u32(&mut reply, 0);
                    if socket.write_all(&frame_bytes(kind, 0, seq, &reply)).is_err() {
                        break;
                    }
                    continue;
                }
                // 他のコマンドは空の成功応答で足りる（このテストは使わない）。
                if socket.write_all(&frame_bytes(kind, 0, seq, &[])).is_err() {
                    break;
                }
            }
            seen
        });

        let client = NxusClient::connect("127.0.0.1", port).expect("connect");
        let reply = client.cheat_upload(&program).expect("upload");
        assert_eq!(reply.accepted_blocks, 1);
        assert_eq!(reply.accepted_insns, 1);
        assert!(reply.rejected_text().is_none(), "{reply:?}");

        drop(client);
        let seen = server.join().expect("server thread");
        assert_eq!(
            seen.as_deref(),
            Some(program.as_slice()),
            "the wire payload must be exactly ir::build_program's output"
        );
    }

    /// `NxusEvent_CheatFault` は理由つきで開き、`TARGET_GONE` /
    /// `JOURNAL_FULL` は利用者が次の行動を選べる文になる。
    #[test]
    fn a_cheat_fault_event_decodes_into_its_reason() {
        let mut payload = Vec::new();
        put_u32(&mut payload, CheatFault::TARGET_GONE);
        put_u32(&mut payload, u32::MAX);
        put_u32(&mut payload, 0);
        put_u32(&mut payload, 7);
        let event = Event {
            kind: EVENT_CHEAT_FAULT,
            payload: payload.clone(),
        };

        match event.decode() {
            IncomingEvent::CheatFault {
                reason,
                block,
                pc,
                restored,
            } => {
                assert_eq!(reason, CheatFault::TARGET_GONE);
                assert_eq!(block, u32::MAX);
                assert_eq!(pc, 0);
                assert_eq!(restored, 7);
            }
            other => panic!("decoded as {other:?}"),
        }

        let fault = event.cheat_fault().expect("a fault");
        assert!(fault.reason_text().contains("closed or restarted"));
        assert!(fault.reason_text().contains("7 address(es) restored"));

        let full = CheatFault {
            reason: CheatFault::JOURNAL_FULL,
            block: 2,
            pc: 0,
            restored: 0,
        };
        assert!(full.reason_text().contains("restore table is full"));
        assert!(full.reason_text().contains("block 2"));

        // 命令の失敗は NXUS_CHEATVM_ERR_* の名前で出る。
        let write = CheatFault {
            reason: 0xFFFF_FFFA, // -6 = NXUS_CHEATVM_ERR_WRITE
            block: 0,
            pc: 3,
            restored: 1,
        };
        assert!(write.reason_text().contains("target write failed"));

        // 短すぎるペイロードや別種のイベントは素通りする。
        assert!(CheatFault::parse(&[0u8; 4]).is_none());
        assert_eq!(
            Event {
                kind: 0x8001,
                payload: payload,
            }
            .decode(),
            IncomingEvent::Other
        );
    }

    /// 「このコマンドは知らない」を 1 か所で判定する。
    ///
    /// GUI と NCL の両方が、この判定で PC 実行へフォールバックする。
    #[test]
    fn an_unimplemented_command_is_recognised_from_result_or_reason() {
        let unimplemented = NxusError {
            message: "command 0x0082 failed - the console does not implement this command"
                .to_string(),
            result: Some(0x8003_C801),
        };
        assert!(is_unsupported_command(&unimplemented));

        let unsupported = NxusError {
            message: "command 0x0080 failed".to_string(),
            result: Some(0x8003_C802),
        };
        assert!(is_unsupported_command(&unsupported));

        // Result だけ返す古いコンソール: 理由コード 6 で判定する。
        let reason_only = NxusError {
            message: "command 0x0082 failed - unknown command (reason=6)".to_string(),
            result: Some(RESULT_BUSY),
        };
        assert!(is_unsupported_command(&reason_only));

        for other in [
            NxusError {
                message: "connection lost".to_string(),
                result: None,
            },
            NxusError {
                message: "command 0x0082 failed - busy (reason=4)".to_string(),
                result: Some(RESULT_BUSY),
            },
        ] {
            assert!(!is_unsupported_command(&other), "{other}");
        }
    }
}
