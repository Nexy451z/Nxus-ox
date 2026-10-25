//! Nxus TCP client: seq-correlated requests plus an asynchronous event queue.
//!
//! Works against the real sysmodule and against pc/nxus/mock_switch.py, so the
//! whole protocol can be exercised without a console.

use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::atomic::Ordering;
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

/// The title's pointer width in bytes (4 or 8) - the ONE width rule on the PC.
///
/// Nothing here is ever sent to the console: a pointer scan request carries
/// `value_width = 0` ("automatic") and the console decides.  This mirrors the
/// console's `nxusPtrScanAutoWidth()` (core/nxus_ptrscan.c) so the PC can
/// *explain* that decision and pick the matching parts: the address format in
/// the GUI, the pointer width a PC-side dump walk uses, and the 540F/580F pointer
/// load plus the 640F/680F value write of a cheat export.
///
/// It exists because the PC used to answer this in three places with three
/// different rules (the GUI said 4 for an unknown base, a dump walk said 8, and
/// the CLI decided from the mapping table), so a display, a PC-side scan and an
/// exported cheat could disagree about the very same title.
///
/// The rule, in the console's order:
///
/// * `mappings` is the target's memory map.  An entry whose end lies above 4 GiB
///   proves a 64-bit address space; when every entry ends at or below 4 GiB,
///   4-byte pointers cover the whole map.  An end exactly at 4 GiB still holds
///   only 32-bit-addressable bytes, so it does not prove 8 (the console compares
///   the same way).  Entries the console could not walk (size 0, not readable)
///   are ignored exactly like `buildPtrRegions()` ignores them.
/// * Without a usable mapping table the main module base is the only evidence:
///   `0` means "unknown" and defaults to 8 (AArch64 is the common case, and a
///   wide load on a 32-bit title only costs a failed scan while a narrow load on
///   a 64-bit title silently loses every chain), a base at or above 4 GiB is
///   already outside the 32-bit address space, everything else is 4.
pub fn pointer_width_for(metadata: &Metadata, mappings: Option<&[Mapping]>) -> u32 {
    /// Highest address a 4-byte pointer can describe.
    const WIDTH_LIMIT: u64 = 0x1_0000_0000;

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
        return if wide { 8 } else { 4 };
    }
    if metadata.main_base == 0 || metadata.main_base >= WIDTH_LIMIT { 8 } else { 4 }
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
            flags: if value_type.is_float() { SCAN_F_FLOAT } else { 0 },
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
    let mut payload = Vec::with_capacity(56 + 16 + spec.pattern.len() * 2
                                        + spec.ranges.len() * crate::protocol::RANGE_ENTRY_SIZE);
    put_u32(&mut payload, kind);
    put_u32(&mut payload, spec.value_size);
    put_u32(&mut payload, spec.compare as u32);
    put_u32(&mut payload, spec.scope as u32);
    put_u64(&mut payload, spec.range_begin);
    put_u64(&mut payload, spec.range_end);
    put_u64(&mut payload, spec.value);
    put_u64(&mut payload, spec.target2);
    put_u32(&mut payload, 0);            // chunk size (server default)
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
        put_u32(&mut payload, 0);                       // reserved
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

/// Conservative default until the server tells us its real limit.
pub const DEFAULT_MAX_READ: u32 = 64 * 1024;

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
            message: format!(
                "cannot resolve {}:{} - {}",
                host, port, net_error_text(&e)
            ),
            result: None,
        }),
        Err(RecvTimeoutError::Timeout) => Err(NxusError {
            message: format!(
                "cannot resolve {}:{} - the host name lookup did not answer within {} s",
                host, port, RESOLVE_TIMEOUT.as_secs()
            ),
            result: None,
        }),
        Err(RecvTimeoutError::Disconnected) => Err(NxusError {
            message: format!("cannot resolve {}:{} - the host name lookup failed", host, port),
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
    stream: Mutex<TcpStream>,
    pending: Arc<Mutex<HashMap<u32, Sender<Response>>>>,
    events: Mutex<Receiver<Event>>,
    seq: Mutex<u32>,
    /// Shared with the reader thread; an `AtomicBool` (not a `Mutex<bool>`) so `Drop`
    /// can flag it without ever blocking behind a busy lock.
    running: Arc<std::sync::atomic::AtomicBool>,
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
        12 => Some("a fixed table is full (breakpoint slots or pinned views): clear something first"),
        13 => Some("the previous session is still being released: retry in a moment"),
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
        && e.message.ends_with(&format!("(reason={})", REASON_RETRY_LATER))
}

/// Build the client error for a `FLAG_ERROR` reply.
///
/// The payload is the s32 Result, optionally followed by one u32 reason code
/// (see [`error_reason_text`]).  A short or reason-less payload keeps the old
/// message exactly ("command 0x.... failed"), so a console that predates the
/// reason word still produces the familiar text.
fn error_from_reply(cmd: u16, body: &[u8]) -> NxusError {
    let rc = if body.len() >= 4 { rd_u32(body, 0) } else { 0 };
    let mut message = format!("command 0x{:04X} failed", cmd);
    if body.len() >= 8 {
        let reason = rd_u32(body, 4);
        match error_reason_text(reason) {
            Some(text) => message.push_str(&format!(" - {} (reason={})", text, reason)),
            None => message.push_str(&format!(" (reason={})", reason)),
        }
    }
    NxusError { message, result: Some(rc) }
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

impl NxusClient {
    pub fn connect(host: &str, port: u16) -> Result<NxusClient> {
        let stream = connect_with_timeout(host, port)?;
        stream.set_nodelay(true).ok();
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .map_err(|e| NxusError { message: e.to_string(), result: None })?;
        // Without a write deadline a dead link makes `write_all` block for
        // minutes: the TCP stack keeps retrying and the request never fails, so
        // the GUI would look frozen instead of noticing the console went away.
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| NxusError { message: e.to_string(), result: None })?;
        let reader_stream = stream
            .try_clone()
            .map_err(|e| NxusError { message: e.to_string(), result: None })?;

        let pending: Arc<Mutex<HashMap<u32, Sender<Response>>>> = Arc::new(Mutex::new(HashMap::new()));
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let (event_tx, event_rx) = mpsc::channel::<Event>();

        {
            let pending = Arc::clone(&pending);
            let running = Arc::clone(&running);
            thread::spawn(move || reader_loop(reader_stream, pending, event_tx, running));
        }

        Ok(NxusClient {
            max_read: std::sync::atomic::AtomicU32::new(DEFAULT_MAX_READ),
            truncated: std::sync::atomic::AtomicBool::new(false),
            stream: Mutex::new(stream),
            pending,
            events: Mutex::new(event_rx),
            seq: Mutex::new(0),
            running,
            last_frozen: Mutex::new(Vec::new()),
            released_frozen: Mutex::new(Vec::new()),
            last_stop: Mutex::new(None),
        })
    }

    fn next_seq(&self) -> u32 {
        let mut seq = lock(&self.seq);
        *seq = seq.wrapping_add(1);
        *seq
    }

    pub fn request(&self, cmd: u16, payload: &[u8]) -> Result<(u16, Vec<u8>)> {
        self.request_timeout(cmd, payload, Duration::from_secs(30))
    }

    pub fn request_timeout(&self, cmd: u16, payload: &[u8], timeout: Duration) -> Result<(u16, Vec<u8>)> {
        let seq = self.next_seq();
        let (tx, rx) = mpsc::channel::<Response>();
        lock(&self.pending).insert(seq, tx);

        let mut header = Vec::with_capacity(HEADER_SIZE);
        put_u32(&mut header, MAGIC);
        put_u16(&mut header, cmd);
        put_u16(&mut header, 0);
        put_u32(&mut header, payload.len() as u32);
        put_u32(&mut header, seq);

        // The write happens with no reply registered yet, so a failed send has to
        // unregister the request itself: the reader thread never will, and the
        // map would grow by one dead entry per failed request on a dying link.
        let sent = {
            let mut stream = lock(&self.stream);
            stream
                .write_all(&header)
                .and_then(|_| stream.write_all(payload))
                .and_then(|_| stream.flush())
        };
        if let Err(e) = sent {
            lock(&self.pending).remove(&seq);
            return Err(NxusError { message: format!("send failed: {}", e), result: None });
        }

        match rx.recv_timeout(timeout) {
            Ok(Some((_kind, flags, body))) => {
                if flags & FLAG_ERROR != 0 {
                    return Err(error_from_reply(cmd, &body));
                }
                Ok((cmd, body))
            }
            Ok(None) => Err(NxusError { message: "connection closed".into(), result: None }),
            Err(RecvTimeoutError::Timeout) => {
                lock(&self.pending).remove(&seq);
                Err(NxusError { message: format!("no reply for command 0x{:04X}", cmd), result: None })
            }
            Err(RecvTimeoutError::Disconnected) => {
                Err(NxusError { message: "connection closed".into(), result: None })
            }
        }
    }

    /// Send a short command, retrying it while the console is still releasing
    /// the previous debug session (BUSY + [`REASON_RETRY_LATER`]).
    ///
    /// Only short commands use this: Attach, Detach, Continue, Step and
    /// Pause/Resume.  Scans and pointer scans never do - a scan can run for
    /// minutes, and a pointer scan has its own RESULT_BUSY polling contract
    /// (see [`ptrscan_begin`](Self::ptrscan_begin)).
    fn request_when_released(&self, cmd: u16, payload: &[u8],
                             timeout: Duration) -> Result<(u16, Vec<u8>)> {
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
            *lock(&self.last_stop) = if thread_id != 0 { Some(thread_id) } else { None };
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
            return Err(NxusError { message: "short metadata reply".into(), result: None });
        }
        Ok(Metadata::parse(&body))
    }

    pub fn pause(&self) -> Result<()> {
        self.request_when_released(cmd::PAUSE, &[], Duration::from_secs(30)).map(|_| ())
    }

    pub fn resume(&self) -> Result<()> {
        self.request_when_released(cmd::RESUME, &[], Duration::from_secs(30)).map(|_| ())
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
        self.request_timeout(cmd::HEARTBEAT, &[], timeout).map(|_| ())
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
            return Err(NxusError { message: "short mapping count reply".into(), result: None });
        }
        Ok(rd_u64(&body, 0))
    }

    pub fn mappings(&self, offset: u64, count: u32) -> Result<Vec<MemoryInfo>> {
        let mut payload = Vec::new();
        put_u64(&mut payload, offset);
        put_u32(&mut payload, count);
        put_u32(&mut payload, 0);
        let (_, body) = self.request(cmd::GET_MAPPINGS, &payload)?;
        Ok(body.chunks_exact(MemoryInfo::SIZE).map(MemoryInfo::parse).collect())
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
                break;                                  // would wrap: stop
            };
            let mut payload = Vec::new();
            put_u64(&mut payload, chunk_address);
            put_u32(&mut payload, want);
            put_u32(&mut payload, 0);
            let (_, body) = self.request(cmd::READ, &payload)?;
            if body.is_empty() {
                break;                                  // nothing readable here
            }
            offset += body.len() as u64;
            got.extend_from_slice(&body);
            if body.len() < want as usize {
                // The console halves a read dmnt refuses, so a short reply means
                // "not that much at once", not "end of region": ask for the rest
                // in smaller pieces instead of handing back partial data.
                let smaller = (body.len() as u32).max(MIN_READ);
                if smaller >= want {
                    break;                              // no smaller step possible
                }
                want_cap = smaller;
            }
        }
        Ok(got)
    }

    pub fn read_u32(&self, address: u64) -> Result<u32> {
        let data = self.read(address, 4)?;
        if data.len() < 4 {
            return Err(NxusError { message: "short read reply".into(), result: None });
        }
        Ok(rd_u32(&data, 0))
    }

    pub fn write(&self, address: u64, data: &[u8]) -> Result<()> {
        let mut payload = Vec::new();
        put_u64(&mut payload, address);
        put_u32(&mut payload, data.len() as u32);
        put_u32(&mut payload, 0);
        payload.extend_from_slice(data);
        self.request(cmd::WRITE, &payload).map(|_| ())
    }

    pub fn modules(&self) -> Result<Vec<ModuleInfo>> {
        let (_, body) = self.request(cmd::GET_MODULES, &[])?;
        Ok(body.chunks_exact(ModuleInfo::SIZE).map(ModuleInfo::parse).collect())
    }

    // ---- scanning ----

    pub fn scan_begin(&self, value: u64, value_size: u32, compare: Compare, scope: Scope,
                      range_begin: u64, range_end: u64) -> Result<Status> {
        let spec = ScanSpec {
            value, target2: 0, value_size, value_type: ValueType::U32, compare, scope,
            range_begin, range_end, ranges: Vec::new(), flags: 0, pattern: Vec::new(),
            mask: Vec::new(), epsilon_decimals: 0,
        };
        self.scan_begin_spec(&spec)
    }

    pub fn scan_next(&self, value: u64, compare: Compare) -> Result<Status> {
        let spec = ScanSpec {
            value, target2: 0, value_size: 4, value_type: ValueType::U32, compare, scope: Scope::All,
            range_begin: 0, range_end: 0, ranges: Vec::new(), flags: 0, pattern: Vec::new(),
            mask: Vec::new(), epsilon_decimals: 0,
        };
        self.scan_next_spec(&spec)
    }

    /// Full Cheat-Engine-style scan: value type, pattern (string / byte array),
    /// wildcards, range compare and alignment all go through here.
    pub fn scan_begin_spec(&self, spec: &ScanSpec) -> Result<Status> {
        let payload = buildScanPayload(spec, 0);
        let (_, body) = self.request_timeout(cmd::SCAN_BEGIN, &payload, Duration::from_secs(600))?;
        if body.len() < Status::SIZE {
            return Err(NxusError { message: "short status reply".into(), result: None });
        }
        Ok(Status::parse(&body))
    }

    pub fn scan_next_spec(&self, spec: &ScanSpec) -> Result<Status> {
        let payload = buildScanPayload(spec, 1);
        let (_, body) = self.request_timeout(cmd::SCAN_NEXT, &payload, Duration::from_secs(600))?;
        if body.len() < Status::SIZE {
            return Err(NxusError { message: "short status reply".into(), result: None });
        }
        Ok(Status::parse(&body))
    }

    pub fn scan_status(&self) -> Result<Status> {
        let (_, body) = self.request(cmd::SCAN_STATUS, &[])?;
        // A truncated reply would otherwise decode as scan_state 0 (idle) and
        // make `scan_wait` spin until its own timeout instead of reporting
        // "the console sent something broken".
        if body.len() < Status::SIZE {
            return Err(NxusError { message: "short status reply".into(), result: None });
        }
        Ok(Status::parse(&body))
    }

    /// Like scan_wait(), but stops early when the UI asks to cancel: the worker
    /// thread is single threaded, so the cancel button can only be honoured from
    /// inside the wait itself.
    pub fn scan_wait_cancellable(&self, timeout: Duration,
                                 cancel: &std::sync::atomic::AtomicBool) -> Result<Status> {
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
    pub fn scan_wait_cancellable_reporting<F>(&self, timeout: Duration,
                                              cancel: &std::sync::atomic::AtomicBool,
                                              mut report: F) -> Result<Status>
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
            let seen = (status.scan_state, status.hit_count, status.progress_permille);
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
                return Err(NxusError { message: "scan did not finish".into(), result: None });
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
                return Err(NxusError { message: "scan did not finish".into(), result: None });
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
            return Err(NxusError { message: "short hit batch".into(), result: None });
        }
        Ok(HitBatch::parse(&body))
    }

    /// Upper bound on the pre-allocation [`NxusClient::scan_all_hits`] derives from
    /// the total the console reports in its first reply.
    ///
    /// 8 M entries is the console's own `max_hits` ceiling and the PC scanner's
    /// `DEFAULT_MAX_HITS`, so a corrupt or hostile `total` can never turn into an
    /// arbitrarily large `Vec::with_capacity`.
    pub const MAX_ALL_HITS: usize = crate::pcscan::DEFAULT_MAX_HITS;

    /// True when the last `scan_all_hits()` reply reported a full hit list on the
    /// console, i.e. the returned set may be missing matches.
    pub fn last_scan_truncated(&self) -> bool {
        self.truncated.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn set_last_scan_truncated(&self, value: bool) {
        self.truncated.store(value, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn scan_all_hits(&self, page: u32) -> Result<Vec<Hit>> {
        // Collected hits are only ever appended, so every growth step used to
        // copy everything gathered so far (thousands of pages -> ~15 reallocs and
        // tens of millions of copied `Hit`s for a big scan).  The first reply
        // already carries the final count, so size the vector once from it.
        let mut all: Vec<Hit> = Vec::new();
        let mut sized = false;
        let mut truncated = false;
        loop {
            let batch = self.scan_hits(all.len() as u32, page)?;
            if !sized {
                sized = true;
                let want = (batch.total as usize).min(Self::MAX_ALL_HITS);
                if want > all.capacity() {
                    all.reserve_exact(want - all.capacity());
                }
            }
            // The console flags "my hit list filled up" on the batch, so a cut-off
            // result is not mistaken for the complete set.
            truncated |= batch.truncated;
            if batch.hits.is_empty() {
                self.set_last_scan_truncated(truncated);
                return Ok(all);
            }
            let done = all.len() + batch.hits.len() >= batch.total as usize;
            all.extend(batch.hits);
            if done {
                self.set_last_scan_truncated(truncated);
                return Ok(all);
            }
        }
    }

    pub fn scan_reset(&self) -> Result<()> {
        self.request(cmd::SCAN_RESET, &[]).map(|_| ())
    }

    pub fn scan_undo(&self) -> Result<Status> {
        let (_, body) = self.request(cmd::SCAN_UNDO, &[])?;
        if body.len() < Status::SIZE {
            return Err(NxusError { message: "short status reply".into(), result: None });
        }
        Ok(Status::parse(&body))
    }

    // ---- snapshots ----

    pub fn snapshot_capture(&self, slot: u32, scope: Scope, block_size: u32) -> Result<SnapshotSummary> {
        let mut payload = Vec::new();
        put_u32(&mut payload, slot);
        put_u32(&mut payload, block_size);
        put_u32(&mut payload, scope as u32);
        put_u32(&mut payload, 0);
        put_u64(&mut payload, 0);
        put_u64(&mut payload, 0);
        let (_, body) = self.request_timeout(cmd::SNAPSHOT_CAPTURE, &payload, Duration::from_secs(300))?;
        Ok(SnapshotSummary::parse(&body))
    }

    pub fn snapshot_diff(&self, from_slot: u32, to_slot: u32) -> Result<SnapshotSummary> {
        let mut payload = Vec::new();
        put_u32(&mut payload, from_slot);
        put_u32(&mut payload, to_slot);
        put_u32(&mut payload, 0);
        put_u32(&mut payload, 0);
        let (_, body) = self.request_timeout(cmd::SNAPSHOT_DIFF, &payload, Duration::from_secs(300))?;
        Ok(SnapshotSummary::parse(&body))
    }

    pub fn snapshot_changed(&self, offset: u32, count: u32) -> Result<Vec<ChangedBlock>> {
        let mut payload = Vec::new();
        put_u32(&mut payload, offset);
        put_u32(&mut payload, count);
        put_u32(&mut payload, 0);
        put_u32(&mut payload, 0);
        let (_, body) = self.request(cmd::SNAPSHOT_CHANGED, &payload)?;
        Ok(body.chunks_exact(ChangedBlock::SIZE).map(ChangedBlock::parse).collect())
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

    pub fn ptrscan_begin(&self, target: u64, module_base: u64, max_depth: u32,
                         max_offset: u32, max_results: u32, value_width: u32)
                         -> Result<(Vec<PtrChain>, bool)> {
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

    pub fn cheat_export(&self, index: u32, value: u64, value_width: u32, is_32bit: bool) -> Result<String> {
        let mut payload = Vec::new();
        put_u32(&mut payload, index);
        put_u32(&mut payload, value_width);
        put_u32(&mut payload, if is_32bit { CHEAT_F_32BIT } else { 0 });
        put_u32(&mut payload, 0);
        put_u64(&mut payload, value);
        let (_, body) = self.request(cmd::CHEAT_EXPORT, &payload)?;
        Ok(String::from_utf8_lossy(&body).to_string())
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
            return Err(NxusError { message: "short frozen handle reply".into(), result: None });
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
        let (_, body) = self.request_when_released(cmd::DEBUG_ATTACH, &payload,
                                                   Duration::from_secs(60))?;
        Ok(DebugStatus::parse(&body))
    }

    pub fn debug_detach(&self) -> Result<()> {
        *lock(&self.last_stop) = None;
        self.request_when_released(cmd::DEBUG_DETACH, &[], Duration::from_secs(60)).map(|_| ())
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
        debug_assert_eq!(payload.len(), DEBUG_CONFIG_LEN, "NxusDebugConfig is 16 bytes");
        self.request(cmd::CONFIG, &payload).map(|_| ())
    }

    pub fn break_set(&self, address: u64, kind: u32, size: u32, slot: u32, ctrl: u64) -> Result<Vec<BreakEntry>> {
        let mut payload = Vec::new();
        put_u32(&mut payload, slot);
        put_u32(&mut payload, kind);
        put_u32(&mut payload, size);
        put_u32(&mut payload, 0);
        put_u64(&mut payload, address);
        let _ = ctrl;
        let (_, body) = self.request_timeout(cmd::BREAK_SET, &payload, Duration::from_secs(60))?;
        Ok(body.chunks_exact(BreakEntry::SIZE).map(BreakEntry::parse).collect())
    }

    pub fn break_clear(&self, slot: u32) -> Result<()> {
        let mut payload = Vec::new();
        put_u32(&mut payload, slot);
        self.request(cmd::BREAK_CLEAR, &payload).map(|_| ())
    }

    pub fn break_list(&self) -> Result<Vec<BreakEntry>> {
        let (_, body) = self.request(cmd::BREAK_LIST, &[])?;
        Ok(body.chunks_exact(BreakEntry::SIZE).map(BreakEntry::parse).collect())
    }

    pub fn thread_list(&self) -> Result<Vec<ThreadEntry>> {
        let (_, body) = self.request(cmd::THREAD_LIST, &[])?;
        Ok(body.chunks_exact(ThreadEntry::SIZE).map(ThreadEntry::parse).collect())
    }

    pub fn regs_get(&self, thread_id: u64) -> Result<ThreadContext> {
        let mut payload = Vec::new();
        put_u64(&mut payload, thread_id);
        let (_, body) = self.request(cmd::REGS_GET, &payload)?;
        // 96 bytes is the minimum that fills the whole `r` array (the ARM32 half
        // of the legacy 100-byte layout); `ThreadContext::parse` zero-fills the
        // rest, so anything shorter would silently show made-up registers.
        if body.len() < 96 {
            return Err(NxusError { message: "short thread context reply".into(), result: None });
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
        Ok(body.chunks_exact(BreakHit::SIZE).map(BreakHit::parse).collect())
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
    pub fn set_config(&self, hotkey_mask: u64, hotkey_hold_ms: u32, hotkey_enabled: u32,
                      chunk_size: u32, watchdog_ms: u32, heartbeat_ms: u32, log_level: u32,
                      debug: Option<(u32, u32)>) -> Result<Vec<u8>> {
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
        chains.push(PtrChain { root_offset, final_offset, steps });
    }
    (chains, truncated)
}

fn reader_loop(mut stream: TcpStream, pending: Arc<Mutex<HashMap<u32, Sender<Response>>>>,
               events: Sender<Event>, running: Arc<std::sync::atomic::AtomicBool>) {
    let mut header = [0u8; HEADER_SIZE];
    loop {
        if !running.load(Ordering::SeqCst) {
            break;
        }
        if !read_exact(&mut stream, &mut header) {
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
        if length > 0 && !read_exact(&mut stream, &mut payload) {
            break;
        }

        if flags & FLAG_ASYNC != 0 || kind >= 0x8000 {
            let _ = events.send(Event { kind, payload });
        } else {
            let sender = lock(&pending).remove(&seq);
            if let Some(tx) = sender {
                let _ = tx.send(Some((kind, flags, payload)));
            }
        }
    }
    // Wake anyone still waiting.
    let mut map = lock(&pending);
    for (_, tx) in map.drain() {
        let _ = tx.send(None);
    }
}

fn read_exact(stream: &mut TcpStream, buffer: &mut [u8]) -> bool {
    let mut got = 0;
    while got < buffer.len() {
        match stream.read(&mut buffer[got..]) {
            Ok(0) => return false,
            Ok(n) => got += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{error_from_reply, error_reason_text, is_retry_later, pointer_width_for,
                released_addresses, select_stopped_thread, Mapping, Metadata, NxusError,
                PERM_R, RESULT_BUSY};
    use crate::protocol::{put_u32, DebugStatus};

    fn error_body(rc: u32, reason: Option<u32>) -> Vec<u8> {
        let mut body = Vec::new();
        put_u32(&mut body, rc);
        if let Some(reason) = reason {
            put_u32(&mut body, reason);
        }
        body
    }

    fn mapping(base: u64, size: u64, perm: u32) -> Mapping {
        Mapping { base, size, memory_type: 5, attr: 0, perm }
    }

    fn metadata(main_base: u64) -> Metadata {
        Metadata { main_base, ..Default::default() }
    }

    /// The mapping table decides: any traversable mapping ending above 4 GiB
    /// means 8-byte pointers, an end at or below it does not.
    #[test]
    fn pointer_width_follows_the_console_auto_rule() {
        let low = 0x0070_0000u64;              // MockSwitch's main module base
        // A 32-bit title: every mapping ends below 4 GiB.
        assert_eq!(pointer_width_for(&metadata(low), Some(&[mapping(0x0070_0000, 0x80000, PERM_R),
                                                            mapping(0x42CA_0000, 0x3000, PERM_R)])), 4);
        // A 64-bit title whose main module ASLR'd below 4 GiB: the high mapping
        // is the evidence that the address space is wide.
        assert_eq!(pointer_width_for(&metadata(low), Some(&[mapping(low, 0x80000, PERM_R),
                                                            mapping(0x7F_0000_0000, 0x1000, PERM_R)])), 8);
        // An end exactly at 4 GiB still addresses only 32-bit-reachable bytes.
        assert_eq!(pointer_width_for(&metadata(low),
                                     Some(&[mapping(0xFFFF_F000, 0x1000, PERM_R)])), 4);
        // A mapping that wraps past the top is 64-bit evidence, not a small end.
        assert_eq!(pointer_width_for(&metadata(low),
                                     Some(&[mapping(u64::MAX - 0xFFF, 0x2000, PERM_R)])), 8);
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
        let unusable = [mapping(0x7F_0000_0000, 0x1000, 0), mapping(0x0070_0000, 0, PERM_R)];
        assert_eq!(pointer_width_for(&metadata(0x0070_0000), Some(&unusable)), 4,
                   "unreadable / empty mappings fall back to the main base");
        assert_eq!(pointer_width_for(&metadata(0), Some(&unusable)), 8);
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
        assert_eq!(error_reason_text(0), None, "0 means 'no detail', never sent");
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
            message: "command 0x0013 failed - busy: a scan or pause/resume is in progress (reason=4)".into(),
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
        DebugStatus { stopped_thread_low: low, stopped_thread: full, ..Default::default() }
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
        assert_eq!(select_stopped_thread(&status, Some(0x1_0000_1F00)),
                   Some(0x2A3B), "the truncated half beats the wrong thread");
        // A new-firmware status names the real thread even with a stale event.
        let status = stopped(0x2A3B, 0x1_0000_2A3B);
        assert_eq!(select_stopped_thread(&status, Some(0x1_0000_1F00)),
                   Some(0x1_0000_2A3B));
    }

    #[test]
    fn the_appended_status_field_works_without_any_event() {
        let full = 0x1_0000_2A3Bu64;
        assert_eq!(select_stopped_thread(&stopped(full as u32, full), None), Some(full));
    }

    #[test]
    fn a_running_target_is_none_even_with_a_cached_event() {
        assert_eq!(select_stopped_thread(&stopped(0, 0), Some(0x1001)), None);
    }

    #[test]
    fn without_the_new_field_the_truncated_half_is_the_last_resort() {
        // Old console whose event was never polled: still the legacy behaviour.
        assert_eq!(select_stopped_thread(&stopped(0x1001, 0), None), Some(0x1001));
    }
}
