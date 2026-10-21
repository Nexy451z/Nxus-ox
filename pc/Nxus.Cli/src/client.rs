//! Nxus TCP client: seq-correlated requests plus an asynchronous event queue.
//!
//! Works against the real sysmodule and against pc/nxus/mock_switch.py, so the
//! whole protocol can be exercised without a console.

use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::protocol::*;

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

pub struct NxusClient {
    max_read: std::sync::atomic::AtomicU32,
    stream: Mutex<TcpStream>,
    pending: Arc<Mutex<HashMap<u32, Sender<Response>>>>,
    events: Mutex<Receiver<Event>>,
    seq: Mutex<u32>,
    running: Arc<Mutex<bool>>,
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

impl NxusClient {
    pub fn connect(host: &str, port: u16) -> Result<NxusClient> {
        let stream = TcpStream::connect((host, port))
            .map_err(|e| NxusError {
                message: format!("cannot connect to {}:{} - {}. Is the console running Nxus                                   and is this the console's IP?", host, port, net_error_text(&e)),
                result: None,
            })?;
        stream.set_nodelay(true).ok();
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .map_err(|e| NxusError { message: e.to_string(), result: None })?;
        let reader_stream = stream
            .try_clone()
            .map_err(|e| NxusError { message: e.to_string(), result: None })?;

        let pending: Arc<Mutex<HashMap<u32, Sender<Response>>>> = Arc::new(Mutex::new(HashMap::new()));
        let running = Arc::new(Mutex::new(true));
        let (event_tx, event_rx) = mpsc::channel::<Event>();

        {
            let pending = Arc::clone(&pending);
            let running = Arc::clone(&running);
            thread::spawn(move || reader_loop(reader_stream, pending, event_tx, running));
        }

        Ok(NxusClient {
            max_read: std::sync::atomic::AtomicU32::new(DEFAULT_MAX_READ),
            stream: Mutex::new(stream),
            pending,
            events: Mutex::new(event_rx),
            seq: Mutex::new(0),
            running,
        })
    }

    fn next_seq(&self) -> u32 {
        let mut seq = self.seq.lock().unwrap();
        *seq = seq.wrapping_add(1);
        *seq
    }

    pub fn request(&self, cmd: u16, payload: &[u8]) -> Result<(u16, Vec<u8>)> {
        self.request_timeout(cmd, payload, Duration::from_secs(30))
    }

    pub fn request_timeout(&self, cmd: u16, payload: &[u8], timeout: Duration) -> Result<(u16, Vec<u8>)> {
        let seq = self.next_seq();
        let (tx, rx) = mpsc::channel::<Response>();
        self.pending.lock().unwrap().insert(seq, tx);

        let mut header = Vec::with_capacity(HEADER_SIZE);
        put_u32(&mut header, MAGIC);
        put_u16(&mut header, cmd);
        put_u16(&mut header, 0);
        put_u32(&mut header, payload.len() as u32);
        put_u32(&mut header, seq);

        {
            let mut stream = self.stream.lock().unwrap();
            stream
                .write_all(&header)
                .and_then(|_| stream.write_all(payload))
                .map_err(|e| NxusError { message: format!("send failed: {}", e), result: None })?;
        }

        match rx.recv_timeout(timeout) {
            Ok(Some((_kind, flags, body))) => {
                if flags & FLAG_ERROR != 0 {
                    let rc = if body.len() >= 4 { rd_u32(&body, 0) } else { 0 };
                    return Err(NxusError { message: format!("command 0x{:04X} failed", cmd), result: Some(rc) });
                }
                Ok((cmd, body))
            }
            Ok(None) => Err(NxusError { message: "connection closed".into(), result: None }),
            Err(RecvTimeoutError::Timeout) => {
                self.pending.lock().unwrap().remove(&seq);
                Err(NxusError { message: format!("no reply for command 0x{:04X}", cmd), result: None })
            }
            Err(RecvTimeoutError::Disconnected) => {
                Err(NxusError { message: "connection closed".into(), result: None })
            }
        }
    }

    /// Wait for the next asynchronous event (Switch-initiated).
    pub fn poll_event(&self, timeout: Duration) -> Option<Event> {
        self.events.lock().unwrap().recv_timeout(timeout).ok()
    }

    // ---- session ----

    pub fn status(&self) -> Result<Status> {
        let (_, body) = self.request(cmd::GET_STATUS, &[])?;
        let status = Status::parse(&body);
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
        self.request(cmd::PAUSE, &[]).map(|_| ())
    }

    pub fn resume(&self) -> Result<()> {
        self.request(cmd::RESUME, &[]).map(|_| ())
    }

    pub fn heartbeat(&self) -> Result<()> {
        self.request(cmd::HEARTBEAT, &[]).map(|_| ())
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
        Ok(Status::parse(&body))
    }

    pub fn scan_next_spec(&self, spec: &ScanSpec) -> Result<Status> {
        let payload = buildScanPayload(spec, 1);
        let (_, body) = self.request_timeout(cmd::SCAN_NEXT, &payload, Duration::from_secs(600))?;
        Ok(Status::parse(&body))
    }

    pub fn scan_status(&self) -> Result<Status> {
        let (_, body) = self.request(cmd::SCAN_STATUS, &[])?;
        Ok(Status::parse(&body))
    }

    /// Like scan_wait(), but stops early when the UI asks to cancel: the worker
    /// thread is single threaded, so the cancel button can only be honoured from
    /// inside the wait itself.
    pub fn scan_wait_cancellable(&self, timeout: Duration,
                                 cancel: &std::sync::atomic::AtomicBool) -> Result<Status> {
        let start = Instant::now();
        let mut last_heartbeat = Instant::now();
        loop {
            if cancel.load(Ordering::Relaxed) {
                cancel.store(false, Ordering::Relaxed);
                let _ = self.request(cmd::SCAN_CANCEL, &[]);
                let _ = self.heartbeat();
                return self.scan_status();
            }
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
        if body.len() < 24 {
            return Err(NxusError { message: "short hit batch".into(), result: None });
        }
        let session_id = rd_u32(&body, 0);
        let n = rd_u32(&body, 4) as usize;
        let total = rd_u32(&body, 8);
        let value_size = rd_u32(&body, 12);
        let mapping_count = rd_u32(&body, 16) as usize;
        let mut pos = 24;
        let mut bases = Vec::with_capacity(mapping_count);
        for _ in 0..mapping_count {
            bases.push(rd_u64(&body, pos));
            pos += 8;
        }
        let mut hits = Vec::with_capacity(n);
        for _ in 0..n {
            if pos + 16 > body.len() {
                break;
            }
            let off = rd_u32(&body, pos);
            let map_idx = rd_u16(&body, pos + 4);
            let value_type = rd_u16(&body, pos + 6);
            let value = rd_u64(&body, pos + 8);
            pos += 16;
            let base = bases.get(map_idx as usize).copied().unwrap_or(0);
            hits.push(Hit { address: base + off as u64, mapping_idx: map_idx, value_type, value });
        }
        Ok(HitBatch { session_id, total, value_size, hits })
    }

    pub fn scan_all_hits(&self, page: u32) -> Result<Vec<Hit>> {
        let mut all = Vec::new();
        loop {
            let batch = self.scan_hits(all.len() as u32, page)?;
            if batch.hits.is_empty() {
                return Ok(all);
            }
            let done = all.len() + batch.hits.len() >= batch.total as usize;
            all.extend(batch.hits);
            if done {
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
        let (_, body) = self.request_timeout(cmd::PTRSCAN_BEGIN, &payload, Duration::from_secs(120))?;
        Ok(parse_chains(&body))
    }

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

    pub fn frozen_enable(&self, address: u64, width: u32) -> Result<u64> {
        let mut payload = Vec::new();
        put_u64(&mut payload, address);
        put_u32(&mut payload, width);
        put_u32(&mut payload, 0);
        let (_, body) = self.request(cmd::FROZEN_ENABLE, &payload)?;
        Ok(rd_u64(&body, 0))
    }

    pub fn frozen_disable(&self, address: u64) -> Result<()> {
        let mut payload = Vec::new();
        put_u64(&mut payload, address);
        self.request(cmd::FROZEN_DISABLE, &payload).map(|_| ())
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
        let (_, body) = self.request_timeout(cmd::DEBUG_ATTACH, &payload, Duration::from_secs(60))?;
        Ok(DebugStatus::parse(&body))
    }

    pub fn debug_detach(&self) -> Result<()> {
        self.request_timeout(cmd::DEBUG_DETACH, &[], Duration::from_secs(60)).map(|_| ())
    }

    pub fn debug_status(&self) -> Result<DebugStatus> {
        let (_, body) = self.request(cmd::DEBUG_STATUS, &[])?;
        Ok(DebugStatus::parse(&body))
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

impl Drop for NxusClient {
    fn drop(&mut self) {
        if let Ok(mut running) = self.running.lock() {
            *running = false;
        }
    }
}

/// Returns the chains and whether the console hit its own cap (the header's
/// truncated flag: count == 64 is NOT the same thing).
fn parse_chains(body: &[u8]) -> (Vec<PtrChain>, bool) {
    if body.len() < 16 {
        return (Vec::new(), false);
    }
    let count = rd_u32(body, 0) as usize;
    let truncated = rd_u32(body, 8) != 0;
    let mut chains = Vec::with_capacity(count);
    let mut pos = 16;
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
               events: Sender<Event>, running: Arc<Mutex<bool>>) {
    let mut header = [0u8; HEADER_SIZE];
    loop {
        if !*running.lock().unwrap() {
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

        let mut payload = vec![0u8; length as usize];
        if length > 0 && !read_exact(&mut stream, &mut payload) {
            break;
        }

        if flags & FLAG_ASYNC != 0 || kind >= 0x8000 {
            let _ = events.send(Event { kind, payload });
        } else {
            let sender = pending.lock().unwrap().remove(&seq);
            if let Some(tx) = sender {
                let _ = tx.send(Some((kind, flags, payload)));
            }
        }
    }
    // Wake anyone still waiting.
    let mut map = pending.lock().unwrap();
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
