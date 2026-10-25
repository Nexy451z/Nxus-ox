//! Nxus GUI (egui/eframe).
//!
//! Usability first: a real hex editor, sortable results, pointer-chain and
//! watchpoint tooling, and settings that persist between runs.  All network work
//! happens on a worker thread, so the UI never blocks.

pub mod hexview;
pub mod panels;

use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui;
use serde::{Deserialize, Serialize};

use crate::client::NxusClient;
use crate::protocol::{self as P, break_kind, event, scan_state, BreakHit, ChangedBlock, Compare,
                      Hit, Metadata, ModuleInfo, PtrChain, Scope, Status, ValueType};

// ---------------------------------------------------------------- worker

#[derive(Clone, Debug)]
pub enum Cmd {
    Connect { host: String, port: u16 },
    Disconnect,
    Refresh,
    FetchModules,
    /// The target's memory map: shown as a list so a scan range can be picked from
    /// the real regions (what "nxus mappings" prints on the CLI).
    FetchMappings,
    /// Pull the console's own log (SD log tail): it carries the scan statistics
    /// (dropped regions, retried reads) that the status reply has no room for.
    FetchConsoleLog,
    ScanBegin { spec: crate::client::ScanSpec },
    ScanNext { spec: crate::client::ScanSpec },
    /// PC-side scans: the console only serves memory reads, the candidate list
    /// lives in the PC's memory (see pcscan.rs).
    PcScanUnknown { value_size: u32, scope: u32, begin: u64, end: u64, max_hits: usize },
    PcScanRefine { compare: u32, target: u64, target2: u64, flags: u32 },
    PcScanCancel,
    ScanCancel,
    ScanReset,
    ScanUndo,
    FetchHits,
    Read { address: u64, size: u32 },
    /// Raw bytes for the Disasm tab.  Decoding stays on the UI thread (it needs the
    /// user's arch choice), so the worker only fetches memory.
    ReadDisasm { address: u64, size: u32 },
    /// Resolve the running thread's PC, fetch its whole context and the code around
    /// the PC in one round trip ("At Current PC (Regs)").
    FetchCurrentPcAndDisasm { size: u32 },
    Write { address: u64, data: Vec<u8> },
    Freeze { address: u64, width: u32 },
    Unfreeze { address: u64 },
    RefreshWatchlist { entries: Vec<(u64, u32)> },
    PtrScan { target: u64, module_base: u64, depth: u32, max_offset: u32 },
    PtrScanPc { target: u64, module_base: u64, depth: u32, max_offset: u32, dump_path: Option<String> },
    SaveDump { path: String, scope: u32, begin: u64, end: u64 },
    Cheat { index: u32, value: u64 },
    Attach,
    Detach,
    BreakSet { address: u64, kind: u32, size: u32 },
    BreakClear { slot: u32 },
    HitGet,
    HitClear,
    SnapshotCapture { slot: u32, scope: u32 },
    SnapshotDiff { from: u32, to: u32 },
    /// The Settings window's "Apply": the FULL config request (hotkey, watchdog,
    /// chunk, watch style) plus the current stop-on-hit policy, because the
    /// console rewrites every field from it and a stale auto_continue would thaw
    /// a target the user expects to be held.
    Config { mask: u64, hold: u32, enabled: u32, watchdog: u32, style: u32,
             auto_continue: u32 },
    Pause,
    Resume,
    /// Push ONLY the debug block before arming (a 16-byte `NxusDebugConfig`):
    /// `auto_continue = 0` means "hold the target at the hit" (GDB style), `1`
    /// means "record the hit and resume".  The console treats that length as
    /// "debug settings only", so the hotkey/watchdog block applied from Settings
    /// is NOT rewritten (sending the full request used to zero it).
    DebugConfigure { auto_continue: u32, style: u32 },
    /// Resume the threads the console parked at a breakpoint
    /// (NxusCmd_DebugContinue -> svcContinueDebugEvent).
    DebugContinue,
    /// Single-step a held thread.  `thread_id == 0` steps the thread the console
    /// stopped; the step keeps the stop published, only the PC moves.
    DebugStep { thread_id: u64 },
    /// Fetch the context of the thread a stop event named, plus the code around
    /// its PC.  `FetchCurrentPcAndDisasm` picks "the first thread", which is the
    /// wrong one as soon as a breakpoint parked a worker thread.
    FetchThreadPcAndDisasm { thread_id: u64, pc: u64, size: u32 },
}

#[derive(Clone, Debug)]
pub enum Ev {
    ConsoleLog(String),
    /// The console confirmed a breakpoint (only then may the UI say "armed").
    WatchArmed { address: u64, kind: u32, slot: u32 },
    Connected { status: Status, metadata: Option<Metadata> },
    Disconnected,
    Status(Status),
    Metadata(Metadata),
    Modules(Vec<ModuleInfo>),
    Mappings(Vec<crate::protocol::MemoryInfo>),
    Hits { hits: Vec<Hit>, value_size: u32, message: String },
    Read { address: u64, data: Vec<u8> },
    /// Bytes for the disassembler; `address` is where `data` starts.
    DisasmData { address: u64, data: Vec<u8> },
    /// Thread context plus the code around its PC.
    RegsAndDisasm { ctx: P::ThreadContext, address: u64, data: Vec<u8> },
    Wrote { address: u64, data: Vec<u8> },
    Frozen { address: u64, value: u64 },
    Unfrozen { address: u64 },
    WatchlistValues(Vec<(u64, u64)>),
    Chains(Vec<PtrChain>, bool),          // chains, truncated-by-console
    Cheat(String),
    BreakHits(Vec<BreakHit>),
    /// The target is parked at a breakpoint/watchpoint (NxusEvent_DebugStopped).
    /// The UI turns this into the stop banner, a register fetch and the
    /// disassembly around the PC.
    DebugStopped { thread_id: u64, pc: u64, address: u64, kind: u32, slot: u32 },
    /// The debug session itself changed (Attach / Detach answered).  Everything
    /// the UI knows about a parked thread belongs to the session that reported
    /// it, so the banner and the cached register/code views are dropped; the
    /// status reply sent just before this event decides whether anything is held.
    DebugSession { attached: bool },
    Snapshot { summary: P::SnapshotSummary, changed: Vec<ChangedBlock> },
    Async { kind: u16, payload: Vec<u8> },
    Progress { done: u64, total: u64, label: String },
    PcHits { hits: Vec<(u64, u64)>, value_size: u32, message: String, truncated: bool },
    Message(String),
    Error(String),
}

/// The console logs how many hits it kept and how many regions it could NOT read.
/// A refine that drops candidates because a mapping was invalidated otherwise looks
/// exactly like "the value changed", so show that line with the result.
fn console_scan_stats(c: &NxusClient) -> String {
    c.log().ok()
        .and_then(|log| {
            log.lines().rev().find(|l| l.contains("scan done")).map(|l| l.trim().to_string())
        })
        .map(|l| format!("  [{}]", l))
        .unwrap_or_default()
}

/// Idle keep-alive period.  The console's watchdog resumes a paused target when
/// it hears nothing for its own timeout, so even an idle PC has to keep talking.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(4);
/// Deadline for one keep-alive.  Deliberately short: a Switch that went to sleep
/// (or a Wi-Fi link that dropped) must be noticed in seconds instead of after the
/// 30 s a normal request would wait for its reply.
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(8);
/// How often a disconnected-but-wanted session is retried in the background.
const RECONNECT_INTERVAL: Duration = Duration::from_secs(5);

/// Bytes fetched when the disassembler opens itself on a stop: 32 AArch64
/// instructions, or the same byte count of ARM/Thumb ones.
pub const DISASM_PAGE: u32 = 128;

/// kind/slot the console reports for a stop it created itself (`svcBreakDebugProcess`,
/// i.e. the Pause button), as opposed to a hardware breakpoint hit.  Those are a
/// "the target is held" state, not a watchpoint hit, so they get no stop banner.
const NO_BREAK_SLOT: u32 = 0xFFFF_FFFF;

/// True when a DebugStopped describes a stop the console made for itself
/// (`svcBreakDebugProcess`: the Pause button, the scan pause) rather than a
/// hardware breakpoint hit.  Decided on `kind` only: a real hit whose hardware
/// slot could not be paired up also reports 0xFFFFFFFF in `slot`.
pub fn is_manual_stop(kind: u32) -> bool {
    kind == NO_BREAK_SLOT
}

/// NxusDebugConfig.auto_continue for the "stop on hit" preference: 0 holds the
/// target at the hit (GDB style), 1 records the hit and resumes the game.
pub fn auto_continue_for(stop_on_hit: bool) -> u32 {
    if stop_on_hit { 0 } else { 1 }
}

/// Forward whatever the console pushed while the worker was blocked.  A scan can
/// run for minutes and the event loop only polls between commands, so without
/// this a DebugStopped would be delivered AFTER the scan result and re-open the
/// banner for a stop that the follow-up Resume already undid.
fn drain_events(c: &NxusClient, tx: &Sender<Ev>) {
    while let Some(ev) = c.poll_event(Duration::from_millis(0)) {
        if ev.kind == event::DEBUG_STOPPED && ev.payload.len() >= P::DebugStop::SIZE {
            let stop = P::DebugStop::parse(&ev.payload);
            let _ = tx.send(Ev::DebugStopped {
                thread_id: stop.thread_id, pc: stop.pc, address: stop.address,
                kind: stop.kind, slot: stop.slot,
            });
            continue;
        }
        let _ = tx.send(Ev::Async { kind: ev.kind, payload: ev.payload });
    }
}

/// Re-read the status after a pause/resume/step so the UI stops guessing: the
/// stopped bit (and the held-thread field) are the console's own answer.
fn push_status(c: &NxusClient, tx: &Sender<Ev>) {
    if let Ok(status) = c.status() {
        let _ = tx.send(Ev::Status(status));
    }
}

/// One silent reconnect attempt: connect, prove the session works with a status
/// request, and hand both back.  On failure the half-open socket is dropped (the
/// `Drop` impl sends the FIN), so no stale session is left on the console.
fn try_reconnect(host: &str, port: u16) -> Option<(NxusClient, Status)> {
    let c = NxusClient::connect(host, port).ok()?;
    match c.status() {
        Ok(st) => Some((c, st)),
        Err(_) => None,
    }
}

fn worker(rx: Receiver<Cmd>, tx: Sender<Ev>, cancel: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let mut client: Option<NxusClient> = None;
    let mut pc_scan: Option<crate::pcscan::PcScan> = None;
    let mut prev_pc_scan: Option<crate::pcscan::PcScan> = None;

    // Where to go back to, and whether a session is still wanted.  A manual
    // Disconnect clears `want_connected`, so the worker never reconnects behind
    // the user's back; pressing Connect again re-arms it.
    let mut last_host: Option<String> = None;
    let mut last_port: u16 = P::DEFAULT_PORT;
    let mut want_connected = false;
    // What the UI currently believes.  Only real transitions are reported, so a
    // console that stays away does not fill the log with "disconnected" lines.
    let mut ui_connected = false;

    let mut last_heartbeat = Instant::now();
    let mut last_reconnect = Instant::now();

    loop {
        let cmd = match rx.recv_timeout(Duration::from_millis(25)) {
            Ok(cmd) => Some(cmd),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };

        // The console resumes a paused target if it hears nothing for the
        // watchdog timeout, so an idle PC (user staring at the hex editor) must
        // keep saying it is alive.  A failed keep-alive means the link is gone
        // (Switch asleep, Wi-Fi dropped, cable pulled): drop the socket, try once
        // to rebuild the session, and tell the UI what happened.
        let heartbeat_failed = match client.as_ref() {
            Some(c) if last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL => {
                last_heartbeat = Instant::now();
                c.heartbeat_timeout(HEARTBEAT_TIMEOUT).is_err()
            }
            _ => false,
        };
        if heartbeat_failed {
            client = None;                       // Drop sends the FIN right away
            last_reconnect = Instant::now();
            let reconnected = last_host.as_deref()
                .and_then(|host| try_reconnect(host, last_port)
                    .map(|(c, st)| (host.to_string(), c, st)));
            match reconnected {
                Some((host, new_client, status)) => {
                    // Same console, same session from the UI's point of view: a
                    // status push keeps CONNECTED and the panels live.
                    client = Some(new_client);
                    ui_connected = true;
                    let _ = tx.send(Ev::Status(status));
                    let _ = tx.send(Ev::Message(format!("link lost - reconnected to {}:{}", host, last_port)));
                }
                None => {
                    if ui_connected {
                        ui_connected = false;
                        let _ = tx.send(Ev::Disconnected);
                        let _ = tx.send(Ev::Message(
                            "connection lost - retrying in the background".into()));
                    }
                }
            }
        }

        // Nothing connected but the session is still wanted: keep retrying so a
        // Switch waking up (or Wi-Fi coming back) turns into CONNECTED by itself.
        if client.is_none() && want_connected && last_host.is_some()
            && last_reconnect.elapsed() >= RECONNECT_INTERVAL {
            last_reconnect = Instant::now();
            if let Some(host) = last_host.as_deref() {
                if let Some((new_client, status)) = try_reconnect(host, last_port) {
                    let metadata = new_client.metadata().ok();
                    let host = host.to_string();
                    let _ = tx.send(Ev::Connected { status, metadata });
                    let _ = tx.send(Ev::Message(format!("auto-reconnected to {}:{}", host, last_port)));
                    client = Some(new_client);
                    ui_connected = true;
                    last_heartbeat = Instant::now();
                }
            }
        }

        if let Some(c) = client.as_ref() {
            drain_events(c, &tx);
        }

        let Some(cmd) = cmd else { continue };

        let outcome: Result<(), String> = (|| {
            match cmd {
                Cmd::Connect { host, port } => {
                    // Close the old session BEFORE opening the new one: two live
                    // connections to the same console fight over the read thread
                    // and leave a half-dead socket holding a pending request map.
                    client = None;
                    last_host = Some(host.clone());
                    last_port = port;
                    want_connected = true;             // re-arm background recovery
                    let attempt = NxusClient::connect(&host, port).and_then(|c| {
                        let status = c.status()?;
                        let metadata = c.metadata().ok();
                        Ok((c, status, metadata))
                    });
                    last_reconnect = Instant::now();   // the retry loop waits a full interval
                    match attempt {
                        Ok((c, status, metadata)) => {
                            client = Some(c);
                            ui_connected = true;
                            last_heartbeat = Instant::now();   // no keep-alive on the fresh socket yet
                            let _ = tx.send(Ev::Connected { status, metadata });
                            let _ = tx.send(Ev::Message(format!("connected to {}:{}", host, port)));
                        }
                        Err(e) => {
                            // The old session is already gone, so the UI must stop
                            // claiming CONNECTED: the background retry loop below
                            // is silent until it actually finds a console.
                            ui_connected = false;
                            let _ = tx.send(Ev::Disconnected);
                            return Err(e.to_string());
                        }
                    }
                }
                Cmd::Disconnect => {
                    // The user wants it gone: stop the automatic recovery, or the
                    // worker would reconnect a moment later and undo the click.
                    want_connected = false;
                    client = None;
                    ui_connected = false;
                    let _ = tx.send(Ev::Disconnected);
                    let _ = tx.send(Ev::Message("disconnected".into()));
                }
                Cmd::PtrScanPc { target, module_base, depth, max_offset, dump_path: Some(path) } => {
                    cancel.store(false, std::sync::atomic::Ordering::Relaxed);
                    if crate::edizon::is_edizon_file(&path) {
                        let dump = crate::edizon::EdizonDump::load(&path).map_err(|e| e.to_string())?;
                        // Offline: the GUI may have no live module base, and the
                        // cursor may be 0 - fall back to what the dump recorded.
                        let target = if target != 0 { target } else { dump.target };
                        let module_base = if module_base != 0 { module_base } else { dump.main_base };
                        let res = crate::edizon::ptrscan_edizon(
                            &dump,
                            &crate::dump::PtrScanOptions {
                                target,
                                module_base,
                                module_size: dump.main_end.saturating_sub(dump.main_base),
                                max_depth: depth,
                                max_offset,
                                width: 8,
                                max_results: 64,
                            },
                            &cancel,
                        );
                        let note = if res.truncated { " - TRUNCATED" } else { "" };
                        let _ = tx.send(Ev::Message(format!(
                            "EdiZon pointer scan: {} chain(s) from {} ({} pointer(s)){}",
                            res.chains.len(), path, res.pointers_indexed, note)));
                        let _ = tx.send(Ev::Chains(res.chains, res.truncated));
                    } else {
                        let dump = crate::dump::MemoryDump::load(&path).map_err(|e| e.to_string())?;
                        let (inf_base, inf_size) = dump.infer_main_module();
                        let res = crate::dump::ptrscan_dump(
                            &dump,
                            &crate::dump::PtrScanOptions {
                                target,
                                module_base: if module_base != 0 { module_base } else { inf_base },
                                module_size: inf_size,
                                max_depth: depth,
                                max_offset,
                                width: 4,
                                max_results: 64,
                            },
                            &cancel,
                        );
                        let note = if res.truncated { " - TRUNCATED" } else { "" };
                        let _ = tx.send(Ev::Message(format!("NDMP pointer scan: {} chain(s) from {}{}",
                                                            res.chains.len(), path, note)));
                        let _ = tx.send(Ev::Chains(res.chains, res.truncated));
                    }
                }
                other => {
                    let c = client.as_ref().ok_or("not connected")?;
                    match other {
                        Cmd::Refresh => {
                            let st = c.status().map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Status(st));
                        }
                        Cmd::FetchConsoleLog => {
                            match c.log() {
                                Ok(text) => { let _ = tx.send(Ev::ConsoleLog(text)); }
                                Err(e) => {
                                    let _ = tx.send(Ev::ConsoleLog(format!("(log unavailable: {})", e)));
                                }
                            }
                        }
                        Cmd::FetchModules => {
                            let modules = c.modules().map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Modules(modules));
                        }
                        Cmd::FetchMappings => {
                            let maps = c.mappings(0, 256).map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Mappings(maps));
                        }
                        Cmd::ScanBegin { spec } => {
                            prev_pc_scan = None;
                            let value_size = spec.value_size;
                            c.scan_begin_spec(&spec).map_err(|e| e.to_string())?;
                            let st = c.scan_wait_cancellable(Duration::from_secs(900), &cancel)
                                .map_err(|e| e.to_string())?;
                            let hits = c.scan_all_hits(8192).map_err(|e| e.to_string())?;
                            // anything the console pushed during the scan (e.g. the
                            // stop that "pause while scanning" asked for) must reach
                            // the UI BEFORE the result, or it would arrive after the
                            // matching Resume and re-open a stale banner
                            drain_events(c, &tx);
                            let _ = tx.send(Ev::Hits {
                                message: format!("first scan {} (result=0x{:08X}): {} hit(s){}",
                                                 scan_state::name(st.scan_state),
                                                 st.last_result, hits.len(),
                                                 console_scan_stats(c)),
                                hits, value_size,
                            });
                        }
                        Cmd::ScanNext { spec } => {
                            let value_size = spec.value_size;
                            c.scan_next_spec(&spec).map_err(|e| e.to_string())?;
                            let st = c.scan_wait_cancellable(Duration::from_secs(900), &cancel)
                                .map_err(|e| e.to_string())?;
                            let hits = c.scan_all_hits(8192).map_err(|e| e.to_string())?;
                            drain_events(c, &tx);
                            let _ = tx.send(Ev::Hits {
                                message: format!("next scan {} (result=0x{:08X}): {} hit(s){}",
                                                 scan_state::name(st.scan_state),
                                                 st.last_result, hits.len(),
                                                 console_scan_stats(c)),
                                hits, value_size,
                            });
                        }
                        Cmd::PcScanUnknown { value_size, scope, begin, end, max_hits } => {
                            let regions = crate::pcscan::regions_for_scope(c, scope_by_index(scope), begin, end)
                                .map_err(|e| e)?;
                            if regions.is_empty() {
                                return Err("no readable memory for this scope".into());
                            }
                            cancel.store(false, std::sync::atomic::Ordering::Relaxed);

                            let mut last = 0u64;
                            let mut progress = |done: u64, total: u64| {
                                if done - last > 512 * 1024 || done == total {
                                    last = done;
                                    let _ = tx.send(Ev::Progress { done, total, label: "reading memory".into() });
                                }
                            };
                            let scan = crate::pcscan::scan_unknown(c, &regions, value_size, max_hits,
                                                                    &cancel, &mut progress)?;
                            let total_candidates = scan.len();
                            let hits: Vec<(u64, u64)> = scan.hits_page(0, 65536).into_iter().map(|h| (h.address, h.value)).collect();
                            let mut message = format!("unknown-value scan: {} candidate(s) from {} MB ({} reads)",
                                                  total_candidates, scan.bytes_read / (1024 * 1024), scan.reads);
                            if total_candidates == 0 && scan.failed_reads > 0 {
                                message.push_str(&format!(" - {} read(s) failed, check the scope/range",
                                                          scan.failed_reads));
                            }
                            let truncated = scan.truncated;
                            prev_pc_scan = None;
                            pc_scan = Some(scan);
                            drain_events(c, &tx);      // see ScanBegin
                            let _ = tx.send(Ev::PcHits { hits, value_size, message, truncated });
                        }
                        Cmd::PcScanRefine { compare, target, target2, flags } => {
                            let mut scan = pc_scan.take()
                                .ok_or("run an unknown-value scan first (the candidate list is kept on the PC)")?;
                            prev_pc_scan = Some(scan.clone());
                            cancel.store(false, std::sync::atomic::Ordering::Relaxed);
                            let mut last = 0u64;
                            let mut progress = |done: u64, total: u64| {
                                if done - last > 2048 || done == total {
                                    last = done;
                                    let _ = tx.send(Ev::Progress { done, total, label: "re-reading candidates".into() });
                                }
                            };
                            crate::pcscan::refine(c, &mut scan, compare_by_index(compare), target, target2,
                                                  flags, &cancel, &mut progress)?;
                            let total_candidates = scan.len();
                            let hits: Vec<(u64, u64)> = scan.hits_page(0, 65536).into_iter().map(|h| (h.address, h.value)).collect();
                            let message = format!("next scan: {} candidate(s)", total_candidates);
                            let value_size = scan.value_size;
                            let truncated = scan.truncated;
                            pc_scan = Some(scan);
                            drain_events(c, &tx);      // see ScanBegin
                            let _ = tx.send(Ev::PcHits { hits, value_size, message, truncated });
                        }
                        Cmd::PcScanCancel => {
                            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                        Cmd::ScanCancel => {
                            c.request(P::cmd::SCAN_CANCEL, &[]).map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Message("scan cancelled".into()));
                        }
                        Cmd::ScanReset => {
                            pc_scan = None;           // forget the PC-side candidate list too
                            prev_pc_scan = None;
                            c.scan_reset().map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Hits { hits: Vec::new(), value_size: 0, message: "scan reset".into() });
                        }
                        Cmd::ScanUndo => {
                            if let Some(scan) = prev_pc_scan.take() {
                                let total_candidates = scan.len();
                                let hits: Vec<(u64, u64)> = scan.hits_page(0, 65536).into_iter().map(|h| (h.address, h.value)).collect();
                                let value_size = scan.value_size;
                                let truncated = scan.truncated;
                                let message = format!("undo scan: {} candidate(s) restored", total_candidates);
                                pc_scan = Some(scan);
                                let _ = tx.send(Ev::PcHits { hits, value_size, message, truncated });
                            } else {
                                let st = c.scan_undo().map_err(|e| e.to_string())?;
                                let hits = c.scan_all_hits(8192).map_err(|e| e.to_string())?;
                                let _ = tx.send(Ev::Hits {
                                    message: format!("undo scan: {} hit(s) restored", st.hit_count),
                                    hits,
                                    value_size: 0,
                                });
                            }
                        }
                        Cmd::FetchHits => {
                            let hits = c.scan_all_hits(8192).map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Hits { message: format!("{} hit(s)", hits.len()), hits, value_size: 0 });
                        }
                        Cmd::RefreshWatchlist { entries } => {
                            let mut out = Vec::with_capacity(entries.len());
                            for (address, size) in entries {
                                let width = size.clamp(1, 8);
                                if let Ok(bytes) = c.read(address, width) {
                                    if bytes.len() >= width as usize {
                                        let mut raw = [0u8; 8];
                                        raw[..width as usize].copy_from_slice(&bytes[..width as usize]);
                                        out.push((address, u64::from_le_bytes(raw)));
                                    }
                                }
                            }
                            let _ = tx.send(Ev::WatchlistValues(out));
                        }
                        Cmd::Read { address, size } => {
                            let data = c.read(address, size).map_err(|e| e.to_string())?;
                            if data.len() < size as usize {
                                // the hex view would paint the missing tail as 00
                                let _ = tx.send(Ev::Message(format!(
                                    "short read at {:08X}: {} of {} byte(s) - the rest is unknown, not zero",
                                    address, data.len(), size)));
                            }
                            let _ = tx.send(Ev::Read { address, data });
                        }
                        Cmd::ReadDisasm { address, size } => {
                            let data = c.read(address, size).map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::DisasmData { address, data });
                        }
                        Cmd::FetchCurrentPcAndDisasm { size } => {
                            // The first thread is the one the game runs on; dmnt
                            // only reports contexts for threads that are stopped.
                            let threads = c.thread_list().map_err(|e| e.to_string())?;
                            let first = threads.first()
                                .ok_or("no thread reported (is the target running?)")?;
                            let ctx = c.regs_get(first.thread_id).map_err(|e| e.to_string())?;
                            let address = ctx.pc.saturating_sub(32);
                            let data = c.read(address, size).map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::RegsAndDisasm { ctx, address, data });
                        }
                        Cmd::Write { address, data } => {
                            c.write(address, &data).map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Message(format!("wrote {} byte(s) at {:08X}", data.len(), address)));
                            if let Ok(current) = c.read(address, data.len() as u32) {
                                let _ = tx.send(Ev::Wrote { address, data: current });
                            }
                        }
                        Cmd::Freeze { address, width } => {
                            let value = c.frozen_enable(address, width).map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Frozen { address, value });
                            let _ = tx.send(Ev::Message(format!("freezing {:08X} = {}", address, value)));
                        }
                        Cmd::Unfreeze { address } => {
                            c.frozen_disable(address).map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Unfrozen { address });
                            let _ = tx.send(Ev::Message(format!("unfrozen {:08X}", address)));
                        }
                        Cmd::PtrScan { target, module_base, depth, max_offset } => {
                            let (chains, truncated) = c.ptrscan_begin(target, module_base, depth, max_offset, 64, 4)
                                .map_err(|e| e.to_string())?;
                            let note = if truncated { " - TRUNCATED by the console" } else { "" };
                            let _ = tx.send(Ev::Message(format!("pointer scan: {} chain(s){}", chains.len(), note)));
                            let _ = tx.send(Ev::Chains(chains, truncated));
                        }
                        Cmd::PtrScanPc { target, module_base, depth, max_offset, dump_path: None } => {
                            cancel.store(false, std::sync::atomic::Ordering::Relaxed);
                            let mut last = 0u64;
                            let mut progress = |done: u64, total: u64| {
                                if done - last > 512 * 1024 || done == total {
                                    last = done;
                                    let _ = tx.send(Ev::Progress { done, total, label: "dumping for PC ptrscan".into() });
                                }
                            };
                            let dump = crate::dump::MemoryDump::capture(c, Scope::Writable, 0, 0, &cancel, &mut progress)?;
                            let (inf_base, inf_size) = dump.infer_main_module();
                            let res = crate::dump::ptrscan_dump(
                                &dump,
                                &crate::dump::PtrScanOptions {
                                    target,
                                    module_base: if module_base != 0 { module_base } else { inf_base },
                                    module_size: inf_size,
                                    max_depth: depth,
                                    max_offset,
                                    width: 4,
                                    max_results: 64,
                                },
                                &cancel,
                            );
                            let note = if res.truncated { " - TRUNCATED" } else { "" };
                            let _ = tx.send(Ev::Message(format!("PC pointer scan: {} chain(s) ({} ptrs indexed){}",
                                                                res.chains.len(), res.pointers_indexed, note)));
                            let _ = tx.send(Ev::Chains(res.chains, res.truncated));
                        }
                        Cmd::SaveDump { path, scope, begin, end } => {
                            cancel.store(false, std::sync::atomic::Ordering::Relaxed);
                            let mut last = 0u64;
                            let mut progress = |done: u64, total: u64| {
                                if done - last > 512 * 1024 || done == total {
                                    last = done;
                                    let _ = tx.send(Ev::Progress { done, total, label: "saving NDMP dump".into() });
                                }
                            };
                            let dump = crate::dump::MemoryDump::capture(
                                c, scope_by_index(scope), begin, end, &cancel, &mut progress)?;
                            dump.save(&path).map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Message(format!(
                                "saved NDMP dump to {} ({} blocks, {} MB)",
                                path, dump.indices.len(), dump.total_bytes() / (1024 * 1024))));
                        }
                        Cmd::Cheat { index, value } => {
                            let text = c.cheat_export(index, value, 4, true).map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Cheat(text));
                        }
                        Cmd::Attach => {
                            let st = c.debug_attach().map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Message(format!("debug attached (watch style {})", st.watch_style)));
                            // A fresh session owns whatever the previous one left
                            // parked: re-read the status so the stop badge comes
                            // from the console again, and tell the UI to drop the
                            // banner/caches of the old session.
                            push_status(c, &tx);
                            let _ = tx.send(Ev::DebugSession { attached: true });
                        }
                        Cmd::Detach => {
                            c.debug_detach().map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Message("debug detached (dmnt restored)".into()));
                            // dmnt cannot be holding anything after a detach: the
                            // status reply (no stopped bit) clears the badge, the
                            // event clears the banner and the cached context.
                            push_status(c, &tx);
                            let _ = tx.send(Ev::DebugSession { attached: false });
                        }
                        Cmd::BreakSet { address, kind, size } => {
                            let slot = if kind == break_kind::EXECUTE { 0 } else { 0x10 };
                            let entries = c.break_set(address, kind, size, slot, 0).map_err(|e| e.to_string())?;
                            let actual = entries.first().map(|e| e.slot).unwrap_or(slot);
                            let _ = tx.send(Ev::WatchArmed { address, kind, slot: actual });
                            let _ = tx.send(Ev::Message(format!("watchpoint armed at {:08X} (slot {})",
                                                                address, actual)));
                        }
                        Cmd::BreakClear { slot } => {
                            c.break_clear(slot).map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Message("watchpoint cleared".into()));
                        }
                        Cmd::HitGet => {
                            let hits = c.hit_get(64).map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::BreakHits(hits));
                        }
                        Cmd::HitClear => {
                            c.hit_clear().map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::BreakHits(Vec::new()));
                        }
                        Cmd::SnapshotCapture { slot, scope } => {
                            let summary = c.snapshot_capture(slot, scope_by_index(scope), 0)
                                .map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Message(format!("snapshot slot {}: {} blocks of {} bytes",
                                        if slot == 0 { "A" } else { "B" }, summary.block_count, summary.block_size)));
                            let _ = tx.send(Ev::Snapshot { summary, changed: Vec::new() });
                        }
                        Cmd::SnapshotDiff { from, to } => {
                            let summary = c.snapshot_diff(from, to).map_err(|e| e.to_string())?;
                            let changed = if summary.changed_count > 0 {
                                c.snapshot_changed_all(1024).map_err(|e| e.to_string())?
                            } else {
                                Vec::new()
                            };
                            let _ = tx.send(Ev::Message(format!("diff: {} changed block(s)", summary.changed_count)));
                            let _ = tx.send(Ev::Snapshot { summary, changed });
                        }
                        Cmd::Config { mask, hold, enabled, watchdog, style, auto_continue } => {
                            // "Apply" is the full request on purpose: the user is
                            // applying EVERY setting.  auto_continue is the current
                            // stop-on-hit choice - hardcoding 1 here used to
                            // silently release a held target / break a --stop watch.
                            c.set_config(mask, hold, enabled, 0, watchdog, 5000, 1,
                                         Some((style, auto_continue)))
                                .map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Message(format!(
                                "settings applied (hotkey 0x{:X}, watchdog {} ms, {} on hit)",
                                mask, watchdog,
                                if auto_continue == 0 { "stop" } else { "auto-resume" })));
                        }
                        Cmd::Pause => {
                            c.pause().map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Message("paused".into()));
                            // While attached this maps to svcBreakDebugProcess, which
                            // publishes a stop: the status is where that shows up.
                            push_status(c, &tx);
                        }
                        Cmd::Resume => {
                            c.resume().map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Message("resumed".into()));
                            push_status(c, &tx);
                        }
                        Cmd::DebugConfigure { auto_continue, style } => {
                            // 16 bytes only (NxusDebugConfig): the console applies
                            // the debug half and keeps its hotkey/watchdog block,
                            // so arming a watchpoint cannot reset the settings the
                            // user applied from the Settings window.
                            c.set_debug_auto_continue(style, auto_continue)
                                .map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Message(format!(
                                "debug: {} (auto_continue={})",
                                if auto_continue == 0 { "stop on hit" } else { "auto-resume on hit" },
                                auto_continue)));
                        }
                        Cmd::DebugContinue => {
                            c.debug_continue().map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Message("debug continue: target running".into()));
                            push_status(c, &tx);       // clears the stopped bit
                        }
                        Cmd::DebugStep { thread_id } => {
                            // 0 = "the thread the console stopped" (it remembers it).
                            c.debug_step(thread_id).map_err(|e| e.to_string())?;
                            let _ = tx.send(Ev::Message("debug step".into()));
                            // A step keeps the stop published (only the PC moves), so
                            // the status is re-read and the caller refreshes the
                            // context afterwards.
                            push_status(c, &tx);
                        }
                        Cmd::FetchThreadPcAndDisasm { thread_id, pc, size } => {
                            // The thread the console parked is the interesting one; dmnt
                            // only reports contexts for stopped threads, so a failure
                            // here must still show the code at the event's PC.
                            let (ctx, address, data) = match c.regs_get(thread_id) {
                                Ok(ctx) => {
                                    let pc = if ctx.pc != 0 { ctx.pc } else { pc };
                                    let address = pc.saturating_sub(32);
                                    let data = c.read(address, size).map_err(|e| e.to_string())?;
                                    (ctx, address, data)
                                }
                                Err(e) => {
                                    let address = pc.saturating_sub(32);
                                    let data = c.read(address, size).map_err(|e| e.to_string())?;
                                    let _ = tx.send(Ev::Message(format!(
                                        "registers of thread {} unavailable: {}", thread_id, e)));
                                    let ctx = P::ThreadContext { thread_id, pc, ..Default::default() };
                                    (ctx, address, data)
                                }
                            };
                            let _ = tx.send(Ev::RegsAndDisasm { ctx, address, data });
                        }
                        Cmd::Connect { .. } | Cmd::Disconnect | Cmd::PtrScanPc { dump_path: Some(_), .. } => {}
                    }
                }
            }
            Ok(())
        })();

        if let Err(message) = outcome {
            let _ = tx.send(Ev::Error(message));
        }
    }
}

pub fn compare_by_index(index: u32) -> Compare {
    match index {
        1 => Compare::NotEqual,
        2 => Compare::Greater,
        3 => Compare::Less,
        4 => Compare::Increased,
        5 => Compare::Decreased,
        6 => Compare::Unchanged,
        7 => Compare::Changed,
        8 => Compare::FuzzyEqual,
        9 => Compare::Between,
        10 => Compare::Unknown,
        11 => Compare::GreaterOrEqual,
        12 => Compare::LessOrEqual,
        13 => Compare::Different,
        _ => Compare::Equal,
    }
}

pub fn scope_by_index(index: u32) -> Scope {
    match index {
        1 => Scope::Main,
        2 => Scope::Heap,
        6 => Scope::Ranges,
        3 => Scope::Custom,
        4 => Scope::Writable,
        5 => Scope::Tls,
        _ => Scope::All,
    }
}

// ---------------------------------------------------------------- state

pub const COMPARE_NAMES: [&str; 12] = [
    "==", "!=", ">", "<", ">=", "<=", "increased", "decreased",
    "unchanged", "changed", "changed by", "fuzzy",
];
pub const SCOPE_NAMES: [&str; 7] =
    ["all", "main", "heap", "custom", "writable", "tls", "ranges"];
pub const WATCH_KINDS: [(&str, u32); 4] = [
    ("write", break_kind::WRITE),
    ("read", break_kind::READ),
    ("exec", break_kind::EXECUTE),
    ("access", break_kind::ACCESS),
];

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct WatchEntry {
    pub label: String,
    pub address: u64,
    pub value_type: u16,
    #[serde(default)]
    pub value: u64,
    #[serde(default)]
    pub edit_text: String,
}

/// serde default for the preference flags that must stay ON when an old
/// `nxus-prefs` blob (written before the field existed) is loaded.
fn default_true() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Prefs {
    pub host: String,
    pub port: String,
    pub scan_value: String,
    pub scan_value2: String,
    pub scan_size: u32,
    pub compare: usize,
    pub scope: usize,
    pub value_type: usize,
    pub hex_input: bool,
    pub case_insensitive: bool,
    pub utf16: bool,
    pub aligned: bool,
    pub write_protect: bool,
    pub follow_selection: bool,
    pub auto_connect: bool,
    pub hotkey_enabled: bool,
    pub hotkey_mask: u64,
    pub hotkey_hold: u32,
    pub watchdog_ms: u32,
    pub watch_style: u32,
    pub watch_kind: usize,
    pub watch_size: u32,
    /// GDB style: hold the target at a watchpoint hit instead of resuming it.
    /// Sent as NxusDebugConfig.auto_continue = 0 right before an arm.
    #[serde(default = "default_true")]
    pub watch_stop_on_hit: bool,
    /// Freeze the target for the duration of a scan, so no value changes under
    /// the scan (only meaningful while Nxus owns the debug session).
    #[serde(default = "default_true")]
    pub scan_pause: bool,
    pub ptr_depth: u32,
    pub ptr_max_offset: u32,
    #[serde(default)]
    pub ptr_pc_mode: bool,
    pub cheat_value: String,
    #[serde(default)]
    pub watchlist: Vec<WatchEntry>,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            host: "127.0.0.1".into(),
            port: P::DEFAULT_PORT.to_string(),
            scan_value: "6440".into(),
            scan_value2: String::new(),
            scan_size: 4,
            compare: 0,
            scope: 0,
            value_type: 2,
            hex_input: false,
            case_insensitive: false,
            utf16: false,
            aligned: false,
            write_protect: true,
            follow_selection: true,
            auto_connect: true,
            hotkey_enabled: false,
            hotkey_mask: 0x400,
            hotkey_hold: 300,
            watchdog_ms: 15000,
            watch_style: 1,
            watch_kind: 0,
            watch_size: 4,
            // GDB behaviour by default: a hit is a stop, not a log line.
            watch_stop_on_hit: true,
            scan_pause: true,
            ptr_depth: 3,
            ptr_max_offset: 0x1000,
            ptr_pc_mode: false,
            cheat_value: "9999999".into(),
            watchlist: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Results,
    Hex,
    Disasm,
    Snapshot,
    Watch,
    Info,
}

pub struct SnapshotState {
    pub summary: Option<P::SnapshotSummary>,
    pub changed: Vec<ChangedBlock>,
    pub slot: u32,
}

/// Above this many rows the filter box is ignored: formatting millions of rows per
/// keystroke freezes the UI for seconds (see build_visible_hits).
pub const FILTER_LIMIT: usize = 2_000_000;

pub struct State {
    pub connected: bool,
    pub busy: bool,
    pub status: Option<Status>,
    pub metadata: Option<Metadata>,
    pub modules: Vec<ModuleInfo>,
    /// Target memory map (scopes/region picker).  Kept as raw MemoryInfo so the list can
    /// show base/size/perms/type exactly like the CLI does.
    pub mappings: Vec<crate::protocol::MemoryInfo>,
    pub regions_writable_only: bool,
    /// Regions picked with "+range": scanned together when the scope is "ranges".
    pub scan_ranges: Vec<(u64, u64)>,
    pub hits: Vec<Hit>,
    pub value_size: u32,
    pub selected: Option<usize>,
    pub filter: String,
    pub sort_desc: bool,
    /// Bumped whenever the hit list itself changes (not when the filter does).
    pub hits_generation: u64,
    /// Cached (filter, sort, generation) -> rows, so the per-frame rebuild only
    /// happens when something actually changed.
    pub visible_cache: Option<(u64, String, bool, std::rc::Rc<Vec<(usize, Hit)>>)>,
    pub break_hits: Vec<BreakHit>,
    pub chains: Vec<PtrChain>,
    /// Set by the console's own truncated flag (not by counting chains).
    pub chains_truncated: bool,
    pub cheat_text: String,
    pub snapshot: SnapshotState,
    pub watch_armed: Option<u64>,
    pub frozen: Vec<u64>,
    pub log: Vec<String>,
    pub started: Instant,
    pub scan_progress: f32,
    pub last_message: String,
    pub scan_range_begin: String,
    pub scan_range_end: String,
    pub watch_label_input: String,
    pub watch_addr_input: String,
    pub watch_type_index: usize,
    /// Disasm tab: address expression the user typed ("main+0x12345" or 16-hex).
    pub disasm_addr_input: String,
    /// Index into the arch combo: 0 = Auto/AArch64, 1 = ARM32, 2 = Thumb.
    pub disasm_arch: usize,
    /// Address `disasm_bytes` starts at (the listing base).
    pub disasm_base: u64,
    /// PC to mark with "=>" (a watchpoint hit, or the live PC of a thread).
    pub disasm_highlight_pc: Option<u64>,
    pub disasm_bytes: Vec<u8>,
    /// Registers fetched by "At Current PC (Regs)"; shown above the listing.
    pub last_regs: Option<P::ThreadContext>,
    /// Set while the console holds the target at a breakpoint and the stop
    /// details are known (P::DebugStop).  `None` with the status bit set means
    /// "held, but this stop is not a breakpoint hit" (e.g. the Pause button).
    pub debug_stop: Option<P::DebugStop>,
    /// The scan section paused the target and still owes it a Resume.
    pub scan_paused_target: bool,
}

impl State {
    pub fn new() -> State {
        State {
            connected: false,
            busy: false,
            status: None,
            metadata: None,
            modules: Vec::new(),
            mappings: Vec::new(),
            regions_writable_only: true,     // the interesting regions are writable ones
            scan_ranges: Vec::new(),
            hits: Vec::new(),
            value_size: 4,
            selected: None,
            filter: String::new(),
            sort_desc: false,
            hits_generation: 0,
            visible_cache: None,
            break_hits: Vec::new(),
            chains: Vec::new(),
            chains_truncated: false,
            cheat_text: String::new(),
            snapshot: SnapshotState { summary: None, changed: Vec::new(), slot: 0 },
            watch_armed: None,
            frozen: Vec::new(),
            log: vec!["Nxus ready - set the console IP and press Connect".into()],
            started: Instant::now(),
            scan_progress: 0.0,
            last_message: String::new(),
            scan_range_begin: String::new(),
            scan_range_end: String::new(),
            watch_label_input: "Bookmark".into(),
            watch_addr_input: String::new(),
            watch_type_index: 2,
            disasm_addr_input: "main+0x0".into(),
            disasm_arch: 0,
            disasm_base: 0,
            disasm_highlight_pc: None,
            disasm_bytes: Vec::new(),
            last_regs: None,
            debug_stop: None,
            scan_paused_target: false,
        }
    }

    pub fn main_base(&self) -> u64 {
        self.status.as_ref().map(|s| s.main_base).unwrap_or(0)
    }

    /// The target is held.  `NxusStatus.status_flags & ST_DEBUG_STOPPED` is the
    /// ONLY source of truth: a `DebugStopped` event sets the bit immediately (that
    /// is what makes the badge appear without waiting for a poll), and every
    /// status reply corrects it - including to "running" when the console resumed
    /// the target (Continue, the watchdog, a detach).  `debug_stop` only carries
    /// the details of a breakpoint hit; it never decides the state on its own,
    /// because a failed Continue would otherwise show a running game.
    pub fn is_stopped(&self) -> bool {
        self.status.as_ref().map(|s| s.debug_stopped()).unwrap_or(false)
    }

    pub fn heap_base(&self) -> u64 {
        self.metadata.as_ref().map(|m| m.heap_base).unwrap_or(0)
    }

    pub fn log(&mut self, line: impl Into<String>) {
        let stamp = self.started.elapsed().as_secs_f32();
        let line = format!("[{:7.1}s] {}", stamp, line.into());
        self.last_message = line.clone();
        self.log.push(line);
        if self.log.len() > 500 {
            self.log.remove(0);
        }
    }

    pub fn module_offset(&self, address: u64) -> u64 {
        address.wrapping_sub(self.main_base())
    }

    /// Hits after the filter box and sort order are applied.
    ///
    /// The result is cached and handed out as an Rc, because rebuilding it costs
    /// ~159 ms per frame at 7.9M rows (1703 ms while typing a filter) and the
    /// table only ever looks at a few hundred of them.
    pub fn visible_hits(&mut self) -> std::rc::Rc<Vec<(usize, Hit)>> {
        // While the filter is ignored the key must not change with it, or every
        // keystroke would rebuild millions of rows for nothing.
        let key_filter = if self.hits.len() > FILTER_LIMIT { String::new() }
                         else { self.filter.trim().to_string() };
        let key = (self.hits_generation, key_filter, self.sort_desc);
        if let Some((generation, filter, desc, rows)) = &self.visible_cache {
            if *generation == key.0 && *filter == key.1 && *desc == key.2 {
                return std::rc::Rc::clone(rows);
            }
        }
        let rows = std::rc::Rc::new(self.build_visible_hits());
        self.visible_cache = Some((key.0, key.1, key.2, std::rc::Rc::clone(&rows)));
        rows
    }

    fn build_visible_hits(&self) -> Vec<(usize, Hit)> {
        // The needle is computed once, not per hit, and the address is formatted
        // once per hit instead of twice: with a 7.9M-row list this loop runs on
        // every frame (measured 159 ms/frame unfiltered, 1703 ms while typing).
        // Formatting millions of rows per keystroke freezes the UI for seconds, so
        // above this size the filter box is ignored (refine the list instead).
        let filtering_too_big = self.hits.len() > FILTER_LIMIT && !self.filter.trim().is_empty();
        let needle = if filtering_too_big { String::new() }
                     else { self.filter.trim().to_ascii_lowercase() };
        let filtered = !needle.is_empty();

        let mut rows: Vec<(usize, Hit)> = self.hits.iter().cloned().enumerate()
            .filter(|(_, hit)| {
                if !filtered {
                    return true;
                }
                // only format what the filter can actually match
                if format!("{:08X}", hit.address).to_ascii_lowercase().contains(&needle) {
                    return true;
                }
                if hit.value.to_string().contains(&needle) {
                    return true;
                }
                format!("{}", hit.value as u32).contains(&needle)
            })
            .collect();

        // The console returns hits ordered by mapping and offset, so the common
        // case is already sorted; checking costs one pass and saves a full sort.
        let mut sorted = true;
        for window in rows.windows(2) {
            if window[0].1.address > window[1].1.address {
                sorted = false;
                break;
            }
        }
        if !sorted {
            rows.sort_by_key(|(_, hit)| hit.address);
        }
        if self.sort_desc {
            rows.reverse();
        }
        rows
    }
}

pub struct App {
    pub st: State,
    pub prefs: Prefs,
    pub hex: hexview::HexView,
    pub tab: Tab,
    pub show_settings: bool,
    pub show_modules: bool,
    pub(crate) cmd_tx: Sender<Cmd>,
    pub(crate) ev_rx: Receiver<Ev>,
    pub demo: bool,
    /// True while the candidate list lives on the PC (unknown-value scans).
    pub pc_scan_active: bool,
    /// Set by the UI to stop whatever the worker is doing.
    pub scan_cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Tail of the console's log, shown in the log panel (scan statistics).
    pub console_log: Vec<String>,
    screenshot: Option<String>,
    frames: u32,
    shot_requested: bool,
    shot_saved: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(test)]
mod font_tests {
    use super::*;

    /// The GUI used to draw Windows' Japanese error text as a row of boxes.  This pins
    /// both halves of the fix: the bundled font HAS the glyphs, and it is wired into the
    /// families the UI actually uses.
    #[test]
    fn bundled_font_covers_japanese() {
        let mut fonts = egui::epaint::text::Fonts::new(
            egui::epaint::text::TextOptions::default(),
            font_definitions(),
        );
        let ui_font = egui::FontId::proportional(14.0);
        let log_font = egui::FontId::monospace(12.0);
        for s in ["接続が拒否されました", "所持金", "日本語のタイトル", "変更"] {
            assert!(
                fonts.has_glyphs(&ui_font, s),
                "proportional family is missing glyphs for {s}"
            );
            assert!(
                fonts.has_glyphs(&log_font, s),
                "monospace family (the LOG panel) is missing glyphs for {s}"
            );
        }
        // Latin text must keep working too
        assert!(fonts.has_glyphs(&ui_font, "Nxus ready - connect"));
        // The stop marker must render as well.  ⏸ (U+23F8) is NOT in any bundled
        // face - it came out as a tofu box - so the UI draws ■ (U+25A0) instead.
        for marker in ["■ STOPPED", "▌▌", "●"] {
            assert!(
                fonts.has_glyphs(&ui_font, marker),
                "stop marker {marker} would render as a box"
            );
        }
    }
}

#[cfg(test)]
mod debug_stop_tests {
    use super::*;

    /// The wire sentinel decides whether the UI opens a stop banner at all, and it
    /// is `kind` that carries it: a genuine hit whose hardware slot could not be
    /// paired up also reports 0xFFFFFFFF in `slot`, so `slot` must not be used.
    #[test]
    fn manual_break_is_told_apart_from_a_hit() {
        assert!(is_manual_stop(0xFFFF_FFFF));
        assert!(!is_manual_stop(break_kind::WRITE));
        assert!(!is_manual_stop(break_kind::READ));
        assert!(!is_manual_stop(break_kind::EXECUTE));
        assert!(!is_manual_stop(break_kind::ACCESS));
    }

    /// "stop on hit" must reach the console as auto_continue = 0 (hold), because
    /// 1 silently resumes the game and the banner would describe a running target.
    #[test]
    fn stop_on_hit_sends_auto_continue_zero() {
        assert_eq!(auto_continue_for(true), 0);
        assert_eq!(auto_continue_for(false), 1);
    }
}

/// Japanese text (Windows error strings, module paths, cheat names) has no glyphs in
/// egui's default Latin fonts and used to render as a row of boxes.  M PLUS 1p is a
/// readable OFL font that covers JIS level 1+2 for ~1.7 MB.
pub const JP_FONT: &[u8] = include_bytes!("../../assets/fonts/MPLUS1p-Regular.ttf");

pub fn font_definitions() -> egui::FontDefinitions {
    let mut defs = egui::FontDefinitions::default();
    defs.font_data.insert(
        "mplus1p".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(JP_FONT)),
    );
    // Appended, not prepended: Latin keeps the crisp default font and only glyphs the
    // default lacks (CJK) fall through to M PLUS.
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        defs.families.entry(family).or_default().push("mplus1p".to_owned());
    }
    defs
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, prefs: Prefs, screenshot: Option<String>,
               demo: bool) -> App {
        cc.egui_ctx.set_fonts(font_definitions());
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        cc.egui_ctx.all_styles_mut(|style| {
            style.spacing.item_spacing = egui::vec2(8.0, 6.0);
            style.spacing.button_padding = egui::vec2(10.0, 5.0);
            style.spacing.interact_size.y = 22.0;
        });

        let (cmd_tx, cmd_rx) = channel::<Cmd>();
        let (ev_tx, ev_rx) = channel::<Ev>();
        let scan_cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_cancel = std::sync::Arc::clone(&scan_cancel);
        thread::spawn(move || worker(cmd_rx, ev_tx, worker_cancel));

        let mut app = App {
            st: State::new(),
            prefs,
            hex: hexview::HexView::new(),
            tab: Tab::Results,
            show_settings: false,
            show_modules: false,
            cmd_tx,
            ev_rx,
            demo,
            pc_scan_active: false,
            scan_cancel,
            console_log: Vec::new(),
            screenshot,
            frames: 0,
            shot_requested: false,
            shot_saved: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        if demo {
            app.fill_demo();
        } else if app.prefs.auto_connect {
            // Connect on launch: the console IP is remembered, so this is what a
            // returning user expects.
            let host = app.prefs.host.clone();
            let port = app.prefs.port.trim().parse().unwrap_or(P::DEFAULT_PORT);
            if !host.trim().is_empty() {
                let _ = app.cmd_tx.send(Cmd::Connect { host, port });
                app.st.busy = true;
                app.st.last_message = "connecting...".into();
            }
        }
        app
    }

    /// Ask whatever the worker is busy with to stop (a scan can run for
    /// minutes; the worker is single threaded, so this flag is the only way).
    pub fn cancel_work(&mut self, label: &str) {
        self.scan_cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = self.cmd_tx.send(Cmd::ScanCancel);
        let _ = self.cmd_tx.send(Cmd::PcScanCancel);
        // The worker processes this after the cancel, so the game is not left
        // frozen by the "pause while scanning" checkbox.
        self.end_scan_pause();
        self.st.last_message = label.to_string();
    }

    pub fn send(&mut self, cmd: Cmd, label: &str) {
        if !matches!(cmd, Cmd::Connect { .. } | Cmd::Disconnect) && !self.st.connected {
            self.st.log("not connected");
            return;
        }
        self.st.busy = true;
        self.st.last_message = label.to_string();
        let _ = self.cmd_tx.send(cmd);
    }

    pub fn goto(&mut self, address: u64) {
        self.hex.jump_to(address, true, &mut self.st, &self.cmd_tx);
    }

    fn pump(&mut self) {
        loop {
            match self.ev_rx.try_recv() {
                Ok(ev) => self.apply(ev),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
    }

    fn apply(&mut self, ev: Ev) {
        match ev {
            Ev::Connected { status, metadata } => {
                self.st.connected = true;
                self.st.busy = false;
                self.st.status = Some(status);
                self.st.metadata = metadata;
                // a fresh session holds nothing: never inherit the previous stop
                self.st.debug_stop = None;
                self.st.scan_paused_target = false;
                self.st.log("connected");
                let _ = self.cmd_tx.send(Cmd::FetchModules);
                // the region list is needed as soon as a scan range has to be chosen
                let _ = self.cmd_tx.send(Cmd::FetchMappings);
                if self.prefs.follow_selection && self.st.hits.is_empty() {
                    let address = self.hex.base;
                    let _ = self.cmd_tx.send(Cmd::Read { address, size: hexview::PAGE as u32 });
                }
            }
            Ev::WatchArmed { address, kind, slot } => {
                if kind == crate::protocol::break_kind::WRITE {
                    self.st.watch_armed = Some(address);
                }
                self.st.log(format!("armed: {:08X} slot {} ({})", address, slot,
                                    break_kind::name(kind)));
            }
            Ev::ConsoleLog(text) => {
                // keep the tail: this is where "scan done: ... dropped=N" lands
                self.console_log = text.lines().rev().take(400).map(|s| s.to_string())
                    .collect::<Vec<_>>();
                self.console_log.reverse();
                self.st.log(format!("console log: {} line(s)", self.console_log.len()));
            }
            Ev::Disconnected => {
                self.st.connected = false;
                self.st.busy = false;
                self.st.status = None;
                self.st.debug_stop = None;         // no console, no stop
                self.st.scan_paused_target = false;
                self.console_log.clear();      // belongs to the console we just lost
            }
            Ev::Status(status) => {
                // No stopped bit means the console let the target run again (the
                // Continue button, its own watchdog, or a fresh attach), so a
                // banner left over from the stale stop must go away.
                if !status.debug_stopped() {
                    self.st.debug_stop = None;
                }
                self.st.status = Some(status);
                self.st.busy = false;
            }
            Ev::Metadata(metadata) => {
                if let Some(st) = self.st.status.as_mut() {
                    st.main_base = metadata.main_base;
                    st.main_size = metadata.main_size;
                }
                self.st.metadata = Some(metadata);
            }
            Ev::Modules(modules) => {
                self.st.log(format!("{} module(s)", modules.len()));
                self.st.modules = modules;
            }
            Ev::Mappings(maps) => {
                self.st.log(format!("{} mapping(s) - use 'scan this' to set a custom range",
                                    maps.len()));
                self.st.mappings = maps;
            }
            Ev::Hits { hits, value_size, message } => {
                self.st.busy = false;
                self.pc_scan_active = false;      // console-side result: PC list is gone
                if value_size > 0 {
                    self.st.value_size = value_size;
                }
                self.st.log(format!("{} ({} total)", message, hits.len()));
                self.st.hits = hits;
                self.st.hits_generation = self.st.hits_generation.wrapping_add(1);
                self.st.selected = None;
                self.st.scan_progress = 0.0;
                if self.prefs.follow_selection {
                    if let Some(first) = self.st.hits.first() {
                        let address = first.address;
                        self.st.selected = Some(0);
                        self.goto(address);
                    }
                }
                self.end_scan_pause();           // the scan is over: let the game run
            }
            Ev::Read { address, data } => {
                self.hex.set_data(address, data);
            }
            Ev::DisasmData { address, data } => {
                self.st.disasm_base = address;
                self.st.disasm_bytes = data;
                self.st.busy = false;
            }
            Ev::RegsAndDisasm { ctx, address, data } => {
                // Keep the listing valid: the code is fetched 32 bytes before the PC
                // so the instruction at PC is not the first line.
                self.st.disasm_highlight_pc = Some(ctx.pc);
                self.st.disasm_base = address;
                self.st.disasm_bytes = data;
                self.st.disasm_addr_input =
                    format!("main+{:#x}", ctx.pc.wrapping_sub(self.st.main_base()));
                // Thumb code has T set in CPSR; AArch64/ARM leave that bit clear.
                if ctx.cpsr & 0x20 != 0 {
                    self.st.disasm_arch = 2;
                }
                // A Step moves the PC: the banner has to follow the listing, or it
                // keeps naming the address the target left behind.
                if let Some(stop) = self.st.debug_stop.as_mut() {
                    if stop.thread_id == ctx.thread_id || stop.thread_id == 0 {
                        stop.pc = ctx.pc;
                    }
                }
                self.st.last_regs = Some(ctx);
                self.st.busy = false;
            }
            Ev::Wrote { address, data } => {
                self.hex.patch(address, &data);
                self.st.busy = false;
            }
            Ev::Frozen { address, value } => {
                self.st.log(format!("frozen {:08X} (current value {})", address, value));
                if !self.st.frozen.contains(&address) {
                    self.st.frozen.push(address);
                }
                self.st.busy = false;
            }
            Ev::Unfrozen { address } => {
                self.st.frozen.retain(|a| *a != address);
                self.st.busy = false;
            }
            Ev::WatchlistValues(values) => {
                for (addr, val) in values {
                    for entry in &mut self.prefs.watchlist {
                        if entry.address == addr {
                            entry.value = val;
                        }
                    }
                }
                self.st.busy = false;
            }
            Ev::Chains(chains, truncated) => {
                self.st.chains_truncated = truncated;
                self.st.log(format!("{} pointer chain(s)", chains.len()));
                self.st.chains = chains;
                self.st.busy = false;
            }
            Ev::Cheat(text) => {
                self.st.cheat_text = text;
                self.st.busy = false;
            }
            Ev::BreakHits(hits) => {
                self.st.break_hits = hits;
                self.st.busy = false;
            }
            Ev::DebugStopped { thread_id, pc, address, kind, slot } => {
                if let Some(status) = self.st.status.as_mut() {
                    status.status_flags |= P::ST_DEBUG_STOPPED;
                }
                let offset = pc.wrapping_sub(self.st.main_base());
                if is_manual_stop(kind) {
                    // A stop the console made for itself (`svcBreakDebugProcess`,
                    // i.e. the Pause button / the scan pause): the target is held,
                    // but nothing was "hit", so no banner, no tab jump - just the
                    // STOPPED badge and a log line.
                    self.st.debug_stop = None;
                    self.st.log(format!(
                        "STOPPED: target held by a manual break (pc=main+{:#x}); resume to run again",
                        offset));
                    return;
                }
                self.st.busy = true;             // the register/code fetch is next
                self.st.debug_stop = Some(P::DebugStop { thread_id, pc, address, kind, slot });
                self.st.log(format!(
                    "STOPPED: thread {} at pc=main+{:#x} ({:08X}) - {} hit on {:08X} (slot {:#x})",
                    thread_id, offset, pc, break_kind::name(kind), address, slot));
                // Open the disassembly at the hitting instruction right away; the
                // bytes and the registers arrive from the worker a moment later.
                self.st.disasm_highlight_pc = Some(pc);
                self.st.disasm_base = pc.saturating_sub(32);
                self.st.disasm_addr_input = format!("main+{:#x}", offset);
                self.st.disasm_bytes.clear();    // stale code from the old base
                self.st.last_regs = None;        // the previous thread's regs, not this one's
                self.tab = Tab::Disasm;          // show the hit, not the tab we were on
                let _ = self.cmd_tx.send(Cmd::FetchThreadPcAndDisasm {
                    thread_id, pc, size: DISASM_PAGE,
                });
            }
            Ev::DebugSession { attached } => {
                // Attach/Detach answered.  Whatever the previous session parked is
                // gone: the banner and the cached context describe a thread that no
                // longer exists.  The stopped badge is NOT decided here - the status
                // reply the worker sent just before this event is the truth
                // (a fresh attach can legitimately report a held target again).
                self.st.debug_stop = None;
                self.invalidate_debug_views();
                self.st.log(if attached {
                    "debug session attached - stop state re-read from the console"
                } else {
                    "debug session detached - stop banner and cached context cleared"
                });
            }
            Ev::Snapshot { summary, changed } => {
                self.st.snapshot.summary = Some(summary);
                self.st.snapshot.changed = changed;
                self.st.busy = false;
            }
            Ev::Async { kind, payload } => match kind {
                event::BREAK_HIT if payload.len() >= BreakHit::SIZE => {
                    let hit = BreakHit::parse(&payload);
                    self.st.log(format!("watch hit: {} to {:08X}  pc=main+{:#x}",
                                        break_kind::name(hit.kind), hit.address,
                                        self.st.module_offset(hit.pc)));
                    self.st.break_hits.insert(0, hit);
                // a hot watchpoint fires continuously: keep the UI list bounded
                // (the console's ring holds the full history)
                const MAX_WATCH_ROWS: usize = 512;
                if self.st.break_hits.len() > MAX_WATCH_ROWS {
                    self.st.break_hits.truncate(MAX_WATCH_ROWS);
                }
                }
                event::HOTKEY_PAUSED => {
                    self.st.log("hotkey: target paused");
                    // NXUS_ST_PAUSED (0x0001).  0x0004 is NXUS_ST_HAS_PROCESS, and
                    // setting it here claimed a process existed long after the
                    // game had gone.  Only this bit is touched: an event must not
                    // rewrite the rest of the flag word.
                    if let Some(st) = self.st.status.as_mut() {
                        st.status_flags |= P::ST_PAUSED;
                    }
                }
                event::AUTO_RESUME => {
                    self.st.log("watchdog: target auto-resumed");
                    // The console released the target: clear the paused flag and
                    // the debug-stop bit it implies, nothing else (a `&= !bits`
                    // keeps every other flag the status reply reported).
                    if let Some(st) = self.st.status.as_mut() {
                        st.status_flags &= !(P::ST_PAUSED | P::ST_DEBUG_STOPPED);
                    }
                    self.st.debug_stop = None;   // it is running again, banner goes
                }
                event::SCAN_PROGRESS => {}
                other => self.st.log(format!("event 0x{:04X} ({} bytes)", other, payload.len())),
            },
            Ev::Progress { done, total, label } => {
                self.st.scan_progress = if total > 0 { done as f32 / total as f32 } else { 0.0 };
                self.st.last_message = format!("{} - {} / {} MB", label, done / (1024 * 1024), total / (1024 * 1024));
            }
            Ev::PcHits { hits, value_size, message, truncated } => {
                self.st.busy = false;
                let value_type = match value_size {
                    1 => ValueType::U8, 2 => ValueType::U16, 8 => ValueType::U64, _ => ValueType::U32,
                };
                self.st.value_size = value_size;
                self.st.hits = hits.into_iter().map(|(address, value)| Hit {
                    address, mapping_idx: 0, value_type: value_type as u16, value,
                }).collect();
                self.st.hits_generation = self.st.hits_generation.wrapping_add(1);
                self.st.selected = None;
                self.st.scan_progress = 0.0;
                self.st.log(message);
                self.pc_scan_active = true;      // "Next Scan" must refine the PC list
                if truncated {
                    self.st.log("hit list hit the PC-side cap - narrow the scope or raise the limit");
                }
                if self.prefs.follow_selection {
                    if let Some(first) = self.st.hits.first() {
                        let address = first.address;
                        self.st.selected = Some(0);
                        self.goto(address);
                    }
                }
                self.end_scan_pause();           // the scan is over: let the game run
            }
            Ev::Message(message) => {
                self.st.busy = false;
                self.st.log(message);
            }
            Ev::Error(message) => {
                self.st.busy = false;
                // a failed arm (e.g. not attached) must not leave the panel
                // claiming a watchpoint is armed
                self.st.watch_armed = None;
                // a scan that failed must not leave the game frozen either
                self.end_scan_pause();
                self.st.log(format!("error: {}", message));
            }
        }
    }

    fn fill_demo(&mut self) {
        let mut status = Status::default();
        status.proto_version = 1;
        status.program_id = 0x0100C3800049C000;
        status.process_id = 0x1234;
        status.main_base = 0x00700000;
        status.main_size = 0x0186B03E;
        status.hit_count = 41;
        status.status_flags = 0x0004;
        self.st.status = Some(status);
        self.st.connected = true;
        self.st.value_size = 4;

        for i in 0..41u64 {
            self.st.hits.push(Hit { address: 0x42CA1DC4 + i * 0x30, mapping_idx: 2,
                                    value_type: ValueType::U32 as u16, value: 6440 + i });
        }
        let mut data = vec![0u8; hexview::PAGE as usize];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = ((i * 7 + 0x11) & 0xFF) as u8;
        }
        self.hex.set_data(0x42CA1DC0, data);
        self.hex.base = 0x42CA1DC0;
        self.hex.cursor = 0x42CA1DC4;
        self.hex.anchor = Some(0x42CA1DC4);

        // --screenshot demo: a plausible AArch64 listing around a watch hit's PC.
        self.st.disasm_base = 0x00712300;
        self.st.disasm_highlight_pc = Some(0x00712340);
        self.st.disasm_addr_input = "main+0x12300".into();
        let mut code = Vec::with_capacity(128);
        for _ in 0..32 {
            code.extend_from_slice(&[0x1F, 0x20, 0x03, 0xD5]);   // nop
        }
        self.st.disasm_bytes = code;
        self.st.last_regs = Some(P::ThreadContext {
            thread_id: 0x1001,
            pc: 0x00712340,
            lr: 0x00712341,
            sp: 0x3600F000,
            cpsr: 0x60000010,
            ..Default::default()
        });

        self.st.chains = vec![PtrChain { root_offset: 0x81000, final_offset: 4, steps: vec![0x20] }];
        self.st.cheat_text = "[Nxus]\n540F0000 00081000\n540F1000 00000020\n780F0000 00000004\n640F0000 00000000 0098967F\n".into();
        let mut hit = BreakHit::default();
        hit.index = 3;
        hit.kind = break_kind::WRITE;
        hit.slot = 0x10;
        hit.thread_id_low = 0x1001;
        hit.address = 0x42CA1DC4;
        hit.pc = 0x00712345;
        hit.lr = 0x00712341;
        hit.sp = 0x3600F000;
        hit.cpsr = 0x60000010;
        hit.regs[3] = 3940;
        self.st.break_hits = vec![hit];
        self.st.watch_armed = Some(0x42CA1DC4);
        // --screenshot demo: the GDB-style stop that the stop banner shows.
        self.st.debug_stop = Some(P::DebugStop {
            thread_id: 0x1001,
            pc: 0x00712340,
            address: 0x42CA1DC4,
            kind: break_kind::WRITE,
            slot: 0x10,
        });
        if let Some(status) = self.st.status.as_mut() {
            status.status_flags |= P::ST_DEBUG_STOPPED;
        }
        self.st.log = vec![
            "[    0.0s] Nxus demo data (no console attached)".into(),
            "[    0.3s] connected to 127.0.0.1:7332".into(),
            "[    0.6s] 1 module(s)".into(),
            "[    1.2s] scan done: 41 hit(s)".into(),
            "[    2.0s] watchpoint armed at 42CA1DC4 (slot 16) - stop on hit".into(),
            "[    2.6s] STOPPED: thread 4097 at pc=main+0x12340 (00712340) - write hit on 42CA1DC4 (slot 0x10)".into(),
        ];
    }
}

impl eframe::App for App {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, "nxus-prefs", &self.prefs);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.pump();
        // A console that speaks another protocol version is only detectable in
        // `NxusClient::status` (worker thread, stderr there is invisible to the
        // GUI), so the worker parks the text for us: take it once and log it.
        if let Some(warning) = crate::client::take_protocol_warning() {
            self.st.log(format!("warning: {}", warning));
        }
        self.frames += 1;
        let ctx = ui.ctx().clone();

        self.handle_keys(&ctx);
        panels::top_bar(self, ui);
        panels::status_bar(self, ui);
        panels::log_panel(self, ui);
        panels::side_panel(self, ui);
        panels::central(self, ui);
        panels::settings_window(self, &ctx);

        if self.st.busy {
            ctx.request_repaint_after(Duration::from_millis(120));
        }

        // --screenshot: render a few frames, save one, then close.
        if let Some(path) = self.screenshot.clone() {
            // Wait for live data before capturing, otherwise the screenshot would
            // only show the empty state.
            let ready = if self.demo { self.frames >= 3 } else { self.st.connected || self.frames >= 150 };
            if ready && !self.shot_requested {
                self.shot_requested = true;
                let flag = std::sync::Arc::clone(&self.shot_saved);
                ctx.request_screenshot(move |image| {
                    let mut rgba = Vec::with_capacity(image.pixels.len() * 4);
                    for pixel in &image.pixels {
                        rgba.extend_from_slice(&pixel.to_array());
                    }
                    match crate::png::write_png(&path, image.width() as u32, image.height() as u32, &rgba) {
                        Ok(()) => println!("screenshot written: {} ({}x{})", path, image.width(), image.height()),
                        Err(e) => println!("screenshot failed: {}", e),
                    }
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                });
            }
            if self.shot_saved.load(std::sync::atomic::Ordering::SeqCst) {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            } else if self.frames > 3 {
                ctx.request_repaint();
            }
        }
    }
}

impl App {
    fn handle_keys(&mut self, ctx: &egui::Context) {
        let (f5, f6, f7, f8, f9, f10) = ctx.input(|i| (
            i.key_pressed(egui::Key::F5), i.key_pressed(egui::Key::F6),
            i.key_pressed(egui::Key::F7), i.key_pressed(egui::Key::F8),
            i.key_pressed(egui::Key::F9), i.key_pressed(egui::Key::F10),
        ));
        if f5 {
            self.start_scan(false);
        }
        if f6 {
            self.start_scan(true);
        }
        if f7 {
            self.send(Cmd::ScanReset, "reset");
        }
        if f8 {
            if self.st.watch_armed.is_some() {
                self.send(Cmd::Detach, "detaching");
                self.st.watch_armed = None;
            } else {
                self.send(Cmd::Attach, "attaching");
            }
        }
        if f9 {
            self.arm_watchpoint();
        }
        if f10 && self.st.is_stopped() {
            // the "let it run again" key, next to the two buttons in the banner
            self.debug_continue();
        }
    }

    pub fn start_scan(&mut self, refine: bool) {
        // "Unknown initial value" keeps millions of candidates: that list lives
        // in the PC's memory, so it goes through the PC-side path.
        let compare = SCAN_TYPE_COMPARE[self.prefs.compare.min(SCAN_TYPE_COMPARE.len() - 1)];
        if compare == Compare::Unknown {
            let value_type = crate::protocol::VALUE_TYPE_NAMES
                .get(self.prefs.value_type.min(crate::protocol::VALUE_TYPE_NAMES.len() - 1))
                .map(|(_, t)| *t)
                .unwrap_or(crate::protocol::ValueType::U32);
            if value_type.is_pattern() || value_type == crate::protocol::ValueType::All {
                self.st.log("unknown-value scans work on numeric types (byte .. double)");
                return;
            }
            let (begin, end) = panels::parse_range_ex(
                &self.st.scan_range_begin, &self.st.scan_range_end,
                self.st.main_base(), self.st.heap_base(),
            );
            self.begin_scan_pause();
            self.send(Cmd::PcScanUnknown {
                value_size: value_type.size(),
                scope: self.prefs.scope as u32,
                begin,
                end,
                max_hits: crate::pcscan::DEFAULT_MAX_HITS,
            }, "unknown-value scan (PC side)");
            return;
        }
        if refine && self.st.hits.len() > 0 && self.pc_scan_active {

            let _ = compare;
            let target = parse_scalar(&self.prefs.scan_value, self.prefs.value_type).unwrap_or(0);
            let target2 = parse_scalar(&self.prefs.scan_value2, self.prefs.value_type).unwrap_or(0);
            let mut flags = 0u32;
            if crate::protocol::VALUE_TYPE_NAMES
                .get(self.prefs.value_type.min(crate::protocol::VALUE_TYPE_NAMES.len() - 1))
                .map(|(_, t)| t.is_float()).unwrap_or(false) {
                flags |= crate::protocol::SCAN_F_FLOAT;
            }
            self.begin_scan_pause();
            self.send(Cmd::PcScanRefine {
                compare: compare as u32, target, target2, flags,
            }, "next scan (PC side)");
            return;
        }
        match build_scan_spec(&self.prefs, &self.st.scan_ranges, refine) {
            Ok(mut spec) => {
                let (begin, end) = panels::parse_range_ex(
                    &self.st.scan_range_begin, &self.st.scan_range_end,
                    self.st.main_base(), self.st.heap_base(),
                );
                spec.range_begin = begin;
                spec.range_end = end;
                let label = if refine { "next scan" } else { "first scan" };
                self.begin_scan_pause();
                if refine {
                    self.send(Cmd::ScanNext { spec }, label);
                } else {
                    self.send(Cmd::ScanBegin { spec }, label);
                }
            }
            Err(message) => self.st.log(format!("scan: {}", message)),
        }
    }

    /// "Pause target while scanning": freeze the game for the duration of a scan
    /// so nothing moves under the reads.  Only while Nxus owns the debug session
    /// (the console maps Pause to svcBreakDebugProcess there); otherwise the scan
    /// runs against a live game exactly as before.
    fn begin_scan_pause(&mut self) {
        if !self.prefs.scan_pause || self.st.scan_paused_target || !self.st.connected {
            return;
        }
        if self.st.is_stopped() {
            return;                 // already held at a breakpoint: nothing to do
        }
        let attached = self.st.status.as_ref()
            .map(|s| s.debug_attached() || s.debug_mode())
            .unwrap_or(false);
        if !attached {
            return;
        }
        self.st.scan_paused_target = true;
        self.send(Cmd::Pause, "pausing target for the scan");
    }

    /// Undo `begin_scan_pause`, from every path a scan can end on (result, error,
    /// cancel) - leaving the game frozen would look like a crash.  The pause IS a
    /// manual break while Nxus owns the debug session, so the held state has to be
    /// released here too (Resume maps to DebugContinue on the console).
    fn end_scan_pause(&mut self) {
        if !self.st.scan_paused_target {
            return;
        }
        self.st.scan_paused_target = false;
        if !self.st.connected {
            return;
        }
        self.clear_stop();
        self.send(Cmd::Resume, "resuming target");
    }

    /// Build the arm-time policy push.  It carries ONLY the debug block (16
    /// bytes, `NxusDebugConfig`): the console's hotkey/watchdog settings belong
    /// to the Settings window, and rewriting them here used to wipe a hotkey the
    /// user had just applied (the CLI had the same bug).
    fn debug_config_cmd(&self, auto_continue: u32) -> Cmd {
        Cmd::DebugConfigure { auto_continue, style: self.prefs.watch_style }
    }

    /// Arm a breakpoint the way the WATCHPOINT section does: push "stop on hit"
    /// first, then the break itself.  Used by the results table and the
    /// disassembler so those shortcuts behave identically.
    pub fn arm_breakpoint(&mut self, address: u64, kind: u32, size: u32, label: &str) {
        let auto_continue = auto_continue_for(self.prefs.watch_stop_on_hit);
        let configure = self.debug_config_cmd(auto_continue);
        self.send(configure, "configuring debug session");
        self.send(Cmd::BreakSet { address, kind, size }, label);
    }

    /// Push the current "stop on hit" choice on its own (the checkbox moved): an
    /// already armed breakpoint then keeps the new policy instead of only the
    /// next arm picking it up.
    pub fn apply_stop_on_hit(&mut self) {
        if !self.st.connected {
            return;                 // nothing to talk to; the next arm sends it
        }
        let auto_continue = auto_continue_for(self.prefs.watch_stop_on_hit);
        let configure = self.debug_config_cmd(auto_continue);
        self.send(configure, "configuring debug session");
    }

    pub fn arm_watchpoint(&mut self) {
        let address = self.hex.cursor;
        let (_, kind) = WATCH_KINDS[self.prefs.watch_kind.min(WATCH_KINDS.len() - 1)];
        let size = self.prefs.watch_size;
        // the label is set when the console confirms (Ev::WatchArmed), not here
        self.arm_breakpoint(address, kind, size, "arming watchpoint");
    }

    /// Continue past a debug stop (banner button, F10).
    ///
    /// The stop is NOT cleared here: the console has no "resumed" event, so the
    /// status reply the worker fetches right after the command is what clears the
    /// banner and the STOPPED flag.  Clearing it optimistically showed a running
    /// game for a target a failed `DebugContinue` had left stopped (and the
    /// banner, with Continue/Step on it, was gone with it).
    pub fn debug_continue(&mut self) {
        if !self.st.connected {
            self.st.log("not connected: Continue needs a live debug session (F8 attaches)");
            return;
        }
        self.send(Cmd::DebugContinue, "continuing (the banner clears once the console confirms)");
    }

    /// Single step the held thread.  A step does NOT release the target (the
    /// console keeps the stop published), so the banner stays and the context is
    /// re-read afterwards - only the PC moves.  Nothing is cleared before the
    /// console answers, for the same reason as [`App::debug_continue`].
    pub fn debug_step(&mut self) {
        if !self.st.connected {
            self.st.log("not connected: Step needs a live debug session (F8 attaches)");
            return;
        }
        let stop = self.st.debug_stop.clone();
        let thread_id = stop.as_ref().map(|s| s.thread_id).unwrap_or(0);
        let pc = stop.as_ref().map(|s| s.pc).unwrap_or(0);
        self.send(Cmd::DebugStep { thread_id }, "stepping");
        if thread_id != 0 {
            // the worker steps first and reads the fresh context right after, so
            // the listing follows the PC without a second click
            self.st.busy = true;
            let _ = self.cmd_tx.send(Cmd::FetchThreadPcAndDisasm {
                thread_id, pc, size: DISASM_PAGE,
            });
        }
    }

    /// Drop the register bar and the code listing: both belong to the thread the
    /// session had parked, so they are meaningless once the session changes
    /// (attach, detach, a fresh stop on another thread).
    fn invalidate_debug_views(&mut self) {
        self.st.last_regs = None;
        self.st.disasm_bytes.clear();
        self.st.disasm_highlight_pc = None;
    }

    /// Forget the stop DETAILS.  The stopped state itself is not cleared here:
    /// `status_flags & ST_DEBUG_STOPPED` is the only truth, and only the console
    /// (through the next status reply) can say the target runs again.
    fn clear_stop(&mut self) {
        self.st.debug_stop = None;
    }
}

/// The scan types shown in the GUI (Cheat Engine + jnoexs full set).
pub const SCAN_TYPE_NAMES: [&str; 14] = [
    "Exact Value", "Not equal (!=)", "Bigger than (>)", "Smaller than (<)",
    "Greater or equal (>=)", "Less or equal (<=)", "Value between",
    "Unknown initial value", "Increased value", "Decreased value",
    "Changed value", "Unchanged value", "Changed by (|cur-prev|)", "Fuzzy equal",
];

pub const SCAN_TYPE_COMPARE: [Compare; 14] = [
    Compare::Equal, Compare::NotEqual, Compare::Greater, Compare::Less,
    Compare::GreaterOrEqual, Compare::LessOrEqual, Compare::Between,
    Compare::Unknown, Compare::Increased, Compare::Decreased,
    Compare::Changed, Compare::Unchanged, Compare::Different, Compare::FuzzyEqual,
];

/// Parse what the user typed into a scan spec, honouring the value type.
pub fn build_scan_spec(prefs: &Prefs, ranges: &[(u64, u64)],
                        refine: bool) -> std::result::Result<crate::client::ScanSpec, String> {
    use crate::protocol::{ValueType, VALUE_TYPE_NAMES};
    let value_type = VALUE_TYPE_NAMES
        .get(prefs.value_type.min(VALUE_TYPE_NAMES.len() - 1))
        .map(|(_, t)| *t)
        .unwrap_or(ValueType::U32);

    let compare = SCAN_TYPE_COMPARE[prefs.compare.min(SCAN_TYPE_NAMES.len() - 1)];
    let mut spec = crate::client::ScanSpec::new(value_type, compare);
    spec.scope = scope_by_index(prefs.scope as u32);
    spec.value_size = value_type.size();
    if spec.scope == crate::protocol::Scope::Ranges {
        if ranges.is_empty() {
            return Err("pick at least one region (Info tab -> Memory regions -> +range)".into());
        }
        spec.ranges = ranges.to_vec();
    }
    if prefs.aligned {
        spec.flags |= crate::protocol::SCAN_F_ALIGNED;
    }

    let text = prefs.scan_value.trim();
    if value_type.is_pattern() {
        if text.is_empty() {
            return Err("enter a string or a byte pattern".into());
        }
        if value_type == ValueType::Str {
            spec.pattern = text.as_bytes().to_vec();
            if prefs.case_insensitive {
                spec.flags |= crate::protocol::SCAN_F_CASE_INSENS;
            }
            if prefs.utf16 {
                spec.flags |= crate::protocol::SCAN_F_UTF16;
            }
        } else {
            let (pattern, mask) = parseBytePattern(text)?;
            spec.pattern = pattern;
            spec.mask = mask.clone();
            if mask.iter().any(|m| *m != 0xFF) {
                spec.flags |= crate::protocol::SCAN_F_WILDCARD;
            }
        }
        if spec.pattern.len() > crate::protocol::SCAN_MAX_PATTERN {
            return Err(format!("pattern too long (max {} bytes)", crate::protocol::SCAN_MAX_PATTERN));
        }
    } else if matches!(compare, Compare::Increased | Compare::Decreased | Compare::Changed | Compare::Unchanged | Compare::Unknown) && text.is_empty() {
        spec.value = 0;
    } else {
        if text.is_empty() {
            return Err("enter a value".into());
        }
        let raw = match value_type {
            ValueType::F32 => {
                let value: f32 = text.parse().map_err(|_| format!("not a float: {}", text))?;
                value.to_bits() as u64
            }
            ValueType::F64 => {
                let value: f64 = text.parse().map_err(|_| format!("not a double: {}", text))?;
                value.to_bits()
            }
            _ => parseNumber(text).ok_or_else(|| format!("not a number: {}", text))?,
        };
        spec.value = raw;
        spec.flags |= crate::protocol::SCAN_F_FLOAT; // ignored for integers
        if !value_type.is_float() {
            spec.flags &= !crate::protocol::SCAN_F_FLOAT;
        }
        if prefs.hex_input {
            spec.flags |= crate::protocol::SCAN_F_HEX;
        }
        if compare == Compare::Between {
            let second = prefs.scan_value2.trim();
            if second.is_empty() {
                return Err("Value between needs a second number".into());
            }
            spec.target2 = match value_type {
                ValueType::F32 => second.parse::<f32>()
                    .map_err(|_| format!("not a float: {}", second))?.to_bits() as u64,
                ValueType::F64 => second.parse::<f64>()
                    .map_err(|_| format!("not a double: {}", second))?.to_bits(),
                _ => parseNumber(second).ok_or_else(|| format!("not a number: {}", second))?,
            };
        }
    }

    if refine && compare == Compare::Equal && !value_type.is_pattern() {
        // "Next Scan" with Exact Value re-checks the same value.
    }
    Ok(spec)
}

/// "DE AD ?? EF" -> (bytes, mask).  "?" or "??" means "do not care".
#[allow(non_snake_case)]
pub fn parseBytePattern(text: &str) -> std::result::Result<(Vec<u8>, Vec<u8>), String> {
    let cleaned = text.replace([' ', ',', '-'], "");
    if cleaned.is_empty() {
        return Err("empty pattern".into());
    }
    if cleaned.len() % 2 != 0 {
        return Err("byte patterns need an even number of hex digits".into());
    }
    let mut pattern = Vec::new();
    let mut mask = Vec::new();
    let bytes = cleaned.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let pair = &cleaned[i..i + 2];
        if pair == "??" || pair == "?" {
            pattern.push(0);
            mask.push(0);
        } else {
            let byte = u8::from_str_radix(pair, 16).map_err(|_| format!("not hex: {}", pair))?;
            pattern.push(byte);
            mask.push(0xFF);
        }
    }
    Ok((pattern, mask))
}

/// Parse the value box according to the selected value type (returns raw bits).
pub fn parse_scalar(text: &str, value_type_index: usize) -> Option<u64> {
    use crate::protocol::{ValueType, VALUE_TYPE_NAMES};
    let value_type = VALUE_TYPE_NAMES.get(value_type_index.min(VALUE_TYPE_NAMES.len() - 1))
        .map(|(_, t)| *t).unwrap_or(ValueType::U32);
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    match value_type {
        ValueType::F32 => text.parse::<f32>().ok().map(|v| v.to_bits() as u64),
        ValueType::F64 => text.parse::<f64>().ok().map(|v| v.to_bits()),
        _ => parseNumber(text),
    }
}

#[allow(non_snake_case)]
pub fn parseNumber(text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(&hex.replace('_', ""), 16).ok()
    } else {
        text.replace('_', "").parse::<u64>().ok()
    }
}

pub fn run(host: Option<String>, port: Option<u16>, screenshot: Option<String>, start_tab: Option<String>) -> i32 {
    let demo = screenshot.is_some() && host.is_none() && port.is_none();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("Nxus - Switch memory analysis"),
        ..Default::default()
    };

    let result = eframe::run_native(
        "Nxus",
        native_options,
        Box::new(move |cc| {
            let prefs = cc.storage
                .and_then(|storage| eframe::get_value::<Prefs>(storage, "nxus-prefs"))
                .unwrap_or_default();
            let mut prefs = prefs;
            if !demo {
                if let Some(ref h) = host {
                    prefs.host = h.clone();
                }
                if let Some(p) = port {
                    prefs.port = p.to_string();
                }
            }
            let mut app = App::new(cc, prefs, screenshot.clone(), demo);
            app.tab = match start_tab.as_deref() {
                Some("hex") => Tab::Hex,
                Some("disasm") => Tab::Disasm,
                Some("snapshot") => Tab::Snapshot,
                Some("watch") => Tab::Watch,
                Some("info") => Tab::Info,
                _ => Tab::Results,
            };
            Ok(Box::new(app))
        }),
    );

    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("gui error: {}", e);
            1
        }
    }
}
