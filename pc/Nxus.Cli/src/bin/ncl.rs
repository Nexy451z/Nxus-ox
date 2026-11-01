//! NCL - the standalone Nxus Cheat Loader.
//!
//! A small, self-contained companion to `nxus.exe`:
//!
//! * **Cheats** - connect to the console, list the cheats for the running title,
//!   turn them on/off, tick loop cheats and panic-off every patched byte.
//! * **Editor** - a built-in cheat-code editor with parse diagnostics, atomic
//!   saves and a block outline.  It works offline, without a console.
//! * **Library** - every `<BUILDID>.txt` in `cheats/` next to the executable.
//!
//! It has no dependency on `nxus.exe`: the protocol, client and cheat engine are
//! compiled into this binary.  The command line also offers `--list` and
//! `--check` for scripted verification of a cheat file.
//!
//! Usage:
//!   NCL.exe                          open the GUI
//!   NCL.exe --host 192.168.1.13      open the GUI with an address prefilled
//!   NCL.exe --list FILE              list the blocks in a cheat file
//!   NCL.exe --check FILE             validate a cheat file (exit 1 on issues)
//!   NCL.exe --screenshot out.png     render one frame and exit
#![allow(dead_code)]

// The engine re-exports its whole public surface for both binaries; each one
// uses a different subset, so unused re-exports are expected here.
#[allow(unused_imports)]
#[path = "../cheat/mod.rs"]
mod cheat;
#[path = "../client.rs"]
mod client;
#[path = "../pcscan.rs"]
mod pcscan;
#[path = "../png.rs"]
mod png;
#[path = "../protocol.rs"]
mod protocol;

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use egui::{Color32, RichText};

use cheat::{
    normalize_build_id, save_text_atomic, CheatDocument, CheatKey, CheatManager, CheatMemoryIo,
    MemoryRegions, TargetIdentity, MAX_CHEAT_FILE_BYTES,
};
use client::NxusClient;
use protocol::{Metadata, Status, WRITE_FLAG_ALLOW_RX};

const APP_NAME: &str = "NCL";
const DEFAULT_PORT: u16 = 7332;
const TICK_INTERVAL: Duration = Duration::from_millis(250);
const MAX_LOG_LINES: usize = 500;

const ACCENT: Color32 = Color32::from_rgb(96, 174, 255);
const GREEN: Color32 = Color32::from_rgb(104, 208, 128);
const RED: Color32 = Color32::from_rgb(244, 112, 112);
const YELLOW: Color32 = Color32::from_rgb(238, 200, 96);
const DIM: Color32 = Color32::from_rgb(150, 156, 166);

const JP_FONT: &[u8] = include_bytes!("../../assets/fonts/MPLUS1p-Regular.ttf");

const TEMPLATE: &str = "\
; NCL cheat file
; A [Name] line starts a cheat. Append :OFF to leave it off initially.
; Code lines are Atmosphere cheat opcodes; ';', '#' and '//' start a comment.
;
; [Nxus example]
; 580F0000 00000000            ; load [main+0] into register 0
; 640F0000 00000000 00000001   ; write 1 to [reg0+0]
";

// ---------------------------------------------------------------------------
// Shared snapshots (worker -> UI)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct CheatRow {
    key: CheatKey,
    name: String,
    kind: String,
    mode: String,
    live: bool,
    file_on: bool,
    restore_only: bool,
    trigger: bool,
    instructions: usize,
    off_instructions: usize,
    issues: usize,
    error: Option<String>,
    source_line: usize,
    explicit_off: bool,
}

#[derive(Clone, Debug)]
struct BackupRow {
    address: u64,
    width: u8,
    owners: usize,
    state: String,
}

#[derive(Clone, Debug)]
struct TargetView {
    pid: u64,
    program_id: u64,
    incarnation: u64,
    build_id: String,
    main_base: u64,
    heap_base: u64,
    alias_base: u64,
    aslr_base: u64,
    path: PathBuf,
    journal: PathBuf,
    enabled: usize,
    loops: usize,
    patches: usize,
    backups: usize,
    issues: usize,
    last_error: Option<String>,
}

#[derive(Clone, Debug)]
struct LiveView {
    target: TargetView,
    rows: Vec<CheatRow>,
    backup_rows: Vec<BackupRow>,
}

impl LiveView {
    fn any_enabled(&self) -> bool {
        self.rows.iter().any(|row| row.live)
    }

    fn has_loops(&self) -> bool {
        self.rows.iter().any(|row| row.live && row.mode == "Loop")
    }
}

fn make_view(manager: &CheatManager) -> LiveView {
    let snapshot = manager.snapshot();
    let rows = manager
        .blocks()
        .iter()
        .map(|block| CheatRow {
            key: block.key,
            name: block.name.clone(),
            kind: block.kind.as_str().to_string(),
            mode: block.mode.as_str().to_string(),
            live: manager.is_enabled(block.key),
            file_on: block.enabled,
            restore_only: block.is_restore_only(),
            trigger: block.has_keypad_trigger(),
            instructions: block.on.instructions.len(),
            off_instructions: block
                .off
                .as_ref()
                .map(|code| code.instructions.len())
                .unwrap_or(0),
            issues: block.all_issues().len(),
            error: manager.errors().get(&block.key).cloned(),
            source_line: block.source_line,
            explicit_off: block.explicit_off || block.off.is_some(),
        })
        .collect();
    let backup_rows = manager
        .backups()
        .values()
        .map(|entry| BackupRow {
            address: entry.address,
            width: entry.width,
            owners: entry.owners.len(),
            state: match entry.state {
                cheat::BackupState::Pending => "pending".to_string(),
                cheat::BackupState::Committed => "committed".to_string(),
            },
        })
        .collect();
    let identity = manager.identity().clone();
    let regions = manager.regions();
    let target = TargetView {
        pid: identity.pid,
        program_id: identity.program_id,
        incarnation: identity.incarnation,
        build_id: identity.build_id.clone(),
        main_base: regions.main,
        heap_base: regions.heap,
        alias_base: regions.alias,
        aslr_base: regions.aslr,
        path: manager.path().to_path_buf(),
        journal: manager.journal_path().to_path_buf(),
        enabled: snapshot.enabled,
        loops: snapshot.loops,
        patches: snapshot.patches,
        backups: snapshot.backups,
        issues: snapshot.issues,
        last_error: snapshot.last_error.clone(),
    };
    LiveView {
        target,
        rows,
        backup_rows,
    }
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

enum Job {
    Connect { host: String, port: u16 },
    Disconnect,
    Refresh,
    Toggle { key: CheatKey, on: bool },
    Tick,
    PanicOff,
    ReloadFile,
}

enum Ev {
    Opened(LiveView, String),
    Updated(LiveView, String),
    /// Panic-off finished.  `complete` is false when some original bytes could
    /// not be written, in which case the quit modal must stay open.
    Restored(LiveView, String, bool),
    Ticked(LiveView),
    Error(String),
    Disconnected(String),
    Log(String),
}

struct Session {
    client: NxusClient,
    manager: CheatManager,
    /// True once *this* session has enabled a cheat and its bytes are not all
    /// back yet.  Journal entries loaded from an earlier run do not set it, so
    /// connecting or disconnecting never silently undoes another tool's work.
    dirty: bool,
}

struct ClientCheatIo<'a> {
    client: &'a NxusClient,
}

impl CheatMemoryIo for ClientCheatIo<'_> {
    fn read_mem(&mut self, address: u64, size: u32) -> Result<Vec<u8>, String> {
        self.client
            .read(address, size)
            .map_err(|error| error.to_string())
    }

    fn write_mem(&mut self, address: u64, data: &[u8], allow_rx: bool) -> Result<(), String> {
        let result = if allow_rx {
            self.client
                .write_with_flags(address, data, WRITE_FLAG_ALLOW_RX)
        } else {
            self.client.write(address, data)
        };
        result.map_err(|error| error.to_string())
    }

    fn pause_process(&mut self) -> Result<(), String> {
        self.client.pause().map_err(|error| error.to_string())
    }

    fn resume_process(&mut self) -> Result<(), String> {
        self.client.resume().map_err(|error| error.to_string())
    }
}

/// Identity of the process the console is running *now*.
fn probe_target(client: &NxusClient) -> Result<(TargetIdentity, MemoryRegions), String> {
    let status = client
        .status()
        .map_err(|error| format!("status: {error}"))?;
    let metadata = client
        .metadata()
        .map_err(|error| format!("metadata: {error}"))?;
    let pid = if metadata.process_id != 0 {
        metadata.process_id
    } else {
        status.process_id
    };
    let program_id = if metadata.program_id != 0 {
        metadata.program_id
    } else {
        status.program_id
    };
    let incarnation = metadata.main_base
        ^ metadata.heap_base.rotate_left(17)
        ^ metadata.alias_base.rotate_left(33)
        ^ metadata.aslr_base.rotate_left(49);
    let identity = TargetIdentity::new(pid, program_id, incarnation, metadata.build_id_hex())?;
    let regions = MemoryRegions::new(
        metadata.main_base,
        metadata.heap_base,
        metadata.alias_base,
        metadata.aslr_base,
    );
    Ok((identity, regions))
}

/// `Ok(true)` same process, `Ok(false)` the title restarted, `Err` cannot tell.
///
/// The distinction matters: a restart means the old patches died with the old
/// process and must never be written to the new one, while an unreadable console
/// means the session must be kept so the user can retry.
fn check_target(session: &Session) -> Result<bool, String> {
    let (identity, _) = probe_target(&session.client)?;
    Ok(identity.is_same_target(session.manager.identity()))
}

fn open_session(host: &str, port: u16) -> Result<(Session, String), String> {
    let client = NxusClient::connect(host, port)
        .map_err(|error| format!("connect {host}:{port}: {error}"))?;
    let status: Status = client
        .status()
        .map_err(|error| format!("status: {error}"))?;
    let metadata: Metadata = match client.metadata() {
        Ok(metadata) => metadata,
        Err(first) => {
            // A fresh dmnt has no cheat process yet.  Opening it is exactly what
            // `metadata`/`scan begin` does; retry once so NCL can start first.
            client
                .force_open()
                .map_err(|error| format!("metadata: {first}; opening dmnt: {error}"))?;
            client
                .metadata()
                .map_err(|error| format!("metadata after force-open: {error}"))?
        }
    };

    let pid = if metadata.process_id != 0 {
        metadata.process_id
    } else {
        status.process_id
    };
    let program_id = if metadata.program_id != 0 {
        metadata.program_id
    } else {
        status.program_id
    };
    // The protocol carries no incarnation counter.  Use the same per-process
    // address fingerprint as `nxus cheat ...`, so NCL and the CLI share one
    // backup journal for the lifetime of a title process.
    let incarnation = metadata.main_base
        ^ metadata.heap_base.rotate_left(17)
        ^ metadata.alias_base.rotate_left(33)
        ^ metadata.aslr_base.rotate_left(49);
    let identity = TargetIdentity::new(pid, program_id, incarnation, metadata.build_id_hex())
        .map_err(|message| format!("{message} (is a title running and dmnt attached?)"))?;
    let regions = MemoryRegions::new(
        metadata.main_base,
        metadata.heap_base,
        metadata.alias_base,
        metadata.aslr_base,
    );
    let path = cheat::resolve_cheat_path(&identity.build_id)?;
    let manager = CheatManager::open_with_path(identity, regions, path)?;
    let text = manager.document().raw_text.clone();
    Ok((
        Session {
            client,
            manager,
            dirty: false,
        },
        text,
    ))
}

/// Restore the patches this session enabled.  The session is only dropped when
/// every original byte is back; otherwise the UI keeps it so the user can retry.
fn retire(session: &mut Session) -> Result<String, String> {
    if !session.dirty {
        return Ok("disconnected".to_string());
    }
    match check_target(session) {
        Ok(true) => {}
        Ok(false) => {
            // The process is gone; its patches went with it.  Writing the old
            // originals to whatever now owns those addresses would corrupt the
            // new title.
            session.dirty = false;
            return Ok("the title restarted; old patches died with it".to_string());
        }
        Err(error) => {
            return Err(format!(
                "cannot verify the target before restoring ({error}); not writing anything"
            ));
        }
    }
    let mut io = ClientCheatIo {
        client: &session.client,
    };
    let report = session.manager.restore_all_backups(&mut io);
    if !report.is_complete() {
        let failures = report
            .failed
            .iter()
            .map(|(address, error)| format!("{address:08X}: {error}"))
            .collect::<Vec<_>>()
            .join(", ");
        // `restore_all_backups` clears the enabled set even when a write fails,
        // so keep `dirty` set: the next attempt must retry the remaining
        // journal entries instead of dropping the session.
        return Err(format!(
            "restored {} address(es) but failed for {}; still connected so you can retry",
            report.restored, failures
        ));
    }
    session.dirty = false;
    Ok(format!(
        "restored {} address(es) before disconnecting",
        report.restored
    ))
}

fn run_worker(rx: Receiver<Job>, tx: Sender<Ev>) {
    let mut session: Option<Session> = None;

    while let Ok(job) = rx.recv() {
        match job {
            Job::Connect { host, port } => {
                if let Some(mut old) = session.take() {
                    if let Err(error) = retire(&mut old) {
                        session = Some(old);
                        let _ = tx.send(Ev::Error(error));
                        continue;
                    }
                }
                match open_session(&host, port) {
                    Ok((new_session, text)) => {
                        let view = make_view(&new_session.manager);
                        session = Some(new_session);
                        let _ = tx.send(Ev::Opened(view, text));
                    }
                    Err(error) => {
                        // The old session (if any) is already gone; the UI must not
                        // keep showing its rows as if it were still connected.
                        let _ = tx.send(Ev::Disconnected("not connected".to_string()));
                        let _ = tx.send(Ev::Error(error));
                    }
                }
            }
            Job::Disconnect => {
                let Some(mut current) = session.take() else {
                    let _ = tx.send(Ev::Disconnected("not connected".to_string()));
                    continue;
                };
                match retire(&mut current) {
                    Ok(message) => {
                        drop(current);
                        let _ = tx.send(Ev::Disconnected(message));
                    }
                    Err(error) => {
                        session = Some(current);
                        let _ = tx.send(Ev::Error(error));
                    }
                }
            }
            Job::Refresh => {
                let Some(current) = session.take() else {
                    let _ = tx.send(Ev::Error("not connected".to_string()));
                    continue;
                };
                match check_target(&current) {
                    Ok(true) => {
                        let view = make_view(&current.manager);
                        session = Some(current);
                        let _ = tx.send(Ev::Updated(view, "refreshed".to_string()));
                    }
                    Ok(false) => {
                        let _ = tx.send(Ev::Disconnected(
                            "the title restarted - reconnect".to_string(),
                        ));
                        let _ = tx.send(Ev::Error(
                            "target process changed; NCL dropped the old session instead of \
                             writing to the new process"
                                .to_string(),
                        ));
                    }
                    Err(error) => {
                        session = Some(current);
                        let _ = tx.send(Ev::Error(format!("refresh: {error}")));
                    }
                }
            }
            Job::Toggle { key, on } => {
                let Some(mut current) = session.take() else {
                    let _ = tx.send(Ev::Error("not connected".to_string()));
                    continue;
                };
                match check_target(&current) {
                    Ok(true) => {}
                    Ok(false) => {
                        let _ = tx.send(Ev::Disconnected(
                            "the title restarted - reconnect".to_string(),
                        ));
                        let _ = tx.send(Ev::Error(
                            "target process changed; refusing to write to the new process"
                                .to_string(),
                        ));
                        continue;
                    }
                    Err(error) => {
                        session = Some(current);
                        let _ = tx.send(Ev::Error(format!(
                            "cannot verify the target before toggling ({error}); nothing written"
                        )));
                        continue;
                    }
                }
                let name = current
                    .manager
                    .block(key)
                    .map(|block| block.name.clone())
                    .unwrap_or_else(|| key.to_string());
                let mut io = ClientCheatIo {
                    client: &current.client,
                };
                match current.manager.toggle(key, on, &mut io) {
                    Ok(()) => {
                        if on {
                            current.dirty = true;
                        } else if current.manager.enabled_keys().is_empty()
                            && current.manager.backups().is_empty()
                        {
                            current.dirty = false;
                        }
                        let view = make_view(&current.manager);
                        session = Some(current);
                        let message = if on {
                            format!("enabled '{name}'")
                        } else {
                            format!("disabled '{name}'")
                        };
                        let _ = tx.send(Ev::Updated(view, message));
                    }
                    Err(error) => {
                        let view = make_view(&current.manager);
                        session = Some(current);
                        let _ = tx.send(Ev::Updated(view, format!("could not toggle '{name}'")));
                        let _ = tx.send(Ev::Error(format!("{name}: {error}")));
                    }
                }
            }
            Job::Tick => {
                let Some(mut current) = session.take() else {
                    continue;
                };
                // Key-conditional cheats need the live button mask; the same
                // status request proves the title is still the one this manager
                // belongs to.  A mismatch must stop the loops BEFORE another
                // write reaches the restarted process.
                let status = current.client.status();
                if let Ok(status) = &status {
                    let identity = current.manager.identity();
                    let pid_changed = status.process_id != 0 && status.process_id != identity.pid;
                    let program_changed =
                        status.program_id != 0 && status.program_id != identity.program_id;
                    if pid_changed || program_changed {
                        let _ = tx.send(Ev::Disconnected(
                            "the title restarted - reconnect".to_string(),
                        ));
                        let _ = tx.send(Ev::Error(
                            "target process changed; stopped the loop cheats without writing"
                                .to_string(),
                        ));
                        continue;
                    }
                }
                let keys = status.map(|status| status.keys_held).unwrap_or(0);
                let mut io = ClientCheatIo {
                    client: &current.client,
                };
                let report = current.manager.tick(&mut io, keys);
                let view = make_view(&current.manager);
                session = Some(current);
                let _ = tx.send(Ev::Ticked(view));
                if let Some((_, error)) = report.errors.first() {
                    let _ = tx.send(Ev::Log(format!("loop: {error}")));
                }
            }
            Job::PanicOff => {
                let Some(mut current) = session.take() else {
                    let _ = tx.send(Ev::Error("not connected".to_string()));
                    continue;
                };
                match check_target(&current) {
                    Ok(true) => {}
                    Ok(false) => {
                        let _ = tx.send(Ev::Disconnected(
                            "the title restarted - nothing to restore".to_string(),
                        ));
                        let _ = tx.send(Ev::Error(
                            "target process changed; the old patches died with it".to_string(),
                        ));
                        continue;
                    }
                    Err(error) => {
                        session = Some(current);
                        let _ = tx.send(Ev::Error(format!(
                            "cannot verify the target before restoring ({error}); nothing written"
                        )));
                        continue;
                    }
                }
                let mut io = ClientCheatIo {
                    client: &current.client,
                };
                let report = current.manager.restore_all_backups(&mut io);
                if report.is_complete() {
                    current.dirty = false;
                }
                let view = make_view(&current.manager);
                session = Some(current);
                let message = format!(
                    "restored {} address(es), cleared {} enabled cheat(s)",
                    report.restored, report.cleared_cheats
                );
                let complete = report.is_complete();
                let failed = report.failed.len();
                let _ = tx.send(Ev::Restored(view, message, complete));
                if !complete {
                    let _ = tx.send(Ev::Error(format!(
                        "{failed} address(es) could not be restored - keep the console and retry"
                    )));
                }
            }
            Job::ReloadFile => {
                let Some(current) = session.as_mut() else {
                    let _ = tx.send(Ev::Error("not connected".to_string()));
                    continue;
                };
                if !current.manager.enabled_keys().is_empty() {
                    let _ = tx.send(Ev::Error(
                        "turn every cheat off before reloading the file".to_string(),
                    ));
                    continue;
                }
                match current.manager.reload() {
                    Ok(()) => {
                        let view = make_view(&current.manager);
                        let text = current.manager.document().raw_text.clone();
                        let _ = tx.send(Ev::Opened(view, text));
                    }
                    Err(error) => {
                        let _ = tx.send(Ev::Error(format!("reload: {error}")));
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Editor / library state
// ---------------------------------------------------------------------------

#[derive(Default)]
struct EditorState {
    text: String,
    path: PathBuf,
    build_id: String,
    last_saved: String,
    validated_text: String,
    report: Option<EditorReport>,
    last_edit: Option<Instant>,
}

impl EditorState {
    fn dirty(&self) -> bool {
        self.text != self.last_saved
    }

    fn set_text(&mut self, text: impl Into<String>) {
        self.text = text.into();
        self.last_saved = self.text.clone();
        self.validated_text.clear();
        self.report = None;
        self.last_edit = None;
    }

    fn load(&mut self, path: &Path) -> Result<(), String> {
        let metadata = std::fs::metadata(path)
            .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
        if metadata.len() > MAX_CHEAT_FILE_BYTES {
            return Err(format!(
                "{} is {} bytes; the maximum is {} bytes",
                path.display(),
                metadata.len(),
                MAX_CHEAT_FILE_BYTES
            ));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        self.build_id = build_id_from_path(path).unwrap_or_default();
        self.path = path.to_path_buf();
        self.set_text(text);
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct EditorReport {
    blocks: usize,
    instructions: usize,
    issues: Vec<String>,
    bytes: usize,
    lines: usize,
}

fn build_id_from_path(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    normalize_build_id(stem).ok()
}

#[derive(Clone, Debug)]
struct LibFile {
    path: PathBuf,
    name: String,
    build_id: String,
    blocks: usize,
    issues: usize,
    bytes: u64,
}

#[derive(Default)]
struct LibraryState {
    dir: PathBuf,
    files: Vec<LibFile>,
    error: Option<String>,
}

fn scan_library(dir: &Path) -> (Vec<LibFile>, Option<String>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            return (
                Vec::new(),
                Some(format!("cannot list {}: {error}", dir.display())),
            )
        }
    };
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let is_txt = path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.eq_ignore_ascii_case("txt"))
            .unwrap_or(false);
        if !is_txt {
            continue;
        }
        // `cheats/README.txt` (shipped by the build) and other notes are not
        // cheat files.  Only the canonical <BUILDID>.txt belongs in the library;
        // anything else can still be opened with the Editor's path box.
        let Some(build_id) = build_id_from_path(&path) else {
            continue;
        };
        let bytes = entry.metadata().map(|metadata| metadata.len()).unwrap_or(0);
        let document = if bytes <= MAX_CHEAT_FILE_BYTES {
            cheat::parse_file(&path, &build_id).ok()
        } else {
            None
        };
        files.push(LibFile {
            name: path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("?")
                .to_string(),
            build_id,
            blocks: document.as_ref().map(|doc| doc.blocks.len()).unwrap_or(0),
            issues: document
                .as_ref()
                .map(|doc| doc.issues_with_block().len())
                .unwrap_or(0),
            bytes,
            path,
        });
    }
    files.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    (files, None)
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Cheats,
    Editor,
    Library,
    Log,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct Prefs {
    host: String,
    port: String,
    auto_tick: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            host: "127.0.0.1".to_string(),
            port: DEFAULT_PORT.to_string(),
            auto_tick: true,
        }
    }
}

struct NclApp {
    tab: Tab,
    host: String,
    port: String,
    auto_tick: bool,

    tx: Sender<Job>,
    rx: Receiver<Ev>,
    busy: Option<String>,
    message: String,

    live: Option<LiveView>,
    live_text: Option<String>,

    editor: EditorState,
    library: LibraryState,

    filter: String,
    only_enabled: bool,

    log: VecDeque<String>,
    started: Instant,
    last_tick: Instant,
    last_loop_error: Option<String>,

    panic_confirm: bool,
    quit_confirm: bool,
    quit_after_restore: bool,
    allow_close: bool,
    pending_close: bool,

    screenshot: Option<PathBuf>,
    auto_connect: bool,
    frames: u64,
    shot_requested: bool,
    shot_saved: Arc<AtomicBool>,
}

impl NclApp {
    fn new(
        cc: &eframe::CreationContext<'_>,
        prefs: Prefs,
        screenshot: Option<PathBuf>,
        initial_file: Option<PathBuf>,
        auto_connect: bool,
        start_tab: Option<Tab>,
    ) -> NclApp {
        cc.egui_ctx.set_fonts(font_definitions());
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        cc.egui_ctx.all_styles_mut(|style| {
            style.spacing.item_spacing = egui::vec2(8.0, 6.0);
            style.spacing.button_padding = egui::vec2(10.0, 5.0);
            style.spacing.interact_size.y = 22.0;
        });

        let (tx, job_rx) = mpsc::channel::<Job>();
        let (ev_tx, ev_rx) = mpsc::channel::<Ev>();
        std::thread::Builder::new()
            .name("ncl-worker".to_string())
            .spawn(move || run_worker(job_rx, ev_tx))
            .expect("cannot start the NCL worker thread");

        let dir = cheat::cheats_directory().unwrap_or_else(|_| PathBuf::from("cheats"));
        let (files, library_error) = scan_library(&dir);

        let mut app = NclApp {
            tab: Tab::Cheats,
            host: prefs.host,
            port: prefs.port,
            auto_tick: prefs.auto_tick,
            tx,
            rx: ev_rx,
            busy: None,
            message: "ready".to_string(),
            live: None,
            live_text: None,
            editor: EditorState::default(),
            library: LibraryState {
                dir,
                files,
                error: library_error,
            },
            filter: String::new(),
            only_enabled: false,
            log: VecDeque::new(),
            started: Instant::now(),
            last_tick: Instant::now(),
            last_loop_error: None,
            panic_confirm: false,
            quit_confirm: false,
            quit_after_restore: false,
            allow_close: screenshot.is_some(),
            pending_close: false,
            screenshot,
            auto_connect,
            frames: 0,
            shot_requested: false,
            shot_saved: Arc::new(AtomicBool::new(false)),
        };
        if let Some(tab) = start_tab {
            app.tab = tab;
        }
        app.log(format!(
            "NCL {} - cheats directory {}",
            env!("CARGO_PKG_VERSION"),
            app.library.dir.display()
        ));
        if let Some(error) = app.library.error.clone() {
            app.log(format!("warning: {error}"));
        }
        if let Some(path) = initial_file {
            app.open_file(path);
        }
        if auto_connect {
            app.connect();
        }
        app
    }

    fn log(&mut self, message: impl Into<String>) {
        let elapsed = self.started.elapsed().as_secs_f64();
        self.log
            .push_back(format!("[{elapsed:6.1}s] {}", message.into()));
        while self.log.len() > MAX_LOG_LINES {
            self.log.pop_front();
        }
    }

    fn submit(&mut self, label: &str, job: Job) {
        // A periodic loop tick is a short, cancellable unit: let a real user
        // action queue behind it instead of being swallowed four times a second.
        if self
            .busy
            .as_deref()
            .map(|busy| busy != "tick")
            .unwrap_or(false)
        {
            self.message = format!("busy: {}", self.busy.as_deref().unwrap_or(""));
            return;
        }
        match self.tx.send(job) {
            Ok(()) => {
                self.busy = Some(label.to_string());
                self.message = label.to_string();
            }
            Err(error) => {
                self.message = format!("worker stopped: {error}");
                self.log(self.message.clone());
            }
        }
    }

    fn connect(&mut self) {
        let host = self.host.trim().to_string();
        if host.is_empty() {
            self.message = "enter the console IP address".to_string();
            return;
        }
        let port = self.port.trim().parse::<u16>().unwrap_or(DEFAULT_PORT);
        self.submit("connecting", Job::Connect { host, port });
    }

    fn any_enabled(&self) -> bool {
        self.live
            .as_ref()
            .map(LiveView::any_enabled)
            .unwrap_or(false)
    }

    fn drain_events(&mut self) {
        loop {
            match self.rx.try_recv() {
                Ok(Ev::Opened(view, text)) => {
                    self.busy = None;
                    self.message = format!("opened {}", view.target.path.display());
                    self.log(self.message.clone());
                    self.editor.path = view.target.path.clone();
                    self.editor.build_id = view.target.build_id.clone();
                    if self.editor.dirty() {
                        self.log(
                            "editor has unsaved changes; kept them (use \"Use target file\" to replace)",
                        );
                    } else {
                        self.editor.set_text(text.clone());
                    }
                    self.live_text = Some(text);
                    self.live = Some(view);
                    self.last_tick = Instant::now();
                }
                Ok(Ev::Updated(view, message)) => {
                    self.busy = None;
                    self.message = message.clone();
                    self.log(message);
                    self.live = Some(view);
                }
                Ok(Ev::Restored(view, message, complete)) => {
                    self.busy = None;
                    self.message = message.clone();
                    self.log(message);
                    self.live = Some(view);
                    if complete {
                        if self.quit_after_restore {
                            self.quit_after_restore = false;
                            self.allow_close = true;
                            self.quit_confirm = false;
                            self.pending_close = true;
                        }
                    } else {
                        // Keep the quit confirmation visible so the user can retry
                        // instead of closing with patches still in place.
                        self.quit_after_restore = false;
                    }
                }
                Ok(Ev::Ticked(view)) => {
                    if self.busy.as_deref() == Some("tick") {
                        self.busy = None;
                    }
                    self.live = Some(view);
                }
                Ok(Ev::Error(error)) => {
                    self.busy = None;
                    self.message = error.clone();
                    self.log(format!("error: {error}"));
                }
                Ok(Ev::Disconnected(message)) => {
                    self.busy = None;
                    self.message = message.clone();
                    self.log(message);
                    self.live = None;
                    self.live_text = None;
                }
                Ok(Ev::Log(message)) => {
                    // A broken Loop cheat would otherwise repeat the same error
                    // four times a second and flush the whole log.
                    if message.starts_with("loop:")
                        && self.last_loop_error.as_deref() == Some(&message)
                    {
                        continue;
                    }
                    if message.starts_with("loop:") {
                        self.last_loop_error = Some(message.clone());
                    }
                    self.log(message);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.busy = None;
                    break;
                }
            }
        }
    }

    fn schedule_tick(&mut self) {
        let Some(live) = self.live.as_ref() else {
            return;
        };
        if !self.auto_tick || !live.has_loops() || self.busy.is_some() {
            return;
        }
        if self.last_tick.elapsed() < TICK_INTERVAL {
            return;
        }
        self.last_tick = Instant::now();
        self.busy = Some("tick".to_string());
        if self.tx.send(Job::Tick).is_err() {
            self.busy = None;
        }
    }

    fn open_file(&mut self, path: PathBuf) {
        match self.editor.load(&path) {
            Ok(()) => {
                self.tab = Tab::Editor;
                self.message = format!("loaded {}", path.display());
                self.log(self.message.clone());
                self.refresh_parse();
            }
            Err(error) => {
                self.message = error.clone();
                self.log(format!("error: {error}"));
            }
        }
    }

    fn refresh_parse(&mut self) {
        let raw_build_id = self.editor.build_id.trim();
        let build_id = if raw_build_id.is_empty() {
            "0000000000000000".to_string()
        } else {
            match normalize_build_id(raw_build_id) {
                Ok(build_id) => build_id,
                Err(error) => {
                    // Parse anyway so the code can be checked offline, but say why
                    // saving under this name will fail.
                    let document = CheatDocument::parse(&self.editor.text, "0000000000000000");
                    let mut issues: Vec<String> = Vec::new();
                    issues.push(format!("build id: {error}"));
                    issues.extend(
                        document
                            .issues_with_block()
                            .into_iter()
                            .map(|issue| issue.to_string()),
                    );
                    self.editor.report = Some(EditorReport {
                        blocks: document.blocks.len(),
                        instructions: document
                            .blocks
                            .iter()
                            .map(|block| block.on.instructions.len())
                            .sum(),
                        issues,
                        bytes: self.editor.text.len(),
                        lines: self.editor.text.lines().count(),
                    });
                    self.editor.validated_text = self.editor.text.clone();
                    self.editor.last_edit = None;
                    return;
                }
            }
        };
        let document = CheatDocument::parse(&self.editor.text, &build_id);
        let mut issues: Vec<String> = document
            .issues_with_block()
            .into_iter()
            .map(|issue| issue.to_string())
            .collect();
        let instructions = document
            .blocks
            .iter()
            .map(|block| block.on.instructions.len())
            .sum();
        if issues.len() > 200 {
            let extra = issues.len() - 200;
            issues.truncate(200);
            issues.push(format!("... and {extra} more issue(s)"));
        }
        self.editor.report = Some(EditorReport {
            blocks: document.blocks.len(),
            instructions,
            issues,
            bytes: self.editor.text.len(),
            lines: self.editor.text.lines().count(),
        });
        self.editor.validated_text = self.editor.text.clone();
        self.editor.last_edit = None;
    }

    fn editor_path(&self) -> Result<PathBuf, String> {
        if !self.editor.path.as_os_str().is_empty() {
            return Ok(self.editor.path.clone());
        }
        let build_id = normalize_build_id(&self.editor.build_id)?;
        Ok(self.library.dir.join(format!("{build_id}.txt")))
    }

    fn save_editor(&mut self, force: bool) {
        if self.any_enabled() && !force {
            self.message =
                "turn every cheat off before saving (the manager would lose its backups)"
                    .to_string();
            self.log(self.message.clone());
            return;
        }
        let path = match self.editor_path() {
            Ok(path) => path,
            Err(error) => {
                self.message = error.clone();
                self.log(format!("error: {error}"));
                return;
            }
        };
        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                self.message = format!("cannot create {}: {error}", parent.display());
                self.log(self.message.clone());
                return;
            }
        }
        match save_text_atomic(&path, &self.editor.text) {
            Ok(()) => {
                self.editor.path = path.clone();
                self.editor.last_saved = self.editor.text.clone();
                self.refresh_parse();
                let (files, error) = scan_library(&self.library.dir);
                self.library.files = files;
                self.library.error = error;
                self.message = format!("saved {}", path.display());
                self.log(self.message.clone());
                if let Some(live) = &self.live {
                    if live.target.path == path {
                        self.submit("reloading the target file", Job::ReloadFile);
                    }
                }
            }
            Err(error) => {
                self.message = format!("save failed: {error}");
                self.log(self.message.clone());
            }
        }
    }

    fn new_file(&mut self) {
        self.editor.path = PathBuf::new();
        self.editor.build_id = self
            .live
            .as_ref()
            .map(|live| live.target.build_id.clone())
            .unwrap_or_default();
        let header = if self.editor.build_id.is_empty() {
            TEMPLATE.to_string()
        } else {
            format!(
                "; NCL cheat file for build {}\n{}",
                self.editor.build_id, TEMPLATE
            )
        };
        self.editor.set_text(header);
        self.tab = Tab::Editor;
        self.refresh_parse();
    }

    fn use_target_file(&mut self) {
        if let Some(text) = self.live_text.clone() {
            self.editor.set_text(text);
            if let Some(live) = &self.live {
                self.editor.path = live.target.path.clone();
                self.editor.build_id = live.target.build_id.clone();
            }
            self.refresh_parse();
            self.message = "loaded the connected target's cheat file".to_string();
        } else {
            self.message = "connect first".to_string();
        }
    }

    // -- UI ----------------------------------------------------------------

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("ncl-top").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("NCL").heading().color(ACCENT));
                ui.label(RichText::new("Nxus Cheat Loader").color(DIM));
                ui.separator();
                ui.label("host");
                ui.add(egui::TextEdit::singleline(&mut self.host).desired_width(130.0));
                ui.label("port");
                ui.add(egui::TextEdit::singleline(&mut self.port).desired_width(55.0));
                if self.live.is_some() {
                    if ui
                        .button("Disconnect")
                        .on_hover_text("restore patches this session enabled, then disconnect")
                        .clicked()
                    {
                        self.submit("disconnecting", Job::Disconnect);
                    }
                } else if ui
                    .add(egui::Button::new(RichText::new("Connect").strong()))
                    .clicked()
                {
                    self.connect();
                }
                if ui
                    .add_enabled(self.live.is_some(), egui::Button::new("Refresh"))
                    .clicked()
                {
                    self.submit("refreshing", Job::Refresh);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(live) = &self.live {
                        ui.label(
                            RichText::new(format!("BUILD {}", live.target.build_id))
                                .monospace()
                                .color(GREEN),
                        );
                        ui.label(
                            RichText::new(format!("pid {}", live.target.pid))
                                .monospace()
                                .color(DIM),
                        );
                    } else {
                        ui.label(RichText::new("OFFLINE").strong().color(DIM));
                    }
                });
            });
            ui.add_space(4.0);
        });
    }

    fn tab_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("ncl-tabs").show(ui, |ui| {
            ui.horizontal(|ui| {
                for (tab, name) in [
                    (Tab::Cheats, "Cheats"),
                    (Tab::Editor, "Editor"),
                    (Tab::Library, "Library"),
                    (Tab::Log, "Log"),
                ] {
                    if ui
                        .selectable_label(self.tab == tab, RichText::new(name).strong())
                        .clicked()
                    {
                        self.tab = tab;
                    }
                }
                ui.separator();
                ui.checkbox(&mut self.auto_tick, "auto-tick loops")
                    .on_hover_text("evaluate Loop-mode cheats every 250 ms");
                if let Some(live) = &self.live {
                    ui.label(
                        RichText::new(format!(
                            "{} enabled / {} loop / {} patch / {} backup",
                            live.target.enabled,
                            live.target.loops,
                            live.target.patches,
                            live.target.backups
                        ))
                        .color(DIM),
                    );
                }
            });
        });
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("ncl-status").show(ui, |ui| {
            ui.horizontal(|ui| {
                if self.busy.is_some() {
                    ui.spinner();
                }
                ui.label(RichText::new(&self.message).color(DIM));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.editor.dirty() {
                        ui.label(RichText::new("editor: UNSAVED").color(YELLOW));
                    }
                    if let Some(live) = &self.live {
                        ui.label(
                            RichText::new(format!("main {:08X}", live.target.main_base))
                                .monospace()
                                .color(DIM),
                        );
                    }
                    ui.label(RichText::new(APP_NAME).strong().color(ACCENT));
                });
            });
        });
    }

    fn cheats_tab(&mut self, ui: &mut egui::Ui) {
        let Some(live) = self.live.clone() else {
            ui.add_space(12.0);
            ui.heading("No console connected");
            ui.label(
                "Enter the Switch address above and press Connect.  The editor and library work \
                 offline: no console is needed to write or validate a cheat file.",
            );
            ui.add_space(8.0);
            if ui.button("New cheat file").clicked() {
                self.new_file();
            }
            if ui.button("Open the library").clicked() {
                self.tab = Tab::Library;
            }
            return;
        };

        ui.horizontal(|ui| {
            ui.label(RichText::new("cheat file").color(DIM));
            ui.label(
                RichText::new(live.target.path.display().to_string())
                    .monospace()
                    .color(ACCENT),
            );
            if ui.button("Use target file").clicked() {
                self.use_target_file();
                self.tab = Tab::Editor;
            }
            if ui
                .button("Reveal")
                .on_hover_text("open cheats/ in Explorer")
                .clicked()
            {
                let _ = std::process::Command::new("explorer")
                    .arg(live.target.path.parent().unwrap_or(Path::new(".")))
                    .spawn();
            }
        });
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("pid {}", live.target.pid)).monospace());
            ui.label(RichText::new(format!("build {}", live.target.build_id)).monospace());
            ui.label(
                RichText::new(format!("{} issue(s) in the file", live.target.issues))
                    .color(if live.target.issues > 0 { YELLOW } else { DIM }),
            );
            ui.separator();
            let panic = ui
                .add_enabled(
                    live.target.backups > 0 || live.any_enabled(),
                    egui::Button::new(RichText::new("Panic OFF").strong().color(RED)),
                )
                .on_hover_text("restore every original byte recorded in the backup journal");
            if panic.clicked() {
                self.panic_confirm = true;
            }
            if ui
                .add_enabled(live.has_loops(), egui::Button::new("Tick now"))
                .clicked()
            {
                self.submit("ticking", Job::Tick);
            }
        });
        if let Some(error) = &live.target.last_error {
            ui.label(RichText::new(error).color(RED));
        }
        if live.target.backups > 0 {
            ui.label(
                RichText::new(format!(
                    "{} backed-up address(es) in {}",
                    live.target.backups,
                    live.target.journal.display()
                ))
                .color(YELLOW),
            );
        }
        ui.separator();

        ui.horizontal(|ui| {
            ui.label("filter");
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .desired_width(180.0)
                    .hint_text("name or mode"),
            );
            ui.checkbox(&mut self.only_enabled, "only enabled");
        });

        let filter = self.filter.trim().to_lowercase();
        let only_enabled = self.only_enabled;
        let busy = self.busy.is_some();
        let mut toggle: Option<(CheatKey, bool)> = None;
        let mut open_editor = false;

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .max_height(ui.available_height() - 8.0)
            .show(ui, |ui| {
                egui::Grid::new("ncl-cheat-grid")
                    .num_columns(6)
                    .striped(true)
                    .spacing([14.0, 6.0])
                    .show(ui, |ui| {
                        for label in ["ON", "cheat", "mode", "ops", "trigger", "state"] {
                            ui.label(RichText::new(label).strong().color(DIM));
                        }
                        ui.end_row();

                        let mut shown = 0usize;
                        for row in &live.rows {
                            if only_enabled && !row.live {
                                continue;
                            }
                            if !filter.is_empty() {
                                let haystack = format!("{} {} {}", row.name, row.mode, row.kind)
                                    .to_lowercase();
                                if !haystack.contains(&filter) {
                                    continue;
                                }
                            }
                            shown += 1;
                            let mut on = row.live;
                            if ui
                                .add_enabled(
                                    !busy && !row.restore_only && row.issues == 0,
                                    egui::Checkbox::without_text(&mut on),
                                )
                                .on_hover_text(if row.restore_only {
                                    "restore-only block: there is no ON code"
                                } else if row.issues > 0 {
                                    "this block has parse errors and cannot run"
                                } else {
                                    "toggle this cheat on the console"
                                })
                                .changed()
                            {
                                toggle = Some((row.key, on));
                            }
                            let name = ui.add(
                                egui::Label::new(RichText::new(&row.name).strong().color(
                                    if row.live {
                                        GREEN
                                    } else {
                                        Color32::from_gray(220)
                                    },
                                ))
                                .sense(egui::Sense::click()),
                            );
                            if name.clicked() {
                                open_editor = true;
                            }
                            name.on_hover_text(format!(
                                "line {}\nkey {}\nkind {}\nfile state: {}",
                                row.source_line,
                                row.key,
                                row.kind,
                                if row.file_on { "ON" } else { "OFF" }
                            ));
                            ui.label(RichText::new(&row.mode).monospace().color(DIM));
                            let ops = if row.off_instructions > 0 {
                                format!("{} +{}", row.instructions, row.off_instructions)
                            } else {
                                row.instructions.to_string()
                            };
                            ui.label(RichText::new(ops).monospace().color(DIM));
                            ui.label(if row.trigger {
                                RichText::new("keys").color(YELLOW)
                            } else {
                                RichText::new("-").color(DIM)
                            });
                            if let Some(error) = &row.error {
                                ui.label(RichText::new("ERROR").strong().color(RED))
                                    .on_hover_text(error);
                            } else if row.live {
                                ui.label(RichText::new("ON").strong().color(GREEN));
                            } else if row.restore_only {
                                ui.label(RichText::new("restore-only").color(DIM));
                            } else if row.issues > 0 {
                                ui.label(
                                    RichText::new(format!("{} issue(s)", row.issues)).color(RED),
                                );
                            } else {
                                ui.label(RichText::new("off").color(DIM));
                            }
                            ui.end_row();
                        }
                        if shown == 0 {
                            ui.label(RichText::new("(no cheat matches)").color(DIM));
                            for _ in 0..5 {
                                ui.label("");
                            }
                            ui.end_row();
                        }
                    });

                if !live.backup_rows.is_empty() {
                    ui.add_space(8.0);
                    egui::CollapsingHeader::new(
                        RichText::new(format!(
                            "backup journal ({} address(es))",
                            live.backup_rows.len()
                        ))
                        .strong(),
                    )
                    .id_salt("ncl-backups")
                    .show(ui, |ui| {
                        egui::Grid::new("ncl-backup-grid")
                            .num_columns(4)
                            .striped(true)
                            .show(ui, |ui| {
                                for label in ["address", "width", "owners", "state"] {
                                    ui.label(RichText::new(label).strong().color(DIM));
                                }
                                ui.end_row();
                                for row in &live.backup_rows {
                                    ui.label(
                                        RichText::new(format!("{:08X}", row.address)).monospace(),
                                    );
                                    ui.label(RichText::new(row.width.to_string()).monospace());
                                    ui.label(RichText::new(row.owners.to_string()).monospace());
                                    ui.label(RichText::new(&row.state).color(
                                        if row.state == "committed" {
                                            GREEN
                                        } else {
                                            YELLOW
                                        },
                                    ));
                                    ui.end_row();
                                }
                            });
                    });
                }
            });

        if let Some((key, on)) = toggle {
            self.submit(
                if on { "enabling" } else { "disabling" },
                Job::Toggle { key, on },
            );
        }
        if open_editor {
            if !self.editor.dirty() {
                self.use_target_file();
            }
            self.tab = Tab::Editor;
        }
    }

    fn editor_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("file");
            let mut path_text = self.editor.path.display().to_string();
            if ui
                .add(
                    egui::TextEdit::singleline(&mut path_text)
                        .desired_width((ui.available_width() - 330.0).max(160.0))
                        .hint_text("cheats/<BUILDID>.txt"),
                )
                .changed()
            {
                self.editor.path = PathBuf::from(path_text);
            }
            if ui
                .add_enabled(self.live.is_some(), egui::Button::new("Use target file"))
                .clicked()
            {
                self.use_target_file();
            }
            if ui
                .button("Open")
                .on_hover_text("load the file shown here")
                .clicked()
            {
                let path = self.editor.path.clone();
                if path.as_os_str().is_empty() {
                    self.message = "enter a file path first".to_string();
                } else {
                    self.open_file(path);
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("build");
            ui.add(
                egui::TextEdit::singleline(&mut self.editor.build_id)
                    .desired_width(150.0)
                    .hint_text("16 hex digits"),
            )
            .on_hover_text("used for the save name and for parse diagnostics");
            if ui.button("Validate").clicked() {
                self.refresh_parse();
            }
            if ui
                .add_enabled(
                    !self.any_enabled(),
                    egui::Button::new(RichText::new("Save").strong()),
                )
                .on_hover_text(if self.any_enabled() {
                    "turn every cheat off first"
                } else {
                    "write atomically; Ctrl+S"
                })
                .clicked()
            {
                self.save_editor(false);
            }
            if ui.button("New").clicked() {
                self.new_file();
            }
            if ui.button("Library").clicked() {
                self.tab = Tab::Library;
            }
            if self.editor.dirty() {
                ui.label(RichText::new("unsaved").color(YELLOW));
            }
            if let Some(report) = &self.editor.report {
                let color = if report.issues.is_empty() { GREEN } else { RED };
                ui.label(
                    RichText::new(format!(
                        "{} block(s), {} opcode(s), {} line(s), {} B{}",
                        report.blocks,
                        report.instructions,
                        report.lines,
                        report.bytes,
                        if report.issues.is_empty() {
                            String::new()
                        } else {
                            format!(", {} issue(s)", report.issues.len())
                        }
                    ))
                    .color(color),
                );
            }
        });
        if self.any_enabled() {
            ui.label(
                RichText::new(
                    "Cheats are enabled: saving/reloading is blocked until they are turned off, \
                     so the manager cannot forget its original-byte backups.",
                )
                .color(YELLOW),
            );
        }
        ui.separator();

        egui::ScrollArea::vertical()
            .id_salt("ncl-editor-scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let edit = ui.add(
                    egui::TextEdit::multiline(&mut self.editor.text)
                        .font(egui::TextStyle::Monospace)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(30)
                        .hint_text("; NCL cheat file\n[My cheat]\n580F0000 00000000"),
                );
                if edit.changed() {
                    self.editor.last_edit = Some(Instant::now());
                }
            });

        if self
            .editor
            .report
            .as_ref()
            .map(|report| !report.issues.is_empty())
            .unwrap_or(false)
        {
            let issues = self
                .editor
                .report
                .as_ref()
                .map(|report| report.issues.clone())
                .unwrap_or_default();
            ui.collapsing(
                RichText::new(format!("{} issue(s)", issues.len())).color(RED),
                |ui| {
                    egui::ScrollArea::vertical()
                        .max_height(130.0)
                        .show(ui, |ui| {
                            for issue in issues {
                                ui.label(RichText::new(issue).monospace().color(RED));
                            }
                        });
                },
            );
        }
    }

    fn library_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("directory");
            ui.label(
                RichText::new(self.library.dir.display().to_string())
                    .monospace()
                    .color(ACCENT),
            );
            if ui.button("Refresh").clicked() {
                let (files, error) = scan_library(&self.library.dir);
                self.library.files = files;
                self.library.error = error;
            }
            if ui.button("Open folder").clicked() {
                let _ = std::process::Command::new("explorer")
                    .arg(&self.library.dir)
                    .spawn();
            }
            if ui.button("New cheat file").clicked() {
                self.new_file();
            }
        });
        if let Some(error) = &self.library.error {
            ui.label(RichText::new(error).color(YELLOW));
        }
        ui.separator();

        let files = self.library.files.clone();
        if files.is_empty() {
            ui.label(
                RichText::new(
                    "No .txt cheat files yet.  Connect to a title to create one, or press \
                     \"New cheat file\".",
                )
                .color(DIM),
            );
            return;
        }
        let mut load: Option<PathBuf> = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("ncl-library-grid")
                .num_columns(5)
                .striped(true)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    for label in ["file", "build id", "blocks", "issues", "size"] {
                        ui.label(RichText::new(label).strong().color(DIM));
                    }
                    ui.end_row();
                    for file in &files {
                        if ui
                            .add(
                                egui::Label::new(
                                    RichText::new(&file.name).monospace().color(ACCENT),
                                )
                                .sense(egui::Sense::click()),
                            )
                            .on_hover_text(file.path.display().to_string())
                            .clicked()
                        {
                            load = Some(file.path.clone());
                        }
                        ui.label(RichText::new(&file.build_id).monospace());
                        ui.label(RichText::new(file.blocks.to_string()).monospace());
                        ui.label(
                            RichText::new(file.issues.to_string())
                                .monospace()
                                .color(if file.issues > 0 { RED } else { DIM }),
                        );
                        ui.label(
                            RichText::new(format!("{} B", file.bytes))
                                .monospace()
                                .color(DIM),
                        );
                        ui.end_row();
                    }
                });
        });
        if let Some(path) = load {
            self.open_file(path);
        }
    }

    fn log_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("LOG").strong());
            if ui.button("Copy").clicked() {
                let text = self.log.iter().cloned().collect::<Vec<_>>().join("\n");
                ui.ctx().copy_text(text);
            }
            if ui.button("Clear").clicked() {
                self.log.clear();
            }
        });
        ui.separator();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for line in &self.log {
                    ui.label(RichText::new(line).monospace().color(DIM));
                }
            });
    }

    fn modals(&mut self, ctx: &egui::Context) {
        if self.panic_confirm {
            egui::Window::new("Panic OFF")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ctx, |ui| {
                    ui.label(
                        "Restore every original byte recorded in the backup journal? \
                         All enabled cheats will be turned off.",
                    );
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add(egui::Button::new(
                                RichText::new("Restore all").strong().color(RED),
                            ))
                            .clicked()
                        {
                            self.panic_confirm = false;
                            self.submit("restoring every patch", Job::PanicOff);
                        }
                        if ui.button("Cancel").clicked() {
                            self.panic_confirm = false;
                        }
                    });
                });
        }

        if self.quit_confirm {
            let enabled = self
                .live
                .as_ref()
                .map(|live| live.target.enabled)
                .unwrap_or(0);
            let dirty = self.editor.dirty();
            egui::Window::new("Quit NCL?")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ctx, |ui| {
                    if enabled > 0 {
                        ui.label(format!(
                            "{enabled} cheat(s) are still enabled.  Quitting without restoring \
                             leaves the console patched until the title restarts."
                        ));
                    }
                    if dirty {
                        ui.label(
                            RichText::new(
                                "The editor has unsaved changes.  Save first (Ctrl+S), or \
                                 discard them.",
                            )
                            .color(YELLOW),
                        );
                    }
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if enabled > 0
                            && ui
                                .add_enabled(
                                    self.busy.is_none(),
                                    egui::Button::new(RichText::new("Restore && quit").strong()),
                                )
                                .clicked()
                        {
                            self.quit_after_restore = true;
                            self.submit("restoring before quit", Job::PanicOff);
                        }
                        if ui
                            .add(egui::Button::new(
                                RichText::new(if enabled > 0 {
                                    "Quit without restoring"
                                } else {
                                    "Discard && quit"
                                })
                                .color(RED),
                            ))
                            .clicked()
                        {
                            self.allow_close = true;
                            self.quit_confirm = false;
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                        if ui.button("Cancel").clicked() {
                            self.quit_confirm = false;
                        }
                    });
                });
        }
    }

    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        if ctx.input_mut(|input| input.consume_key(egui::Modifiers::CTRL, egui::Key::S)) {
            self.save_editor(false);
        }
        if ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::F5)) {
            self.refresh_parse();
        }
        if ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::F9)) {
            if self.live.is_some() {
                self.submit("refreshing", Job::Refresh);
            }
        }
    }

    fn handle_close(&mut self, ctx: &egui::Context) {
        if self.allow_close {
            return;
        }
        if ctx.input(|input| input.viewport().close_requested()) {
            if self.any_enabled() || self.editor.dirty() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.quit_confirm = true;
            } else {
                self.allow_close = true;
            }
        }
    }

    fn handle_screenshot(&mut self, ctx: &egui::Context) {
        let Some(path) = self.screenshot.clone() else {
            return;
        };
        self.frames += 1;
        if self.shot_saved.load(Ordering::Relaxed) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if self.shot_requested {
            return;
        }
        // With --connect, wait for the worker to open the target (or give up) so
        // the capture shows real rows instead of the offline placeholder.
        let ready = self.frames >= 4
            && (!self.auto_connect || self.live.is_some() || self.started.elapsed().as_secs() >= 8);
        if !ready {
            ctx.request_repaint_after(Duration::from_millis(60));
            return;
        }
        self.shot_requested = true;
        let flag = Arc::clone(&self.shot_saved);
        let path_text = path.to_string_lossy().to_string();
        ctx.request_screenshot(move |image| {
            let mut rgba = Vec::with_capacity(image.pixels.len() * 4);
            for pixel in &image.pixels {
                rgba.extend_from_slice(&pixel.to_array());
            }
            match png::write_png(
                &path_text,
                image.width() as u32,
                image.height() as u32,
                &rgba,
            ) {
                Ok(()) => {
                    println!("screenshot written: {path_text}");
                    flag.store(true, Ordering::Relaxed);
                }
                Err(error) => eprintln!("screenshot failed: {error}"),
            }
        });
        ctx.request_repaint();
    }
}

impl eframe::App for NclApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        let prefs = Prefs {
            host: self.host.clone(),
            port: self.port.clone(),
            auto_tick: self.auto_tick,
        };
        eframe::set_value(storage, "ncl-prefs", &prefs);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain_events();
        if self.pending_close {
            self.pending_close = false;
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
        self.schedule_tick();
        self.handle_shortcuts(ui.ctx());
        self.handle_close(ui.ctx());
        self.handle_screenshot(ui.ctx());

        // Parse while the user pauses, so diagnostics stay current without
        // re-parsing a large file on every keystroke.
        if self.editor.validated_text != self.editor.text {
            let due = self
                .editor
                .last_edit
                .map(|edit| edit.elapsed() >= Duration::from_millis(400))
                .unwrap_or(true);
            if due && self.editor.text.len() <= 262_144 {
                self.refresh_parse();
            }
        }

        self.top_bar(ui);
        self.status_bar(ui);
        self.tab_bar(ui);

        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Cheats => self.cheats_tab(ui),
            Tab::Editor => self.editor_tab(ui),
            Tab::Library => self.library_tab(ui),
            Tab::Log => self.log_tab(ui),
        });

        self.modals(ui.ctx());

        if self.busy.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(120));
        } else if self.live.as_ref().map(LiveView::has_loops).unwrap_or(false) && self.auto_tick {
            ui.ctx().request_repaint_after(TICK_INTERVAL);
        }
    }
}

// ---------------------------------------------------------------------------
// Command line (works without a console / display)
// ---------------------------------------------------------------------------

fn usage() -> String {
    format!(
        "NCL {} - Nxus Cheat Loader\n\
         \n\
         GUI:\n\
           NCL.exe                          open the cheat loader\n\
           NCL.exe --host 192.168.1.13      prefill the console address\n\
           NCL.exe --port 7332              prefill the port\n\
           NCL.exe --file FILE              open FILE in the editor\n\
           NCL.exe --connect                connect immediately at startup\n\
           NCL.exe --tab editor|library     open that tab at startup\n\
           NCL.exe --screenshot OUT.png     render one frame and exit\n\
         \n\
         Cheat files:\n\
           NCL.exe --list FILE              list the blocks in FILE\n\
           NCL.exe --check FILE             validate FILE (exit 1 on issues)\n\
           NCL.exe --build-id ID --check FILE\n\
         \n\
         Cheat files live next to the executable in cheats/<BUILDID>.txt.\n",
        env!("CARGO_PKG_VERSION")
    )
}

fn file_build_id(path: &Path) -> String {
    build_id_from_path(path).unwrap_or_else(|| "0000000000000000".to_string())
}

fn list_file(path: &Path) -> i32 {
    let build_id = file_build_id(path);
    match cheat::parse_file(path, &build_id) {
        Ok(document) => {
            println!("file      : {}", path.display());
            println!("build id  : {build_id}");
            println!("blocks    : {}", document.blocks.len());
            println!("issues    : {}", document.issues_with_block().len());
            for (index, block) in document.blocks.iter().enumerate() {
                println!(
                    "[{index}] {}  mode={}  state={}  master={}  off={}  ops={}",
                    block.name,
                    block.mode.as_str(),
                    if block.enabled { "ON" } else { "OFF" },
                    if block.is_master() { "yes" } else { "no" },
                    if block.explicit_off || block.off.is_some() {
                        "yes"
                    } else {
                        "no"
                    },
                    block.on.instructions.len()
                );
                for issue in block.all_issues() {
                    println!("      ! {issue}");
                }
            }
            0
        }
        Err(error) => {
            eprintln!("NCL: {error}");
            1
        }
    }
}

fn check_file(path: &Path, build_id: Option<&str>) -> i32 {
    // An explicit id must be valid.  A file name that is not a build id is fine
    // for offline editing; only the parser's `document.build_id` is cosmetic.
    let build_id = match build_id {
        Some(value) => match normalize_build_id(value) {
            Ok(build_id) => build_id,
            Err(error) => {
                eprintln!("NCL: {error}");
                return 2;
            }
        },
        None => build_id_from_path(path).unwrap_or_else(|| "0000000000000000".to_string()),
    };
    match cheat::parse_file(path, &build_id) {
        Ok(document) => {
            let issues = document.issues_with_block();
            println!(
                "{}: {} block(s), {} opcode(s), {} issue(s)",
                path.display(),
                document.blocks.len(),
                document
                    .blocks
                    .iter()
                    .map(|block| block.on.instructions.len())
                    .sum::<usize>(),
                issues.len()
            );
            for issue in &issues {
                println!("  {issue}");
            }
            if issues.is_empty() {
                0
            } else {
                1
            }
        }
        Err(error) => {
            eprintln!("NCL: {error}");
            1
        }
    }
}

/// Positional argument of a subcommand, skipping the `--build-id` value if it
/// appears before the file (`NCL --build-id ID --check FILE`).
fn subcommand_path(args: &[String], command: &str) -> Option<PathBuf> {
    let mut skip_next = false;
    for argument in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if argument == "--build-id" {
            skip_next = true;
            continue;
        }
        if argument == command || argument.starts_with('-') {
            continue;
        }
        return Some(PathBuf::from(argument));
    }
    None
}

fn parse_cli(args: &[String]) -> Option<i32> {
    if args.is_empty() {
        return None;
    }
    if args.iter().any(|argument| argument == "--check") {
        let Some(path) = subcommand_path(args, "--check") else {
            eprintln!("NCL: --check needs a file\n\n{}", usage());
            return Some(2);
        };
        let build_id = args
            .windows(2)
            .find(|pair| pair[0] == "--build-id")
            .map(|pair| pair[1].as_str());
        return Some(check_file(&path, build_id));
    }
    if args.iter().any(|argument| argument == "--list") {
        let Some(path) = subcommand_path(args, "--list") else {
            eprintln!("NCL: --list needs a file\n\n{}", usage());
            return Some(2);
        };
        return Some(list_file(&path));
    }
    match args[0].as_str() {
        "-h" | "--help" | "-help" | "help" | "/?" => {
            print!("{}", usage());
            Some(0)
        }
        "--version" | "-V" => {
            println!("NCL {}", env!("CARGO_PKG_VERSION"));
            Some(0)
        }
        // GUI options and a bare file name are handled by `main`.
        "--host" | "--port" | "--file" | "--screenshot" | "--connect" | "--tab" => None,
        other if other.starts_with('-') => {
            eprintln!("NCL: unknown option {other}\n\n{}", usage());
            Some(2)
        }
        _ => None,
    }
}

fn font_definitions() -> egui::FontDefinitions {
    let mut defs = egui::FontDefinitions::default();
    defs.font_data.insert(
        "mplus1p".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(JP_FONT)),
    );
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        defs.families
            .entry(family)
            .or_default()
            .push("mplus1p".to_owned());
    }
    defs
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if let Some(code) = parse_cli(&args) {
        std::process::exit(code);
    }

    let env_host = std::env::var("NXUS_HOST")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let env_port = std::env::var("NXUS_PORT")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let mut host_given = env_host.is_some();
    let mut port_given = env_port.is_some();
    let mut host = env_host.unwrap_or_else(|| "127.0.0.1".to_string());
    let mut port = env_port.unwrap_or_else(|| DEFAULT_PORT.to_string());
    let mut screenshot: Option<PathBuf> = None;
    let mut initial_file: Option<PathBuf> = None;
    let mut auto_connect = false;
    let mut start_tab: Option<Tab> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--connect" => auto_connect = true,
            "--tab" => {
                if let Some(value) = args.get(index + 1) {
                    start_tab = match value.to_ascii_lowercase().as_str() {
                        "cheats" => Some(Tab::Cheats),
                        "editor" => Some(Tab::Editor),
                        "library" => Some(Tab::Library),
                        "log" => Some(Tab::Log),
                        other => {
                            eprintln!("NCL: unknown tab {other}");
                            std::process::exit(2);
                        }
                    };
                    index += 1;
                }
            }
            "--host" => {
                if let Some(value) = args.get(index + 1) {
                    host = value.clone();
                    host_given = true;
                    index += 1;
                }
            }
            "--port" => {
                if let Some(value) = args.get(index + 1) {
                    port = value.clone();
                    port_given = true;
                    index += 1;
                }
            }
            "--screenshot" => {
                if let Some(value) = args.get(index + 1) {
                    screenshot = Some(PathBuf::from(value));
                    index += 1;
                }
            }
            "--file" => {
                if let Some(value) = args.get(index + 1) {
                    initial_file = Some(PathBuf::from(value));
                    index += 1;
                }
            }
            other if !other.starts_with('-') => {
                initial_file = Some(PathBuf::from(other));
            }
            other => {
                eprintln!("NCL: unknown option {other}");
                std::process::exit(2);
            }
        }
        index += 1;
    }

    let prefs = Prefs {
        host,
        port,
        ..Prefs::default()
    };
    // Distinguish "explicitly set" from "the default value" so an explicitly
    // passed 127.0.0.1 still wins over a remembered LAN address.
    let host_override = host_given.then(|| prefs.host.clone());
    let port_override = port_given.then(|| prefs.port.clone());
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 780.0])
            .with_min_inner_size([860.0, 560.0])
            .with_title("NCL - Nxus Cheat Loader"),
        ..Default::default()
    };

    let result = eframe::run_native(
        APP_NAME,
        native_options,
        Box::new(move |cc| {
            let stored = cc
                .storage
                .and_then(|storage| eframe::get_value::<Prefs>(storage, "ncl-prefs"));
            let mut prefs = stored.unwrap_or(prefs);
            // Command-line / environment values win over the remembered ones.
            if let Some(host) = host_override {
                prefs.host = host;
            }
            if let Some(port) = port_override {
                prefs.port = port;
            }
            Ok(Box::new(NclApp::new(
                cc,
                prefs,
                screenshot,
                initial_file,
                auto_connect,
                start_tab,
            )))
        }),
    );

    let code = match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("NCL: GUI error: {error}");
            1
        }
    };
    std::process::exit(code);
}
