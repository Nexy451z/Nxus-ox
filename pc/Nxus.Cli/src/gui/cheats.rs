//! The `[Cheats]` tab: Atmosphere cheat files driven from the main GUI.
//!
//! The tab is a thin front end over [`crate::cheat`], the same engine the
//! standalone `NCL.exe` and `nxus cheat ...` use.  Files live in
//! `<exe_dir>/cheats/<16-HEX-BUILDID>.txt`; the target's own Build ID decides
//! which one is live, so switching games can never apply another title's
//! addresses.
//!
//! All network work (connect, toggle, tick, restore) happens on one worker
//! thread.  The UI thread only edits text, lists files and draws snapshots.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui;
use egui::{Color32, RichText};

use crate::cheat::{
    self, normalize_build_id, save_text_atomic, CheatDocument, CheatKey, CheatManager,
    CheatMemoryIo, MemoryRegions, TargetIdentity, MAX_CHEAT_FILE_BYTES,
};
use crate::client::NxusClient;
use crate::protocol::{Metadata, Status, WRITE_FLAG_ALLOW_RX};

const TICK_INTERVAL: Duration = Duration::from_millis(250);
const PARSE_DELAY: Duration = Duration::from_millis(300);
const MAX_LOG_LINES: usize = 200;

const ACCENT: Color32 = Color32::from_rgb(0x4C, 0x8D, 0xFF);
const GREEN: Color32 = Color32::from_rgb(0x5A, 0xD0, 0x8A);
const YELLOW: Color32 = Color32::from_rgb(0xFF, 0xC8, 0x66);
const RED: Color32 = Color32::from_rgb(0xFF, 0x6B, 0x6B);
const DIM: Color32 = Color32::from_rgb(0x9A, 0xA3, 0xB0);

/// New-file skeleton.  The header doubles as a reminder of the two pieces of
/// syntax that are easy to get wrong (the `:OFF` suffix and the mode hint).
fn template(build_id: &str) -> String {
    format!(
        "; Nxus cheat file for {build_id}\n\
         ; A [Name] line starts a cheat. Append :OFF to leave it off initially.\n\
         ; Patch = write once and restore on OFF; Loop = re-run every 250 ms.\n\
         ; Code lines are Atmosphere cheat opcodes; ';', '#' and '//' start a comment.\n\
         ;\n\
         ; Example:\n\
         ; [Infinite money]\n\
         ; 580F0000 00000000            ; load [main+0] into register 0\n\
         ; 640F0000 00000000 000F423F   ; write 999999 to [reg0+0]\n"
    )
}

fn build_id_from_path(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    normalize_build_id(stem).ok()
}

fn ncl_path() -> Result<PathBuf, String> {
    let dir = cheat::exe_dir()?;
    let name = if cfg!(windows) { "NCL.exe" } else { "NCL" };
    Ok(dir.join(name))
}

// ---------------------------------------------------------------------------
// Snapshots shared by the worker and the UI
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct CheatRow {
    key: CheatKey,
    name: String,
    kind: String,
    mode: String,
    live: bool,
    file_on: bool,
    trigger: bool,
    instructions: usize,
    off_instructions: usize,
    issues: usize,
    error: Option<String>,
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
    build_id: String,
    main_base: u64,
    heap_base: u64,
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
    fn has_loops(&self) -> bool {
        self.rows.iter().any(|row| row.live && row.mode == "loop")
    }

    fn any_enabled(&self) -> bool {
        self.rows.iter().any(|row| row.live)
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
            trigger: block.has_keypad_trigger(),
            instructions: block.on.instructions.len(),
            off_instructions: block
                .off
                .as_ref()
                .map(|code| code.instructions.len())
                .unwrap_or(0),
            issues: block.all_issues().len(),
            error: manager.errors().get(&block.key).cloned(),
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
    let identity = manager.identity();
    let regions = manager.regions();
    LiveView {
        target: TargetView {
            pid: identity.pid,
            program_id: identity.program_id,
            build_id: identity.build_id.clone(),
            main_base: regions.main,
            heap_base: regions.heap,
            path: manager.path().to_path_buf(),
            journal: manager.journal_path().to_path_buf(),
            enabled: snapshot.enabled,
            loops: snapshot.loops,
            patches: snapshot.patches,
            backups: snapshot.backups,
            issues: snapshot.issues,
            last_error: snapshot.last_error.clone(),
        },
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
    Reload,
    Toggle { key: CheatKey, on: bool },
    Tick,
    PanicOff,
    LoadFile { path: PathBuf },
    Save { path: PathBuf, text: String },
}

enum Ev {
    Opened(LiveView, String),
    Updated(LiveView, String),
    /// Panic restore finished.  `complete == false` means some original bytes
    /// could not be written and the user must retry.
    Restored(LiveView, String, bool),
    Ticked(LiveView),
    Saved { path: PathBuf, text: String, view: Option<LiveView> },
    Editor { path: PathBuf, text: String, build_id: String },
    Error(String),
    Disconnected(String),
    Log(String),
}

struct Session {
    client: NxusClient,
    manager: CheatManager,
    /// True once *this* session enabled a cheat whose bytes are not back yet.
    /// Journal entries from an earlier run never set it: connecting or
    /// disconnecting must not silently undo another tool's work.
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
    // The wire protocol has no incarnation counter.  Use the same per-process
    // address fingerprint as `nxus cheat ...` and NCL.exe so all three share
    // one backup journal for the lifetime of a title process.
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
fn check_target(session: &Session) -> Result<bool, String> {
    let (identity, _) = probe_target(&session.client)?;
    Ok(identity.is_same_target(session.manager.identity()))
}

fn open_session(host: &str, port: u16) -> Result<(Session, String), String> {
    let client =
        NxusClient::connect(host, port).map_err(|error| format!("connect {host}:{port}: {error}"))?;
    let status: Status = client
        .status()
        .map_err(|error| format!("status: {error}"))?;
    let metadata: Metadata = match client.metadata() {
        Ok(metadata) => metadata,
        Err(first) => {
            // A fresh dmnt has no cheat process yet.  Opening it is exactly what
            // `metadata`/`scan begin` does; retry once so this tab can start first.
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
    let session = Session {
        client,
        manager,
        dirty: false,
    };
    Ok((session, text))
}

/// Restore the patches this session enabled.  The session is only dropped when
/// every original byte is back; otherwise it is kept so the user can retry.
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

fn load_editor_file(path: PathBuf) -> Result<Ev, String> {
    let metadata = std::fs::metadata(&path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    if metadata.len() > MAX_CHEAT_FILE_BYTES {
        return Err(format!(
            "{} is {} bytes; the maximum is {} bytes",
            path.display(),
            metadata.len(),
            MAX_CHEAT_FILE_BYTES
        ));
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let build_id = build_id_from_path(&path).unwrap_or_default();
    Ok(Ev::Editor {
        path,
        text,
        build_id,
    })
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
            Job::Reload => {
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
            Job::LoadFile { path } => match load_editor_file(path) {
                Ok(event) => {
                    let _ = tx.send(event);
                }
                Err(error) => {
                    let _ = tx.send(Ev::Error(error));
                }
            },
            Job::Save { path, text } => {
                // A live manager only owns this file when every cheat is OFF:
                // writing under an enabled Patch/Loop would replace the document
                // the manager still holds backups for.
                if let Some(current) = session.as_ref() {
                    if current.manager.path() == path
                        && !current.manager.enabled_keys().is_empty()
                    {
                        let _ = tx.send(Ev::Error(
                            "turn every cheat off before saving the live target's file"
                                .to_string(),
                        ));
                        continue;
                    }
                }
                if let Some(dir) = path.parent() {
                    if let Err(error) = std::fs::create_dir_all(dir) {
                        let _ = tx.send(Ev::Error(format!(
                            "cannot create {}: {error}",
                            dir.display()
                        )));
                        continue;
                    }
                }
                if let Err(error) = save_text_atomic(&path, &text) {
                    let _ = tx.send(Ev::Error(format!("{}: {error}", path.display())));
                    continue;
                }
                let mut reloaded = None;
                if let Some(current) = session.as_mut() {
                    if current.manager.path() == path {
                        if let Err(error) = current.manager.reload() {
                            let _ = tx.send(Ev::Error(format!(
                                "file saved, but reloading the live manager failed: {error}"
                            )));
                        } else {
                            reloaded = Some(make_view(&current.manager));
                        }
                    }
                }
                let _ = tx.send(Ev::Saved {
                    path,
                    text,
                    view: reloaded,
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Editor / library state
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Editor {
    text: String,
    last_saved: String,
    path: PathBuf,
    build_id: String,
    preview: Option<Preview>,
    parsed_text: String,
    last_edit: Option<Instant>,
}

impl Editor {
    fn dirty(&self) -> bool {
        self.text != self.last_saved
    }

    fn set_text(&mut self, path: Option<&Path>, text: String, build_id: String) {
        self.text = text;
        self.last_saved = self.text.clone();
        self.path = path.map(Path::to_path_buf).unwrap_or_default();
        self.build_id = build_id;
        self.preview = None;
        self.parsed_text.clear();
        self.last_edit = None;
    }
}

#[derive(Clone, Debug)]
struct Preview {
    blocks: usize,
    instructions: usize,
    issues: Vec<String>,
    bytes: usize,
    lines: usize,
}

impl Preview {
    fn build(text: &str, build_id: &str) -> Preview {
        let document = CheatDocument::parse(text, build_id);
        let mut issues: Vec<String> = document
            .issues_with_block()
            .into_iter()
            .map(|issue| issue.to_string())
            .collect();
        if issues.len() > 50 {
            let extra = issues.len() - 50;
            issues.truncate(50);
            issues.push(format!("... and {extra} more issue(s)"));
        }
        Preview {
            blocks: document.blocks.len(),
            instructions: document
                .blocks
                .iter()
                .map(|block| block.on.instructions.len())
                .sum(),
            issues,
            bytes: text.len(),
            lines: text.lines().count(),
        }
    }
}

#[derive(Clone, Debug)]
struct CheatFile {
    path: PathBuf,
    build_id: String,
    blocks: usize,
    issues: usize,
    bytes: u64,
    parse_error: Option<String>,
}

fn scan_library(dir: &Path) -> (Vec<CheatFile>, Option<String>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return (Vec::new(), None),
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
        // `README.txt` and notes are not cheat files.  Only the canonical
        // <16-HEX>.txt belongs in the library.
        let Some(build_id) = build_id_from_path(&path) else {
            continue;
        };
        let bytes = entry.metadata().map(|metadata| metadata.len()).unwrap_or(0);
        let (blocks, issues, parse_error) = match cheat::parse_file(&path, &build_id) {
            Ok(document) => (document.blocks.len(), document.issues_with_block().len(), None),
            Err(error) => (0, 1, Some(error)),
        };
        files.push(CheatFile {
            path,
            build_id,
            blocks,
            issues,
            bytes,
            parse_error,
        });
    }
    files.sort_by(|a, b| a.build_id.cmp(&b.build_id));
    (files, None)
}

// ---------------------------------------------------------------------------
// Tab state
// ---------------------------------------------------------------------------

pub struct CheatUi {
    tx: Sender<Job>,
    rx: Receiver<Ev>,
    pub dir: PathBuf,
    files: Vec<CheatFile>,
    library_error: Option<String>,
    live: Option<LiveView>,
    editor: Editor,
    build_id_input: String,
    message: String,
    log: VecDeque<String>,
    busy: Option<String>,
    auto_tick: bool,
    panic_confirm: bool,
    last_tick: Instant,
    last_loop_error: Option<String>,
    started: Instant,
}

impl CheatUi {
    pub fn new() -> CheatUi {
        let (tx, job_rx) = channel::<Job>();
        let (ev_tx, rx) = channel::<Ev>();
        std::thread::Builder::new()
            .name("nxus-cheat-worker".to_string())
            .spawn(move || run_worker(job_rx, ev_tx))
            .expect("cannot start the cheat worker thread");

        let dir = cheat::cheats_directory().unwrap_or_else(|_| PathBuf::from("cheats"));
        let (files, library_error) = scan_library(&dir);
        CheatUi {
            tx,
            rx,
            dir,
            files,
            library_error,
            live: None,
            editor: Editor::default(),
            build_id_input: String::new(),
            message: "ready - connect to a title or open a file".to_string(),
            log: VecDeque::new(),
            busy: None,
            auto_tick: true,
            panic_confirm: false,
            last_tick: Instant::now(),
            last_loop_error: None,
            started: Instant::now(),
        }
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
        // A loop tick is a short, cancellable unit: let a real user action queue
        // behind it instead of being swallowed four times a second.
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

    fn refresh_library(&mut self) {
        let (files, error) = scan_library(&self.dir);
        self.files = files;
        self.library_error = error;
    }

    fn drain_events(&mut self) {
        loop {
            match self.rx.try_recv() {
                Ok(Ev::Opened(view, text)) => {
                    self.busy = None;
                    self.message = format!("opened {}", view.target.path.display());
                    self.log(self.message.clone());
                    self.build_id_input = view.target.build_id.clone();
                    if self.editor.dirty() {
                        self.log("editor has unsaved changes; kept them");
                    } else {
                        self.editor.set_text(
                            Some(&view.target.path),
                            text,
                            view.target.build_id.clone(),
                        );
                    }
                    self.live = Some(view);
                    self.last_tick = Instant::now();
                    self.refresh_library();
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
                    self.panic_confirm = !complete;
                }
                Ok(Ev::Ticked(view)) => {
                    if self.busy.as_deref() == Some("tick") {
                        self.busy = None;
                    }
                    self.live = Some(view);
                }
                Ok(Ev::Saved { path, text, view }) => {
                    self.busy = None;
                    if self.editor.path == path && self.editor.text == text {
                        self.editor.last_saved = text;
                    }
                    if let Some(view) = view {
                        self.live = Some(view);
                    }
                    self.message = format!("saved {}", path.display());
                    self.log(self.message.clone());
                    self.refresh_library();
                }
                Ok(Ev::Editor {
                    path,
                    text,
                    build_id,
                }) => {
                    self.busy = None;
                    if !self.editor.dirty() || self.editor.path == path {
                        self.editor
                            .set_text(Some(&path), text, build_id.clone());
                        self.build_id_input = build_id;
                    } else {
                        self.log("editor has unsaved changes; kept them");
                    }
                    self.message = format!("loaded {}", path.display());
                    self.log(self.message.clone());
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
                }
                Ok(Ev::Log(message)) => {
                    // A broken Loop cheat would otherwise repeat the same error
                    // four times a second and flush the whole log.
                    if message.starts_with("loop:") {
                        if self.last_loop_error.as_deref() == Some(&message) {
                            continue;
                        }
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

    fn maybe_parse(&mut self) {
        if self.editor.text == self.editor.parsed_text {
            return;
        }
        let due = self
            .editor
            .last_edit
            .map(|last| last.elapsed() >= PARSE_DELAY)
            .unwrap_or(true);
        if !due {
            return;
        }
        let build_id = normalize_build_id(&self.editor.build_id)
            .unwrap_or_else(|_| "0000000000000000".to_string());
        self.editor.preview = Some(Preview::build(&self.editor.text, &build_id));
        self.editor.parsed_text = self.editor.text.clone();
        self.editor.last_edit = None;
    }

    /// Run every frame, whichever tab is visible, so Loop cheats keep ticking
    /// while the user is looking at the hex editor.
    pub fn poll(&mut self, ctx: &egui::Context) {
        self.drain_events();
        self.maybe_parse();

        let wants_tick = self.auto_tick
            && self
                .live
                .as_ref()
                .map(LiveView::has_loops)
                .unwrap_or(false);
        if wants_tick
            && self.busy.is_none()
            && self.last_tick.elapsed() >= TICK_INTERVAL
        {
            self.last_tick = Instant::now();
            self.busy = Some("tick".to_string());
            if self.tx.send(Job::Tick).is_err() {
                self.busy = None;
            }
        }
        if wants_tick {
            ctx.request_repaint_after(TICK_INTERVAL);
        }
        if self.busy.is_some() {
            ctx.request_repaint_after(Duration::from_millis(120));
        }
    }

    fn connect(&mut self, host: &str, port: u16) {
        if host.trim().is_empty() {
            self.message = "set the console address in the top bar first".to_string();
            return;
        }
        self.submit("connecting", Job::Connect {
            host: host.trim().to_string(),
            port,
        });
    }

    fn load_path(&mut self, path: PathBuf) {
        self.submit("loading", Job::LoadFile { path });
    }

    fn new_file(&mut self) {
        let build_id = match normalize_build_id(&self.build_id_input) {
            Ok(build_id) => build_id,
            Err(error) => {
                self.message = error;
                return;
            }
        };
        let path = self.dir.join(format!("{build_id}.txt"));
        if path.exists() {
            self.load_path(path);
            return;
        }
        self.editor
            .set_text(Some(&path), template(&build_id), build_id.clone());
        self.build_id_input = build_id;
        self.message = format!("new file: {}", path.display());
        self.log(self.message.clone());
    }

    fn editor_path(&self) -> Result<PathBuf, String> {
        if !self.editor.path.as_os_str().is_empty() {
            return Ok(self.editor.path.clone());
        }
        let build_id = normalize_build_id(&self.build_id_input)?;
        Ok(self.dir.join(format!("{build_id}.txt")))
    }

    fn save(&mut self) {
        if self.live.as_ref().map(LiveView::any_enabled).unwrap_or(false) {
            self.message =
                "turn every cheat off before saving (the live manager keeps backups)".to_string();
            return;
        }
        if self.editor.text.len() as u64 > MAX_CHEAT_FILE_BYTES {
            self.message = format!(
                "file is {} bytes; the maximum is {} bytes",
                self.editor.text.len(),
                MAX_CHEAT_FILE_BYTES
            );
            return;
        }
        let path = match self.editor_path() {
            Ok(path) => path,
            Err(error) => {
                self.message = error;
                return;
            }
        };
        let text = self.editor.text.clone();
        self.submit("saving", Job::Save { path, text });
    }

    fn launch_ncl(&mut self, host: &str, port: u16, connected: bool) {
        let path = match ncl_path() {
            Ok(path) => path,
            Err(error) => {
                self.message = error;
                return;
            }
        };
        if !path.exists() {
            self.message = format!(
                "{} not found - run tools/build_pc.sh to stage it",
                path.display()
            );
            return;
        }
        let mut command = std::process::Command::new(&path);
        command.current_dir(path.parent().unwrap_or(Path::new(".")));
        if !host.trim().is_empty() {
            command.arg("--host").arg(host.trim());
        }
        command.arg("--port").arg(port.to_string());
        if connected {
            command.arg("--connect");
        }
        match command.spawn() {
            Ok(_) => {
                self.message = format!("launched {}", path.display());
                self.log(self.message.clone());
            }
            Err(error) => {
                self.message = format!("cannot launch {}: {error}", path.display());
                self.log(self.message.clone());
            }
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, host: &str, port: u16, main_connected: bool) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Atmosphere cheats").strong().color(ACCENT));
            ui.label(RichText::new(self.dir.display().to_string()).color(DIM));
            if ui.button("Reload list").clicked() {
                self.refresh_library();
            }
            if ui
                .button("Launch NCL.exe")
                .on_hover_text("open the standalone cheat loader (same files and backup journal)")
                .clicked()
            {
                self.launch_ncl(host, port, main_connected);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.busy.is_some() {
                    ui.spinner();
                    ui.label(RichText::new(self.busy.as_deref().unwrap_or("")).color(YELLOW));
                } else {
                    ui.label(RichText::new(&self.message).color(DIM));
                }
            });
        });
        ui.separator();

        let target_row = self.target_row(ui, host, port);
        if target_row {
            ui.separator();
        }

        ui.columns(2, |columns| {
            self.library_ui(&mut columns[0]);
            self.editor_ui(&mut columns[1]);
        });
    }

    /// Target connection strip.  Returns true when a target is attached.
    fn target_row(&mut self, ui: &mut egui::Ui, host: &str, port: u16) -> bool {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Target").strong());
            if let Some(view) = self.live.as_ref() {
                ui.label(
                    RichText::new(format!(
                        "pid {}  program {:016X}  build {}",
                        view.target.pid, view.target.program_id, view.target.build_id
                    ))
                    .color(GREEN),
                );
                ui.separator();
                ui.label(format!(
                    "{} enabled ({} loop / {} patch), {} backup(s)",
                    view.target.enabled, view.target.loops, view.target.patches, view.target.backups
                ));
            } else {
                ui.label(RichText::new("not connected").color(DIM));
                ui.label(format!("({host}:{port})"));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let enabled = self.busy.is_none() || self.busy.as_deref() == Some("tick");
                if self.live.is_some() {
                    if ui
                        .add_enabled(enabled, egui::Button::new("Disconnect"))
                        .clicked()
                    {
                        self.submit("disconnecting", Job::Disconnect);
                    }
                    if ui
                        .add_enabled(enabled, egui::Button::new("Reload file"))
                        .on_hover_text("re-read the file from disk (all cheats must be OFF)")
                        .clicked()
                    {
                        self.submit("reloading", Job::Reload);
                    }
                } else if ui
                    .add_enabled(enabled, egui::Button::new(RichText::new("Connect target").strong()))
                    .clicked()
                {
                    self.connect(host, port);
                }

                let can_restore = self
                    .live
                    .as_ref()
                    .map(|view| view.target.backups > 0 || view.target.enabled > 0)
                    .unwrap_or(false);
                if can_restore {
                    if self.panic_confirm {
                        if ui
                            .add(egui::Button::new(
                                RichText::new("CONFIRM RESTORE ALL").strong().color(RED),
                            ))
                            .clicked()
                        {
                            self.panic_confirm = false;
                            self.submit("restoring all", Job::PanicOff);
                        }
                        if ui.button("Cancel").clicked() {
                            self.panic_confirm = false;
                        }
                    } else if ui
                        .add(egui::Button::new(
                            RichText::new("Panic Restore All").color(RED),
                        ))
                        .on_hover_text(
                            "write every original byte back and clear all enabled cheats",
                        )
                        .clicked()
                    {
                        self.panic_confirm = true;
                    }
                }
            });
        });
        if let Some(view) = self.live.as_ref() {
            if let Some(error) = &view.target.last_error {
                ui.label(RichText::new(error).color(RED));
            }
        }
        self.live.is_some()
    }

    fn library_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("Cheat files").strong());
        if let Some(error) = &self.library_error {
            ui.label(RichText::new(error).color(YELLOW));
        }
        if ui
            .button("Open containing folder")
            .on_hover_text(self.dir.display().to_string())
            .clicked()
        {
            let _ = std::process::Command::new("explorer")
                .arg(self.dir.as_os_str())
                .spawn();
        }
        let mut load: Option<PathBuf> = None;
        egui::ScrollArea::vertical()
            .id_salt("cheat-library")
            .max_height(210.0)
            .show(ui, |ui| {
                if self.files.is_empty() {
                    ui.label(
                        RichText::new("no <BUILDID>.txt files yet - create one below")
                            .color(DIM),
                    );
                }
                for file in &self.files {
                    let selected = self.editor.path == file.path;
                    let label = format!(
                        "{}  {} block(s){}  {} B",
                        file.build_id,
                        file.blocks,
                        if file.issues > 0 {
                            format!(", {} issue(s)", file.issues)
                        } else {
                            String::new()
                        },
                        file.bytes
                    );
                    let mut text = RichText::new(label);
                    if file.issues > 0 || file.parse_error.is_some() {
                        text = text.color(YELLOW);
                    }
                    if ui.selectable_label(selected, text).clicked() {
                        load = Some(file.path.clone());
                    }
                    if let Some(error) = &file.parse_error {
                        ui.label(RichText::new(format!("  ! {error}")).small().color(RED));
                    }
                }
            });
        if let Some(path) = load {
            self.load_path(path);
        }

        ui.separator();
        ui.label(RichText::new("New / open by Build ID").strong());
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.build_id_input)
                    .desired_width(150.0)
                    .hint_text("16 hex digits"),
            );
            if ui.button("New / Open").clicked() {
                self.new_file();
            }
        });
        ui.label(
            RichText::new("New files are created as <exe_dir>/cheats/<BUILDID>.txt.")
                .color(DIM),
        );

        ui.separator();
        if let Some(view) = self.live.as_ref() {
            ui.label(RichText::new("Backups (original bytes)").strong());
            ui.label(
                RichText::new(format!(
                    "{} address(es) - journal {}",
                    view.backup_rows.len(),
                    view.target.journal.display()
                ))
                .small()
                .color(DIM),
            );
            if view.backup_rows.is_empty() {
                ui.label(RichText::new("none").color(DIM));
            } else {
                egui::ScrollArea::vertical()
                    .id_salt("cheat-backups")
                    .max_height(170.0)
                    .show(ui, |ui| {
                        egui::Grid::new("cheat-backup-grid")
                            .striped(true)
                            .num_columns(4)
                            .show(ui, |ui| {
                                ui.label(RichText::new("address").strong());
                                ui.label(RichText::new("width").strong());
                                ui.label(RichText::new("owners").strong());
                                ui.label(RichText::new("state").strong());
                                ui.end_row();
                                for row in &view.backup_rows {
                                    ui.monospace(format!("{:08X}", row.address));
                                    ui.monospace(row.width.to_string());
                                    ui.monospace(row.owners.to_string());
                                    ui.label(&row.state);
                                    ui.end_row();
                                }
                            });
                    });
            }
        }
    }

    fn editor_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Editor").strong());
            if self.editor.dirty() {
                ui.label(RichText::new("● unsaved").color(YELLOW));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let enabled = self.busy.is_none() || self.busy.as_deref() == Some("tick");
                if ui.add_enabled(enabled, egui::Button::new("Save")).clicked() {
                    self.save();
                }
                if ui
                    .add_enabled(enabled, egui::Button::new("Reload from disk"))
                    .clicked()
                {
                    if !self.editor.path.as_os_str().is_empty() {
                        let path = self.editor.path.clone();
                        self.load_path(path);
                    } else {
                        self.message = "no file selected".to_string();
                    }
                }
                if let Some(view) = self.live.as_ref() {
                    if ui
                        .add_enabled(enabled, egui::Button::new("Use target file"))
                        .on_hover_text("replace the editor with the connected target's file")
                        .clicked()
                    {
                        let path = view.target.path.clone();
                        self.load_path(path);
                    }
                }
            });
        });
        let path_text = if self.editor.path.as_os_str().is_empty() {
            "(not saved yet)".to_string()
        } else {
            self.editor.path.display().to_string()
        };
        ui.label(RichText::new(path_text).small().color(DIM));

        let mut changed = false;
        egui::ScrollArea::vertical()
            .id_salt("cheat-editor")
            .max_height(300.0)
            .show(ui, |ui| {
                let response = ui.add(
                    egui::TextEdit::multiline(&mut self.editor.text)
                        .code_editor()
                        .desired_rows(16)
                        .desired_width(f32::INFINITY),
                );
                changed = response.changed();
            });
        if changed {
            self.editor.last_edit = Some(Instant::now());
        }
        if let Some(preview) = self.editor.preview.as_ref() {
            ui.horizontal_wrapped(|ui| {
                ui.label(format!(
                    "{} block(s), {} opcode(s), {} line(s), {} B",
                    preview.blocks, preview.instructions, preview.lines, preview.bytes
                ));
                if preview.issues.is_empty() {
                    ui.label(RichText::new("no parse issues").color(GREEN));
                } else {
                    ui.label(
                        RichText::new(format!("{} parse issue(s)", preview.issues.len()))
                            .color(YELLOW),
                    );
                }
            });
            if !preview.issues.is_empty() {
                egui::ScrollArea::vertical()
                    .id_salt("cheat-issues")
                    .max_height(80.0)
                    .show(ui, |ui| {
                        for issue in &preview.issues {
                            ui.label(RichText::new(format!("! {issue}")).small().color(YELLOW));
                        }
                    });
            }
        }

        ui.separator();
        self.block_list_ui(ui);
        ui.separator();
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.auto_tick, "auto tick")
                .on_hover_text("evaluate enabled Loop cheats every 250 ms with live keys_held");
            if let Some(view) = self.live.as_ref() {
                if view.has_loops() {
                    ui.label(RichText::new("loop running").color(GREEN));
                }
            }
        });
        egui::ScrollArea::vertical()
            .id_salt("cheat-log")
            .max_height(90.0)
            .show(ui, |ui| {
                for line in &self.log {
                    ui.label(RichText::new(line).small().color(DIM));
                }
            });
    }

    fn block_list_ui(&mut self, ui: &mut egui::Ui) {
        let Some(view) = self.live.clone() else {
            ui.label(
                RichText::new(
                    "Connect a target to toggle cheats. Editing, validation and saving work offline.",
                )
                .color(DIM),
            );
            return;
        };
        ui.label(RichText::new(format!("Cheats in {}", view.target.build_id)).strong());
        if view.rows.is_empty() {
            ui.label(
                RichText::new("the target's file has no [Name] block yet - edit it above and save")
                    .color(DIM),
            );
            return;
        }
        let mut actions: Vec<(CheatKey, bool)> = Vec::new();
        egui::ScrollArea::vertical()
            .id_salt("cheat-blocks")
            .max_height(220.0)
            .show(ui, |ui| {
                egui::Grid::new("cheat-block-grid")
                    .striped(true)
                    .num_columns(6)
                    .show(ui, |ui| {
                        ui.label(RichText::new("ON").strong());
                        ui.label(RichText::new("Name").strong());
                        ui.label(RichText::new("Mode").strong());
                        ui.label(RichText::new("Kind").strong());
                        ui.label(RichText::new("Ops").strong());
                        ui.label(RichText::new("Status").strong());
                        ui.end_row();

                        for row in &view.rows {
                            let mut on = row.live;
                            ui.push_id(row.key.0, |ui| {
                                if ui.checkbox(&mut on, "").changed() {
                                    actions.push((row.key, on));
                                }
                            });
                            let mut name = RichText::new(&row.name);
                            if row.live {
                                name = name.strong().color(GREEN);
                            }
                            ui.label(name);
                            ui.label(&row.mode);
                            ui.label(&row.kind);
                            ui.monospace(format!(
                                "{}{}",
                                row.instructions,
                                if row.off_instructions > 0 {
                                    format!(" / -{}", row.off_instructions)
                                } else {
                                    String::new()
                                }
                            ));
                            if let Some(error) = &row.error {
                                ui.label(RichText::new(error).small().color(RED));
                            } else if row.issues > 0 {
                                ui.label(
                                    RichText::new(format!("{} issue(s)", row.issues))
                                        .small()
                                        .color(YELLOW),
                                );
                            } else if row.trigger {
                                ui.label(RichText::new("keys").small().color(DIM));
                            } else if row.file_on {
                                ui.label(RichText::new("file ON").small().color(DIM));
                            } else {
                                ui.label("");
                            }
                            ui.end_row();
                        }
                    });
            });
        for (key, on) in actions {
            let label = if on { "enabling" } else { "disabling" };
            self.submit(label, Job::Toggle { key, on });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_id_is_read_from_the_file_name() {
        assert_eq!(
            build_id_from_path(Path::new("cheats/0100C3800049C000.txt")).as_deref(),
            Some("0100C3800049C000")
        );
        assert_eq!(
            build_id_from_path(Path::new("cheats/0100c3800049c000.txt")).as_deref(),
            Some("0100C3800049C000")
        );
        assert_eq!(build_id_from_path(Path::new("cheats/README.txt")), None);
    }

    #[test]
    fn the_template_names_the_target_build_id() {
        let text = template("0100C3800049C000");
        assert!(text.contains("0100C3800049C000"));
        assert!(text.contains("[Infinite money]"));
        assert!(text.contains(":OFF"));
    }

    #[test]
    fn a_missing_cheats_directory_is_empty_not_an_error() {
        let missing = std::env::temp_dir().join(format!(
            "nxus-cheats-missing-{}-{}",
            std::process::id(),
            1
        ));
        let (files, error) = scan_library(&missing);
        assert!(files.is_empty());
        assert!(error.is_none());
    }

    #[test]
    fn a_preview_reports_blocks_and_instructions() {
        let text = "[A]\n580F0000 00000000\n640F0000 00000000 00000001\n";
        let preview = Preview::build(text, "0100C3800049C000");
        assert_eq!(preview.blocks, 1);
        assert_eq!(preview.instructions, 2);
        assert!(preview.issues.is_empty(), "{:?}", preview.issues);
        assert_eq!(preview.lines, 3);
    }

    #[test]
    fn ncl_lives_next_to_nxus() {
        let path = ncl_path().expect("exe dir");
        assert_eq!(path.file_name().unwrap(), if cfg!(windows) { "NCL.exe" } else { "NCL" });
        assert_eq!(path.parent(), Some(cheat::exe_dir().unwrap().as_path()));
    }
}
