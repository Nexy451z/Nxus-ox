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
#[path = "../console.rs"]
mod console;
#[path = "../pcscan.rs"]
mod pcscan;
#[path = "../png.rs"]
mod png;
#[path = "../protocol.rs"]
mod protocol;

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use eframe::egui;
use egui::{Color32, RichText};

use cheat::manager::CheatExecution;
use cheat::{
    normalize_build_id, save_text_atomic, CheatDocument, CheatExecMode, CheatKey, CheatManager,
    CheatMemoryIo, FailureKind, MemoryRegions, TargetIdentity, MAX_CHEAT_FILE_BYTES,
};
use client::{is_unsupported_command, CheatFault, CheatRestore, CheatStatus, NxusClient};
use protocol::{Metadata, Status};

const APP_NAME: &str = "NCL";
const DEFAULT_PORT: u16 = 7332;
const TICK_INTERVAL: Duration = Duration::from_millis(250);
const MAX_LOG_LINES: usize = 500;

/// コンソールのチートワーカーの状態を聞き直す間隔。
///
/// 本体のワーカーは 16 ms で回るが、カウンタは 2 秒でも十分動きが分かる。
/// 毎 tick（250 ms）で問い合わせると、コンソールの単一接続スレッドと Wi-Fi を
/// 無駄に使う。
const CONSOLE_STATUS_INTERVAL: Duration = Duration::from_secs(2);

/// A job that has not answered after this long is already a bug (a hung
/// console call, a stuck tick).  The UI says so and offers the abort.
const BUSY_WATCHDOG: Duration = Duration::from_secs(10);

/// Hard limit: past this the UI aborts on its own.  No click may ever leave the
/// window "busy forever" again - that was the original hang.
const BUSY_HARD_LIMIT: Duration = Duration::from_secs(60);

const ACCENT: Color32 = Color32::from_rgb(96, 174, 255);
const GREEN: Color32 = Color32::from_rgb(104, 208, 128);
const RED: Color32 = Color32::from_rgb(244, 112, 112);
const YELLOW: Color32 = Color32::from_rgb(238, 200, 96);
const DIM: Color32 = Color32::from_rgb(150, 156, 166);
/// The idle status line: the last message, kept on screen but clearly "already
/// said" (a live toast uses [`DIM`]).
const FAINT: Color32 = Color32::from_rgb(104, 110, 120);

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
    /// ON, but the file was edited after it was applied: the console still runs
    /// (or the target still holds) the old code and nothing re-applies the new
    /// code by itself.
    stale: bool,
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
    /// ON blocks whose code changed since they were applied.
    stale: usize,
    last_error: Option<String>,
    /// いまチートを実行している場所（切替の表示に使う）。
    execution: CheatExecution,
}

/// コンソールのチートワーカー（`NxusCheatStatus`）を 1 行にまとめたもの。
///
/// `cheat_status` は 2 秒に 1 回しか取らないので、UI はこのスナップショットを
/// 描くだけにする（描画のたびにネットワークへ行かない）。
#[derive(Clone, Debug, Default)]
struct ConsoleRow {
    program_valid: bool,
    block_count: u32,
    enabled_count: u32,
    insn_count: u32,
    tick_count: u32,
    journal_count: u32,
    last_error: Option<String>,
    fault_count: u32,
    running: bool,
    keys_held: u64,
    /// 直近の `NxusEvent_CheatFault` の説明。
    fault: Option<String>,
}

impl ConsoleRow {
    fn from_status(status: &CheatStatus) -> ConsoleRow {
        ConsoleRow {
            program_valid: status.program_valid != 0,
            block_count: status.block_count,
            enabled_count: status.enabled_count,
            insn_count: status.insn_count,
            tick_count: status.tick_count,
            journal_count: status.journal_count,
            last_error: status.last_error_text(),
            fault_count: status.fault_count,
            running: status.running != 0,
            keys_held: status.keys_held,
            fault: None,
        }
    }
}

#[derive(Clone, Debug)]
struct LiveView {
    target: TargetView,
    rows: Vec<CheatRow>,
    backup_rows: Vec<BackupRow>,
    /// コンソール実行のときだけ入る（pc 実行では `None`）。
    console: Option<ConsoleRow>,
}

impl LiveView {
    fn any_enabled(&self) -> bool {
        self.rows.iter().any(|row| row.live)
    }

    fn has_loops(&self) -> bool {
        self.rows.iter().any(|row| row.live && row.mode == "Loop")
    }

    /// コンソールで実行しているか。
    ///
    /// pc 実行では Loop ブロックがあるときだけ tick が要るが、コンソール実行
    /// ではループが無くても状態取得と fault の監視のために tick を回す。
    fn runs_on_console(&self) -> bool {
        self.target.execution.is_console()
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
            stale: manager.is_stale(block.key),
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
        stale: snapshot.stale,
        last_error: snapshot.last_error.clone(),
        execution: manager.execution(),
    };
    LiveView {
        target,
        rows,
        backup_rows,
        console: None,
    }
}

/// セッション全体（マネージャ + コンソールの状態）のスナップショット。
///
/// [`make_view`] はマネージャだけを見る。ネットワーク越しに取った
/// `NxusCheatStatus` と、直近の fault の説明はここで重ねる。
fn make_session_view(session: &Session) -> LiveView {
    let mut view = make_view(&session.manager);
    if session.manager.is_console_mode() {
        view.console = session.console_row();
    }
    view
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

/// What the app is waiting for.
///
/// This used to be a `String` compared with `==`: the automatic tick wrote
/// `"tick"`, the "Tick now" button wrote `"ticking"`, and the only code that
/// cleared the label looked for `"tick"`.  One manual tick therefore left the
/// window "busy" for the rest of the session, and because [`NclApp::submit`]
/// refused every job while busy, Disconnect, Refresh and the ON/OFF checkboxes
/// were all dead.  An enum cannot be spelled wrong, the label shown to the user
/// is derived from it, and the only transition out of a state is the completion
/// event of *that* job (see [`Ev::Done`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Busy {
    Connecting,
    Disconnecting,
    Refreshing,
    Enabling,
    Disabling,
    Ticking,
    Restoring,
    Reloading,
    /// 実行場所（console / PC）の切替。
    ModeSwitch,
}

impl Busy {
    fn label(self) -> &'static str {
        match self {
            Busy::Connecting => "connecting",
            Busy::Disconnecting => "disconnecting",
            Busy::Refreshing => "refreshing",
            Busy::Enabling => "enabling",
            Busy::Disabling => "disabling",
            Busy::Ticking => "ticking",
            Busy::Restoring => "restoring",
            Busy::Reloading => "reloading",
            Busy::ModeSwitch => "switching where cheats run",
        }
    }

    /// A loop tick is a short unit of work: other jobs may queue behind it.
    /// Everything else must finish (or be aborted) before the next job starts.
    fn is_soft(self) -> bool {
        matches!(self, Busy::Ticking)
    }
}

/// The job in flight, and since when (the watchdog reads `since`).
#[derive(Clone, Copy, Debug)]
struct BusyJob {
    kind: Busy,
    since: Instant,
}

impl BusyJob {
    fn new(kind: Busy) -> BusyJob {
        BusyJob {
            kind,
            since: Instant::now(),
        }
    }

    fn elapsed(&self) -> Duration {
        self.since.elapsed()
    }
}

/// The worker thread plus both of its channels.
///
/// The `JoinHandle` used to be dropped, so a worker that panicked left the
/// window with a live-looking channel, a session nobody could end and every
/// button dead.  Keeping the handle lets [`NclApp::poll_worker`] notice the end
/// of the thread and start a fresh one.
struct Worker {
    jobs: Sender<Job>,
    events: Receiver<Ev>,
    /// A copy of the event sender for short-lived helper threads (the library
    /// scan, the screenshot encoder), tagged with this generation: after a
    /// restart their results are dropped instead of reviving stale state.
    events_tx: Sender<Ev>,
    /// Set by an abort so a worker stuck in a long console call exits as soon
    /// as that call returns instead of processing more jobs.
    abort: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Worker {
    fn spawn() -> Worker {
        let (jobs, job_rx) = mpsc::channel::<Job>();
        let (events_tx, events) = mpsc::channel::<Ev>();
        let abort = Arc::new(AtomicBool::new(false));
        let thread_abort = Arc::clone(&abort);
        let thread_tx = events_tx.clone();
        let handle = std::thread::Builder::new()
            .name("ncl-worker".to_string())
            .spawn(move || run_worker(job_rx, thread_tx, thread_abort))
            .expect("cannot start the NCL worker thread");
        Worker {
            jobs,
            events,
            events_tx,
            abort,
            handle: Some(handle),
        }
    }

    fn send(&self, job: Job) -> bool {
        self.jobs.send(job).is_ok()
    }

    /// Next event, without holding a borrow of the worker across the handler.
    fn next_event(&self) -> Option<Ev> {
        self.events.try_recv().ok()
    }

    fn is_finished(&self) -> bool {
        self.handle
            .as_ref()
            .map(|handle| handle.is_finished())
            .unwrap_or(true)
    }

    /// Stop this generation without waiting for it: the flag covers a worker
    /// inside a console call, the dropped channels cover one idle in `recv`.
    /// Either way the thread exits on its own and drops the session (and with
    /// it the socket) as soon as the current call returns.
    fn retire(self) {
        self.abort.store(true, Ordering::SeqCst);
        drop(self.jobs);
        drop(self.events);
    }
}

/// Text of a caught panic payload.
fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "unknown panic".to_string()
    }
}

/// Send one event from a detached helper thread (file I/O that is too slow for
/// a frame).  The sender belongs to the current worker generation, so a result
/// that arrives after a restart is dropped instead of reviving stale state.
fn spawn_io<F>(tx: Sender<Ev>, name: &str, task: F) -> bool
where
    F: FnOnce() -> Ev + Send + 'static,
{
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            let _ = tx.send(task());
        })
        .is_ok()
}

enum Job {
    Connect { host: String, port: u16 },
    Disconnect,
    Refresh,
    Toggle { key: CheatKey, on: bool },
    /// チートを実行する場所を切り替える（`console` / `pc`）。
    SetMode(CheatExecution),
    Tick,
    PanicOff,
    ReloadFile,
}

impl Job {
    /// The busy state this job puts the UI in.
    ///
    /// Derived from the job itself (never passed in by the caller) so the state
    /// and the completion event that clears it cannot disagree - that mismatch
    /// was the original "busy forever" bug.
    fn kind(&self) -> Busy {
        match self {
            Job::Connect { .. } => Busy::Connecting,
            Job::Disconnect => Busy::Disconnecting,
            Job::Refresh => Busy::Refreshing,
            Job::Toggle { on: true, .. } => Busy::Enabling,
            Job::Toggle { on: false, .. } => Busy::Disabling,
            Job::SetMode(_) => Busy::ModeSwitch,
            Job::Tick => Busy::Ticking,
            Job::PanicOff => Busy::Restoring,
            Job::ReloadFile => Busy::Reloading,
        }
    }

    /// Disconnect and panic-off must never wait for a stuck job.
    fn is_priority(&self) -> bool {
        matches!(self, Job::Disconnect | Job::PanicOff)
    }
}

enum Ev {
    Opened(LiveView, String),
    Updated(LiveView, String),
    /// Panic-off finished.  `complete` is false when some original bytes could
    /// not be written, in which case the quit modal must stay open.
    Restored(LiveView, String, bool),
    Ticked(LiveView),
    /// The job with this kind has finished - whatever it sent before.  The UI
    /// only clears `busy` here, and only when the kind matches the job it is
    /// waiting for, so an unrelated `Error` can no longer release a live job.
    Done(Busy),
    /// Result of the background library scan (it parses every file in
    /// `cheats/`, which is far too slow for a UI frame).
    Library {
        files: Vec<LibFile>,
        error: Option<String>,
    },
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
    /// コンソールのチートワーカーの直近の状態（2 秒間隔で取り直す）。
    console: Option<ConsoleRow>,
    /// 直近の `NxusEvent_CheatFault` の説明。
    ///
    /// 状態とは別に持つ: fault の直後は `cheat_status` が取れないことがあり、
    /// そのときも理由を出したい。
    console_fault: Option<String>,
    /// `cheat_status` を最後に取った時刻（2 秒間隔に絞る）。
    last_console_status: Instant,
}

impl Session {
    /// 表示用のコンソール行（状態がまだ無くても fault があれば作る）。
    fn console_row(&self) -> Option<ConsoleRow> {
        match (&self.console, &self.console_fault) {
            (None, None) => None,
            (status, fault) => {
                let mut row = status.clone().unwrap_or_default();
                row.fault = fault.clone();
                Some(row)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// コンソール実行モード
// ---------------------------------------------------------------------------

/// コンソールで 1 ブロックを ON/OFF した結果。
enum ConsoleToggle {
    /// 成功（利用者に見せる 1 行）。
    Done(String),
    /// 失敗（対象の状態は変えていない）。
    Failed(String),
    /// 接続先がこのコマンドを知らない。pc 経路へフォールバックする。
    Unsupported(String),
}

/// コンソールで 1 ブロックを ON/OFF する。
///
/// コンソールは **loop を含むプログラムだけを常駐**させ（16 ms ごとに実行）、
/// **patch だけのプログラムはアップロード直後に 1 回実行して解放する**。
/// だから ON の経路はブロックの種別で分かれる:
///
/// * **loop**: 常駐プログラム（loop ブロックだけ）をアップロード（同一内容なら
///   省略）→ `cheat_enable(index, true)`。index は常駐プログラム内の位置。
/// * **patch**: そのブロック単体のプログラムをアップロードするだけで、コンソール
///   が 1 回実行して解放する。常駐しないので `cheat_enable` は送らない（index が
///   存在しない）。コンソール側に復元表は残らないため、送信の**前に**原本を
///   PC のジャーナルへ控え、OFF は PC 側の復元で戻す。
fn console_toggle(session: &mut Session, key: CheatKey, on: bool) -> ConsoleToggle {
    let Some(mode) = session.manager.block(key).map(|block| block.mode) else {
        return ConsoleToggle::Failed(format!("cheat {key} is not part of the program"));
    };
    match (mode, on) {
        (CheatExecMode::Loop, true) => console_enable_loop(session, key),
        (CheatExecMode::Loop, false) => console_disable_loop(session, key),
        (CheatExecMode::Patch, true) => console_apply_patch(session, key),
        (CheatExecMode::Patch, false) => console_restore_patch(session, key),
    }
}

fn console_block_name(session: &Session, key: CheatKey) -> String {
    session
        .manager
        .block(key)
        .map(|block| block.name.clone())
        .unwrap_or_else(|| key.to_string())
}

/// loop ブロックの ON: 常駐プログラム → `cheat_enable(index, true)`。
fn console_enable_loop(session: &mut Session, key: CheatKey) -> ConsoleToggle {
    let Some(index) = session.manager.block_index(key) else {
        return ConsoleToggle::Failed(format!(
            "cheat {key} is not part of the resident (loop) program"
        ));
    };
    let program = match session.manager.build_console_program() {
        Ok(program) => program,
        Err(error) => {
            // リンクできないブロックを部分的に送ると、利用者が書いていない
            // コードが走る。断って、何が駄目かをそのまま見せる。
            return ConsoleToggle::Failed(format!("cannot link the cheat program: {error}"));
        }
    };
    if session.manager.need_console_upload(&program) {
        match session.client.cheat_upload(&program) {
            Ok(reply) => {
                if let Some(reason) = reply.rejected_text() {
                    return ConsoleToggle::Failed(format!(
                        "the console refused the cheat program: {reason}"
                    ));
                }
                session.manager.note_console_upload(&program);
            }
            Err(error) => {
                return if is_unsupported_command(&error) {
                    ConsoleToggle::Unsupported(error.to_string())
                } else {
                    ConsoleToggle::Failed(format!("cheat upload: {error}"))
                };
            }
        }
    }
    match session.client.cheat_enable(index, true) {
        Ok(()) => {
            let name = console_block_name(session, key);
            match session.manager.note_console_toggle(key, true) {
                Ok(()) => ConsoleToggle::Done(format!("enabled '{name}' on the console")),
                Err(error) => ConsoleToggle::Failed(error),
            }
        }
        Err(error) => {
            if is_unsupported_command(&error) {
                ConsoleToggle::Unsupported(error.to_string())
            } else {
                ConsoleToggle::Failed(format!("cheat_enable({index}) failed: {error}"))
            }
        }
    }
}

/// loop ブロックの OFF: `cheat_enable(index, false)`（原本はコンソールが戻す）。
fn console_disable_loop(session: &mut Session, key: CheatKey) -> ConsoleToggle {
    let Some(index) = session.manager.block_index(key) else {
        return ConsoleToggle::Failed(format!(
            "cheat {key} is not part of the resident (loop) program"
        ));
    };
    match session.client.cheat_enable(index, false) {
        Ok(()) => {
            let name = console_block_name(session, key);
            match session.manager.note_console_toggle(key, false) {
                Ok(()) => ConsoleToggle::Done(format!("disabled '{name}' on the console")),
                Err(error) => ConsoleToggle::Failed(error),
            }
        }
        Err(error) => {
            if is_unsupported_command(&error) {
                ConsoleToggle::Unsupported(error.to_string())
            } else {
                ConsoleToggle::Failed(format!("cheat_enable({index}) failed: {error}"))
            }
        }
    }
}

/// patch ブロックの ON: 原本を PC ジャーナルへ控えてから単体プログラムを送る。
///
/// 送信が成功した時点でコンソールは 1 回実行してプログラムを解放している。
/// 控えを残すのは OFF のため（コンソール側に復元表は無い）。
fn console_apply_patch(session: &mut Session, key: CheatKey) -> ConsoleToggle {
    let program = match session.manager.build_patch_program(key) {
        Ok(program) => program,
        Err(error) => {
            return ConsoleToggle::Failed(format!("cannot link the cheat program: {error}"));
        }
    };
    let name = console_block_name(session, key);
    if !session.manager.need_patch_upload(key, &program) {
        // 同じ内容を送って実行済み。二重に実行しない（既存方針）。
        return match session.manager.note_console_toggle(key, true) {
            Ok(()) => ConsoleToggle::Done(format!(
                "applied '{name}' on the console (ran once already)"
            )),
            Err(error) => ConsoleToggle::Failed(error),
        };
    }
    // 原本はコンソールが書き換える前に読む。ここで失敗したら、送信して
    // 復元できなくなるより前に止める。
    {
        let mut io = ClientCheatIo {
            client: &session.client,
        };
        if let Err(error) = session.manager.prepare_console_patch(key, &mut io) {
            return ConsoleToggle::Failed(format!("cannot record the original bytes: {error}"));
        }
    }
    match session.client.cheat_upload(&program) {
        Ok(reply) => {
            if let Some(reason) = reply.rejected_text() {
                let extra = discard_patch_journal(session);
                return ConsoleToggle::Failed(with_extra(
                    format!("the console refused the cheat program: {reason}"),
                    extra,
                ));
            }
            session.manager.note_patch_upload(key, &program);
        }
        Err(error) => {
            let extra = discard_patch_journal(session);
            return if is_unsupported_command(&error) {
                ConsoleToggle::Unsupported(error.to_string())
            } else {
                ConsoleToggle::Failed(with_extra(format!("cheat upload: {error}"), extra))
            };
        }
    }
    match session.manager.finish_console_patch() {
        // 常駐しないので表示は「適用した（1 回実行）」。
        Ok(()) => ConsoleToggle::Done(format!(
            "applied '{name}' on the console (ran once)"
        )),
        Err(error) => ConsoleToggle::Failed(error),
    }
}

/// patch ブロックの OFF: コンソールは既に解放しているので PC ジャーナルで戻す。
///
/// `cheat_enable(index, false)` は送らない（常駐していないので index が無い）。
fn console_restore_patch(session: &mut Session, key: CheatKey) -> ConsoleToggle {
    let name = console_block_name(session, key);
    let restored = {
        let mut io = ClientCheatIo {
            client: &session.client,
        };
        session.manager.disable(key, &mut io)
    };
    match restored {
        Ok(()) => {
            // 次に同じ patch を ON したら、もう一度送って実行させる。
            session.manager.forget_patch_upload(key);
            ConsoleToggle::Done(format!(
                "disabled '{name}' (the console released it; the original bytes came back from \
                 the PC journal)"
            ))
        }
        Err(error) => ConsoleToggle::Failed(error),
    }
}

/// 送信に失敗した patch のジャーナル記録を捨てる。戻り値は追加の失敗理由。
fn discard_patch_journal(session: &mut Session) -> Option<String> {
    let mut io = ClientCheatIo {
        client: &session.client,
    };
    session.manager.abort_console_patch(&mut io).err()
}

/// 主たる失敗理由に、後始末の失敗を 1 行で足す。
fn with_extra(message: String, extra: Option<String>) -> String {
    match extra {
        Some(extra) => format!("{message}; {extra}"),
        None => message,
    }
}

/// 2 秒に 1 回だけ `cheat_status` を取り直す。
///
/// 戻り値はログに出す 1 行で、これは未対応だったときのフォールバック通知だけ。
/// 通信エラーは状態行の `last_error` に出す（2 秒ごとにログを溢れさせない）。
fn refresh_console_status(session: &mut Session) -> Option<String> {
    if !session.manager.is_console_mode() {
        return None;
    }
    if session.last_console_status.elapsed() < CONSOLE_STATUS_INTERVAL {
        return None;
    }
    session.last_console_status = Instant::now();
    match session.client.cheat_status() {
        Ok(status) => {
            if status.program_valid == 0 {
                // コンソール側のプログラムが消えた（再起動・CheatClear）。
                // 控えを捨てないと、次の ON が「載っている」前提で有効化だけを
                // 送って BAD_STATE になる。
                session.manager.forget_console_upload();
            }
            let mut row = ConsoleRow::from_status(&status);
            row.fault = session.console_fault.clone();
            session.console = Some(row);
            None
        }
        Err(error) => {
            let notice = if is_unsupported_command(&error) {
                session.manager.fallback_to_pc(&error.to_string())
            } else {
                None
            };
            if let Some(row) = session.console.as_mut() {
                row.last_error = Some(error.to_string());
            }
            notice
        }
    }
}

/// `NxusEvent_CheatFault` を受けたときの後始末。
///
/// 実行はコンソール側のワーカーが持っているので、PC が書き戻すものは無い。
/// 表示（全ブロック OFF）と理由だけを合わせ、利用者に 1 行で伝える。
///
/// ただし patch の原本はコンソールが持っていない（1 回実行して解放するため）。
/// PC のジャーナルに残っている分は Panic Restore で戻すしかないので、その
/// 責務が残っていることを黙って隠さない。
fn apply_cheat_fault(manager: &mut CheatManager, fault: &CheatFault) -> String {
    let off = manager.mark_all_off();
    let mut message = format!(
        "the console stopped every cheat ({off} block(s) turned off): {}",
        fault.reason_text()
    );
    if manager.dirty() {
        message.push_str(&format!(
            "; the PC journal still owes {} address(es) - Panic Restore writes them back",
            manager.backup_count()
        ));
    }
    message
}

/// コンソールの非同期イベントを空にするまで読み、fault だけ処理する。
///
/// `poll_event` は受信キューの唯一の読み手なので、ここで吸い出さないと
/// キューが溜まる。関心のあるイベント（CheatFault）以外は捨てる。
fn drain_cheat_faults(session: &mut Session) -> Vec<String> {
    let mut messages = Vec::new();
    // 0 秒待ちなので、キューが空になった時点で必ず戻る。
    while let Some(event) = session.client.poll_event(Duration::ZERO) {
        if let Some(fault) = event.cheat_fault() {
            let message = apply_cheat_fault(&mut session.manager, &fault);
            session.console_fault = Some(fault.reason_text());
            if let Some(row) = session.console.as_mut() {
                row.fault = session.console_fault.clone();
            }
            messages.push(message);
        }
    }
    messages
}

/// panic-off の戻り値を 1 行にする。
///
/// コンソールは「書き戻せた数」と「失敗した数」を返す。失敗を隠すと
/// 「全部戻した」と誤解されるので、必ず両方出す。
fn panic_off_console_text(restore: &CheatRestore) -> String {
    let mut text = format!(
        "the console restored {} address(es) and stopped {} block(s)",
        restore.restored, restore.blocks_stopped
    );
    if restore.failed > 0 {
        text.push_str(&format!(
            "; {} address(es) could not be restored (the title is gone)",
            restore.failed
        ));
    }
    text
}

/// 接続時にコンソールの対応を 1 度だけ確かめる。
///
/// 既定はコンソール実行。新コマンドを持たないコンソールなら、最初の ON で
/// 初めて失敗するより、接続した時点で pc へ落ちて 1 行ログを出す方が分かり
/// やすい。未対応以外の失敗は tick ごとの再試行に任せる。
fn probe_console(session: &mut Session) {
    if !session.manager.is_console_mode() {
        return;
    }
    match session.client.cheat_status() {
        Ok(status) => {
            session.console = Some(ConsoleRow::from_status(&status));
            session.last_console_status = Instant::now();
        }
        Err(error) => {
            if is_unsupported_command(&error) {
                // 通知文面は manager 側に残る（`console_fallback`）。ワーカーが
                // `Ev::Log` で 1 回だけ流す。
                session.manager.fallback_to_pc(&error.to_string());
                session.console = None;
            }
        }
    }
}

struct ClientCheatIo<'a> {
    client: &'a NxusClient,
}

impl CheatMemoryIo for ClientCheatIo<'_> {
    fn read_mem(&mut self, address: u64, size: u32) -> Result<Vec<u8>, String> {
        // Cheat I/O is interactive: a console that stops answering must fail the
        // block within seconds, not park the worker for the 30 s default.  A 61
        // instruction block is 61 of these, so the old timeout turned "enabling"
        // into minutes of frozen UI.
        self.client
            .read_for_cheat(address, size)
            .map_err(|error| error.to_string())
    }

    fn write_mem(&mut self, address: u64, data: &[u8], allow_rx: bool) -> Result<(), String> {
        let result = if allow_rx {
            self.client.write_code_for_cheat(address, data)
        } else {
            self.client.write_for_cheat(address, data)
        };
        result.map_err(|error| error.to_string())
    }

    fn failure_kind(&self, error: &str) -> FailureKind {
        // 0x8003C806 = BAD_STATE (the process is no longer in a state we can
        // touch), 0x8003C805 = NO_PROCESS, 0x0032C80D = dmnt CheatNotAttached.
        if error.contains("0x8003C806")
            || error.contains("0x8003C805")
            || error.contains("0x0032C80D")
        {
            FailureKind::TargetGone
        } else {
            FailureKind::Other
        }
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
    let mut session = Session {
        client,
        manager,
        dirty: false,
        console: None,
        console_fault: None,
        last_console_status: Instant::now(),
    };
    // 実行場所の既定はコンソール。対応していないコンソールはここで pc へ
    // 落ちるので、最初のチート ON で初めて失敗する、ということが起きない。
    probe_console(&mut session);
    Ok((session, text))
}

/// Restore the patches this session enabled.  The session is only dropped when
/// every original byte is back; otherwise the UI keeps it so the user can retry.
fn retire(session: &mut Session) -> Result<String, String> {
    // コンソール実行では PC 側のジャーナルに何も無いので、`dirty` だけを見て
    // いると ON のまま切断してしまう。コンソールに載っているブロックは
    // タイトルが終わるまで書き換え続けるので、必ず先に止める。
    let mut console_note = None;
    if session.manager.is_console_mode() && !session.manager.enabled_keys().is_empty() {
        match session.client.cheat_panic_off() {
            Ok(restore) => {
                let _ = session.manager.mark_all_off();
                console_note = Some(panic_off_console_text(&restore));
            }
            Err(error) if is_unsupported_command(&error) => {
                // 旧コンソールはここへ来ない（接続時の probe で pc へ落ちる）。
            }
            Err(error) => {
                return Err(format!(
                    "cannot stop the console cheats before disconnecting: {error}"
                ));
            }
        }
    }
    if !session.dirty {
        return Ok(console_note.unwrap_or_else(|| "disconnected".to_string()));
    }
    match check_target(session) {
        Ok(true) => {}
        Ok(false) => {
            // The process is gone; its patches went with it.  Writing the old
            // originals to whatever now owns those addresses would corrupt the
            // new title.
            session.dirty = false;
            return Ok(match console_note {
                Some(note) => format!("{note}; the title restarted"),
                None => "the title restarted; old patches died with it".to_string(),
            });
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
    let message = format!(
        "restored {} address(es) before disconnecting",
        report.restored
    );
    Ok(match console_note {
        Some(note) => format!("{note}; {message}"),
        None => message,
    })
}

fn run_worker(rx: Receiver<Job>, tx: Sender<Ev>, abort: Arc<AtomicBool>) {
    // A panicking job (a bug in a cheat, a broken manager invariant count) used
    // to kill the worker silently: the channel stayed open, `busy` stayed set
    // and every button was dead.  The panic is caught here, reported as an
    // event, and `NclApp::poll_worker` replaces the thread on the next frame.
    let report = tx.clone();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        worker_loop(rx, tx, abort);
    }));
    if let Err(payload) = outcome {
        let _ = report.send(Ev::Error(format!(
            "the worker panicked: {}",
            panic_text(payload.as_ref())
        )));
    }
}

/// Sends [`Ev::Done`] when a job ends, however it ends.
///
/// Several arms below bail out with `continue` (the `let ... else` ones too),
/// which is exactly how "not connected" used to leave `busy` set forever.  A
/// guard releases the state on *every* exit path, including a `break` out of
/// the loop.
struct DoneGuard {
    tx: Sender<Ev>,
    kind: Busy,
}

impl Drop for DoneGuard {
    fn drop(&mut self) {
        // Not while unwinding: a panicking job leaves the session unusable and
        // the UI learns about it from the panic report instead.
        if !std::thread::panicking() {
            let _ = self.tx.send(Ev::Done(self.kind));
        }
    }
}

fn worker_loop(rx: Receiver<Job>, tx: Sender<Ev>, abort: Arc<AtomicBool>) {
    let mut session: Option<Session> = None;

    while let Ok(job) = rx.recv() {
        if abort.load(Ordering::SeqCst) {
            // An abort retired this generation; the job in flight has finished,
            // so nothing else may touch the console through it.
            break;
        }
        let _done = DoneGuard {
            tx: tx.clone(),
            kind: job.kind(),
        };
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
                        let view = make_session_view(&new_session);
                        // 旧コンソールで pc 実行へ落ちたなら、黙って済ませず
                        // 1 行だけ知らせる（manager 側で 1 回に絞ってある）。
                        let fallback = new_session
                            .manager
                            .console_fallback()
                            .map(std::string::ToString::to_string);
                        session = Some(new_session);
                        let _ = tx.send(Ev::Opened(view, text));
                        if let Some(notice) = fallback {
                            let _ = tx.send(Ev::Log(notice));
                        }
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
                        let view = make_session_view(&current);
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
                // コンソール実行: PC は「どのブロックか」を送るだけで、実際の
                // 書き込みは本体のワーカーが行う（従来の PC 実行パスはそのまま
                // 下に残してある）。
                if current.manager.is_console_mode() {
                    match console_toggle(&mut current, key, on) {
                        ConsoleToggle::Done(message) => {
                            current.dirty = current.manager.dirty();
                            let view = make_session_view(&current);
                            session = Some(current);
                            let _ = tx.send(Ev::Updated(view, message));
                            continue;
                        }
                        ConsoleToggle::Failed(error) => {
                            current.dirty = current.manager.dirty();
                            let view = make_session_view(&current);
                            session = Some(current);
                            let _ =
                                tx.send(Ev::Updated(view, format!("could not toggle '{name}'")));
                            let _ = tx.send(Ev::Error(format!("{name}: {error}")));
                            continue;
                        }
                        ConsoleToggle::Unsupported(reason) => {
                            // 接続時の probe をすり抜けた（新しいファームで
                            // 一部だけ未実装など）。ここで pc へ落として、
                            // 同じ操作をそのまま PC 経路で実行する。
                            if let Some(notice) = current.manager.fallback_to_pc(&reason) {
                                let _ = tx.send(Ev::Log(notice));
                            }
                        }
                    }
                }
                let mut io = ClientCheatIo {
                    client: &current.client,
                };
                match current.manager.toggle(key, on, &mut io) {
                    Ok(()) => {
                        // The manager owns the truth about leftover patches: a toggle that returned
                        // Ok after a failed restore used to look clean and was then never restored.
                        current.dirty = current.manager.dirty();
                        let view = make_session_view(&current);
                        session = Some(current);
                        let message = if on {
                            format!("enabled '{name}'")
                        } else {
                            format!("disabled '{name}'")
                        };
                        let _ = tx.send(Ev::Updated(view, message));
                    }
                    Err(error) => {
                        current.dirty = current.manager.dirty();
                        let view = make_session_view(&current);
                        session = Some(current);
                        let _ = tx.send(Ev::Updated(view, format!("could not toggle '{name}'")));
                        let _ = tx.send(Ev::Error(format!("{name}: {error}")));
                    }
                }
            }
            Job::Tick => {
                let Some(mut current) = session.take() else {
                    // No session at all (a tick still queued from just before a
                    // disconnect).  Say so instead of returning silently: a
                    // silent bail-out is how `busy` used to stay set forever.
                    // `Ev::Done` for this tick is sent by the guard.
                    let _ = tx.send(Ev::Log("tick skipped: not connected".to_string()));
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
                if current.manager.is_console_mode() {
                    // コンソール実行中は PC からは何も書かない。ループは本体の
                    // 16 ms ワーカーが回しているので、ここでやるのは fault の
                    // 監視と 2 秒ごとの状態取得だけ。
                    for message in drain_cheat_faults(&mut current) {
                        let _ = tx.send(Ev::Log(message));
                    }
                    if let Some(notice) = refresh_console_status(&mut current) {
                        let _ = tx.send(Ev::Log(notice));
                    }
                    let view = make_session_view(&current);
                    session = Some(current);
                    let _ = tx.send(Ev::Ticked(view));
                    continue;
                }
                let keys = status.map(|status| status.keys_held).unwrap_or(0);
                let mut io = ClientCheatIo {
                    client: &current.client,
                };
                let report = current.manager.tick(&mut io, keys);
                let view = make_session_view(&current);
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
                // コンソール実行では、まず本体のワーカーに全部止めさせて原本を
                // 書き戻させる（復元表はコンソールが持っている）。そのあとで
                // 従来のジャーナル復元も走らせる: PC 経路で書いた分が残って
                // いれば、それも戻す必要がある。
                let mut console_note = None;
                if current.manager.is_console_mode() {
                    match current.client.cheat_panic_off() {
                        Ok(restore) => {
                            let _ = current.manager.mark_all_off();
                            console_note = Some(panic_off_console_text(&restore));
                            if !restore.is_complete() {
                                let _ = tx.send(Ev::Error(format!(
                                    "the console could not restore {} address(es) - the title is \
                                     probably gone",
                                    restore.failed
                                )));
                            }
                        }
                        Err(error) if is_unsupported_command(&error) => {
                            if let Some(notice) = current.manager.fallback_to_pc(&error.to_string())
                            {
                                let _ = tx.send(Ev::Log(notice));
                            }
                        }
                        Err(error) => {
                            let view = make_session_view(&current);
                            session = Some(current);
                            let _ = tx.send(Ev::Updated(
                                view,
                                "could not stop the console cheats".to_string(),
                            ));
                            let _ = tx.send(Ev::Error(format!("cheat panic-off: {error}")));
                            continue;
                        }
                    }
                }
                let mut io = ClientCheatIo {
                    client: &current.client,
                };
                let report = current.manager.restore_all_backups(&mut io);
                if report.is_complete() {
                    current.dirty = false;
                }
                let view = make_session_view(&current);
                session = Some(current);
                let pc_message = format!(
                    "restored {} address(es), cleared {} enabled cheat(s)",
                    report.restored, report.cleared_cheats
                );
                let message = match console_note {
                    Some(note) => format!("{note}; PC journal: {pc_message}"),
                    None => pc_message,
                };
                let complete = report.is_complete();
                let failed = report.failed.len();
                let _ = tx.send(Ev::Restored(view, message, complete));
                if !complete {
                    let _ = tx.send(Ev::Error(format!(
                        "{failed} address(es) could not be restored - keep the console and retry"
                    )));
                }
            }
            Job::SetMode(execution) => {
                let Some(current) = session.as_mut() else {
                    let _ = tx.send(Ev::Error("not connected".to_string()));
                    continue;
                };
                if current.manager.execution() == execution {
                    continue;
                }
                if !current.manager.enabled_keys().is_empty() {
                    // 同じアドレスを 2 つの VM が書くと、片方のジャーナルが必ず
                    // 嘘になる。切替は「全部 OFF」のときだけ許す。
                    let view = make_session_view(current);
                    let _ = tx.send(Ev::Updated(
                        view,
                        "turn every cheat off before switching where they run".to_string(),
                    ));
                    continue;
                }
                current.manager.set_execution(execution);
                current.console = None;
                current.console_fault = None;
                // 切替直後に状態を取りに行く（2 秒待たない）。
                current.last_console_status = Instant::now()
                    .checked_sub(CONSOLE_STATUS_INTERVAL)
                    .unwrap_or_else(Instant::now);
                let view = make_session_view(current);
                let _ = tx.send(Ev::Updated(
                    view,
                    format!("cheats now run on the {}", execution.label()),
                ));
            }
            Job::ReloadFile => {
                let Some(current) = session.as_mut() else {
                    let _ = tx.send(Ev::Error("not connected".to_string()));
                    continue;
                };
                // Reloading is allowed while cheats are ON: the live blocks are
                // reconciled with the file instead of being dropped.
                let mut io = ClientCheatIo {
                    client: &current.client,
                };
                match current.manager.reload(&mut io) {
                    Ok(report) => {
                        current.dirty = current.manager.dirty();
                        let view = make_session_view(current);
                        let text = current.manager.document().raw_text.clone();
                        let _ = tx.send(Ev::Opened(view, text));
                        for line in report.log_lines() {
                            let _ = tx.send(Ev::Log(line));
                        }
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
// Status toasts
// ---------------------------------------------------------------------------

// The bottom status bar used to be a single `message` that every event
// overwrote, so a burst (connect, retry, job start, its reply) replaced the
// line faster than it could be read.  NCL is a separate binary and cannot use
// `gui::mod`'s copy, so the small queue lives here too - same rules, same
// thresholds as `nxus.exe`'s status bar (see `gui/mod.rs`).
//
// Keep the two in step: TOAST_DWELL / TOAST_PRIORITY_DWELL / TOAST_QUEUE_MAX
// are deliberately identical, so both windows behave the same way.

/// How long one queued line stays on screen before the next one takes over.
const TOAST_DWELL: Duration = Duration::from_millis(1200);
/// A priority line (an error, a lost link, a busy refusal) stays longer.
const TOAST_PRIORITY_DWELL: Duration = Duration::from_millis(2500);
/// Lines waiting for their turn; the oldest are dropped past this.
const TOAST_QUEUE_MAX: usize = 32;
/// `Toast::priority` of a line that interrupts whatever is on screen.
const TOAST_PRIORITY: u8 = 2;
/// Words that make a line important (case-insensitive).
const TOAST_PRIORITY_WORDS: [&str; 5] = ["error", "lost", "busy", "failed", "stopped"];

/// One line of the bottom status bar, waiting for (or getting) its turn.
struct Toast {
    text: String,
    /// When this line took the screen (or was last refreshed by a repeat).
    shown_at: Instant,
    /// How often the same message arrived in a row: shown as `(x3)`.
    repeats: u32,
    /// 0 = normal, [`TOAST_PRIORITY`] = interrupts and stays longer.
    priority: u8,
}

impl Toast {
    fn dwell(&self) -> Duration {
        if self.priority >= TOAST_PRIORITY {
            TOAST_PRIORITY_DWELL
        } else {
            TOAST_DWELL
        }
    }

    /// The line, how often it was repeated, and whether more is waiting.
    fn render(&self, more_waiting: bool) -> String {
        let mut text = self.text.clone();
        if self.repeats > 1 {
            text.push_str(&format!(" (x{})", self.repeats));
        }
        if more_waiting {
            text.push_str(" …");
        }
        text
    }
}

fn toast_priority(text: &str) -> u8 {
    let lower = text.to_ascii_lowercase();
    if TOAST_PRIORITY_WORDS.iter().any(|word| lower.contains(word)) {
        TOAST_PRIORITY
    } else {
        0
    }
}

/// The message part of a line: `log()`'s `[  12.3s]` stamp is not part of it,
/// so the same message logged twice is still "the same message".
fn toast_key(text: &str) -> &str {
    let Some(rest) = text.strip_prefix('[') else { return text };
    let Some(end) = rest.find(']') else { return text };
    if rest[..end].trim_end().ends_with('s') {
        rest[end + 1..].trim_start()
    } else {
        text
    }
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
    /// チートを実行する場所の選択（実体は worker 側のマネージャが持つ）。
    ///
    /// UI 側にも控えるのは、`Job::SetMode` が断られたとき（ON のブロックが
    /// 残っている間）に表示を戻すため。worker から view が届いたら、そちらの
    /// `execution` に合わせる（フォールバックもこれで画面に反映される）。
    execution: CheatExecution,

    worker: Worker,
    /// The job in flight, or `None`.  Never a `String` any more: see [`Busy`].
    busy: Option<BusyJob>,
    /// The 10 s watchdog warning was already logged for the current job.
    watchdog_warned: bool,
    /// The bottom status bar's queue (see [`Toast`]).  Messages are pushed
    /// here instead of overwriting one string, so a burst of events is
    /// readable.
    toasts: VecDeque<Toast>,
    /// The line the bar shows while the queue is empty: the last one that was
    /// displayed, kept instead of blanking the bar.
    last_shown: String,

    live: Option<LiveView>,
    live_text: Option<String>,

    editor: EditorState,
    library: LibraryState,
    /// Background library scans in flight; each one keeps the frame clock
    /// running so its result is painted when it lands.
    scans: u32,

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
    /// Frames spent waiting for the encoder thread; bounded so `--screenshot`
    /// can never keep the process alive forever.
    shot_wait_frames: u32,
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

        let dir = cheat::cheats_directory().unwrap_or_else(|_| PathBuf::from("cheats"));

        let mut app = NclApp {
            tab: Tab::Cheats,
            host: prefs.host,
            port: prefs.port,
            auto_tick: prefs.auto_tick,
            execution: CheatExecution::Console,
            worker: Worker::spawn(),
            busy: None,
            watchdog_warned: false,
            toasts: VecDeque::new(),
            last_shown: "ready".to_string(),
            live: None,
            live_text: None,
            editor: EditorState::default(),
            library: LibraryState {
                dir,
                files: Vec::new(),
                error: None,
            },
            scans: 0,
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
            shot_wait_frames: 0,
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
        // Parsing every cheat file takes long enough to be seen as a hang, so
        // even the startup scan runs off the UI thread.
        app.refresh_library();
        if let Some(path) = initial_file {
            app.open_file(path);
        }
        if auto_connect {
            app.connect();
        }
        app
    }

    /// Append a line to the log AND queue it for the status bar.
    ///
    /// The signature is unchanged: every caller keeps working, but the status
    /// line is no longer overwritten - the line waits its turn (see [`Toast`]).
    fn log(&mut self, message: impl Into<String>) {
        let elapsed = self.started.elapsed().as_secs_f64();
        let line = format!("[{elapsed:6.1}s] {}", message.into());
        self.toast(line.clone());
        self.log.push_back(line);
        while self.log.len() > MAX_LOG_LINES {
            self.log.pop_front();
        }
    }

    /// Queue a status line without adding it to the log list.
    fn toast(&mut self, message: impl Into<String>) {
        self.push_toast(message.into());
    }

    fn push_toast(&mut self, text: String) {
        let now = Instant::now();
        let priority = toast_priority(&text);
        // The same line again is one line with a counter.
        if let Some(index) = self.repeat_of(&text, priority) {
            let toast = &mut self.toasts[index];
            toast.repeats = toast.repeats.saturating_add(1);
            toast.text = text;
            toast.shown_at = now;      // give the "(x2)" time to be read
            return;
        }
        let toast = Toast { text, shown_at: now, repeats: 1, priority };
        if priority >= TOAST_PRIORITY {
            // Interrupt: what is on screen goes back to the front of the queue.
            self.toasts.push_front(toast);
        } else {
            self.toasts.push_back(toast);
        }
        while self.toasts.len() > TOAST_QUEUE_MAX && self.toasts.len() > 1 {
            if priority >= TOAST_PRIORITY {
                self.toasts.remove(1);   // the oldest waiting line, never the new one
            } else {
                self.toasts.pop_front();
            }
        }
    }

    /// The queued line `text` repeats, if any.  A normal line repeats the newest
    /// entry; a priority line lands at the FRONT, so that is where a repeat of it
    /// has to be looked for.
    fn repeat_of(&self, text: &str, priority: u8) -> Option<usize> {
        let key = toast_key(text);
        let last = self.toasts.len().checked_sub(1)?;
        let candidates: [usize; 2] =
            if priority >= TOAST_PRIORITY { [0, last] } else { [last, last] };
        candidates.into_iter().find(|&index| {
            self.toasts
                .get(index)
                .map(|queued| toast_key(&queued.text) == key)
                .unwrap_or(false)
        })
    }

    /// Retire the lines whose dwell is over.  Called once per frame.
    fn advance_toasts(&mut self) {
        let now = Instant::now();
        loop {
            let Some(front) = self.toasts.front() else { break };
            if now.duration_since(front.shown_at) < front.dwell() {
                break;
            }
            let shown = self.toasts.pop_front().expect("the front was just read");
            self.last_shown = shown.text;
            if let Some(next) = self.toasts.front_mut() {
                next.shown_at = now;     // its dwell starts now, not when queued
            }
        }
    }

    /// What the status bar shows: the current toast, else the last line.
    fn current_status(&self) -> String {
        if let Some(front) = self.toasts.front() {
            return front.render(self.toasts.len() > 1);
        }
        self.last_shown.clone()
    }

    /// How long until the line on screen may be replaced: the frame clock has to
    /// be asked, or the queue would only advance on mouse movement.
    fn toast_wait(&self) -> Option<Duration> {
        let front = self.toasts.front()?;
        Some(front.dwell().saturating_sub(front.shown_at.elapsed()))
    }

    /// Send a job and start waiting for it.
    ///
    /// A job that is already in flight is not silently dropped any more (that
    /// is what made every click after a stuck job vanish): a short loop tick
    /// can be queued behind, anything else answers with the current state plus
    /// the way out.  The priority jobs - Disconnect, Panic OFF and Quit - never
    /// come through here while busy; they call [`NclApp::abort_busy`] first.
    fn submit(&mut self, job: Job) -> bool {
        let kind = job.kind();
        if let Some(busy) = self.busy {
            if kind.is_soft() && busy.kind.is_soft() {
                // "Tick now" while a tick is in flight: do nothing at all.  It
                // must not rewrite the state, or the tick that is really
                // running would never clear it.
                self.toast("a loop tick is already running");
                return false;
            }
            if !busy.kind.is_soft() {
                self.toast(format!(
                    "busy: {} for {} s - press Disconnect to abort it",
                    busy.kind.label(),
                    busy.elapsed().as_secs()
                ));
                if job.is_priority() {
                    // A priority job that reaches here is a programming error:
                    // the callers use `abort_busy` instead.  Say so instead of
                    // dropping it silently.
                    self.log(format!(
                        "warning: {} was submitted while {} was running",
                        kind.label(),
                        busy.kind.label()
                    ));
                }
                return false;
            }
        }
        self.start(job)
    }

    fn start(&mut self, job: Job) -> bool {
        let kind = job.kind();
        if !self.worker.send(job) {
            self.log("the worker is gone - restarting it");
            self.restart_worker();
            self.toast("the worker was restarted; try again");
            return false;
        }
        self.busy = Some(BusyJob::new(kind));
        self.watchdog_warned = false;
        // A tick must not overwrite the log line the user is reading four times
        // a second.
        if !kind.is_soft() {
            self.toast(kind.label());
        }
        true
    }

    /// Abort the job in flight, drop the console session it owns and start a
    /// fresh worker - without waiting for the stuck call to return.
    ///
    /// Returns false when nothing had to be aborted, so the caller can take the
    /// normal (restore, then disconnect) path instead.
    fn abort_busy(&mut self, why: &str) -> bool {
        let Some(busy) = self.busy else {
            return false;
        };
        // A loop tick is over in milliseconds; only a stuck one is worth
        // aborting.
        if busy.kind.is_soft() && busy.elapsed() < BUSY_WATCHDOG {
            return false;
        }
        let seconds = busy.elapsed().as_secs();
        self.log(format!(
            "abort ({why}): {} did not finish within {seconds} s; dropping the console session",
            busy.kind.label()
        ));
        self.busy = None;
        self.watchdog_warned = false;
        // The session belongs to the aborted generation: it is not ours to show
        // any more, and its socket is about to be closed.
        self.live = None;
        self.live_text = None;
        self.restart_worker();
        self.last_tick = Instant::now();
        self.toast(format!(
            "aborted {} after {seconds} s - the console session was abandoned (patches were not \
             restored here); connect again and press Panic OFF",
            busy.kind.label()
        ));
        true
    }

    fn restart_worker(&mut self) {
        let old = std::mem::replace(&mut self.worker, Worker::spawn());
        old.retire();
        // A scan started by the old generation can no longer answer.
        self.scans = 0;
    }

    /// Disconnect, the one button that must always work.
    fn disconnect(&mut self) {
        if self.abort_busy("disconnect") {
            return;
        }
        self.submit(Job::Disconnect);
    }

    /// Panic OFF must always be reachable.  If a job is stuck the restore
    /// cannot run through it, so the connection is aborted instead and the
    /// backup journal (on disk) is left for the next connect.
    fn panic_off(&mut self) {
        self.panic_confirm = false;
        if self.abort_busy("panic off") {
            return;
        }
        self.submit(Job::PanicOff);
    }

    /// Replace a worker that exited (a panic, a failed spawn) so the window can
    /// never keep pointing at a dead thread - that used to look exactly like a
    /// hung connection.
    fn poll_worker(&mut self) {
        if !self.worker.is_finished() {
            return;
        }
        self.restart_worker();
        self.busy = None;
        self.watchdog_warned = false;
        self.live = None;
        self.live_text = None;
        self.log("the worker exited unexpectedly - started a fresh one");
        self.toast("the worker stopped (it crashed); a fresh one is ready - connect again");
    }

    /// 10 s without an answer is already a bug or a dead console: say so.  At
    /// 60 s the window aborts by itself, because a "busy" state nobody can
    /// clear is the exact failure this code exists to prevent.
    fn poll_watchdog(&mut self) {
        let Some(busy) = self.busy else {
            return;
        };
        let elapsed = busy.elapsed();
        if elapsed >= BUSY_HARD_LIMIT {
            self.abort_busy("watchdog");
            return;
        }
        if elapsed >= BUSY_WATCHDOG && !self.watchdog_warned {
            self.watchdog_warned = true;
            self.log(format!(
                "warning: {} has been running for {} s - press Disconnect to stop waiting",
                busy.kind.label(),
                elapsed.as_secs()
            ));
        }
    }

    /// True when a job may be queued behind the current one (nothing running,
    /// or a short loop tick).
    fn can_queue(&self) -> bool {
        self.busy.map(|busy| busy.kind.is_soft()).unwrap_or(true)
    }

    /// The elapsed time of a job that has overstayed the watchdog.
    fn stuck_for(&self) -> Option<Duration> {
        let busy = self.busy?;
        let elapsed = busy.elapsed();
        if elapsed >= BUSY_WATCHDOG {
            Some(elapsed)
        } else {
            None
        }
    }

    /// Status text: the message, or what is running and for how long - the
    /// "busy since N s" the watchdog is about.
    fn busy_text(&self) -> String {
        match self.busy {
            Some(busy) if !busy.kind.is_soft() => format!(
                "{} ... {} s{}",
                busy.kind.label(),
                busy.elapsed().as_secs(),
                if busy.elapsed() >= BUSY_WATCHDOG {
                    " - stuck? press Disconnect"
                } else {
                    ""
                }
            ),
            _ => self.current_status(),
        }
    }

    /// Scan `cheats/` on a helper thread.
    ///
    /// The scan parses every file in the directory; doing that inside the frame
    /// that asked for it froze the window for as long as the disk took.
    fn refresh_library(&mut self) {
        self.scans = self.scans.saturating_add(1);
        let dir = self.library.dir.clone();
        let tx = self.worker.events_tx.clone();
        let started = spawn_io(tx, "ncl-library-scan", move || {
            let (files, error) = scan_library(&dir);
            Ev::Library { files, error }
        });
        if !started {
            self.scans = self.scans.saturating_sub(1);
            self.log("cannot start the library scan thread");
        }
    }

    fn connect(&mut self) {
        let host = self.host.trim().to_string();
        if host.is_empty() {
            self.toast("enter the console IP address");
            return;
        }
        let port = self.port.trim().parse::<u16>().unwrap_or(DEFAULT_PORT);
        self.submit(Job::Connect { host, port });
    }

    fn any_enabled(&self) -> bool {
        self.live
            .as_ref()
            .map(LiveView::any_enabled)
            .unwrap_or(false)
    }

    fn drain_events(&mut self) {
        // `next_event` gives the event back before the handler runs, so the
        // worker is not borrowed while a handler calls another `&mut self`
        // method (which is why this is not a `match self.worker.next_event()`).
        while let Some(event) = self.worker.next_event() {
            self.handle_event(event);
        }
    }

    fn handle_event(&mut self, event: Ev) {
        match event {
            Ev::Opened(view, text) => {
                self.log(format!("opened {}", view.target.path.display()));
                self.editor.path = view.target.path.clone();
                self.editor.build_id = view.target.build_id.clone();
                self.execution = view.target.execution;
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
                self.refresh_library();
            }
            Ev::Updated(view, message) => {
                self.log(message);
                self.execution = view.target.execution;
                self.live = Some(view);
            }
            Ev::Restored(view, message, complete) => {
                self.log(message);
                self.execution = view.target.execution;
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
            Ev::Ticked(view) => {
                self.execution = view.target.execution;
                self.live = Some(view);
            }
            Ev::Done(kind) => {
                // The only way out of a busy state: the completion of the very
                // job the UI is waiting for.
                if self.busy.map(|busy| busy.kind == kind).unwrap_or(false) {
                    self.busy = None;
                    self.watchdog_warned = false;
                }
            }
            Ev::Library { files, error } => {
                self.scans = self.scans.saturating_sub(1);
                self.library.files = files;
                if let Some(error) = &error {
                    // The scan runs off the UI thread now, so this is where a
                    // directory that cannot be read becomes visible.
                    self.log(format!("warning: {error}"));
                }
                self.library.error = error;
            }
            Ev::Error(error) => {
                // No longer clears `busy`: an error that belongs to some other
                // job must not release the one in flight.
                self.log(format!("error: {error}"));
            }
            Ev::Disconnected(message) => {
                self.log(message);
                self.live = None;
                self.live_text = None;
            }
            Ev::Log(message) => {
                // A broken Loop cheat would otherwise repeat the same error
                // four times a second and flush the whole log.
                if message.starts_with("loop:") {
                    if self.last_loop_error.as_deref() == Some(&message) {
                        return;
                    }
                    self.last_loop_error = Some(message.clone());
                }
                self.log(message);
            }
        }
    }

    fn schedule_tick(&mut self) {
        let Some(live) = self.live.as_ref() else {
            return;
        };
        // コンソール実行ではループが無くても tick を回す: fault（本体が自分で
        // 全部止めた）の監視と、2 秒ごとの状態取得がこの tick に乗っている。
        if !self.auto_tick || !(live.has_loops() || live.runs_on_console()) || self.busy.is_some() {
            return;
        }
        if self.last_tick.elapsed() < TICK_INTERVAL {
            return;
        }
        self.last_tick = Instant::now();
        // Through `start` so the state and the `Ev::Done` that clears it are the
        // same value by construction.
        self.start(Job::Tick);
    }

    fn open_file(&mut self, path: PathBuf) {
        match self.editor.load(&path) {
            Ok(()) => {
                self.tab = Tab::Editor;
                self.log(format!("loaded {}", path.display()));
                self.refresh_parse();
            }
            Err(error) => {
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

    fn save_editor(&mut self) {
        // Saving is always allowed, even while cheats are ON: the file is the
        // user's document, not a mirror of the applied bytes.  What happens to
        // the blocks that are ON is decided by the manager when the file is
        // re-read (`Job::ReloadFile`): unchanged ones stay applied, edited ones
        // become stale and deleted ones are restored.
        let path = match self.editor_path() {
            Ok(path) => path,
            Err(error) => {
                self.log(format!("error: {error}"));
                return;
            }
        };
        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                self.log(format!("error: cannot create {}: {error}", parent.display()));
                return;
            }
        }
        match save_text_atomic(&path, &self.editor.text) {
            Ok(()) => {
                self.editor.path = path.clone();
                self.editor.last_saved = self.editor.text.clone();
                self.refresh_parse();
                // Off the UI thread: this parses every file in `cheats/`.
                self.refresh_library();
                self.log(format!("saved {}", path.display()));
                if let Some(live) = &self.live {
                    if live.target.path == path {
                        self.submit(Job::ReloadFile);
                    }
                }
            }
            Err(error) => {
                self.log(format!("error: save failed: {error}"));
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
            self.toast("loaded the connected target's cheat file");
        } else {
            self.toast("connect first");
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
                    // Never disabled: while a job is stuck this aborts it, which
                    // is the whole point of the escape hatch.
                    let label = if self.can_queue() {
                        "Disconnect".to_string()
                    } else {
                        "Disconnect (abort)".to_string()
                    };
                    if ui
                        .button(label)
                        .on_hover_text(
                            "restore the patches this session enabled, then disconnect; \
                             while a job is stuck this aborts it instead",
                        )
                        .clicked()
                    {
                        self.disconnect();
                    }
                } else if ui
                    .add(egui::Button::new(RichText::new("Connect").strong()))
                    .clicked()
                {
                    self.connect();
                }
                if ui
                    .add_enabled(
                        self.live.is_some() && self.can_queue(),
                        egui::Button::new("Refresh"),
                    )
                    .clicked()
                {
                    self.submit(Job::Refresh);
                }
                if let Some(stuck) = self.stuck_for() {
                    let label = format!("Abort ({} s)", stuck.as_secs());
                    if ui
                        .add(egui::Button::new(RichText::new(label).strong().color(RED)))
                        .on_hover_text(
                            "stop waiting for the job in flight: the console session is \
                             dropped without restoring patches",
                        )
                        .clicked()
                    {
                        self.abort_busy("user abort");
                    }
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
                    if live.target.stale > 0 {
                        ui.label(
                            RichText::new(format!(
                                "{} edited (re-toggle to apply)",
                                live.target.stale
                            ))
                            .color(YELLOW),
                        );
                    }
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
                // "busy since N s": the watchdog state is visible, not just a
                // message that never changes while a job hangs.
                let stuck = self.stuck_for();
                // A queued message is live; an empty queue keeps the last line
                // dimmed instead of blanking the bar.
                let live = !self.toasts.is_empty() || self.busy.is_some();
                ui.label(
                    RichText::new(self.busy_text())
                        .color(if stuck.is_some() { RED } else if live { DIM } else { FAINT }),
                );
                if stuck.is_some() {
                    if ui
                        .add(egui::Button::new(
                            RichText::new("Abort").small().color(RED),
                        ))
                        .on_hover_text(
                            "drop the stuck job and its console session (patches are not \
                             restored; reconnect and use Panic OFF)",
                        )
                        .clicked()
                    {
                        self.abort_busy("user abort");
                    }
                }
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
                .add_enabled(self.can_queue(), egui::Button::new("Reload file"))
                .on_hover_text(
                    "re-read the file from disk: cheats that are ON keep the bytes they applied, \
                     edited blocks are marked \"edited - re-toggle to apply\", and blocks that \
                     were deleted from the file are restored and turned off",
                )
                .clicked()
            {
                self.submit(Job::ReloadFile);
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
                .on_hover_text(
                    "restore every original byte recorded in the backup journal; if a job is \
                     stuck this aborts it instead (the journal stays on disk)",
                );
            if panic.clicked() {
                self.panic_confirm = true;
            }
            if ui
                .add_enabled(
                    live.has_loops() && self.can_queue(),
                    egui::Button::new("Tick now"),
                )
                .on_hover_text("evaluate the Loop cheats once, right now")
                .clicked()
            {
                // Refused (and the state left untouched) while a tick is in
                // flight; see `NclApp::submit`.
                self.submit(Job::Tick);
            }
        });
        // 実行場所の切替。既定はコンソール（本体の 16 ms ワーカーで回る）。
        // `PC` は従来の read/write 経路で、新コマンドを持たないコンソール向け。
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("run on").strong());
            let mut wanted = self.execution;
            ui.selectable_value(&mut wanted, CheatExecution::Console, "console")
                .on_hover_text(
                    "upload the linked program and let the console's 16 ms worker run it \
                     (key conditions at frame rate, cheats keep running after a disconnect)",
                );
            ui.selectable_value(&mut wanted, CheatExecution::Pc, "PC")
                .on_hover_text(
                    "run the cheats from this PC (the classic read/write path); nothing is \
                     uploaded, so the PC must stay connected",
                );
            if wanted != self.execution {
                // 表示はすぐ切り替える。ON のブロックが残っている間の切替は
                // worker が断り、その view でここが元に戻る。
                self.execution = wanted;
                self.submit(Job::SetMode(wanted));
            }
            if let Some(console) = &live.console {
                ui.separator();
                ui.label(
                    RichText::new(if console.program_valid {
                        "program loaded"
                    } else {
                        "no program"
                    })
                    .color(if console.program_valid { GREEN } else { DIM }),
                );
                ui.label(
                    RichText::new(format!(
                        "{} loop block(s) / {} on / {} insn",
                        console.block_count, console.enabled_count, console.insn_count
                    ))
                    .color(DIM),
                );
                ui.monospace(format!("tick {}", console.tick_count));
                ui.monospace(format!("journal {}", console.journal_count));
                ui.monospace(format!("faults {}", console.fault_count));
                ui.label(if console.running {
                    RichText::new("running").color(GREEN)
                } else {
                    RichText::new("stopped").color(DIM)
                });
                if let Some(error) = &console.last_error {
                    ui.label(RichText::new(error).color(YELLOW));
                }
                if let Some(fault) = &console.fault {
                    // コンソールが自分で止めた理由。全ブロックは既に OFF 表示に
                    // なっている（`mark_all_off`）。
                    ui.label(RichText::new(fault).color(RED));
                }
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
        // Checkboxes stay usable during a loop tick (a soft job) and are
        // disabled only while a real job is in flight.
        let busy = !self.can_queue();
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
                            } else if row.live && row.stale {
                                // The console still runs (or the target still
                                // holds) the old code; the edited code is not
                                // applied until the block is toggled off and on.
                                ui.label(
                                    RichText::new("edited - re-toggle to apply")
                                        .strong()
                                        .color(YELLOW),
                                )
                                .on_hover_text(
                                    "this block is ON with the bytes it applied before the edit; \
                                     toggle it off and on to apply the new code",
                                );
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
            self.submit(Job::Toggle { key, on });
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
                    self.toast("enter a file path first");
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
                .add(egui::Button::new(RichText::new("Save").strong()))
                .on_hover_text(
                    "write atomically; Ctrl+S.  Saving works while cheats are ON - edited \
                     blocks keep their old bytes and are not re-applied until you toggle them \
                     off and on",
                )
                .clicked()
            {
                self.save_editor();
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
            let stale = self
                .live
                .as_ref()
                .map(|live| live.target.stale)
                .unwrap_or(0);
            ui.label(
                RichText::new(format!(
                    "Cheats are ON: saving and reloading still work.  A block you edit keeps \
                     the bytes it already wrote and is marked \"edited - re-toggle to apply\" \
                     ({stale} now); a block you delete is restored and turned off.",
                ))
                .color(DIM),
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
            if ui
                .add_enabled(self.scans == 0, egui::Button::new("Refresh"))
                .on_hover_text("re-read cheats/ (runs on a helper thread)")
                .clicked()
            {
                // Off the UI thread: the scan parses every file in the folder.
                self.refresh_library();
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
                            // Priority: a stuck job is aborted rather than
                            // waited for (the journal stays on disk).
                            self.panic_off();
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
                    if self.busy.is_some() {
                        ui.label(
                            RichText::new(format!(
                                "A job is still running ({}).  \"Restore && quit\" stays \
                                 unavailable until it finishes; quitting without restoring \
                                 leaves the console patched until the title restarts.",
                                self.busy_text()
                            ))
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
                                .on_hover_text(
                                    "restore every patch, then close; unavailable while a job \
                                     is stuck in the worker",
                                )
                                .clicked()
                        {
                            self.quit_after_restore = true;
                            self.submit(Job::PanicOff);
                        }
                        // Always enabled: a stuck job must never trap the user
                        // in a window that will not close.
                        if ui
                            .add(egui::Button::new(
                                RichText::new(if enabled > 0 {
                                    "Quit without restoring"
                                } else {
                                    "Discard && quit"
                                })
                                .color(RED),
                            ))
                            .on_hover_text("always available, even while a job is stuck")
                            .clicked()
                        {
                            // Make the log honest before the process goes away.
                            self.abort_busy("quit");
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
            self.save_editor();
        }
        if ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::F5)) {
            self.refresh_parse();
        }
        if ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::F9)) {
            if self.live.is_some() {
                self.submit(Job::Refresh);
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
            // The encoder runs on its own thread (a full-window PNG is tens of
            // milliseconds of pure CPU); keep the frame clock going until it
            // sets the flag, but never let it hold the process open forever.
            self.shot_wait_frames += 1;
            if self.shot_wait_frames > 600 {
                eprintln!("screenshot: the encoder thread did not finish; giving up");
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                return;
            }
            ctx.request_repaint_after(Duration::from_millis(30));
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
            // Encoding and writing the PNG is far too much work for the frame
            // that produced it, so it goes to a helper thread.
            let path_text = path_text.clone();
            let spawned = std::thread::Builder::new()
                .name("ncl-screenshot".to_string())
                .spawn(move || {
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
            if spawned.is_err() {
                eprintln!("screenshot: cannot start the encoder thread");
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
        self.poll_worker();
        self.poll_watchdog();
        // Retire the status lines whose dwell is over before drawing them.
        self.advance_toasts();
        if self.pending_close {
            self.pending_close = false;
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
        self.schedule_tick();
        self.handle_shortcuts(ui.ctx());
        self.handle_close(ui.ctx());
        self.handle_screenshot(ui.ctx());

        // Parse while the user pauses, so diagnostics stay current without
        // re-parsing a large file on every keystroke.  The 400 ms debounce
        // needs a frame to fire in, so ask for one while text is unvalidated.
        if self.editor.validated_text != self.editor.text {
            let due = self
                .editor
                .last_edit
                .map(|edit| edit.elapsed() >= Duration::from_millis(400))
                .unwrap_or(true);
            if due && self.editor.text.len() <= 262_144 {
                self.refresh_parse();
            } else {
                ui.ctx().request_repaint_after(Duration::from_millis(120));
            }
        }
        // A background library scan cannot wake the frame clock by itself.
        if self.scans > 0 {
            ui.ctx().request_repaint_after(Duration::from_millis(100));
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
        } else if self.auto_tick
            && self
                .live
                .as_ref()
                .map(|view| view.has_loops() || view.runs_on_console())
                .unwrap_or(false)
        {
            // コンソール実行ではループが無くても tick を回す（状態取得と
            // fault の監視）。フレーム時計を止めると、それも止まる。
            ui.ctx().request_repaint_after(TICK_INTERVAL);
        }
        // The toast queue runs on a wall clock too: without this the next line
        // would appear only when the user moved the mouse.
        // `request_repaint_after` keeps the earliest request, so this never
        // delays the polls above.
        if let Some(wait) = self.toast_wait() {
            ui.ctx().request_repaint_after(wait);
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

    // `--list` / `--check` / `--help` print to stdout: give them a console (or keep an
    // inherited pipe).  Everything else is the GUI, which must stay console-free.
    let cli_like = args.iter().any(|argument| {
        matches!(
            argument.as_str(),
            "--list" | "--check" | "--help" | "-help" | "-h" | "help" | "/?" | "--version" | "-V"
        )
    });
    if cli_like {
        console::ensure_cli_output();
    } else {
        console::hide_own_console();
    }

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
