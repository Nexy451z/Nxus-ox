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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use eframe::egui;
use egui::{Color32, RichText};

use crate::cheat::manager::CheatExecution;
use crate::cheat::{
    self, normalize_build_id, save_text_atomic, CheatDocument, CheatExecMode, CheatKey, CheatManager,
    CheatMemoryIo, FailureKind, MemoryRegions, TargetIdentity, MAX_CHEAT_FILE_BYTES,
};
use crate::client::{is_unsupported_command, CheatFault, CheatRestore, CheatStatus, NxusClient};
use crate::protocol::{Metadata, Status};

const TICK_INTERVAL: Duration = Duration::from_millis(250);
const PARSE_DELAY: Duration = Duration::from_millis(300);
const MAX_LOG_LINES: usize = 200;

/// コンソールのチートワーカーの状態を聞き直す間隔。
///
/// 本体のワーカーは 16 ms で回るが、`tick_count` / `journal_count` は 2 秒でも
/// 十分動きが分かる。毎 tick（250 ms）で問い合わせると、コンソールの単一
/// 接続スレッドと Wi-Fi を無駄に使う。
const CONSOLE_STATUS_INTERVAL: Duration = Duration::from_secs(2);

/// A job that has not answered after this long is already a bug (a hung
/// console call, a stuck loop tick).  The tab says so and offers the abort.
const BUSY_WATCHDOG: Duration = Duration::from_secs(10);

/// Hard limit: past this the tab aborts on its own.  Nothing may ever leave the
/// cheat tab "busy forever" again, which is what the string-labelled busy flag
/// used to do (see [`Busy`]).
const BUSY_HARD_LIMIT: Duration = Duration::from_secs(60);

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
    /// ON, but the file was edited after it was applied: the target still holds
    /// the old code and nothing re-applies the new code by itself.
    stale: bool,
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
    fn has_loops(&self) -> bool {
        self.rows.iter().any(|row| row.live && row.mode == "loop")
    }

    fn any_enabled(&self) -> bool {
        self.rows.iter().any(|row| row.live)
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
            stale: snapshot.stale,
            last_error: snapshot.last_error.clone(),
            execution: manager.execution(),
        },
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
// Busy state machine
// ---------------------------------------------------------------------------

/// What the tab is waiting for.
///
/// This used to be a `String` compared with `==`: the automatic tick wrote
/// `"tick"`, the "Tick now" equivalent wrote nothing at all and the event
/// handler only cleared `"tick"`, so one mismatched label left the tab "busy"
/// for the rest of the session and swallowed every later click.  An enum cannot
/// be spelled wrong, the label shown to the user is derived from it, and the
/// only transition out of a state is the completion event of that same job
/// (see [`Ev::Done`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Busy {
    Connecting,
    Disconnecting,
    Reloading,
    Enabling,
    Disabling,
    Ticking,
    Restoring,
    Loading,
    Saving,
    /// 実行場所（console / PC）の切替。コンソールへ問い合わせることは無いが、
    /// 状態を 1 本の直列なジョブ列に載せるために busy を使う。
    ModeSwitch,
}

impl Busy {
    fn label(self) -> &'static str {
        match self {
            Busy::Connecting => "connecting",
            Busy::Disconnecting => "disconnecting",
            Busy::Reloading => "reloading",
            Busy::Enabling => "enabling",
            Busy::Disabling => "disabling",
            Busy::Ticking => "ticking",
            Busy::Restoring => "restoring",
            Busy::Loading => "loading",
            Busy::Saving => "saving",
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

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

/// The worker thread plus both of its channels.
///
/// The `JoinHandle` used to be thrown away, so a worker that exited (a panic
/// outside `catch_unwind`, or an `expect` while spawning) left the tab with a
/// dead channel, a session nobody could end and every button dead.  Keeping the
/// handle lets [`CheatUi::poll_worker`] notice a dead thread and replace it.
struct Worker {
    jobs: Sender<Job>,
    events: Receiver<Ev>,
    /// A copy of the event sender for short-lived helper threads (the library
    /// scan), tagged with this generation: after a restart their results are
    /// dropped instead of reviving stale state.
    events_tx: Sender<Ev>,
    /// Set by an abort so a worker stuck in a long console call exits as soon
    /// as that call returns, instead of processing more jobs.
    abort: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Worker {
    fn spawn() -> Worker {
        let (jobs, job_rx) = channel::<Job>();
        let (events_tx, events) = channel::<Ev>();
        let abort = Arc::new(AtomicBool::new(false));
        let thread_abort = Arc::clone(&abort);
        let thread_tx = events_tx.clone();
        let handle = std::thread::Builder::new()
            .name("nxus-cheat-worker".to_string())
            .spawn(move || run_worker(job_rx, thread_tx, thread_abort))
            .expect("cannot start the cheat worker thread");
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
    /// that is inside a console call, the dropped channels cover one that is
    /// idle in `recv`.  Either way the thread exits on its own and drops the
    /// session (and with it the socket) as soon as the current call returns.
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

enum Job {
    Connect { host: String, port: u16 },
    Disconnect,
    Reload,
    Toggle { key: CheatKey, on: bool },
    /// チートを実行する場所を切り替える（`console` / `pc`）。
    SetMode(CheatExecution),
    Tick,
    PanicOff,
    LoadFile { path: PathBuf },
    Save { path: PathBuf, text: String },
}

impl Job {
    /// The busy state this job puts the UI in.
    ///
    /// Derived from the job itself (never passed in by the caller) so the state
    /// and the completion event it is cleared by cannot disagree - that
    /// mismatch was the original "busy forever" bug.
    fn kind(&self) -> Busy {
        match self {
            Job::Connect { .. } => Busy::Connecting,
            Job::Disconnect => Busy::Disconnecting,
            Job::Reload => Busy::Reloading,
            Job::Toggle { on: true, .. } => Busy::Enabling,
            Job::Toggle { on: false, .. } => Busy::Disabling,
            Job::SetMode(_) => Busy::ModeSwitch,
            Job::Tick => Busy::Ticking,
            Job::PanicOff => Busy::Restoring,
            Job::LoadFile { .. } => Busy::Loading,
            Job::Save { .. } => Busy::Saving,
        }
    }

    /// Disconnect, panic-restore and quit must never wait for a stuck job.
    fn is_priority(&self) -> bool {
        matches!(self, Job::Disconnect | Job::PanicOff)
    }
}

enum Ev {
    Opened(LiveView, String),
    Updated(LiveView, String),
    /// Panic restore finished.  `complete == false` means some original bytes
    /// could not be written and the user must retry.
    Restored(LiveView, String, bool),
    Ticked(LiveView),
    /// The job with this kind has finished - whatever it sent before.  The UI
    /// only clears `busy` here, and only when the kind matches the job it is
    /// waiting for, so an unrelated `Error` can no longer release a live job.
    Done(Busy),
    Saved { path: PathBuf, text: String, view: Option<LiveView> },
    Editor { path: PathBuf, text: String, build_id: String },
    /// Result of the background library scan (it parses every file in
    /// `cheats/`, which is far too slow for a UI frame).
    Library {
        files: Vec<CheatFile>,
        error: Option<String>,
    },
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
                Ok(()) => ConsoleToggle::Done(format!(
                    "enabled '{name}' on the {}",
                    CheatExecution::Console.label()
                )),
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
                Ok(()) => ConsoleToggle::Done(format!(
                    "disabled '{name}' on the {}",
                    CheatExecution::Console.label()
                )),
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
/// やすい。未対応以外の失敗（dmnt がまだ準備中など）は tick ごとの再試行に
/// 任せる。
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
/// every original byte is back; otherwise it is kept so the user can retry.
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

fn run_worker(rx: Receiver<Job>, tx: Sender<Ev>, abort: Arc<AtomicBool>) {
    // A job that panics (a bug in a cheat, a broken manager invariant count)
    // used to kill the worker silently: the channel stayed open, `busy` stayed
    // set and every button was dead.  The panic is caught here, reported as an
    // event, and `CheatUi::poll_worker` replaces the thread on the next frame.
    let report = tx.clone();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        worker_loop(rx, tx, abort);
    }));
    if let Err(payload) = outcome {
        let _ = report.send(Ev::Error(format!(
            "the cheat worker panicked: {}",
            panic_text(payload.as_ref())
        )));
    }
}

/// Sends [`Ev::Done`] when a job ends, however it ends.
///
/// Half of the arms below bail out with `continue` (and the `let ... else`
/// ones with an early `continue`), which is exactly how "not connected" used to
/// leave `busy` set forever.  A guard releases the state on *every* exit path,
/// including a `break` out of the loop.
struct DoneGuard {
    tx: Sender<Ev>,
    kind: Busy,
}

impl Drop for DoneGuard {
    fn drop(&mut self) {
        // Not while unwinding: a panicking job leaves the session unusable and
        // the UI is told about it by the panic report instead.
        if !std::thread::panicking() {
            let _ = self.tx.send(Ev::Done(self.kind));
        }
    }
}

fn worker_loop(rx: Receiver<Job>, tx: Sender<Ev>, abort: Arc<AtomicBool>) {
    let mut session: Option<Session> = None;

    while let Ok(job) = rx.recv() {
        if abort.load(Ordering::SeqCst) {
            // An abort retired this generation; a job already in flight has
            // finished, so nothing else may touch the console through it.
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
            Job::LoadFile { path } => match load_editor_file(path) {
                Ok(event) => {
                    let _ = tx.send(event);
                }
                Err(error) => {
                    let _ = tx.send(Ev::Error(error));
                }
            },
            Job::Save { path, text } => {
                // Saving is always allowed, even with cheats ON.  When the live
                // manager owns this file the save goes through it, so the blocks
                // that are ON are reconciled (edited ones become stale, deleted
                // ones are restored) instead of the manager silently keeping a
                // document the file no longer describes.
                let mut reloaded = None;
                let mut notes: Vec<String> = Vec::new();
                let mut written = false;
                if let Some(current) = session.as_mut() {
                    if current.manager.path() == path {
                        let mut io = ClientCheatIo {
                            client: &current.client,
                        };
                        match current.manager.save_raw_text(&text, &mut io) {
                            Ok(report) => {
                                current.dirty = current.manager.dirty();
                                notes = report.log_lines();
                                reloaded = Some(make_session_view(current));
                                written = true;
                            }
                            Err(error) => {
                                let _ = tx.send(Ev::Error(format!("{}: {error}", path.display())));
                                continue;
                            }
                        }
                    }
                }
                if !written {
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
                }
                for note in notes {
                    let _ = tx.send(Ev::Log(note));
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
    worker: Worker,
    pub dir: PathBuf,
    files: Vec<CheatFile>,
    library_error: Option<String>,
    /// Background library scans in flight; each one keeps the frame clock
    /// running so its result is painted when it lands.
    scans: u32,
    live: Option<LiveView>,
    editor: Editor,
    build_id_input: String,
    message: String,
    log: VecDeque<String>,
    /// The job in flight, or `None`.  Never a `String` any more: see [`Busy`].
    busy: Option<BusyJob>,
    /// The 10 s watchdog warning was already logged for the current job.
    watchdog_warned: bool,
    auto_tick: bool,
    panic_confirm: bool,
    /// チートを実行する場所の選択（実体は worker 側のマネージャが持つ）。
    ///
    /// UI 側にも控えるのは、`Job::SetMode` が断られたとき（ON のブロックが
    /// 残っている間）に表示を戻すため。worker から view が届いたら、そちらの
    /// `execution` に合わせる（フォールバックもこれで画面に反映される）。
    execution: CheatExecution,
    last_tick: Instant,
    last_loop_error: Option<String>,
    started: Instant,
}

impl CheatUi {
    pub fn new() -> CheatUi {
        let dir = cheat::cheats_directory().unwrap_or_else(|_| PathBuf::from("cheats"));
        let mut ui = CheatUi {
            worker: Worker::spawn(),
            dir,
            files: Vec::new(),
            library_error: None,
            scans: 0,
            live: None,
            editor: Editor::default(),
            build_id_input: String::new(),
            message: "ready - connect to a title or open a file".to_string(),
            log: VecDeque::new(),
            busy: None,
            watchdog_warned: false,
            auto_tick: true,
            panic_confirm: false,
            execution: CheatExecution::Console,
            last_tick: Instant::now(),
            last_loop_error: None,
            started: Instant::now(),
        };
        // Parsing every cheat file in `cheats/` takes long enough to be seen as
        // a hang, so even the startup scan runs off the UI thread.
        ui.refresh_library();
        ui
    }

    fn log(&mut self, message: impl Into<String>) {
        let elapsed = self.started.elapsed().as_secs_f64();
        self.log
            .push_back(format!("[{elapsed:6.1}s] {}", message.into()));
        while self.log.len() > MAX_LOG_LINES {
            self.log.pop_front();
        }
    }

    /// Send a job and start waiting for it.
    ///
    /// A job that is already in flight is not silently dropped any more (that
    /// is what made every click after a stuck job vanish): a short loop tick
    /// can be queued behind, anything else answers with the current state plus
    /// the way out - Disconnect aborts it.
    fn submit(&mut self, job: Job) -> bool {
        let kind = job.kind();
        if let Some(busy) = self.busy {
            if kind.is_soft() && busy.kind.is_soft() {
                // "Tick now" while a tick is in flight: do nothing at all.  It
                // must not rewrite the state, or the tick that is really
                // running would never clear it.
                self.message = "a loop tick is already running".to_string();
                return false;
            }
            if !busy.kind.is_soft() {
                self.message = format!(
                    "busy: {} for {} s - press Disconnect to abort it",
                    busy.kind.label(),
                    busy.elapsed().as_secs()
                );
                return false;
            }
        }
        self.start(job)
    }

    fn start(&mut self, job: Job) -> bool {
        let kind = job.kind();
        if !self.worker.send(job) {
            self.log("the cheat worker is gone - restarting it");
            self.restart_worker();
            self.message = "the cheat worker was restarted; try again".to_string();
            return false;
        }
        self.busy = Some(BusyJob::new(kind));
        self.watchdog_warned = false;
        // A tick must not overwrite the log line the user is reading four
        // times a second.
        if !kind.is_soft() {
            self.message = kind.label().to_string();
        }
        true
    }

    /// Abort the job in flight, drop the console session it owns and start a
    /// fresh worker - without waiting for the stuck call to return.
    ///
    /// Returns false when nothing had to be aborted, so the caller can take the
    /// normal "(restore then) disconnect" path instead.
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
        self.restart_worker();
        self.last_tick = Instant::now();
        self.message = format!(
            "aborted {} after {seconds} s - the console session was abandoned (patches were not \
             restored here); connect again and press Panic Restore All",
            busy.kind.label()
        );
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

    /// Panic restore must always be reachable.  If a job is stuck the restore
    /// cannot run through it, so the connection is aborted instead and the
    /// backup journal (on disk) is left for the next connect.
    fn panic_restore(&mut self) {
        self.panic_confirm = false;
        if self.abort_busy("panic restore") {
            return;
        }
        self.submit(Job::PanicOff);
    }

    /// Replace a worker that exited (a panic, a failed spawn) so the tab can
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
        self.log("the cheat worker exited unexpectedly - started a fresh one");
        self.message =
            "the cheat worker stopped (it crashed); a fresh one is ready - connect again"
                .to_string();
    }

    /// 10 s without an answer is already a bug or a dead console: say so.  At
    /// 60 s the tab aborts by itself, because a "busy" state that nobody can
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
                "warning: {} has been running for {} s - press Disconnect or Abort to stop waiting",
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

    /// Status text for the header: the message, or what is running plus how long
    /// it has been running (the "busy since N s" the watchdog is about).
    fn busy_text(&self) -> String {
        match self.busy {
            Some(busy) if !busy.kind.is_soft() => format!(
                "{} ... {} s{}",
                busy.kind.label(),
                busy.elapsed().as_secs(),
                if busy.elapsed() >= BUSY_WATCHDOG {
                    " - stuck? press Abort"
                } else {
                    ""
                }
            ),
            _ => self.message.clone(),
        }
    }

    /// Scan `cheats/` on a helper thread.
    ///
    /// The scan parses every file in the directory; doing that inside the frame
    /// that asked for it froze the window for as long as the disk took.
    fn refresh_library(&mut self) {
        self.scans = self.scans.saturating_add(1);
        let dir = self.dir.clone();
        let tx = self.worker.events_tx.clone();
        let spawned = std::thread::Builder::new()
            .name("nxus-cheat-scan".to_string())
            .spawn(move || {
                let (files, error) = scan_library(&dir);
                let _ = tx.send(Ev::Library { files, error });
            });
        if spawned.is_err() {
            self.scans = self.scans.saturating_sub(1);
            self.log("cannot start the library scan thread");
        }
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
                self.message = format!("opened {}", view.target.path.display());
                self.log(self.message.clone());
                self.build_id_input = view.target.build_id.clone();
                self.execution = view.target.execution;
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
            Ev::Updated(view, message) => {
                self.message = message.clone();
                self.log(message);
                self.execution = view.target.execution;
                self.live = Some(view);
            }
            Ev::Restored(view, message, complete) => {
                self.message = message.clone();
                self.log(message);
                self.execution = view.target.execution;
                self.live = Some(view);
                self.panic_confirm = !complete;
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
            Ev::Saved { path, text, view } => {
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
            Ev::Editor {
                path,
                text,
                build_id,
            } => {
                if !self.editor.dirty() || self.editor.path == path {
                    self.editor.set_text(Some(&path), text, build_id.clone());
                    self.build_id_input = build_id;
                } else {
                    self.log("editor has unsaved changes; kept them");
                }
                self.message = format!("loaded {}", path.display());
                self.log(self.message.clone());
            }
            Ev::Library { files, error } => {
                self.scans = self.scans.saturating_sub(1);
                self.files = files;
                self.library_error = error;
            }
            Ev::Error(error) => {
                // No longer clears `busy`: an error that belongs to some other
                // job must not release the one in flight.
                self.message = error.clone();
                self.log(format!("error: {error}"));
            }
            Ev::Disconnected(message) => {
                self.message = message.clone();
                self.log(message);
                self.live = None;
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
        self.poll_worker();
        self.poll_watchdog();
        self.maybe_parse();

        // コンソール実行ではループが無くても tick を回す: fault（本体が自分で
        // 全部止めた）の監視と、2 秒ごとの状態取得がこの tick に乗っている。
        let wants_tick = self.auto_tick
            && self
                .live
                .as_ref()
                .map(|view| view.has_loops() || view.runs_on_console())
                .unwrap_or(false);
        if wants_tick
            && self.busy.is_none()
            && self.last_tick.elapsed() >= TICK_INTERVAL
        {
            self.last_tick = Instant::now();
            // Through `start` so the state and the `Ev::Done` that clears it are
            // the same value by construction.
            self.start(Job::Tick);
        }
        if wants_tick {
            ctx.request_repaint_after(TICK_INTERVAL);
        }
        if self.busy.is_some() {
            ctx.request_repaint_after(Duration::from_millis(120));
        }
        // The 300 ms parse debounce needs a frame to fire in: without this the
        // preview only appears once the user touches something else.
        if self.editor.text != self.editor.parsed_text {
            ctx.request_repaint_after(PARSE_DELAY);
        }
        // A background library scan cannot wake the frame clock by itself.
        if self.scans > 0 {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn connect(&mut self, host: &str, port: u16) {
        if host.trim().is_empty() {
            self.message = "set the console address in the top bar first".to_string();
            return;
        }
        self.submit(Job::Connect {
            host: host.trim().to_string(),
            port,
        });
    }

    fn load_path(&mut self, path: PathBuf) {
        self.submit(Job::LoadFile { path });
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
        // No "turn every cheat off" guard: the file is always editable.  Blocks
        // that are ON and changed end up stale (the applied bytes stay as they
        // are), which is what the block list shows.
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
        self.submit(Job::Save { path, text });
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
                    let stuck = self.stuck_for().is_some();
                    ui.label(
                        RichText::new(self.busy_text())
                            .color(if stuck { RED } else { YELLOW }),
                    );
                } else {
                    ui.label(RichText::new(&self.message).color(DIM));
                }
            });
        });
        ui.separator();

        let target_row = self.target_row(ui, host, port);
        self.execution_row(ui);
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
                if view.target.stale > 0 {
                    ui.label(
                        RichText::new(format!(
                            "{} edited (re-toggle to apply)",
                            view.target.stale
                        ))
                        .color(YELLOW),
                    );
                }
            } else {
                ui.label(RichText::new("not connected").color(DIM));
                ui.label(format!("({host}:{port})"));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // `can_queue` is true while nothing runs, or only a short loop
                // tick does.  Disconnect and Abort below ignore it on purpose:
                // they are the way out of a stuck job.
                let can_queue = self.can_queue();
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
                if self.live.is_some() {
                    let label = if can_queue {
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
                    if ui
                        .add_enabled(can_queue, egui::Button::new("Reload file"))
                        .on_hover_text(
                            "re-read the file from disk; cheats that are ON keep their bytes, \
                             edited ones become stale and deleted ones are restored",
                        )
                        .clicked()
                    {
                        self.submit(Job::Reload);
                    }
                } else if ui
                    .add_enabled(can_queue, egui::Button::new(RichText::new("Connect target").strong()))
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
                            self.panic_restore();
                        }
                        if ui.button("Cancel").clicked() {
                            self.panic_confirm = false;
                        }
                    } else if ui
                        .add(egui::Button::new(
                            RichText::new("Panic Restore All").color(RED),
                        ))
                        .on_hover_text(
                            "write every original byte back and clear all enabled cheats; \
                             if a job is stuck this aborts it instead (the journal stays on disk)",
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

    /// 実行場所の切替と、コンソールのチートワーカーの状態。
    ///
    /// 既定はコンソール。`console` は本体の 16 ms ワーカーで回るので、鍵条件
    /// 付きのコードやループが PC のポーリング周期に縛られず、切断後も動く。
    /// `PC` は従来の read/write 経路（新コマンドを持たないコンソール向け）。
    fn execution_row(&mut self, ui: &mut egui::Ui) {
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
            if let Some(view) = self.live.as_ref() {
                if let Some(console) = &view.console {
                    ui.separator();
                    ui.label(
                        RichText::new(if console.program_valid {
                            "program loaded"
                        } else {
                            "no program"
                        })
                        .small()
                        .color(if console.program_valid { GREEN } else { DIM }),
                    );
                    ui.label(
                        RichText::new(format!(
                            "{} loop block(s) / {} on / {} insn",
                            console.block_count, console.enabled_count, console.insn_count
                        ))
                        .small()
                        .color(DIM),
                    );
                    ui.monospace(format!("tick {}", console.tick_count));
                    ui.monospace(format!("journal {}", console.journal_count));
                    ui.monospace(format!("faults {}", console.fault_count));
                    if console.running {
                        ui.label(RichText::new("running").small().color(GREEN));
                    } else {
                        ui.label(RichText::new("stopped").small().color(DIM));
                    }
                    if let Some(error) = &console.last_error {
                        ui.label(RichText::new(error).small().color(YELLOW));
                    }
                    if let Some(fault) = &console.fault {
                        // コンソールが自分で止めた理由。全ブロックは既に OFF
                        // 表示になっている（`mark_all_off`）。
                        ui.label(RichText::new(fault).small().color(RED));
                    }
                }
            }
        });
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
            if self.live.as_ref().map(LiveView::any_enabled).unwrap_or(false) {
                ui.label(RichText::new("cheats ON - saving is allowed").small().color(DIM))
                    .on_hover_text(
                        "a block you edit keeps the bytes it already wrote and is marked \
                         \"edited - re-toggle to apply\"; it is never re-applied by itself",
                    );
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let can_queue = self.can_queue();
                if ui.add_enabled(can_queue, egui::Button::new("Save")).clicked() {
                    self.save();
                }
                if ui
                    .add_enabled(can_queue, egui::Button::new("Reload from disk"))
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
                        .add_enabled(can_queue, egui::Button::new("Use target file"))
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
                            } else if row.stale {
                                // The target still runs the old code; the file no
                                // longer matches it and nothing re-applies it by
                                // itself.
                                ui.label(
                                    RichText::new("edited - re-toggle to apply")
                                        .small()
                                        .color(YELLOW),
                                );
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
            self.submit(Job::Toggle { key, on });
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

    // -- busy state machine -------------------------------------------------
    //
    // These pin the property the string-labelled version could not hold: the
    // state is set from the job and released only by that same job's completion
    // event, and nothing may leave the tab "busy" with no way out.

    /// A state that started `seconds` ago (the watchdog reads that instant).
    fn busy_since(kind: Busy, seconds: u64) -> Option<BusyJob> {
        Some(BusyJob {
            kind,
            since: Instant::now() - Duration::from_secs(seconds),
        })
    }

    /// A tab whose worker is never sent anything, so the state machine can be
    /// poked directly.  The thread itself is idle in `recv` and exits when the
    /// tab is dropped.
    fn idle() -> CheatUi {
        CheatUi::new()
    }

    #[test]
    fn a_manual_tick_cannot_overwrite_the_tick_already_running() {
        let mut ui = idle();
        ui.busy = busy_since(Busy::Ticking, 0);
        let before = ui.busy.expect("the tick in flight is recorded").since;

        assert!(!ui.submit(Job::Tick), "a second tick must be refused");

        let after = ui.busy.expect("the running tick must stay recorded");
        assert_eq!(after.kind, Busy::Ticking);
        assert_eq!(after.since, before, "the busy state was rewritten");
        assert!(ui.message.contains("already running"), "{}", ui.message);
    }

    #[test]
    fn only_the_completion_of_the_waited_for_job_clears_the_state() {
        let mut ui = idle();
        ui.busy = busy_since(Busy::Enabling, 0);

        // An error used to clear the flag unconditionally, which released jobs
        // that were still running.
        ui.handle_event(Ev::Error("boom".to_string()));
        assert_eq!(ui.busy.map(|busy| busy.kind), Some(Busy::Enabling));

        // The completion of some other job.
        ui.handle_event(Ev::Done(Busy::Ticking));
        assert_eq!(ui.busy.map(|busy| busy.kind), Some(Busy::Enabling));

        // The completion of the job the UI is waiting for.
        ui.handle_event(Ev::Done(Busy::Enabling));
        assert!(ui.busy.is_none());
        assert!(!ui.watchdog_warned);
    }

    #[test]
    fn a_job_in_flight_refuses_new_work_without_losing_the_state() {
        let mut ui = idle();
        ui.busy = busy_since(Busy::Enabling, 0);

        assert!(!ui.submit(Job::Reload));

        assert_eq!(ui.busy.map(|busy| busy.kind), Some(Busy::Enabling));
        assert!(ui.message.starts_with("busy: enabling"), "{}", ui.message);
        assert!(!ui.can_queue());
    }

    #[test]
    fn a_loop_tick_lets_a_real_job_queue_behind_it() {
        let mut ui = idle();
        ui.busy = busy_since(Busy::Ticking, 0);
        assert!(ui.can_queue());

        assert!(ui.submit(Job::Toggle {
            key: CheatKey(1),
            on: true
        }));

        // The queued job becomes the state the UI waits for; the tick's own
        // completion will not clear it (see the test above).
        assert_eq!(ui.busy.map(|busy| busy.kind), Some(Busy::Enabling));
    }

    #[test]
    fn abort_gives_up_on_a_stuck_job_but_not_on_a_fresh_tick() {
        let mut ui = idle();

        // A tick that just started is not stuck: the normal path must run.
        ui.busy = busy_since(Busy::Ticking, 0);
        assert!(!ui.abort_busy("test"));
        assert_eq!(ui.busy.map(|busy| busy.kind), Some(Busy::Ticking));

        // A tick that has been running for 15 s is.
        ui.busy = busy_since(Busy::Ticking, 15);
        assert!(ui.abort_busy("test"));
        assert!(ui.busy.is_none());

        // Any other job is abortable at once.
        ui.busy = busy_since(Busy::Restoring, 1);
        assert!(ui.abort_busy("test"));
        assert!(ui.busy.is_none());
        assert!(
            ui.message.contains("aborted restoring"),
            "the user must be told the patches were not restored: {}",
            ui.message
        );
    }

    #[test]
    fn aborting_nothing_is_a_no_op() {
        let mut ui = idle();
        assert!(!ui.abort_busy("test"));
        assert!(ui.busy.is_none());
        assert!(ui.can_queue());
    }

    #[test]
    fn the_watchdog_warns_once_then_frees_the_tab_at_the_hard_limit() {
        let mut ui = idle();
        ui.busy = busy_since(Busy::Saving, 11);
        let lines = ui.log.len();

        ui.poll_watchdog();
        assert_eq!(ui.log.len(), lines + 1);
        assert!(ui.log.back().unwrap().contains("warning:"));
        assert!(ui.busy.is_some(), "10 s is a warning, not an abort");

        ui.poll_watchdog();
        assert_eq!(ui.log.len(), lines + 1, "the warning must not repeat");

        ui.busy = busy_since(Busy::Saving, 61);
        ui.poll_watchdog();
        assert!(ui.busy.is_none(), "the hard limit must free the tab");
    }

    #[test]
    fn the_status_text_shows_how_long_the_job_has_been_running() {
        let mut ui = idle();
        ui.busy = busy_since(Busy::Connecting, 12);
        let text = ui.busy_text();
        assert!(text.starts_with("connecting ... 12 s"), "{text}");
        assert!(text.contains("stuck?"), "{text}");
        assert_eq!(ui.stuck_for().map(|elapsed| elapsed.as_secs()), Some(12));

        ui.busy = busy_since(Busy::Connecting, 2);
        assert!(!ui.busy_text().contains("stuck?"));
        assert!(ui.stuck_for().is_none());
    }

    #[test]
    fn every_job_clears_exactly_its_own_state() {
        // The string version failed here: the loop wrote "tick", the manual
        // button "ticking", and only "tick" was ever cleared.  The state is
        // derived from the job now, so a round trip is the property to pin.
        let jobs = [
            Job::Connect {
                host: "127.0.0.1".to_string(),
                port: 7332,
            },
            Job::Disconnect,
            Job::Reload,
            Job::Toggle {
                key: CheatKey(1),
                on: true,
            },
            Job::Toggle {
                key: CheatKey(1),
                on: false,
            },
            Job::Tick,
            Job::PanicOff,
            Job::LoadFile {
                path: PathBuf::from("cheats/0100C3800049C000.txt"),
            },
            Job::Save {
                path: PathBuf::from("cheats/0100C3800049C000.txt"),
                text: String::new(),
            },
        ];

        let mut ui = idle();
        let mut kinds: Vec<Busy> = Vec::new();
        for job in &jobs {
            let kind = job.kind();
            if !kinds.contains(&kind) {
                kinds.push(kind);
            }

            ui.busy = Some(BusyJob::new(kind));
            ui.handle_event(Ev::Done(kind));
            assert!(
                ui.busy.is_none(),
                "{} was not cleared by its own completion event",
                kind.label()
            );

            let other = if kind == Busy::Ticking {
                Busy::Saving
            } else {
                Busy::Ticking
            };
            ui.busy = Some(BusyJob::new(kind));
            ui.handle_event(Ev::Done(other));
            assert!(
                ui.busy.is_some(),
                "{} was cleared by the completion of {:?}",
                kind.label(),
                other
            );
        }
        assert_eq!(
            kinds.len(),
            jobs.len(),
            "two jobs share one state: {kinds:?}"
        );
    }

    #[test]
    fn only_a_loop_tick_is_soft() {
        assert!(Busy::Ticking.is_soft());
        for kind in [
            Busy::Connecting,
            Busy::Disconnecting,
            Busy::Reloading,
            Busy::Enabling,
            Busy::Disabling,
            Busy::Restoring,
            Busy::Loading,
            Busy::Saving,
        ] {
            assert!(!kind.is_soft(), "{} must block the next job", kind.label());
            assert!(!kind.label().is_empty());
        }
    }

    #[test]
    fn the_disconnect_and_restore_jobs_are_priority() {
        assert!(Job::Disconnect.is_priority());
        assert!(Job::PanicOff.is_priority());
        for job in [
            Job::Tick,
            Job::Reload,
            Job::LoadFile {
                path: PathBuf::from("x.txt"),
            },
        ] {
            assert!(!job.is_priority(), "{}", job.kind().label());
        }
    }

    // -- コンソール実行モード ------------------------------------------------
    //
    // コンソール実行の判断は「どのコマンドが未対応か」「fault のあと表示を
    // どう合わせるか」の 2 点に集まる。どちらもネットワークを挟まずに検証
    // できるよう、純粋な部分を関数に切り出してある。

    static NEXT_CHEAT_DIR: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(1);

    /// テスト用のチートファイル + マネージャ。`Drop` でディレクトリごと消す。
    struct TempCheats {
        dir: PathBuf,
    }

    impl Drop for TempCheats {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn manager_for(label: &str, text: &str) -> (TempCheats, CheatManager) {
        let unique = NEXT_CHEAT_DIR.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "nxus-gui-cheats-{}-{label}-{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let build_id = "9D4C86E6EF74504A";
        let path = dir.join(format!("{build_id}.txt"));
        std::fs::write(&path, text).unwrap();
        let identity = TargetIdentity::new(100, 0x0100_C380_0049_C000, 1, build_id).unwrap();
        let regions = MemoryRegions::new(0x1000, 0x2000, 0x3000, 0x4000);
        let manager = CheatManager::open_with_path(identity, regions, path).unwrap();
        (TempCheats { dir }, manager)
    }

    /// 旧コンソール（新コマンド未実装）では pc 実行へ落ち、ログは 1 行だけ。
    #[test]
    fn an_unsupported_console_command_falls_back_to_the_pc_path() {
        let (_temp, mut manager) =
            manager_for("fallback", "[Value]\n04400000 00001234 00000063\n");
        assert!(manager.is_console_mode(), "console is the default");

        let error = crate::client::NxusError {
            message: "command 0x0082 failed - the console does not implement this command \
                      (reason=6)"
                .to_string(),
            result: Some(0x8003_C801),
        };
        assert!(is_unsupported_command(&error));
        let notice = manager
            .fallback_to_pc(&error.to_string())
            .expect("the first fallback is reported");
        assert!(notice.contains("running the cheats on the PC"), "{notice}");
        assert!(!manager.is_console_mode(), "must run on the PC now");
        assert_eq!(manager.execution(), CheatExecution::Pc);

        // 2 回目以降はログらない（tick ごとに検出しても溢れない）。
        assert!(manager.fallback_to_pc(&error.to_string()).is_none());

        // 未対応「ではない」失敗では落とさない。
        let (_temp, other) = manager_for("no-fallback", "[Value]\n04400000 00001234 00000063\n");
        let busy = crate::client::NxusError {
            message: "command 0x0082 failed (reason=4)".to_string(),
            result: Some(crate::client::RESULT_BUSY),
        };
        assert!(!is_unsupported_command(&busy));
        assert!(other.is_console_mode());
    }

    /// `NxusEvent_CheatFault` は全ブロックを OFF にし、理由を 1 行で返す。
    #[test]
    fn a_cheat_fault_turns_every_block_off_and_names_the_reason() {
        let (_temp, mut manager) = manager_for(
            "fault",
            "[A]\n04000000 00000000 00000001\n[B]\n04000000 00000004 00000002\n",
        );
        let a = manager.find_key("A").unwrap();
        let b = manager.find_key("B").unwrap();
        manager.note_console_toggle(a, true).unwrap();
        manager.note_console_toggle(b, true).unwrap();
        assert_eq!(manager.enabled_keys().len(), 2);

        // ワイヤのペイロード（NxusCheatFault, 16 バイト）から組み立てる。
        let mut payload = Vec::new();
        crate::protocol::put_u32(&mut payload, CheatFault::TARGET_GONE);
        crate::protocol::put_u32(&mut payload, u32::MAX);
        crate::protocol::put_u32(&mut payload, 0);
        crate::protocol::put_u32(&mut payload, 3);
        let event = crate::client::Event {
            kind: crate::client::EVENT_CHEAT_FAULT,
            payload,
        };
        assert_eq!(event.decode(), crate::client::IncomingEvent::CheatFault {
            reason: CheatFault::TARGET_GONE,
            block: u32::MAX,
            pc: 0,
            restored: 3,
        });
        let fault = event.cheat_fault().expect("a fault event");

        let message = apply_cheat_fault(&mut manager, &fault);
        assert!(message.contains("2 block(s) turned off"), "{message}");
        assert!(message.contains("closed or restarted"), "{message}");
        assert!(manager.enabled_keys().is_empty());
        assert!(manager.blocks().iter().all(|block| !block.enabled));

        // JOURNAL_FULL は「次に何をすればよいか」まで書く。
        let full = CheatFault {
            reason: CheatFault::JOURNAL_FULL,
            block: 1,
            pc: 0,
            restored: 0,
        };
        let message = apply_cheat_fault(&mut manager, &full);
        assert!(message.contains("restore table is full"), "{message}");
    }

    /// panic-off は戻り値の restored / failed を必ず両方見せる。
    #[test]
    fn the_panic_off_report_keeps_the_failed_count_visible() {
        let complete = CheatRestore {
            restored: 4,
            failed: 0,
            blocks_stopped: 2,
            reserved: 0,
        };
        let text = panic_off_console_text(&complete);
        assert!(text.contains("restored 4 address(es)"), "{text}");
        assert!(text.contains("stopped 2 block(s)"), "{text}");
        assert!(!text.contains("could not be restored"), "{text}");
        assert!(complete.is_complete());

        let partial = CheatRestore {
            restored: 1,
            failed: 3,
            blocks_stopped: 1,
            reserved: 0,
        };
        let text = panic_off_console_text(&partial);
        assert!(text.contains("3 address(es) could not be restored"), "{text}");
        assert!(!partial.is_complete());

        // 応答は NxusCheatRestore (16 バイト) として読める。
        let mut body = Vec::new();
        crate::protocol::put_u32(&mut body, 4);
        crate::protocol::put_u32(&mut body, 0);
        crate::protocol::put_u32(&mut body, 2);
        crate::protocol::put_u32(&mut body, 0);
        assert_eq!(CheatRestore::parse(&body), complete);
    }

    /// 実行場所の切替は専用の busy 状態を持ち、他のジョブと取り違えない。
    #[test]
    fn the_execution_switch_is_its_own_job() {
        let mut ui = idle();
        assert_eq!(Job::SetMode(CheatExecution::Pc).kind(), Busy::ModeSwitch);
        assert!(!Busy::ModeSwitch.is_soft());
        ui.busy = Some(BusyJob::new(Busy::ModeSwitch));
        ui.handle_event(Ev::Done(Busy::Enabling));
        assert!(ui.busy.is_some(), "another job must not release it");
        ui.handle_event(Ev::Done(Busy::ModeSwitch));
        assert!(ui.busy.is_none());
        // 既定はコンソール。
        assert_eq!(ui.execution, CheatExecution::Console);
    }
    /// チート系 5 コマンドだけを実装したローカルのモックコンソール。
    ///
    /// `console_toggle` の往復（アップロード → 有効化 → 状態 → fault）を実機
    /// なしで固定するために置く。受けたフレームはチャネルでテストへ流す。
    ///
    /// 2 回目の `cheat_enable` の応答のあとに `NxusEvent_CheatFault` を 1 回
    /// 押し込む: 「コンソールが自分で全部止めた」を、実際の非同期フレームと
    /// して通すため。
    fn mock_console() -> (u16, std::sync::mpsc::Receiver<(u16, Vec<u8>)>) {
        use crate::protocol::{put_u16, put_u32, rd_u16, rd_u32, MAGIC};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::{Read, Write};

            let (mut socket, _) = listener.accept().expect("accept");
            let mut enables = 0u32;
            loop {
                let mut header = [0u8; 16];
                if socket.read_exact(&mut header).is_err() {
                    return;
                }
                let kind = rd_u16(&header, 4);
                let length = rd_u32(&header, 8) as usize;
                let seq = rd_u32(&header, 12);
                let mut body = vec![0u8; length];
                if length > 0 && socket.read_exact(&mut body).is_err() {
                    return;
                }
                let _ = tx.send((kind, body.clone()));
                let reply: Vec<u8> = match kind {
                    // READ -> 要求サイズぶんのゼロ（patch の原本控えが読む）。
                    0x0013 => vec![0u8; rd_u32(&body, 8) as usize],
                    // cheat_upload -> accepted blocks/insns, no rejection
                    0x0080 => {
                        let mut reply = Vec::new();
                        put_u32(&mut reply, 2);
                        put_u32(&mut reply, 3);
                        put_u32(&mut reply, 0);
                        put_u32(&mut reply, 0);
                        reply
                    }
                    // cheat_enable -> empty
                    0x0081 => Vec::new(),
                    // cheat_status -> NxusCheatStatus (48 bytes)
                    0x0082 => {
                        let mut reply = Vec::new();
                        put_u32(&mut reply, 1); // program_valid
                        put_u32(&mut reply, 2); // block_count
                        put_u32(&mut reply, 1); // enabled_count
                        put_u32(&mut reply, 3); // insn_count
                        put_u32(&mut reply, 42); // tick_count
                        put_u32(&mut reply, 5); // journal_count
                        put_u32(&mut reply, 0); // last_error
                        put_u32(&mut reply, 0); // last_error_pc
                        put_u32(&mut reply, 1); // fault_count
                        put_u32(&mut reply, 1); // running
                        crate::protocol::put_u64(&mut reply, 1 << 2); // keys_held
                        reply
                    }
                    // cheat_panic_off -> NxusCheatRestore (16 bytes)
                    0x0083 => {
                        let mut reply = Vec::new();
                        put_u32(&mut reply, 3); // restored
                        put_u32(&mut reply, 0); // failed
                        put_u32(&mut reply, 1); // blocks_stopped
                        put_u32(&mut reply, 0);
                        reply
                    }
                    _ => Vec::new(),
                };
                let mut frame = Vec::new();
                put_u32(&mut frame, MAGIC);
                put_u16(&mut frame, kind);
                put_u16(&mut frame, 0);
                put_u32(&mut frame, reply.len() as u32);
                put_u32(&mut frame, seq);
                frame.extend_from_slice(&reply);
                if socket.write_all(&frame).is_err() {
                    return;
                }
                if kind == 0x0081 {
                    enables += 1;
                    // 3 回目の有効化（OFF してからもう一度 ON）のあとに押し込む:
                    // テストはその直前の往復（同一プログラムの再送なし）までを
                    // 先に確かめる。
                    if enables == 3 {
                        // 非同期イベント: seq 0 + FLAG_ASYNC、payload は NxusCheatFault。
                        let mut fault = Vec::new();
                        put_u32(&mut fault, CheatFault::TARGET_GONE);
                        put_u32(&mut fault, u32::MAX);
                        put_u32(&mut fault, 0);
                        put_u32(&mut fault, 4);
                        let mut frame = Vec::new();
                        put_u32(&mut frame, MAGIC);
                        put_u16(&mut frame, crate::client::EVENT_CHEAT_FAULT);
                        put_u16(&mut frame, crate::protocol::FLAG_ASYNC);
                        put_u32(&mut frame, fault.len() as u32);
                        put_u32(&mut frame, 0);
                        frame.extend_from_slice(&fault);
                        if socket.write_all(&frame).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        (port, rx)
    }

    /// コンソール実行の往復をネットワーク越しに固定する。
    ///
    /// 「常駐プログラムのアップロード → 有効化 → 同一内容は送り直さない →
    /// 状態 → CheatFault で全 OFF」を 1 本で通す。loop ブロックだけを載せた
    /// 文書を使う（patch は常駐しないので、この往復には乗らない）。
    /// ここが崩れると、実機では「ON にしたのに何も起きない」「止めたはずの
    /// チートが動き続ける」になる。
    #[test]
    fn the_console_path_uploads_enables_reports_and_honours_a_fault() {
        let (_temp, manager) = manager_for(
            "console-wire",
            "[A]\n@loop\n04000000 00000000 00000001\n[B]\n@loop\n04000000 00000004 00000002\n",
        );
        let expected = manager.build_console_program().expect("program");
        let (port, seen) = mock_console();
        let client = NxusClient::connect("127.0.0.1", port).expect("connect");
        let mut session = Session {
            client,
            manager,
            dirty: false,
            console: None,
            console_fault: None,
            last_console_status: Instant::now() - CONSOLE_STATUS_INTERVAL,
        };
        let key = session.manager.find_key("A").unwrap();

        match console_toggle(&mut session, key, true) {
            ConsoleToggle::Done(message) => assert!(message.contains("enabled 'A'"), "{message}"),
            ConsoleToggle::Failed(error) => panic!("toggle failed: {error}"),
            ConsoleToggle::Unsupported(reason) => panic!("must not fall back: {reason}"),
        }
        let (kind, body) = seen
            .recv_timeout(Duration::from_secs(5))
            .expect("upload frame");
        assert_eq!(kind, crate::client::CMD_CHEAT_UPLOAD);
        assert_eq!(
            body, expected,
            "the wire must carry the loop-only linker output"
        );
        let (kind, body) = seen
            .recv_timeout(Duration::from_secs(5))
            .expect("enable frame");
        assert_eq!(kind, crate::client::CMD_CHEAT_ENABLE);
        assert_eq!(crate::protocol::rd_u32(&body, 0), 0, "block index");
        assert_eq!(crate::protocol::rd_u32(&body, 4), 1, "enabled = 1");
        assert!(session.manager.is_enabled(key));
        assert_eq!(session.manager.backup_count(), 0, "the console owns the loops");

        // OFF はプログラムを送らない。もう一度 ON にすると、コンソールに載って
        // いる内容（OFF のままの P(∅)）と同じになるので送り直さない。
        let _ = console_toggle(&mut session, key, false);
        let (kind, body) = seen
            .recv_timeout(Duration::from_secs(5))
            .expect("disable frame");
        assert_eq!(kind, crate::client::CMD_CHEAT_ENABLE);
        assert_eq!(crate::protocol::rd_u32(&body, 4), 0, "enabled = 0");
        assert!(!session.manager.is_enabled(key));

        let _ = console_toggle(&mut session, key, true);
        let (kind, _) = seen
            .recv_timeout(Duration::from_secs(5))
            .expect("second enable frame");
        assert_eq!(
            kind,
            crate::client::CMD_CHEAT_ENABLE,
            "identical content must not be uploaded again"
        );
        assert!(session.manager.is_enabled(key));

        // 状態は tick / journal / fault のカウンタを拾う。
        assert!(refresh_console_status(&mut session).is_none());
        let row = session.console.as_ref().expect("a status row");
        assert!(row.program_valid);
        assert_eq!(row.block_count, 2);
        assert_eq!(row.tick_count, 42);
        assert_eq!(row.journal_count, 5);
        assert_eq!(row.fault_count, 1);
        assert!(row.running);
        assert!(row.last_error.is_none());

        // 3 回目の enable のあとにコンソールが押し込んだ fault を拾い、
        // 全ブロックが OFF 表示になり理由が残る。
        let mut messages = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        while messages.is_empty() && Instant::now() < deadline {
            messages = drain_cheat_faults(&mut session);
            if messages.is_empty() {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        assert!(!messages.is_empty(), "the fault event was never delivered");
        assert!(messages[0].contains("turned off"), "{}", messages[0]);
        let reason = session.console_fault.clone().expect("the fault reason");
        assert!(reason.contains("closed or restarted"), "{reason}");
        assert!(session.manager.enabled_keys().is_empty());
        assert!(session.manager.blocks().iter().all(|block| !block.enabled));
        assert!(session
            .console_row()
            .and_then(|row| row.fault)
            .is_some_and(|fault| fault.contains("closed or restarted")));

        // Panic OFF は restored / failed をそのまま読める。
        let restore = session.client.cheat_panic_off().expect("panic off");
        assert_eq!(restore.restored, 3);
        assert_eq!(restore.failed, 0);
        assert_eq!(restore.blocks_stopped, 1);
        assert!(panic_off_console_text(&restore).contains("restored 3 address(es)"));
    }

    /// 受信済みのフレームを（次のフレームが来なくなるまで）まとめて取り出す。
    fn drain_frames(rx: &std::sync::mpsc::Receiver<(u16, Vec<u8>)>) -> Vec<(u16, Vec<u8>)> {
        let mut frames = Vec::new();
        while let Ok(frame) = rx.recv_timeout(Duration::from_millis(300)) {
            frames.push(frame);
        }
        frames
    }

    /// patch ブロックの往復: 単体プログラムを送るだけ。`cheat_enable` は送らない。
    ///
    /// コンソールは patch だけのプログラムをアップロード直後に 1 回実行して
    /// 解放するので常駐しない（＝`cheat_enable` に渡せる index が無い）。復元表も
    /// 残らないため、原本は送信の前に PC のジャーナルへ控え、OFF は PC 側の
    /// 書き戻しで戻す。
    #[test]
    fn a_patch_block_is_uploaded_once_and_restored_from_the_pc_journal() {
        let (_temp, manager) = manager_for("console-patch", "[P]\n04400000 00001234 00000063\n");
        let key = manager.find_key("P").unwrap();
        let expected = manager.build_patch_program(key).expect("one-shot program");
        let (port, seen) = mock_console();
        let client = NxusClient::connect("127.0.0.1", port).expect("connect");
        let mut session = Session {
            client,
            manager,
            dirty: false,
            console: None,
            console_fault: None,
            last_console_status: Instant::now() - CONSOLE_STATUS_INTERVAL,
        };

        match console_toggle(&mut session, key, true) {
            ConsoleToggle::Done(message) => {
                assert!(message.contains("applied 'P'"), "{message}");
                assert!(message.contains("ran once"), "{message}");
            }
            ConsoleToggle::Failed(error) => panic!("toggle failed: {error}"),
            ConsoleToggle::Unsupported(reason) => panic!("must not fall back: {reason}"),
        }
        let frames = drain_frames(&seen);
        let upload = frames
            .iter()
            .find(|(kind, _)| *kind == crate::client::CMD_CHEAT_UPLOAD)
            .expect("the one-shot program is uploaded");
        assert_eq!(upload.1, expected, "the wire must carry only that block");
        assert!(
            frames.iter().any(|(kind, _)| *kind == crate::protocol::cmd::READ),
            "the original bytes are read before the console writes them"
        );
        assert!(
            !frames
                .iter()
                .any(|(kind, _)| *kind == crate::client::CMD_CHEAT_ENABLE),
            "a released program has no index to enable"
        );
        assert!(session.manager.is_enabled(key));
        assert_eq!(session.manager.backup_count(), 1, "the PC journals the originals");
        assert!(session.manager.dirty());

        // 同じ内容の再 ON は、アップロードも enable もしない（二重実行しない）。
        match console_toggle(&mut session, key, true) {
            ConsoleToggle::Done(message) => {
                assert!(message.contains("ran once already"), "{message}")
            }
            ConsoleToggle::Failed(error) => panic!("toggle failed: {error}"),
            ConsoleToggle::Unsupported(reason) => panic!("must not fall back: {reason}"),
        }
        assert!(
            drain_frames(&seen).is_empty(),
            "identical one-shot content must not be sent again"
        );

        // OFF はコンソールへ何も送らず、PC のジャーナルで原本を戻す。
        match console_toggle(&mut session, key, false) {
            ConsoleToggle::Done(message) => assert!(message.contains("PC journal"), "{message}"),
            ConsoleToggle::Failed(error) => panic!("toggle failed: {error}"),
            ConsoleToggle::Unsupported(reason) => panic!("must not fall back: {reason}"),
        }
        let frames = drain_frames(&seen);
        assert!(
            frames
                .iter()
                .any(|(kind, _)| *kind == crate::protocol::cmd::WRITE),
            "the originals are written back by the PC"
        );
        assert!(
            !frames
                .iter()
                .any(|(kind, _)| *kind == crate::client::CMD_CHEAT_ENABLE),
            "the console has nothing left to disable"
        );
        assert!(!session.manager.is_enabled(key));
        assert_eq!(session.manager.backup_count(), 0);
        assert!(!session.manager.dirty());

        // OFF で控えを捨てているので、次の ON は同じ内容でも送り直して 1 回実行する。
        match console_toggle(&mut session, key, true) {
            ConsoleToggle::Done(message) => assert!(message.contains("applied 'P'"), "{message}"),
            ConsoleToggle::Failed(error) => panic!("toggle failed: {error}"),
            ConsoleToggle::Unsupported(reason) => panic!("must not fall back: {reason}"),
        }
        let frames = drain_frames(&seen);
        assert!(
            frames
                .iter()
                .any(|(kind, _)| *kind == crate::client::CMD_CHEAT_UPLOAD),
            "OFF clears the one-shot cache, so the next ON really runs"
        );
        assert!(
            !frames
                .iter()
                .any(|(kind, _)| *kind == crate::client::CMD_CHEAT_ENABLE),
            "patches are never enabled by index"
        );

        // コンソールが全部止めたとき、patch の原本は PC のジャーナルにしか無い。
        // その責務を黙って隠さない。
        let message = apply_cheat_fault(
            &mut session.manager,
            &CheatFault {
                reason: CheatFault::JOURNAL_FULL,
                block: 1,
                pc: 0,
                restored: 0,
            },
        );
        assert!(
            message.contains("PC journal still owes 1 address(es)"),
            "{message}"
        );
        assert!(session.manager.enabled_keys().is_empty());
    }

    /// 混在: loop は常駐プログラム + `cheat_enable`、patch は単体プログラムだけ。
    #[test]
    fn a_mixed_document_uploads_the_loop_program_and_the_patch_program_apart() {
        let (_temp, manager) = manager_for(
            "console-mixed",
            "[P]\n04400000 00001234 00000063\n[L]\n@loop\n30050000 00000003\n\
             04400000 00001238 00000001\n31050000\n",
        );
        let patch = manager.find_key("P").unwrap();
        let lp = manager.find_key("L").unwrap();
        let resident = manager.build_console_program().expect("resident program");
        let one_shot = manager.build_patch_program(patch).expect("one-shot program");
        assert_ne!(resident, one_shot);
        assert_eq!(
            crate::cheat::ir::ProgramHeader::from_bytes(
                &resident[..crate::cheat::ir::HEADER_BYTES]
            )
            .unwrap()
            .block_count,
            1,
            "only the loop block stays resident"
        );
        assert_eq!(manager.block_index(lp), Some(0));
        assert_eq!(manager.block_index(patch), None);

        let (port, seen) = mock_console();
        let client = NxusClient::connect("127.0.0.1", port).expect("connect");
        let mut session = Session {
            client,
            manager,
            dirty: false,
            console: None,
            console_fault: None,
            last_console_status: Instant::now() - CONSOLE_STATUS_INTERVAL,
        };

        // loop: 常駐プログラム → enable(index 0)
        match console_toggle(&mut session, lp, true) {
            ConsoleToggle::Done(message) => assert!(message.contains("enabled 'L'"), "{message}"),
            ConsoleToggle::Failed(error) => panic!("toggle failed: {error}"),
            ConsoleToggle::Unsupported(reason) => panic!("must not fall back: {reason}"),
        }
        let frames = drain_frames(&seen);
        let upload = frames
            .iter()
            .find(|(kind, _)| *kind == crate::client::CMD_CHEAT_UPLOAD)
            .expect("the resident program is uploaded");
        assert_eq!(upload.1, resident);
        let enable = frames
            .iter()
            .find(|(kind, _)| *kind == crate::client::CMD_CHEAT_ENABLE)
            .expect("the loop block is enabled by index");
        assert_eq!(crate::protocol::rd_u32(&enable.1, 0), 0);
        assert_eq!(crate::protocol::rd_u32(&enable.1, 4), 1);

        // patch: 単体プログラムだけ。enable も、常駐プログラムの再送もしない。
        match console_toggle(&mut session, patch, true) {
            ConsoleToggle::Done(message) => assert!(message.contains("applied 'P'"), "{message}"),
            ConsoleToggle::Failed(error) => panic!("toggle failed: {error}"),
            ConsoleToggle::Unsupported(reason) => panic!("must not fall back: {reason}"),
        }
        let frames = drain_frames(&seen);
        let upload = frames
            .iter()
            .find(|(kind, _)| *kind == crate::client::CMD_CHEAT_UPLOAD)
            .expect("the one-shot program is uploaded");
        assert_eq!(upload.1, one_shot, "the patch must travel alone");
        assert!(
            !frames
                .iter()
                .any(|(kind, _)| *kind == crate::client::CMD_CHEAT_ENABLE),
            "the patch is not enabled by index"
        );
        assert!(session.manager.is_enabled(lp));
        assert!(session.manager.is_enabled(patch));
    }
}
