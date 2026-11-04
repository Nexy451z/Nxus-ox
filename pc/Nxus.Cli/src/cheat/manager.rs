//! Patch/loop manager: file resolution, enable/disable, periodic ticks,
//! original-byte backups and crash-safe journaling.
//!
//! Backups are keyed by target address and shared between cheats via an owner
//! set.  The original bytes are journalled to `<BuildID>.backup` *before* the
//! first write, so a PC crash cannot lose the restore data.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::ir;
use super::model::{CheatBlock, CheatDocument, CheatExecMode, CheatKey};
use super::parser;
use super::vm::{self, CheatMemoryIo, FailureKind, MemoryRegions, VmReport, VmState};

pub const JOURNAL_MAGIC: &str = "NXUS-CHEAT-BACKUP 1";

/// Default wall-clock budget for one ON block.
///
/// A single block must never be able to hang the UI forever; the interpreter
/// aborts (and rolls the block back) once this elapses.  Callers that know
/// their link is slower can change it with
/// [`CheatManager::set_block_budget`], or pass an explicit budget to
/// [`CheatManager::enable_block`].  `None` disables the limit.
pub const DEFAULT_BLOCK_BUDGET: Option<Duration> = Some(Duration::from_secs(10));

/// How many writes one block may plan and still have the target paused for the
/// apply phase.
///
/// Pausing freezes the whole console, so it only pays off for a block small
/// enough to finish while paused (a hook plus a cave).  A bulk write of many
/// hundreds of bytes would keep the console frozen for far longer than the
/// window it tries to protect.
const PAUSE_WRITE_LIMIT: usize = 16;

/// Page size used only to order the apply phase; addresses inside one page are
/// never reordered.
const APPLY_PAGE_SHIFT: u32 = 12;

// ---------------------------------------------------------------------------
// Target identity
// ---------------------------------------------------------------------------

/// Everything that binds a backup table to one running target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetIdentity {
    pub pid: u64,
    pub program_id: u64,
    pub incarnation: u64,
    /// Exactly 16 uppercase hex digits.
    pub build_id: String,
}

impl TargetIdentity {
    pub fn new(
        pid: u64,
        program_id: u64,
        incarnation: u64,
        build_id: impl AsRef<str>,
    ) -> Result<Self, String> {
        Ok(TargetIdentity {
            pid,
            program_id,
            incarnation,
            build_id: normalize_build_id(build_id.as_ref())?,
        })
    }

    /// Same console process incarnation.  A changed build id also counts as a
    /// different target because the cheat file and code layout change.
    pub fn is_same_target(&self, other: &Self) -> bool {
        self.pid == other.pid
            && self.program_id == other.program_id
            && self.incarnation == other.incarnation
            && self.build_id.eq_ignore_ascii_case(&other.build_id)
    }

    pub fn cheat_file_name(&self) -> String {
        format!("{}.txt", self.build_id)
    }

    pub fn backup_file_name(&self) -> String {
        format!("{}.backup", self.build_id)
    }
}

/// Validate and canonicalise a Build ID for use as a file name.
pub fn normalize_build_id(build_id: &str) -> Result<String, String> {
    let trimmed = build_id.trim();
    let trimmed = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if trimmed.len() != 16 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid build id '{build_id}': expected exactly 16 hex digits"
        ));
    }
    if trimmed.chars().all(|c| c == '0') {
        return Err("build id is all zeroes; the target did not report one".to_string());
    }
    Ok(trimmed.to_ascii_uppercase())
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

pub fn exe_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe()
        .map_err(|error| format!("cannot locate the current executable: {error}"))?;
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "current executable has no parent directory".to_string())
}

pub fn cheats_dir_for(exe_dir: &Path) -> PathBuf {
    exe_dir.join("cheats")
}

pub fn cheats_directory() -> Result<PathBuf, String> {
    Ok(cheats_dir_for(&exe_dir()?))
}

/// Resolve `<dir>/cheats/<BUILDID>.txt`.
pub fn resolve_cheat_path_in(dir: &Path, build_id: &str) -> Result<PathBuf, String> {
    let build_id = normalize_build_id(build_id)?;
    Ok(cheats_dir_for(dir).join(format!("{build_id}.txt")))
}

/// Like [`resolve_cheat_path_in`], but accepts an existing lowercase file so
/// older lowercase-named cheat packs keep loading.  New files use uppercase.
pub fn resolve_existing_cheat_path_in(dir: &Path, build_id: &str) -> Result<PathBuf, String> {
    let upper = resolve_cheat_path_in(dir, build_id)?;
    if upper.exists() {
        return Ok(upper);
    }
    let lower = upper.with_file_name(format!(
        "{}.txt",
        normalize_build_id(build_id)?.to_ascii_lowercase()
    ));
    if lower.exists() {
        return Ok(lower);
    }
    Ok(upper)
}

pub fn resolve_backup_path_in(dir: &Path, build_id: &str) -> Result<PathBuf, String> {
    let build_id = normalize_build_id(build_id)?;
    Ok(cheats_dir_for(dir).join(format!("{build_id}.backup")))
}

/// Resolve the cheat file next to the executable, falling back to
/// `./cheats/<BUILDID>.txt` when only the working-directory copy exists.
///
/// The canonical primary path (uppercase name next to the executable) is
/// returned even when neither file exists yet, so the first save creates it.
pub fn resolve_cheat_path(build_id: &str) -> Result<PathBuf, String> {
    let build_id = normalize_build_id(build_id)?;
    let primary = cheats_dir_for(&exe_dir()?).join(format!("{build_id}.txt"));
    if primary.exists() {
        return Ok(primary);
    }

    let lower = primary.with_file_name(format!("{}.txt", build_id.to_ascii_lowercase()));
    if lower.exists() {
        return Ok(lower);
    }

    if let Ok(cwd) = std::env::current_dir() {
        for candidate in [
            cwd.join("cheats").join(format!("{build_id}.txt")),
            cwd.join("cheats")
                .join(format!("{}.txt", build_id.to_ascii_lowercase())),
        ] {
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    Ok(primary)
}

// ---------------------------------------------------------------------------
// Backup records
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupState {
    /// Original recorded, but the bytes were not journalled yet (the write has
    /// not been issued either).  Only transient inside one block.
    Pending,
    /// The journal on disk records this write.  The record is flushed *before*
    /// the memory write, so recovering from a crash always restores the
    /// original bytes; replaying an original that never got overwritten is a
    /// harmless no-op.
    Committed,
}

impl BackupState {
    fn as_str(self) -> &'static str {
        match self {
            BackupState::Pending => "pending",
            BackupState::Committed => "committed",
        }
    }

    fn parse(text: &str) -> Self {
        if text.eq_ignore_ascii_case("pending") {
            BackupState::Pending
        } else {
            BackupState::Committed
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupEntry {
    pub address: u64,
    pub width: u8,
    pub original: Vec<u8>,
    pub written: Vec<u8>,
    pub owners: BTreeSet<CheatKey>,
    pub state: BackupState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetChange {
    pub changed: bool,
    /// Backups discarded without writing to the old (dead) process.
    pub dropped_backups: usize,
}

#[derive(Clone, Debug, Default)]
pub struct RestoreReport {
    pub restored: usize,
    /// Addresses still holding a backup because restoring failed.
    pub failed: Vec<(u64, String)>,
    /// `failed.len()`; kept as a field for callers that only need the count.
    pub failed_addresses: usize,
    pub cleared_cheats: usize,
    /// The sidecar journal could not be rewritten, so the on-disk restore
    /// record is stale.
    pub journal_error: Option<String>,
    /// The cheat file could not be rewritten, so it still claims the cheats
    /// are on.
    pub save_error: Option<String>,
}

impl RestoreReport {
    /// True only when every original byte is back **and** the sidecar journal
    /// that describes them was rewritten.  Never true while anything is left
    /// to restore, so a caller cannot report a half-finished panic-off as done.
    ///
    /// [`RestoreReport::save_error`] is deliberately *not* part of this: the
    /// bytes are back either way, and a failed cheat-file write must not keep
    /// a session from disconnecting.  Callers that show the file state check
    /// that field (and [`CheatManager::last_error`]) separately.
    pub fn is_complete(&self) -> bool {
        self.failed.is_empty() && self.journal_error.is_none()
    }

    /// Number of addresses whose original bytes are not back yet.
    pub fn failed_count(&self) -> usize {
        self.failed.len()
    }
}

#[derive(Clone, Debug, Default)]
pub struct TickReport {
    pub executed: usize,
    pub failed: usize,
    pub errors: Vec<(CheatKey, String)>,
}

#[derive(Clone, Debug)]
pub struct CheatSnapshot {
    pub build_id: String,
    pub path: PathBuf,
    pub enabled: usize,
    pub loops: usize,
    pub patches: usize,
    pub backups: usize,
    pub issues: usize,
    pub last_error: Option<String>,
    /// `true` while the target may still hold patched bytes that this manager
    /// is responsible for restoring (see [`CheatManager::dirty`]).
    pub dirty: bool,
}

/// State of one address before the block that is currently executing wrote it.
///
/// Captured on first touch inside a block so a failed (or timed-out) block can
/// be written back exactly to the state it found.
#[derive(Clone, Debug)]
struct PreWrite {
    /// Bytes the address held before this block wrote it (a still-unwritten
    /// backup counts as its original bytes).
    previous: Vec<u8>,
    /// Whether a backup already existed before the block.
    existed: bool,
    /// Owner set before the block.
    owners: BTreeSet<CheatKey>,
    /// Journalled `written` bytes before the block.
    written: Vec<u8>,
    /// Journalled state before the block.
    state: BackupState,
}

/// Result of one block evaluation, including what it wrote (for rollback).
///
/// A block is now evaluated in two phases: the plan phase (see [`PlanIo`])
/// records the writes and never touches memory, and the apply phase publishes
/// them.  `applied` therefore lists what actually reached the target, which is
/// what a rollback has to undo.
struct CodeRun {
    result: Result<VmReport, String>,
    writes: Vec<(u64, PreWrite)>,
    /// Addresses the apply phase wrote, in apply order.
    applied: Vec<u64>,
    /// The console reported that the target process is gone while applying.
    target_gone: bool,
}

/// One write the block asked for, in the order it was first requested.
///
/// A block that writes the same address twice keeps only the last value: the
/// intermediate values never reach memory, so replaying them would only cost
/// extra link round-trips without changing the result.
struct PlannedWrite {
    address: u64,
    data: Vec<u8>,
    allow_rx: bool,
}

/// Why the apply phase stopped.
struct ApplyFailure {
    message: String,
    /// The console reported that the process is gone, so a rollback cannot work.
    target_gone: bool,
}

/// What the apply phase did, so the caller can roll the block back.
#[derive(Default)]
struct ApplyReport {
    /// Addresses the target accepted, in apply order.
    applied: Vec<u64>,
    error: Option<ApplyFailure>,
    /// The target could not be paused; the writes were still applied.
    pause_error: Option<String>,
    /// The pause was held but releasing it failed.
    resume_error: Option<String>,
}

// ---------------------------------------------------------------------------
// Execution place (console cheat VM / PC-side VM)
// ---------------------------------------------------------------------------

/// チートをどちらの機械で実行するか。
///
/// 既定は [`CheatExecution::Console`]。コンソールのチートワーカーは本体の
/// 16 ms 周期で回るので、鍵条件付きのコードやループが PC のポーリング周期
/// （250 ms）に縛られず、PC が切断したあとも動き続ける。PC 側の実行経路は
/// そのまま残してある: 新コマンドを持たないコンソールと、PC で 1 命令ずつ
/// 追いながら挙動を確かめたいときのため。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheatExecution {
    /// `core/nxus_cheatvm.c` のインタプリタで実行する（アップロード + 有効化）。
    Console,
    /// `cheat::vm` で PC から read/write しながら実行する（従来の経路）。
    Pc,
}

impl Default for CheatExecution {
    fn default() -> Self {
        // 新コマンドが使えるコンソールでは、常にこちらが正しい既定。
        // 使えないコンソールは接続時に自動で pc へ落ちる（`fallback_to_pc`）。
        CheatExecution::Console
    }
}

impl CheatExecution {
    pub fn is_console(self) -> bool {
        matches!(self, CheatExecution::Console)
    }

    /// 画面とログに出す名前。
    pub fn label(self) -> &'static str {
        match self {
            CheatExecution::Console => "console",
            CheatExecution::Pc => "pc",
        }
    }
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

pub struct CheatManager {
    identity: TargetIdentity,
    regions: MemoryRegions,
    cheats_dir: PathBuf,
    path: PathBuf,
    journal_path: PathBuf,
    document: CheatDocument,
    enabled: BTreeSet<CheatKey>,
    errors: BTreeMap<CheatKey, String>,
    backups: BTreeMap<u64, BackupEntry>,
    vm_state: VmState,
    auto_save: bool,
    last_error: Option<String>,
    /// `true` while the target may hold patched bytes this manager owns.
    dirty: bool,
    /// Wall-clock budget for one ON/OFF block; `None` means no limit.
    block_budget: Option<Duration>,
    /// チートを実行する場所（既定はコンソール）。
    execution: CheatExecution,
    /// コンソールへアップロード済みのプログラムそのもの。
    ///
    /// 同じ内容を何度も送らないための控え。ハッシュではなく実体を持つのは、
    /// 衝突で「送っていないのに送った」と誤認すると、コンソールにプログラムが
    /// 無いまま `cheat_enable` を送って BAD_STATE になるから（最大 48 KiB）。
    console_uploaded: Option<Vec<u8>>,
    /// 旧コンソールで新コマンドが使えなかった理由。ログを 1 行に抑えるため保持。
    console_fallback: Option<String>,
}

impl CheatManager {
    /// Open `<exe_dir>/cheats/<BuildID>.txt` for `identity`.
    pub fn open_for_target(
        identity: TargetIdentity,
        regions: MemoryRegions,
    ) -> Result<Self, String> {
        let path = resolve_cheat_path(&identity.build_id)?;
        Self::open_with_path(identity, regions, path)
    }

    /// Open `<dir>/cheats/<BuildID>.txt`; used by tests and `--cheats-dir`.
    pub fn open_for_target_in(
        identity: TargetIdentity,
        regions: MemoryRegions,
        dir: PathBuf,
    ) -> Result<Self, String> {
        let cheats_dir = cheats_dir_for(&dir);
        let path = resolve_existing_cheat_path_in(&dir, &identity.build_id)?;
        let journal_path = cheats_dir.join(identity.backup_file_name());
        let document = load_document(&path, &identity.build_id)?;
        let mut manager = CheatManager {
            identity,
            regions,
            cheats_dir,
            path,
            journal_path,
            document,
            enabled: BTreeSet::new(),
            errors: BTreeMap::new(),
            backups: BTreeMap::new(),
            vm_state: VmState::default(),
            auto_save: true,
            last_error: None,
            dirty: false,
            block_budget: DEFAULT_BLOCK_BUDGET,
            execution: CheatExecution::default(),
            console_uploaded: None,
            console_fallback: None,
        };
        if let Err(error) = manager.load_journal() {
            manager.last_error = Some(format!("backup journal ignored: {error}"));
        }
        // A journal for this exact target means the target may still be
        // patched; until every original is back, the manager is dirty.
        manager.settle_dirty();
        Ok(manager)
    }

    pub fn open_with_path(
        identity: TargetIdentity,
        regions: MemoryRegions,
        path: PathBuf,
    ) -> Result<Self, String> {
        let dir = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let journal_path = dir.join(identity.backup_file_name());
        let document = load_document(&path, &identity.build_id)?;
        let mut manager = CheatManager {
            identity,
            regions,
            cheats_dir: dir,
            path,
            journal_path,
            document,
            enabled: BTreeSet::new(),
            errors: BTreeMap::new(),
            backups: BTreeMap::new(),
            vm_state: VmState::default(),
            auto_save: true,
            last_error: None,
            dirty: false,
            block_budget: DEFAULT_BLOCK_BUDGET,
            execution: CheatExecution::default(),
            console_uploaded: None,
            console_fallback: None,
        };
        if let Err(error) = manager.load_journal() {
            manager.last_error = Some(format!("backup journal ignored: {error}"));
        }
        // A journal for this exact target means the target may still be
        // patched; until every original is back, the manager is dirty.
        manager.settle_dirty();
        Ok(manager)
    }

    pub fn identity(&self) -> &TargetIdentity {
        &self.identity
    }

    pub fn regions(&self) -> MemoryRegions {
        self.regions
    }

    pub fn set_regions(&mut self, regions: MemoryRegions) {
        self.regions = regions;
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    pub fn document(&self) -> &CheatDocument {
        &self.document
    }

    pub fn document_mut(&mut self) -> &mut CheatDocument {
        &mut self.document
    }

    pub fn blocks(&self) -> &[CheatBlock] {
        &self.document.blocks
    }

    pub fn block(&self, key: CheatKey) -> Option<&CheatBlock> {
        self.document.block(key)
    }

    pub fn find_key(&self, name: &str) -> Option<CheatKey> {
        self.document.block_by_name(name).map(|block| block.key)
    }

    pub fn backups(&self) -> &BTreeMap<u64, BackupEntry> {
        &self.backups
    }

    pub fn backup_count(&self) -> usize {
        self.backups.len()
    }

    pub fn is_enabled(&self, key: CheatKey) -> bool {
        self.enabled.contains(&key)
    }

    pub fn enabled_keys(&self) -> &BTreeSet<CheatKey> {
        &self.enabled
    }

    pub fn errors(&self) -> &BTreeMap<CheatKey, String> {
        &self.errors
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    pub fn auto_save(&self) -> bool {
        self.auto_save
    }

    pub fn set_auto_save(&mut self, auto_save: bool) {
        self.auto_save = auto_save;
    }

    /// `true` while the target may hold patched bytes this manager owns.
    ///
    /// It is set the moment an ON attempt starts (before the first write) and
    /// cleared only when every recorded original byte is back.  A failed
    /// enable that was fully rolled back clears it again; a failed enable that
    /// could not be rolled back keeps it set *and* returns an error, so
    /// "patched but reported off" cannot happen silently.
    pub fn dirty(&self) -> bool {
        self.dirty
    }

    /// Wall-clock budget applied to one ON/OFF block by [`Self::enable`] and
    /// [`Self::tick`] (the default is [`DEFAULT_BLOCK_BUDGET`]).
    pub fn block_budget(&self) -> Option<Duration> {
        self.block_budget
    }

    /// Change the per-block budget; `None` removes the limit.
    pub fn set_block_budget(&mut self, budget: Option<Duration>) {
        self.block_budget = budget;
    }

    // -- コンソール実行モード ------------------------------------------------

    pub fn execution(&self) -> CheatExecution {
        self.execution
    }

    pub fn is_console_mode(&self) -> bool {
        self.execution.is_console()
    }

    /// 実行場所を切り替える。
    ///
    /// ON のブロックがある間の切替は呼び出し側（GUI/CLI）が断ること: 同じ
    /// アドレスを 2 つの VM が書くと、片方のジャーナルが必ず嘘になる。
    pub fn set_execution(&mut self, execution: CheatExecution) {
        self.execution = execution;
    }

    /// 新コマンドが未対応だったコンソールで PC 実行へ落とす。
    ///
    /// 戻り値は「1 行だけログするための文面」で、2 回目以降は `None`。
    /// tick ごとにフォールバックを検出してもログが溢れないようにするため、
    /// 判定は状態側（`console_fallback`）で 1 回だけにする。
    pub fn fallback_to_pc(&mut self, reason: &str) -> Option<String> {
        self.execution = CheatExecution::Pc;
        self.console_uploaded = None;
        if self.console_fallback.is_some() {
            return None;
        }
        let message = format!(
            "the console does not implement the on-console cheat commands ({reason}); \
             running the cheats on the PC instead"
        );
        self.console_fallback = Some(message.clone());
        Some(message)
    }

    /// [`Self::fallback_to_pc`] が記録した理由。
    pub fn console_fallback(&self) -> Option<&str> {
        self.console_fallback.as_deref()
    }

    /// コンソール上のブロック番号（`NxusCheatEnable.index`）。
    ///
    /// [`ir::build_program`] はドキュメント順に `BlockDesc::index` を振るので、
    /// 表示順の位置がそのままワイヤの index になる。
    pub fn block_index(&self, key: CheatKey) -> Option<u32> {
        self.document
            .blocks
            .iter()
            .position(|block| block.key == key)
            .map(|index| index as u32)
    }

    /// 現在のターゲット identity でプログラム全体を組み立てる。
    ///
    /// コンソールはブロック単体を受け付けないので、どのブロックを ON にする
    /// ときもプログラム全体が要る。既に ON のブロックは `BlockDesc::enabled`
    /// に載るため、再アップロードしてもそれらは ON のまま残る。
    pub fn build_console_program(&self) -> Result<Vec<u8>, String> {
        let build_id = u64::from_str_radix(&self.identity.build_id, 16).map_err(|error| {
            format!(
                "build id '{}' is not hexadecimal: {error}",
                self.identity.build_id
            )
        })?;
        // The console adds no region base (`core/nxus_cheatvm.h`, "Address
        // contract"): the PC has to hand over final absolute addresses.  Using the
        // relative builder here would silently write main/heap cheats to the wrong
        // place.
        ir::build_program_resolved(
            &self.document,
            build_id,
            self.identity.program_id,
            &self.enabled,
            &self.regions,
        )
    }

    /// この内容はまだコンソールに載っていないか（同一内容なら送り直さない）。
    ///
    /// ブロックを 1 つ ON にするたびに最大 48 KiB を送ると、コンソールの
    /// 受信バッファとワーカーを無駄に揺さぶる。内容が同じなら何もしない。
    pub fn need_console_upload(&self, program: &[u8]) -> bool {
        self.console_uploaded.as_deref() != Some(program)
    }

    /// アップロードが成功したことを記録する。
    pub fn note_console_upload(&mut self, program: &[u8]) {
        self.console_uploaded = Some(program.to_vec());
    }

    /// 控えを捨てる。
    ///
    /// コンソールがプログラムを失った（`NxusCheatStatus.program_valid == 0`）
    /// ときに呼ぶ。「載っている」と思い込んだまま `cheat_enable` を送ると、
    /// プログラムの無いコンソールでは BAD_STATE になる。
    pub fn forget_console_upload(&mut self) {
        self.console_uploaded = None;
    }

    /// 直近にアップロードしたプログラム（表示とテスト用）。
    pub fn console_program(&self) -> Option<&[u8]> {
        self.console_uploaded.as_deref()
    }

    /// コンソールで実行した ON/OFF を PC 側の状態に反映する。
    ///
    /// メモリには何も書かない: 書き込みはコンソールのワーカーが自分の
    /// ジャーナルで行う。だからバックアップも作らず `dirty` も立てない。
    /// 切断時に PC が「原本」を書き戻すと、コンソールが管理している復元表と
    /// 二重になり、かえってタイトルを壊す。
    pub fn note_console_toggle(&mut self, key: CheatKey, on: bool) -> Result<(), String> {
        if on {
            self.enabled.insert(key);
            self.errors.remove(&key);
        } else {
            self.enabled.remove(&key);
        }
        if let Some(block) = self.document.block_mut(key) {
            block.enabled = on;
        }
        self.settle_dirty();
        if let Err(error) = self.save_document() {
            let message = format!(
                "cheat {} in memory, but the cheat file could not be saved: {error}",
                if on { "enabled" } else { "disabled" }
            );
            self.last_error = Some(message.clone());
            return Err(message);
        }
        Ok(())
    }

    /// コンソールのワーカーが自分から全ブロックを止めたときの後始末。
    ///
    /// `NxusEvent_CheatFault` は「コンソール側で全部止まった」という通知
    /// なので、PC の表示も全部 OFF に合わせる。合わせないと、実際には止まって
    /// いるブロックを ON と表示し続け、利用者は次の ON で「もう入っている」
    /// と誤解する。戻り値は OFF にしたブロック数。
    pub fn mark_all_off(&mut self) -> usize {
        let count = self.enabled.len();
        self.enabled.clear();
        for block in &mut self.document.blocks {
            block.enabled = false;
        }
        if let Err(error) = self.save_document() {
            self.last_error = Some(format!("cheat file save failed: {error}"));
        }
        self.settle_dirty();
        count
    }

    pub fn snapshot(&self) -> CheatSnapshot {
        let mut loops = 0;
        let mut patches = 0;
        for key in &self.enabled {
            match self.document.block(*key).map(|block| block.mode) {
                Some(CheatExecMode::Loop) => loops += 1,
                Some(CheatExecMode::Patch) => patches += 1,
                None => {}
            }
        }
        CheatSnapshot {
            build_id: self.identity.build_id.clone(),
            path: self.path.clone(),
            enabled: self.enabled.len(),
            loops,
            patches,
            backups: self.backups.len(),
            issues: self.document.issues_with_block().len(),
            last_error: self.last_error.clone(),
            dirty: self.dirty,
        }
    }

    /// Reload the text file, dropping runtime enable state.
    pub fn reload(&mut self) -> Result<(), String> {
        self.document = load_document(&self.path, &self.identity.build_id)?;
        self.enabled.clear();
        self.errors.clear();
        self.settle_dirty();
        Ok(())
    }

    /// Save the structured document.  Runtime state is written into headers.
    pub fn save_document(&mut self) -> Result<(), String> {
        if !self.auto_save {
            return Ok(());
        }
        self.document.save_to(&self.path)
    }

    /// Write arbitrary text (raw editor) atomically, then reparse it.
    pub fn save_raw_text(&mut self, text: &str) -> Result<(), String> {
        super::model::save_text_atomic(&self.path, text)
            .map_err(|error| format!("{}: {error}", self.path.display()))?;
        self.document = parser::parse_document(text, &self.identity.build_id);
        self.document.path = Some(self.path.clone());
        self.document.raw_text = text.to_string();
        self.document.generation = self.document.generation.wrapping_add(1);
        self.enabled.clear();
        self.errors.clear();
        Ok(())
    }

    /// Switch to another target.  Old backups are discarded, never written to
    /// a process that no longer exists.
    pub fn set_target(
        &mut self,
        identity: TargetIdentity,
        regions: MemoryRegions,
    ) -> Result<TargetChange, String> {
        if self.identity.is_same_target(&identity) {
            self.regions = regions;
            return Ok(TargetChange {
                changed: false,
                dropped_backups: 0,
            });
        }

        let dropped_backups = self.backups.len();
        self.enabled.clear();
        self.errors.clear();
        self.backups.clear();
        // Remove the old sidecar: those addresses belong to a dead or
        // different process and must never be written again.
        let _ = self.persist_journal();
        self.vm_state.reset_all();
        // 別プロセスではコンソール側のプログラムも別物。送信済みの控えを
        // 捨てないと、新しいタイトルに古いプログラムを「載っている」と
        // 思い込んで有効化だけを送ってしまう。
        self.console_uploaded = None;
        self.console_fallback = None;
        self.identity = identity;
        self.regions = regions;
        self.path = resolve_in_cheats_dir(&self.cheats_dir, &self.identity.build_id)?;
        self.journal_path = self.cheats_dir.join(self.identity.backup_file_name());
        self.document = load_document(&self.path, &self.identity.build_id)?;
        // The old process is gone; its patches died with it, so nothing here
        // is left to restore.
        self.settle_dirty();
        self.last_error = None;
        Ok(TargetChange {
            changed: true,
            dropped_backups,
        })
    }

    /// Enable one cheat.  Patch and Loop both execute once immediately.
    ///
    /// Uses [`Self::block_budget`]; see [`Self::enable_block`] for the
    /// budgeted variant with a progress callback.
    pub fn enable<M: CheatMemoryIo + ?Sized>(
        &mut self,
        key: CheatKey,
        io: &mut M,
    ) -> Result<(), String> {
        let budget = self.block_budget;
        self.enable_block(key, io, budget, &mut |_, _| {})
    }

    /// Enable one cheat with an explicit per-block budget and progress callback.
    ///
    /// * `budget` bounds the wall clock of the whole ON block.  When it is
    ///   exceeded, every byte this block already wrote is written back to the
    ///   state it found (see [`Self::rollback_block`]) and an error whose
    ///   message contains `timed out` is returned.  A half-applied patch is
    ///   therefore never left behind silently.
    /// * The block is evaluated twice: first against a planning adapter that
    ///   only records its writes (and overlays them for its own reads), then --
    ///   only if the block succeeded -- published by [`apply_plan`] with a
    ///   preflight, an optional pause, cave-before-hook ordering and a
    ///   read-back check.  A block that fails or overruns writes nothing.
    /// * `on_progress(done, total)` receives the interpreter's progress, so a
    ///   slow link can drive a progress bar instead of looking frozen.
    ///
    /// On error the manager keeps `errors()` and `last_error()` populated and
    /// tells the caller the truth:
    ///
    /// * `is_enabled(key)` is `false` when the block did not apply (rolled back),
    /// * `dirty()` is `true` whenever anything still needs restoring,
    /// * a save failure is returned as `Err` while the bytes stay applied, so
    ///   the caller can see that the file does not describe memory.
    pub fn enable_block<M: CheatMemoryIo + ?Sized>(
        &mut self,
        key: CheatKey,
        io: &mut M,
        budget: Option<Duration>,
        on_progress: &mut dyn FnMut(usize, usize),
    ) -> Result<(), String> {
        if self.enabled.contains(&key) {
            return Ok(());
        }
        let block = self
            .document
            .block(key)
            .cloned()
            .ok_or_else(|| format!("cheat {key} not found"))?;
        if !block.is_enableable() {
            let message = block
                .on
                .first_issue()
                .map(|issue| issue.to_string())
                .unwrap_or_else(|| "cheat has no executable ON code".to_string());
            self.errors.insert(key, message.clone());
            self.last_error = Some(message.clone());
            return Err(message);
        }

        // From here the target may be patched, so the manager is dirty until
        // the block settles (success keeps it, a full rollback clears it).
        self.dirty = true;
        let run = self.run_code(key, &block.on, 0, true, io, budget, on_progress);
        let CodeRun {
            result,
            writes,
            applied,
            target_gone,
        } = run;
        if let Err(error) = result {
            let rollback = if target_gone {
                // The console says the process is gone.  A rollback would only
                // repeat the same error once per address, and the bytes we did
                // write died with the process.  Drop this block's restore
                // records without a single store, so the manager can settle.
                self.rollback_block(writes, &[], io)
            } else {
                // Only addresses that really reached the target are written
                // back; a block that failed during planning (or preflight)
                // applied nothing and must not store anything at all.
                self.rollback_block(writes, &applied, io)
            };
            self.enabled.remove(&key);
            self.errors.remove(&key);
            if let Some(block) = self.document.block_mut(key) {
                block.enabled = false;
            }
            self.settle_dirty();
            let message = merge_rollback_error(error, rollback, target_gone);
            self.errors.insert(key, message.clone());
            self.last_error = Some(message.clone());
            return Err(message);
        }

        self.enabled.insert(key);
        self.errors.remove(&key);
        if let Some(block) = self.document.block_mut(key) {
            block.enabled = true;
        }
        self.settle_dirty();
        if let Err(error) = self.save_document() {
            let message = format!(
                "cheat enabled in memory, but the cheat file could not be saved: {error}"
            );
            self.last_error = Some(message.clone());
            return Err(message);
        }
        Ok(())
    }

    pub fn enable_by_name<M: CheatMemoryIo + ?Sized>(
        &mut self,
        name: &str,
        io: &mut M,
    ) -> Result<CheatKey, String> {
        let key = self
            .find_key(name)
            .ok_or_else(|| format!("cheat '{name}' not found"))?;
        self.enable(key, io)?;
        Ok(key)
    }

    /// Disable one cheat.
    ///
    /// With an explicit `:OFF` / `@off` block the restore program is executed
    /// and the backup references are dropped.  Otherwise the original bytes
    /// are written back for every address this cheat exclusively owns.
    ///
    /// Every failure is returned as `Err`: a broken OFF block whose fallback
    /// restore also failed, a restore that could not write, an unusable
    /// journal, or a cheat file that could not be updated.  `dirty()` stays
    /// `true` whenever bytes are still not back.
    pub fn disable<M: CheatMemoryIo + ?Sized>(
        &mut self,
        key: CheatKey,
        io: &mut M,
    ) -> Result<(), String> {
        let owns_backups = self
            .backups
            .values()
            .any(|entry| entry.owners.contains(&key));
        if !self.enabled.contains(&key) && !owns_backups {
            // Turning an already-off cheat off is a no-op in memory; only the
            // file state may need updating.
            let marked = self
                .document
                .block(key)
                .map(|block| block.enabled)
                .unwrap_or(false);
            if marked {
                if let Some(block) = self.document.block_mut(key) {
                    block.enabled = false;
                }
                if let Err(error) = self.save_document() {
                    let message = format!("cheat file save failed: {error}");
                    self.last_error = Some(message.clone());
                    return Err(message);
                }
            }
            self.errors.remove(&key);
            self.settle_dirty();
            return Ok(());
        }

        let block = self.document.block(key).cloned();
        let has_explicit_off = block
            .as_ref()
            .map(|block| block.explicit_off && block.off.is_some())
            .unwrap_or(false);
        let budget = self.block_budget;

        if has_explicit_off {
            let Some(off) = block.as_ref().and_then(|block| block.off.as_ref()).cloned() else {
                return Err("explicit OFF block disappeared".to_string());
            };
            let run = self.run_code(key, &off, 0, false, io, budget, &mut |_, _| {});
            let CodeRun {
                result,
                target_gone,
                ..
            } = run;
            match result {
                Ok(_) => {
                    if let Err(error) = self.release_owner(key) {
                        self.enabled.remove(&key);
                        if let Some(block) = self.document.block_mut(key) {
                            block.enabled = false;
                        }
                        self.settle_dirty();
                        let message = format!(
                            "cheat turned off in memory, but the backup journal was not updated: {error}"
                        );
                        if let Err(save_error) = self.save_document() {
                            self.last_error = Some(format!(
                                "{message}; cheat file save failed: {save_error}"
                            ));
                        } else {
                            self.last_error = Some(message.clone());
                        }
                        self.errors.insert(key, message.clone());
                        return Err(message);
                    }
                }
                Err(error) => {
                    let mut message = error;
                    if target_gone {
                        // The console has no process left, so a fallback restore
                        // could only fail once per address.  The bytes died with
                        // the process; treat the cheat as off without writing.
                        self.enabled.remove(&key);
                        if let Some(block) = self.document.block_mut(key) {
                            block.enabled = false;
                        }
                    } else {
                        // A broken OFF block must not leave the target patched.
                        let fallback = self.restore_owned(key, io);
                        match &fallback {
                            Ok(()) => {
                                // The originals are back, so the cheat really is
                                // off.
                                self.enabled.remove(&key);
                                if let Some(block) = self.document.block_mut(key) {
                                    block.enabled = false;
                                }
                            }
                            Err(restore_error) => {
                                // Bytes may still be patched: keep the cheat
                                // marked ON so the UI matches memory, and let it
                                // be retried.
                                message = format!(
                                    "{message}; fallback restore also failed: {restore_error}"
                                );
                            }
                        }
                    }
                    self.settle_dirty();
                    self.errors.insert(key, message.clone());
                    self.last_error = Some(message.clone());
                    if let Err(save_error) = self.save_document() {
                        message = format!("{message}; cheat file save failed: {save_error}");
                        self.last_error = Some(message.clone());
                    }
                    return Err(message);
                }
            }
        } else if let Err(error) = self.restore_owned(key, io) {
            // The original bytes are not back, so this cheat stays enabled:
            // reporting it off while it is patched is exactly the silent
            // failure this path must not have.  The backup (and `dirty`) stay
            // so the next disable or panic-off retries the restore.
            self.errors.insert(key, error.clone());
            self.last_error = Some(error.clone());
            self.settle_dirty();
            return Err(error);
        }

        self.enabled.remove(&key);
        self.errors.remove(&key);
        if let Some(block) = self.document.block_mut(key) {
            block.enabled = false;
        }
        self.settle_dirty();
        if let Err(error) = self.save_document() {
            let message =
                format!("cheat disabled in memory, but the cheat file could not be saved: {error}");
            self.last_error = Some(message.clone());
            return Err(message);
        }
        Ok(())
    }

    pub fn disable_by_name<M: CheatMemoryIo + ?Sized>(
        &mut self,
        name: &str,
        io: &mut M,
    ) -> Result<CheatKey, String> {
        let key = self
            .find_key(name)
            .ok_or_else(|| format!("cheat '{name}' not found"))?;
        self.disable(key, io)?;
        Ok(key)
    }

    pub fn toggle<M: CheatMemoryIo + ?Sized>(
        &mut self,
        key: CheatKey,
        on: bool,
        io: &mut M,
    ) -> Result<(), String> {
        if on {
            self.enable(key, io)
        } else {
            self.disable(key, io)
        }
    }

    pub fn toggle_by_name<M: CheatMemoryIo + ?Sized>(
        &mut self,
        name: &str,
        on: bool,
        io: &mut M,
    ) -> Result<CheatKey, String> {
        let key = self
            .find_key(name)
            .ok_or_else(|| format!("cheat '{name}' not found"))?;
        self.toggle(key, on, io)?;
        Ok(key)
    }

    /// Evaluate every enabled Loop-mode cheat once.
    ///
    /// Each block goes through the same plan-then-apply path as
    /// [`Self::enable`]: a block that fails or overruns during planning wrote
    /// nothing, and a partially applied one is rolled back so the loop's next
    /// tick starts from the state the target really has.  The loop stays
    /// enabled either way and its failure is reported in
    /// [`TickReport::errors`].
    pub fn tick<M: CheatMemoryIo + ?Sized>(&mut self, io: &mut M, keys_held: u64) -> TickReport {
        let mut report = TickReport::default();
        let keys: Vec<CheatKey> = self
            .document
            .blocks
            .iter()
            .filter(|block| self.enabled.contains(&block.key) && block.mode == CheatExecMode::Loop)
            .map(|block| block.key)
            .collect();
        let budget = self.block_budget;

        for key in keys {
            let code = match self.document.block(key) {
                Some(block) if block.on.is_executable() => block.on.clone(),
                Some(_) => {
                    let message = "cheat has no executable ON code".to_string();
                    self.errors.insert(key, message.clone());
                    report.failed += 1;
                    report.errors.push((key, message));
                    continue;
                }
                None => continue,
            };
            let run = self.run_code(key, &code, keys_held, true, io, budget, &mut |_, _| {});
            let CodeRun {
                result,
                writes,
                applied,
                target_gone,
            } = run;
            match result {
                Ok(_) => {
                    report.executed += 1;
                    self.errors.remove(&key);
                }
                Err(error) => {
                    let rollback = if target_gone {
                        // Nothing in a dead process can be restored: drop the
                        // records on paper only.
                        self.rollback_block(writes, &[], io)
                    } else {
                        self.rollback_block(writes, &applied, io)
                    };
                    let message = merge_rollback_error(error, rollback, target_gone);
                    self.errors.insert(key, message.clone());
                    self.last_error = Some(message.clone());
                    report.failed += 1;
                    report.errors.push((key, message));
                }
            }
        }
        self.settle_dirty();
        report
    }

    /// Panic OFF: stop all loops, then restore every recorded original byte.
    ///
    /// `is_complete()` is only true when every original byte is back *and* the
    /// sidecar journal that describes them was rewritten; failures are kept in
    /// `failed` (with a count in `failed_addresses`) so the caller can retry
    /// instead of believing a half-finished restore.  A cheat-file write
    /// failure is reported in `save_error` without blocking the restore.
    pub fn restore_all_backups<M: CheatMemoryIo + ?Sized>(&mut self, io: &mut M) -> RestoreReport {
        let addresses: Vec<u64> = self.backups.keys().copied().collect();
        let cleared_cheats = self.enabled.len();
        self.enabled.clear();

        let mut report = RestoreReport {
            cleared_cheats,
            ..Default::default()
        };
        for address in addresses {
            let original = match self.backups.get(&address) {
                Some(entry) => entry.original.clone(),
                None => continue,
            };
            match io.write_mem(address, &original, true) {
                Ok(()) => {
                    self.backups.remove(&address);
                    report.restored += 1;
                }
                Err(error) => {
                    report.failed.push((address, error.clone()));
                    self.last_error = Some(format!("restore 0x{address:X} failed: {error}"));
                }
            }
        }
        report.failed_addresses = report.failed.len();

        for block in &mut self.document.blocks {
            block.enabled = false;
        }
        // A restore is not complete just because the writes succeeded: the
        // sidecar must lose those entries, otherwise the next run would replay
        // them against a target that no longer needs them.
        if let Err(error) = self.persist_journal() {
            self.last_error = Some(format!("backup journal update failed: {error}"));
            report.journal_error = Some(error);
        }
        if let Err(error) = self.save_document() {
            self.last_error = Some(format!("cheat file save failed: {error}"));
            report.save_error = Some(error);
        }
        self.settle_dirty();
        report
    }

    pub fn panic_off<M: CheatMemoryIo + ?Sized>(&mut self, io: &mut M) -> RestoreReport {
        self.restore_all_backups(io)
    }

    // -- internals ---------------------------------------------------------

    /// `dirty` can only be cleared when nothing is left to restore.
    fn settle_dirty(&mut self) {
        self.dirty = !self.backups.is_empty();
    }

    /// Run one block in two phases and publish what it asked for.
    ///
    /// 1. *Plan*: the block executes against [`PlanIo`], which records the
    ///    writes instead of issuing them and overlays them for later reads.
    ///    A block that fails or overruns therefore leaves memory untouched.
    /// 2. *Apply*: only if the block succeeded, [`apply_plan`] preflights every
    ///    address, optionally pauses the target, writes the plan in
    ///    cave-before-hook order and verifies the result by reading it back.
    ///
    /// The returned [`CodeRun`] carries the memory rollback bookkeeping and the
    /// exact list of addresses that reached the target.
    #[allow(clippy::too_many_arguments)]
    fn run_code<M: CheatMemoryIo + ?Sized>(
        &mut self,
        key: CheatKey,
        code: &super::model::CheatCode,
        keys_held: u64,
        record_backups: bool,
        io: &mut M,
        budget: Option<Duration>,
        on_progress: &mut dyn FnMut(usize, usize),
    ) -> CodeRun {
        if !code.is_executable() {
            return CodeRun {
                result: Err(code
                    .first_issue()
                    .map(|issue| issue.to_string())
                    .unwrap_or_else(|| "code is empty or invalid".to_string())),
                writes: Vec::new(),
                applied: Vec::new(),
                target_gone: false,
            };
        }
        let regions = self.regions;
        // The apply phase finishes the same block, so it shares the budget.
        let deadline = budget.and_then(|limit| Instant::now().checked_add(limit));
        let mut state = std::mem::take(&mut self.vm_state);
        let (planned, writes, plan) = {
            let mut planner = PlanIo {
                manager: self,
                io,
                key,
                record_backups,
                writes: Vec::new(),
                plan: Vec::new(),
                shadow: BTreeMap::new(),
                journal_flushed: false,
            };
            let result = vm::execute_with_budget(
                &code.instructions,
                &code.jumps,
                &mut planner,
                &regions,
                keys_held,
                &mut state,
                budget,
                on_progress,
            );
            (result, planner.writes, planner.plan)
        };
        self.vm_state = state;

        let mut result = planned.map_err(|error| error.to_string());
        let mut applied = Vec::new();
        let mut target_gone = false;
        if result.is_ok() {
            let report = apply_plan(io, &plan, deadline);
            if let Some(error) = report.pause_error {
                // Not fatal: the ordered writes still protect most of the
                // window, so the block continues unpaused (the caller sees why).
                self.last_error = Some(error);
            }
            if let Some(error) = report.resume_error {
                self.last_error = Some(error);
            }
            for address in &report.applied {
                if let Some(write) = plan.iter().find(|write| write.address == *address) {
                    self.mark_written(*address, &write.data);
                }
            }
            applied = report.applied;
            if let Some(failure) = report.error {
                target_gone = failure.target_gone;
                result = Err(failure.message);
            }
        }
        CodeRun {
            result,
            writes,
            applied,
            target_gone,
        }
    }

    /// Write back every byte a failed block applied and restore the backup
    /// bookkeeping it changed.
    ///
    /// Only `applied` addresses are written back: an address the plan recorded
    /// but the target never accepted already holds its previous bytes, so
    /// writing it again would be a pointless (and possibly fatal) extra store.
    /// Its bookkeeping is still restored, so a preflight failure -- where
    /// `applied` is empty -- leaves no backup and no journal entry behind.
    ///
    /// Addresses whose backup already existed keep their previous owner set
    /// and journalled bytes; addresses whose backup was created by this block
    /// lose the backup again.  When a write-back fails the backup is *kept*
    /// (so a later `panic_off` can still restore it) and the failure is
    /// returned, never swallowed.
    fn rollback_block<M: CheatMemoryIo + ?Sized>(
        &mut self,
        writes: Vec<(u64, PreWrite)>,
        applied: &[u64],
        io: &mut M,
    ) -> Result<(), String> {
        if writes.is_empty() {
            return Ok(());
        }
        let applied: BTreeSet<u64> = applied.iter().copied().collect();
        let mut failures: Vec<(u64, String)> = Vec::new();
        for (address, pre) in writes.into_iter().rev() {
            let restored = if applied.contains(&address) {
                io.write_mem(address, &pre.previous, true)
            } else {
                Ok(())
            };
            match restored {
                Ok(()) => {
                    if pre.existed {
                        if let Some(entry) = self.backups.get_mut(&address) {
                            entry.owners = pre.owners;
                            entry.written = pre.written;
                            entry.state = pre.state;
                        }
                    } else {
                        self.backups.remove(&address);
                    }
                }
                Err(error) => {
                    // The target still holds our bytes: keep the restore data.
                    failures.push((address, error));
                }
            }
        }
        let journal_error = self.persist_journal().err();
        if failures.is_empty() && journal_error.is_none() {
            return Ok(());
        }
        let mut summary = failures
            .iter()
            .map(|(address, error)| format!("0x{address:X}: {error}"))
            .collect::<Vec<_>>()
            .join(", ");
        if let Some(error) = journal_error {
            if !summary.is_empty() {
                summary.push_str(", ");
            }
            summary.push_str(&format!("journal: {error}"));
        }
        Err(format!("rollback failed for {summary}"))
    }

    /// Ensure the original bytes for `address` are recorded.  Returns `true`
    /// when a new backup entry was created; its durable journal record is
    /// written by the caller before the memory write.
    fn ensure_backup<M: CheatMemoryIo + ?Sized>(
        &mut self,
        io: &mut M,
        key: CheatKey,
        address: u64,
        width: u8,
        written: &[u8],
    ) -> Result<bool, String> {
        let created = if let Some(entry) = self.backups.get_mut(&address) {
            if entry.width != width {
                return Err(format!(
                    "address 0x{address:X} is already backed up with width {} but this write uses {width}",
                    entry.width
                ));
            }
            entry.owners.insert(key);
            false
        } else {
            let original = io
                .read_mem(address, u32::from(width))
                .map_err(|error| format!("backup read 0x{address:X} failed: {error}"))?;
            if original.len() != width as usize {
                return Err(format!(
                    "backup read 0x{address:X} returned {} bytes, expected {width}",
                    original.len()
                ));
            }
            self.backups.insert(
                address,
                BackupEntry {
                    address,
                    width,
                    original,
                    written: written.to_vec(),
                    owners: BTreeSet::from([key]),
                    state: BackupState::Committed,
                },
            );
            true
        };

        if let Some(entry) = self.backups.get_mut(&address) {
            entry.written = written.to_vec();
            entry.state = BackupState::Committed;
        }
        Ok(created)
    }

    /// Record that the write was issued.
    ///
    /// The journal already holds these bytes: they are written to disk *before*
    /// the memory write (see [`RecordingIo::prepare_write`]), so this is a
    /// memory-only update.  That keeps a block at one fsync per new address
    /// instead of three per write.
    fn mark_written(&mut self, address: u64, data: &[u8]) {
        if let Some(entry) = self.backups.get_mut(&address) {
            entry.written = data.to_vec();
            entry.state = BackupState::Committed;
        }
    }

    fn restore_owned<M: CheatMemoryIo + ?Sized>(
        &mut self,
        key: CheatKey,
        io: &mut M,
    ) -> Result<(), String> {
        let addresses: Vec<u64> = self
            .backups
            .iter()
            .filter(|(_, entry)| entry.owners.contains(&key))
            .map(|(address, _)| *address)
            .collect();
        let mut failures = Vec::new();

        for address in addresses {
            let exclusive = self
                .backups
                .get(&address)
                .map(|entry| entry.owners.len() == 1)
                .unwrap_or(false);
            if !exclusive {
                if let Some(entry) = self.backups.get_mut(&address) {
                    entry.owners.remove(&key);
                }
                if let Err(error) = self.persist_journal() {
                    failures.push((address, error));
                }
                continue;
            }

            let entry = match self.backups.get(&address) {
                Some(entry) => entry.clone(),
                None => continue,
            };
            // Identity is bound to this manager instance; `set_target` clears
            // the table before a different process can be addressed.
            match io.write_mem(address, &entry.original, true) {
                Ok(()) => {
                    self.backups.remove(&address);
                    if let Err(error) = self.persist_journal() {
                        failures.push((address, error));
                    }
                }
                Err(error) => failures.push((address, error)),
            }
        }

        if failures.is_empty() {
            self.settle_dirty();
            Ok(())
        } else {
            let summary = failures
                .iter()
                .map(|(address, error)| format!("0x{address:X}: {error}"))
                .collect::<Vec<_>>()
                .join(", ");
            let message = format!("restore failed for {summary}");
            self.last_error = Some(message.clone());
            Err(message)
        }
    }

    /// Drop this cheat's ownership without writing originals (explicit OFF).
    fn release_owner(&mut self, key: CheatKey) -> Result<(), String> {
        let addresses: Vec<u64> = self
            .backups
            .iter()
            .filter(|(_, entry)| entry.owners.contains(&key))
            .map(|(address, _)| *address)
            .collect();
        for address in addresses {
            if let Some(entry) = self.backups.get_mut(&address) {
                entry.owners.remove(&key);
            }
            let empty = self
                .backups
                .get(&address)
                .map(|entry| entry.owners.is_empty())
                .unwrap_or(false);
            if empty {
                self.backups.remove(&address);
            }
        }
        self.persist_journal()
    }

    fn load_journal(&mut self) -> Result<(), String> {
        if !self.journal_path.exists() {
            return Ok(());
        }
        let text = fs::read_to_string(&self.journal_path)
            .map_err(|error| format!("{}: {error}", self.journal_path.display()))?;
        let parsed = parse_journal(&text)?;
        if parsed.build_id != self.identity.build_id
            || parsed.pid != self.identity.pid
            || parsed.program_id != self.identity.program_id
            || parsed.incarnation != self.identity.incarnation
        {
            return Ok(());
        }
        self.backups = parsed.entries;
        Ok(())
    }

    fn persist_journal(&self) -> Result<(), String> {
        // An empty backup table has nothing to recover; remove the sidecar
        // instead of leaving a stale header behind.
        if self.backups.is_empty() {
            if self.journal_path.exists() {
                fs::remove_file(&self.journal_path)
                    .map_err(|error| format!("{}: {error}", self.journal_path.display()))?;
            }
            return Ok(());
        }
        let text = self.journal_text();
        super::model::save_text_atomic(&self.journal_path, &text)
            .map_err(|error| format!("{}: {error}", self.journal_path.display()))
    }

    fn journal_text(&self) -> String {
        let mut out = String::new();
        out.push_str(JOURNAL_MAGIC);
        out.push('\n');
        out.push_str(&format!("build={}\n", self.identity.build_id));
        out.push_str(&format!("pid={}\n", self.identity.pid));
        out.push_str(&format!("program={}\n", self.identity.program_id));
        out.push_str(&format!("incarnation={}\n", self.identity.incarnation));
        for entry in self.backups.values() {
            out.push_str(&format!(
                "addr={:016X} width={} orig={} written={} state={} owners={}\n",
                entry.address,
                entry.width,
                hex(&entry.original),
                hex(&entry.written),
                entry.state.as_str(),
                entry
                    .owners
                    .iter()
                    .map(|key| key.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Plan / apply
// ---------------------------------------------------------------------------

/// Where each planned write sits in the apply order.
///
/// **Cave first, hook last.**  A cheat that installs a hook normally writes the
/// code cave and then the branch that jumps into it.  If the hook went in
/// first, the game could branch into cave bytes that are still half written --
/// the classic "the game dies while the patch is being written" crash.  Ordering
/// the stores by descending 4 KB page lets the (usually far away, often higher)
/// cave land before the hook page.
///
/// The guarantee is a *heuristic*, not a proof: nothing in the cheat format
/// marks which store is the hook, and a cave that lives below the hook page, or
/// a game thread that is already executing inside the target page, can still
/// observe a partial patch.  It only reduces the window; the conditional pause
/// in [`apply_plan`] closes it for small blocks.
///
/// Writes inside the same 4 KB page keep their original order: they cannot be
/// merged into one store, so reordering them would only make overlapping
/// writes (e.g. a 4-byte and a 1-byte patch on the same address) land in an
/// order the cheat author did not write.
fn apply_order(plan: &[PlannedWrite]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..plan.len()).collect();
    order.sort_by_key(|index| {
        (
            std::cmp::Reverse(plan[*index].address >> APPLY_PAGE_SHIFT),
            *index,
        )
    });
    order
}

/// The one-line report for a process that vanished while bytes were landing.
fn target_gone_message(applied: usize) -> String {
    format!(
        "target is gone (console reports no process) - {applied} write(s) may have been applied"
    )
}

/// Combine a block error with the result of undoing it.
///
/// A target-gone failure never wrote a rollback (there is nothing to write to),
/// so the only thing that can fail is the local journal update.
fn merge_rollback_error(error: String, rollback: Result<(), String>, target_gone: bool) -> String {
    match rollback {
        Ok(()) => error,
        Err(rollback_error) if target_gone => {
            format!("{error}; restore journal update failed: {rollback_error}")
        }
        Err(rollback_error) => format!("{error}; rollback also failed: {rollback_error}"),
    }
}

/// Releases a pause taken for the apply phase on every exit path.
///
/// A paused console cannot resume itself, so the guard is deliberately a
/// `Drop` impl: success, early error return and a panic all run it.  Failures
/// are reported to the caller through [`ResumeGuard::resume_now`]; the drop path
/// is best effort because there is no caller left to tell.
struct ResumeGuard<'a, M: CheatMemoryIo + ?Sized> {
    io: &'a mut M,
    armed: bool,
}

impl<M: CheatMemoryIo + ?Sized> ResumeGuard<'_, M> {
    /// Resume now and disarm the guard so `Drop` does not resume twice.
    fn resume_now(&mut self) -> Result<(), String> {
        self.armed = false;
        self.io.resume_process()
    }
}

impl<M: CheatMemoryIo + ?Sized> Drop for ResumeGuard<'_, M> {
    fn drop(&mut self) {
        if self.armed {
            self.armed = false;
            // Best effort: leaving the console frozen is worse than losing this
            // error message.
            let _ = self.io.resume_process();
        }
    }
}

/// Publish a block's planned writes.
///
/// 1. *Preflight*: read every planned address first.  A target that rejects one
///    of them would reject the later store too, so nothing is written when any
///    read fails -- not one byte.
/// 2. *Pause* (conditional): freeze the process when the block is small and
///    touches executable (`allow_rx`) pages, because those are the bytes the
///    game may jump to.  A failed pause is not fatal: the ordered stores below
///    still apply.
/// 3. *Write* in cave-before-hook order (see [`apply_order`]).
/// 4. *Verify*: read every address back.  A mismatch is a silent bit flip and
///    is reported so the caller can roll the block back.
fn apply_plan<M: CheatMemoryIo + ?Sized>(
    io: &mut M,
    plan: &[PlannedWrite],
    deadline: Option<Instant>,
) -> ApplyReport {
    let mut report = ApplyReport::default();
    if plan.is_empty() {
        return report;
    }
    let order = apply_order(plan);

    // Preflight: a target that cannot be read right now cannot be written.
    for index in &order {
        let write = &plan[*index];
        let size = u32::try_from(write.data.len()).unwrap_or(u32::MAX);
        if let Err(error) = io.read_mem(write.address, size) {
            report.error = Some(ApplyFailure {
                message: format!(
                    "preflight read failed at 0x{:X}: {error}; no byte was written",
                    write.address
                ),
                target_gone: false,
            });
            return report;
        }
    }

    let pause_wanted = plan.iter().any(|write| write.allow_rx) && plan.len() <= PAUSE_WRITE_LIMIT;
    let mut paused = false;
    if pause_wanted {
        match io.pause_process() {
            Ok(()) => paused = true,
            Err(error) => {
                // Not fatal: ordered stores still reduce the window.
                report.pause_error = Some(format!(
                    "pause before applying writes failed: {error}; applying without pausing"
                ));
            }
        }
    }

    {
        let mut guard = ResumeGuard { io, armed: paused };
        for index in &order {
            if let Some(deadline) = deadline {
                if Instant::now() >= deadline {
                    report.error = Some(ApplyFailure {
                        message: format!(
                            "block timed out during apply after {} write(s)",
                            report.applied.len()
                        ),
                        target_gone: false,
                    });
                    break;
                }
            }
            let write = &plan[*index];
            match guard
                .io
                .write_mem(write.address, &write.data, write.allow_rx)
            {
                Ok(()) => report.applied.push(write.address),
                Err(error) => {
                    let target_gone = guard.io.failure_kind(&error) == FailureKind::TargetGone;
                    report.error = Some(ApplyFailure {
                        message: if target_gone {
                            target_gone_message(report.applied.len())
                        } else {
                            format!("write 0x{:X} failed during apply: {error}", write.address)
                        },
                        target_gone,
                    });
                    break;
                }
            }
        }

        // Read back while the target is still paused: this is the only point
        // where nobody can change the watched bytes between store and check.
        if report.error.is_none() {
            let mut mismatches: Vec<String> = Vec::new();
            let mut target_gone = false;
            for index in &order {
                let write = &plan[*index];
                let size = u32::try_from(write.data.len()).unwrap_or(u32::MAX);
                match guard.io.read_mem(write.address, size) {
                    Ok(bytes) if bytes.as_slice() == write.data.as_slice() => {}
                    Ok(bytes) => mismatches.push(format!(
                        "0x{:X}: wrote {} but read {}",
                        write.address,
                        hex(&write.data),
                        hex(&bytes)
                    )),
                    Err(error) => {
                        if guard.io.failure_kind(&error) == FailureKind::TargetGone {
                            target_gone = true;
                        }
                        mismatches.push(format!(
                            "0x{:X}: verify read failed: {error}",
                            write.address
                        ));
                    }
                }
            }
            if target_gone {
                report.error = Some(ApplyFailure {
                    message: target_gone_message(report.applied.len()),
                    target_gone: true,
                });
            } else if !mismatches.is_empty() {
                report.error = Some(ApplyFailure {
                    message: format!("read-back verification failed: {}", mismatches.join(", ")),
                    target_gone: false,
                });
            }
        }

        if paused {
            if let Err(error) = guard.resume_now() {
                report.resume_error = Some(format!("resume after apply failed: {error}"));
            }
        }
    }

    report
}

// ---------------------------------------------------------------------------
// Planning IO
// ---------------------------------------------------------------------------

/// Planning half of the two-phase write.
///
/// The block runs against this adapter: `write_mem` records the store, updates
/// the shadow overlay (so a later read in the same block sees the new value,
/// exactly as it would after a real store) and touches no target memory.
/// `read_mem` starts from the real bytes and overlays the pending writes, which
/// keeps "read the current memory" semantics for everything the block did not
/// plan to change.
struct PlanIo<'a, M: CheatMemoryIo + ?Sized> {
    manager: &'a mut CheatManager,
    io: &'a mut M,
    key: CheatKey,
    record_backups: bool,
    /// Addresses this block wrote, with the state they had before the block.
    writes: Vec<(u64, PreWrite)>,
    /// The stores to publish, in first-touch order, last value per address.
    plan: Vec<PlannedWrite>,
    /// Byte-level overlay of `plan`, so reads inside the block see new values.
    shadow: BTreeMap<u64, u8>,
    /// The journal was already flushed for this block.
    journal_flushed: bool,
}

impl<'a, M: CheatMemoryIo + ?Sized> PlanIo<'a, M> {
    /// Snapshot the pre-block state, extend the backup table, then flush the
    /// journal **before** the block can write anything.
    ///
    /// Flushing once per new address (instead of the old three writes per
    /// write: insert, re-state, commit) keeps the "never write without a
    /// durable restore record" guarantee while cutting the fsync count of a
    /// one-write block from three to one.
    fn prepare_write(&mut self, address: u64, width: u8, data: &[u8]) -> Result<(), String> {
        let tracked = self
            .writes
            .iter()
            .any(|(candidate, _)| *candidate == address);
        let before = if tracked {
            None
        } else {
            self.manager.backups.get(&address).cloned()
        };
        let created = self
            .manager
            .ensure_backup(self.io, self.key, address, width, data)?;
        if !tracked {
            match before {
                Some(entry) => {
                    let previous = if entry.written.is_empty() {
                        entry.original.clone()
                    } else {
                        entry.written.clone()
                    };
                    self.writes.push((
                        address,
                        PreWrite {
                            previous,
                            existed: true,
                            owners: entry.owners,
                            written: entry.written,
                            state: entry.state,
                        },
                    ));
                }
                None => {
                    let previous = self
                        .manager
                        .backups
                        .get(&address)
                        .map(|entry| entry.original.clone())
                        .unwrap_or_default();
                    self.writes.push((
                        address,
                        PreWrite {
                            previous,
                            existed: false,
                            owners: BTreeSet::new(),
                            written: Vec::new(),
                            state: BackupState::Pending,
                        },
                    ));
                }
            }
        }
        if created || !self.journal_flushed {
            self.manager
                .persist_journal()
                .map_err(|error| format!("backup journal write failed: {error}"))?;
            self.journal_flushed = true;
        }
        Ok(())
    }
}

impl<M: CheatMemoryIo + ?Sized> CheatMemoryIo for PlanIo<'_, M> {
    fn read_mem(&mut self, address: u64, size: u32) -> Result<Vec<u8>, String> {
        let mut bytes = self.io.read_mem(address, size)?;
        for (offset, byte) in bytes.iter_mut().enumerate() {
            if let Some(planned) = self.shadow.get(&address.wrapping_add(offset as u64)) {
                *byte = *planned;
            }
        }
        Ok(bytes)
    }

    fn write_mem(&mut self, address: u64, data: &[u8], allow_rx: bool) -> Result<(), String> {
        if data.is_empty() {
            return Ok(());
        }
        let width = u8::try_from(data.len())
            .map_err(|_| format!("cheat write of {} bytes is too large", data.len()))?;
        if self.record_backups {
            self.prepare_write(address, width, data)?;
        }
        // Keep one entry per address: the last value wins and the first-touch
        // position (the order the cheat author wrote) is preserved.
        if let Some(existing) = self.plan.iter_mut().find(|write| write.address == address) {
            existing.data.clear();
            existing.data.extend_from_slice(data);
            existing.allow_rx = allow_rx;
        } else {
            self.plan.push(PlannedWrite {
                address,
                data: data.to_vec(),
                allow_rx,
            });
        }
        for (offset, byte) in data.iter().enumerate() {
            self.shadow
                .insert(address.wrapping_add(offset as u64), *byte);
        }
        Ok(())
    }

    fn pause_process(&mut self) -> Result<(), String> {
        self.io.pause_process()
    }

    fn resume_process(&mut self) -> Result<(), String> {
        self.io.resume_process()
    }

    fn failure_kind(&self, error: &str) -> FailureKind {
        self.io.failure_kind(error)
    }
}

// ---------------------------------------------------------------------------
// Journal parsing
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ParsedJournal {
    build_id: String,
    pid: u64,
    program_id: u64,
    incarnation: u64,
    entries: BTreeMap<u64, BackupEntry>,
}

fn parse_journal(text: &str) -> Result<ParsedJournal, String> {
    let mut parsed = ParsedJournal::default();
    let mut saw_magic = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == JOURNAL_MAGIC {
            saw_magic = true;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "build" => parsed.build_id = normalize_build_id(value)?,
            "pid" => parsed.pid = parse_u64(value)?,
            "program" => parsed.program_id = parse_u64(value)?,
            "incarnation" => parsed.incarnation = parse_u64(value)?,
            "addr" => {
                let mut address = None;
                let mut width = 0u8;
                let mut original = Vec::new();
                let mut written = Vec::new();
                let mut owners = BTreeSet::new();
                let mut state = BackupState::Committed;
                for field in line.split_whitespace() {
                    let Some((name, value)) = field.split_once('=') else {
                        continue;
                    };
                    match name {
                        "addr" => address = Some(parse_hex_u64(value)?),
                        "width" => {
                            width = value
                                .parse::<u8>()
                                .map_err(|_| format!("invalid backup width '{value}'"))?
                        }
                        "orig" => original = parse_hex_bytes(value)?,
                        "written" => written = parse_hex_bytes(value)?,
                        "state" => state = BackupState::parse(value),
                        "owners" => {
                            for owner in value.split(',').filter(|item| !item.is_empty()) {
                                owners.insert(owner.parse::<CheatKey>()?);
                            }
                        }
                        _ => {}
                    }
                }
                let address = address.ok_or_else(|| "backup record is missing addr".to_string())?;
                if !matches!(width, 1 | 2 | 4 | 8) || original.len() != width as usize {
                    return Err(format!(
                        "backup record for 0x{address:X} has invalid width/original length"
                    ));
                }
                parsed.entries.insert(
                    address,
                    BackupEntry {
                        address,
                        width,
                        original,
                        written,
                        owners,
                        state,
                    },
                );
            }
            _ => {}
        }
    }
    if !saw_magic && !text.trim().is_empty() {
        return Err("backup journal is missing its magic header".to_string());
    }
    Ok(parsed)
}

fn parse_u64(value: &str) -> Result<u64, String> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("invalid number '{value}'"))
}

fn parse_hex_u64(value: &str) -> Result<u64, String> {
    let value = value.trim();
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u64::from_str_radix(value, 16).map_err(|_| format!("invalid hex address '{value}'"))
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    if value.is_empty() || value == "-" {
        return Ok(Vec::new());
    }
    if value.len() % 2 != 0 {
        return Err(format!("invalid hex byte string '{value}'"));
    }
    (0..value.len() / 2)
        .map(|index| {
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|_| format!("invalid hex byte string '{value}'"))
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn load_document(path: &Path, build_id: &str) -> Result<CheatDocument, String> {
    if path.exists() {
        parser::parse_file(path, build_id)
    } else {
        let mut document = CheatDocument::new(build_id);
        document.path = Some(path.to_path_buf());
        Ok(document)
    }
}

/// Resolve directly inside an existing `<...>/cheats` directory.
fn resolve_in_cheats_dir(cheats_dir: &Path, build_id: &str) -> Result<PathBuf, String> {
    let build_id = normalize_build_id(build_id)?;
    let upper = cheats_dir.join(format!("{build_id}.txt"));
    if upper.exists() {
        return Ok(upper);
    }
    let lower = cheats_dir.join(format!("{}.txt", build_id.to_ascii_lowercase()));
    if lower.exists() {
        return Ok(lower);
    }
    Ok(upper)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(1);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let unique = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "nxus-cheat-manager-{}-{label}-{unique}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            TempDir { path }
        }

        fn write(&self, name: &str, text: &str) -> PathBuf {
            let path = self.path.join("cheats").join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, text).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    struct TestIo {
        memory: BTreeMap<u64, u8>,
        writes: Vec<(u64, Vec<u8>, bool)>,
        probe: Option<PathBuf>,
        probe_seen: Vec<bool>,
        paused: bool,
        /// Writes to this address fail, like a target that rejects the write.
        fail_write_at: Option<u64>,
        /// Sleep after the Nth write, to simulate a slow console link.
        slow_writes: Option<(usize, Duration)>,
        /// Every failure is classified as "the process is gone".
        target_gone: bool,
        /// Writes to this address are accepted but silently dropped, like a
        /// target whose bytes never change (a read-back mismatch).
        ignore_write_at: Option<u64>,
        /// Reads of `fail_read_at` fail, but only after `fail_read_after`
        /// reads were served -- the plan phase reads every new address once.
        fail_read_at: Option<u64>,
        fail_read_after: usize,
        reads: usize,
        pause_fails: bool,
        pause_calls: usize,
        resume_calls: usize,
    }

    impl Default for TestIo {
        fn default() -> Self {
            TestIo {
                memory: BTreeMap::new(),
                writes: Vec::new(),
                probe: None,
                probe_seen: Vec::new(),
                paused: false,
                fail_write_at: None,
                slow_writes: None,
                target_gone: false,
                ignore_write_at: None,
                fail_read_at: None,
                fail_read_after: 0,
                reads: 0,
                pause_fails: false,
                pause_calls: 0,
                resume_calls: 0,
            }
        }
    }

    impl TestIo {
        fn with_u32(address: u64, value: u32) -> Self {
            let mut io = TestIo::default();
            for (offset, byte) in value.to_le_bytes().iter().enumerate() {
                io.memory.insert(address + offset as u64, *byte);
            }
            io
        }

        fn value_u32(&self, address: u64) -> u32 {
            let mut bytes = [0u8; 4];
            for offset in 0..4 {
                bytes[offset] = self
                    .memory
                    .get(&(address + offset as u64))
                    .copied()
                    .unwrap_or(0);
            }
            u32::from_le_bytes(bytes)
        }

        fn write_count(&self) -> usize {
            self.writes.len()
        }

        fn written_addresses(&self) -> Vec<u64> {
            self.writes.iter().map(|(address, _, _)| *address).collect()
        }
    }

    impl CheatMemoryIo for TestIo {
        fn read_mem(&mut self, address: u64, size: u32) -> Result<Vec<u8>, String> {
            self.reads += 1;
            if self.fail_read_at == Some(address) && self.reads > self.fail_read_after {
                return Err(format!("read from 0x{address:X} rejected by the target"));
            }
            Ok((0..size)
                .map(|offset| {
                    self.memory
                        .get(&(address + u64::from(offset)))
                        .copied()
                        .unwrap_or(0)
                })
                .collect())
        }

        fn write_mem(&mut self, address: u64, data: &[u8], allow_rx: bool) -> Result<(), String> {
            if self.fail_write_at == Some(address) {
                return Err(format!("write to 0x{address:X} rejected by the target"));
            }
            self.writes.push((address, data.to_vec(), allow_rx));
            self.probe_seen.push(
                self.probe
                    .as_ref()
                    .map(|path| path.exists())
                    .unwrap_or(false),
            );
            if self.ignore_write_at != Some(address) {
                for (offset, byte) in data.iter().enumerate() {
                    self.memory.insert(address + offset as u64, *byte);
                }
            }
            if let Some((index, delay)) = self.slow_writes {
                if self.writes.len() == index {
                    std::thread::sleep(delay);
                }
            }
            Ok(())
        }

        fn pause_process(&mut self) -> Result<(), String> {
            self.pause_calls += 1;
            if self.pause_fails {
                return Err("pause rejected by the target".to_string());
            }
            self.paused = true;
            Ok(())
        }

        fn resume_process(&mut self) -> Result<(), String> {
            self.resume_calls += 1;
            self.paused = false;
            Ok(())
        }

        fn failure_kind(&self, _error: &str) -> FailureKind {
            if self.target_gone {
                FailureKind::TargetGone
            } else {
                FailureKind::Other
            }
        }
    }

    const BUILD: &str = "9D4C86E6EF74504A";
    const ADDRESS: u64 = 0x1234;

    fn identity(pid: u64, incarnation: u64) -> TargetIdentity {
        TargetIdentity::new(pid, 0x0100_C380_0049_C000, incarnation, BUILD).unwrap()
    }

    fn regions() -> MemoryRegions {
        MemoryRegions::new(0x1000, 0x2000, 0x3000, 0x4000)
    }

    fn patch_file(name: &str) -> String {
        format!("[{name}]\n04400000 00001234 00000063\n")
    }

    #[test]
    fn patch_on_writes_journal_before_memory_and_off_restores() {
        let dir = TempDir::new("patch-on");
        let mut io = TestIo::with_u32(ADDRESS, 5);
        dir.write(&format!("{BUILD}.txt"), &patch_file("Value"));
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let journal = manager.journal_path().to_path_buf();
        io.probe = Some(journal.clone());
        let key = manager.find_key("Value").unwrap();

        manager.enable(key, &mut io).unwrap();
        assert_eq!(io.value_u32(ADDRESS), 0x63);
        assert_eq!(io.write_count(), 1);
        assert_eq!(io.probe_seen, vec![true]);
        assert_eq!(manager.backup_count(), 1);
        assert!(journal.exists());
        let journal_text = fs::read_to_string(&journal).unwrap();
        assert!(journal_text.contains("orig=05000000"));
        assert!(journal_text.contains("state=committed"));

        let writes_before = io.write_count();
        manager.disable(key, &mut io).unwrap();
        assert_eq!(io.value_u32(ADDRESS), 5);
        assert_eq!(io.write_count(), writes_before + 1);
        assert_eq!(manager.backup_count(), 0);
        assert!(!manager.is_enabled(key));
        assert!(
            !journal.exists() || fs::read_to_string(&journal).unwrap().is_empty(),
            "sidecar should be removed once nothing remains to restore"
        );
    }

    #[test]
    fn repeated_loop_writes_do_not_duplicate_the_backup() {
        let dir = TempDir::new("loop-backup");
        let mut io = TestIo::with_u32(ADDRESS, 9);
        let text = "\
[Value]
@loop
30050000 00000003
04400000 00001234 00000063
31050000
";
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Value").unwrap();
        manager.enable(key, &mut io).unwrap();
        let writes_after_enable = io.write_count();
        assert_eq!(manager.backup_count(), 1);
        // The loop stores the same address three times, but the plan keeps the
        // last value only: one target store per block instead of three
        // identical ones.
        assert_eq!(writes_after_enable, 1);

        manager.tick(&mut io, 0);
        assert_eq!(io.write_count(), writes_after_enable + 1);
        assert_eq!(manager.backup_count(), 1);
    }

    #[test]
    fn disabling_an_already_off_cheat_does_not_write() {
        let dir = TempDir::new("already-off");
        let text = "\
[Value]
04400000 00001234 00000063
--off
04400000 00001234 00000005
";
        let mut io = TestIo::with_u32(ADDRESS, 5);
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Value").unwrap();
        manager.disable(key, &mut io).unwrap();
        assert_eq!(io.write_count(), 0);
        assert_eq!(io.value_u32(ADDRESS), 5);
        assert!(!manager.block(key).unwrap().enabled);
    }

    #[test]
    fn explicit_inline_off_block_runs_and_drops_backup_without_restore() {
        let dir = TempDir::new("explicit-off");
        let mut io = TestIo::with_u32(ADDRESS, 5);
        let text = "\
[Value]
04400000 00001234 00000063
--off
04400000 00001234 00000005
";
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Value").unwrap();
        manager.enable(key, &mut io).unwrap();
        assert_eq!(io.value_u32(ADDRESS), 0x63);

        let writes_before = io.write_count();
        manager.disable(key, &mut io).unwrap();
        assert_eq!(io.value_u32(ADDRESS), 5);
        // Only the OFF program wrote; there was no automatic restore write.
        assert_eq!(io.write_count(), writes_before + 1);
        assert_eq!(manager.backup_count(), 0);
    }

    #[test]
    fn explicit_separate_off_section_is_associated() {
        let dir = TempDir::new("separate-off");
        let text = "\
[Value]
04400000 00001234 00000063

[Value:OFF]
04400000 00001234 00000005
";
        let mut io = TestIo::with_u32(ADDRESS, 5);
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        assert_eq!(manager.blocks().len(), 1);
        let key = manager.find_key("Value").unwrap();
        manager.enable(key, &mut io).unwrap();
        manager.disable(key, &mut io).unwrap();
        assert_eq!(io.value_u32(ADDRESS), 5);
        assert_eq!(manager.backup_count(), 0);
    }

    #[test]
    fn loop_tick_respects_keypad_gating() {
        let dir = TempDir::new("keypad");
        let text = "\
[Value]
80000001
04400000 00001234 00000063
20000000
";
        let mut io = TestIo::with_u32(ADDRESS, 7);
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Value").unwrap();
        assert_eq!(manager.block(key).unwrap().mode, CheatExecMode::Loop);

        manager.enable(key, &mut io).unwrap();
        assert_eq!(io.value_u32(ADDRESS), 7);
        assert_eq!(manager.backup_count(), 0);

        let report = manager.tick(&mut io, 1);
        assert_eq!(report.executed, 1);
        assert_eq!(io.value_u32(ADDRESS), 0x63);
        assert_eq!(manager.backup_count(), 1);

        let writes = io.write_count();
        manager.tick(&mut io, 0);
        assert_eq!(io.write_count(), writes);
        assert_eq!(io.value_u32(ADDRESS), 0x63);
    }

    #[test]
    fn loop_off_restores_original_bytes() {
        let dir = TempDir::new("loop-off");
        let text = "\
[Value]
80000001
04400000 00001234 00000063
20000000
";
        let mut io = TestIo::with_u32(ADDRESS, 7);
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Value").unwrap();
        manager.enable(key, &mut io).unwrap();
        manager.tick(&mut io, 1);
        assert_eq!(io.value_u32(ADDRESS), 0x63);
        manager.disable(key, &mut io).unwrap();
        assert_eq!(io.value_u32(ADDRESS), 7);
        assert_eq!(manager.backup_count(), 0);
    }

    #[test]
    fn owners_share_a_backup_and_only_the_last_restores() {
        let dir = TempDir::new("owners");
        let text = "\
[One]
04400000 00001234 00000063

[Two]
04400000 00001234 00000064
";
        let mut io = TestIo::with_u32(ADDRESS, 5);
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let one = manager.find_key("One").unwrap();
        let two = manager.find_key("Two").unwrap();
        manager.enable(one, &mut io).unwrap();
        manager.enable(two, &mut io).unwrap();
        assert_eq!(manager.backup_count(), 1);
        assert_eq!(manager.backups()[&ADDRESS].owners.len(), 2);

        let writes = io.write_count();
        manager.disable(one, &mut io).unwrap();
        assert_eq!(io.write_count(), writes);
        assert_eq!(manager.backup_count(), 1);
        assert_eq!(manager.backups()[&ADDRESS].owners.len(), 1);

        manager.disable(two, &mut io).unwrap();
        assert_eq!(io.value_u32(ADDRESS), 5);
        assert_eq!(manager.backup_count(), 0);
    }

    #[test]
    fn target_change_discards_backups_without_writing() {
        let dir = TempDir::new("target-change");
        let text = patch_file("Value");
        let mut io = TestIo::with_u32(ADDRESS, 5);
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Value").unwrap();
        manager.enable(key, &mut io).unwrap();
        assert_eq!(manager.backup_count(), 1);

        let writes = io.write_count();
        let change = manager.set_target(identity(200, 2), regions()).unwrap();
        assert!(change.changed);
        assert_eq!(change.dropped_backups, 1);
        assert_eq!(io.write_count(), writes);
        assert_eq!(manager.backup_count(), 0);
        assert!(manager.enabled_keys().is_empty());
    }

    #[test]
    fn same_target_does_not_drop_backups() {
        let dir = TempDir::new("same-target");
        let text = patch_file("Value");
        let mut io = TestIo::with_u32(ADDRESS, 5);
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Value").unwrap();
        manager.enable(key, &mut io).unwrap();
        let change = manager.set_target(identity(100, 1), regions()).unwrap();
        assert!(!change.changed);
        assert_eq!(manager.backup_count(), 1);
    }

    #[test]
    fn panic_off_restores_all_addresses_and_clears_state() {
        let dir = TempDir::new("panic");
        let text = "\
[One]
04400000 00001234 00000063
04400000 00001238 00000064

[Two]
04400000 00001234 00000065
";
        let mut io = TestIo::with_u32(ADDRESS, 5);
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let one = manager.find_key("One").unwrap();
        let two = manager.find_key("Two").unwrap();
        manager.enable(one, &mut io).unwrap();
        manager.enable(two, &mut io).unwrap();
        assert_eq!(manager.backup_count(), 2);

        let report = manager.restore_all_backups(&mut io);
        assert!(report.is_complete());
        assert_eq!(report.restored, 2);
        assert_eq!(manager.backup_count(), 0);
        assert!(manager.enabled_keys().is_empty());
        assert_eq!(io.value_u32(ADDRESS), 5);
        assert_eq!(io.value_u32(ADDRESS + 4), 0);
        assert!(manager.blocks().iter().all(|block| !block.enabled));
    }

    #[test]
    fn journal_is_reloaded_for_the_same_identity() {
        let dir = TempDir::new("journal-reload");
        let text = patch_file("Value");
        let mut io = TestIo::with_u32(ADDRESS, 5);
        dir.write(&format!("{BUILD}.txt"), &text);
        let key = {
            let mut manager =
                CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                    .unwrap();
            let key = manager.find_key("Value").unwrap();
            manager.enable(key, &mut io).unwrap();
            key
        };

        // Simulate a fresh PC process with the target still patched.
        let mut io2 = TestIo::with_u32(ADDRESS, 0x63);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        assert_eq!(manager.backup_count(), 1);
        assert!(manager.backups()[&ADDRESS].owners.contains(&key));
        manager.disable(key, &mut io2).unwrap();
        assert_eq!(io2.value_u32(ADDRESS), 5);
        assert_eq!(manager.backup_count(), 0);
    }

    #[test]
    fn journal_from_another_identity_is_ignored() {
        let dir = TempDir::new("journal-identity");
        let text = patch_file("Value");
        let mut io = TestIo::with_u32(ADDRESS, 5);
        dir.write(&format!("{BUILD}.txt"), &text);
        {
            let mut manager =
                CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                    .unwrap();
            let key = manager.find_key("Value").unwrap();
            manager.enable(key, &mut io).unwrap();
        }

        let manager =
            CheatManager::open_for_target_in(identity(200, 2), regions(), dir.path.clone())
                .unwrap();
        assert_eq!(manager.backup_count(), 0);
    }

    #[test]
    fn enabling_an_invalid_block_is_refused() {
        let dir = TempDir::new("invalid");
        let text = "[Value]\nB4000000 00000000\n";
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut io = TestIo::default();
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.blocks()[0].key;
        let error = manager.enable(key, &mut io).unwrap_err();
        assert!(error.contains("unsupported") || error.contains("invalid"));
        assert_eq!(io.write_count(), 0);
        assert!(manager.errors().contains_key(&key));
    }

    #[test]
    fn missing_file_is_created_on_save() {
        let dir = TempDir::new("missing");
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        assert!(manager.blocks().is_empty());
        manager.document_mut().add_cheat(
            "Value",
            &["04400000 00001234 00000063".to_string()],
            None,
        );
        manager.save_document().unwrap();
        let path = dir.path.join("cheats").join(format!("{BUILD}.txt"));
        assert!(path.exists());
        let text = fs::read_to_string(path).unwrap();
        assert!(text.contains("[Value]"));
        assert!(text.contains("04400000 00001234 00000063"));
    }

    #[test]
    fn raw_text_save_round_trips_and_enable_state_is_written() {
        let dir = TempDir::new("raw-save");
        dir.write(&format!("{BUILD}.txt"), &patch_file("Value"));
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Value").unwrap();
        let mut io = TestIo::with_u32(ADDRESS, 5);
        manager.enable(key, &mut io).unwrap();
        let text = fs::read_to_string(manager.path()).unwrap();
        assert!(text.contains("[Value]"));

        manager.disable(key, &mut io).unwrap();
        let text = fs::read_to_string(manager.path()).unwrap();
        assert!(text.contains("@off"), "unexpected file:\n{text}");
        assert!(text.contains("04400000 00001234 00000063"));

        // Reloading must keep the ON code; `[Name:OFF]` would have turned this
        // into an OFF-only restore section.
        let mut reloaded =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let reloaded_key = reloaded.find_key("Value").unwrap();
        assert!(!reloaded.document().block(reloaded_key).unwrap().enabled);
        assert_eq!(
            reloaded
                .document()
                .block(reloaded_key)
                .unwrap()
                .on
                .instructions
                .len(),
            1
        );
        reloaded.enable(reloaded_key, &mut io).unwrap();
        assert_eq!(io.value_u32(ADDRESS), 0x63);
    }

    #[test]
    fn path_resolution_prefers_uppercase_next_to_the_executable() {
        let dir = TempDir::new("paths");
        let upper = dir.path.join("cheats").join(format!("{BUILD}.txt"));
        fs::create_dir_all(upper.parent().unwrap()).unwrap();
        fs::write(&upper, "").unwrap();
        let resolved =
            resolve_cheat_path_in(&dir.path, BUILD.to_ascii_lowercase().as_str()).unwrap();
        assert_eq!(resolved, upper);
        let backup = resolve_backup_path_in(&dir.path, BUILD).unwrap();
        assert_eq!(
            backup.file_name().unwrap().to_string_lossy(),
            format!("{BUILD}.backup")
        );
    }

    #[test]
    fn open_with_path_switches_to_the_same_cheats_directory() {
        let dir = TempDir::new("open-with-path");
        let path = dir.write(&format!("{BUILD}.txt"), &patch_file("Value"));
        let mut manager =
            CheatManager::open_with_path(identity(100, 1), regions(), path.clone()).unwrap();
        assert_eq!(manager.path(), path);

        let other_build = "0011223344556677";
        let other = TargetIdentity::new(100, 0x100, 2, other_build).unwrap();
        manager.set_target(other, regions()).unwrap();
        assert_eq!(
            manager.path(),
            dir.path.join("cheats").join(format!("{other_build}.txt"))
        );
        assert_ne!(
            manager.path(),
            dir.path
                .join("cheats")
                .join("cheats")
                .join(format!("{other_build}.txt"))
        );
    }

    #[test]
    fn lowercase_existing_file_is_loaded_but_new_files_use_uppercase() {
        let dir = TempDir::new("lowercase");
        let lower = dir.write(
            &format!("{}.txt", BUILD.to_ascii_lowercase()),
            &patch_file("Value"),
        );
        let manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        // Windows is case-insensitive, so the canonical uppercase path may be
        // reported even though the existing file is lowercase.  Either way the
        // file must load.
        assert!(manager.path().exists());
        assert!(manager.find_key("Value").is_some());
        let _ = lower;

        let other_dir = TempDir::new("uppercase-new");
        let mut fresh =
            CheatManager::open_for_target_in(identity(100, 1), regions(), other_dir.path.clone())
                .unwrap();
        fresh
            .document_mut()
            .add_cheat("Value", &["04400000 00001234 00000063".to_string()], None);
        fresh.save_document().unwrap();
        assert!(other_dir
            .path
            .join("cheats")
            .join(format!("{BUILD}.txt"))
            .exists());
    }

    #[test]
    fn build_id_validation_rejects_bad_names() {
        assert!(normalize_build_id("9d4c86e6ef74504a").is_ok());
        assert!(normalize_build_id("0x9D4C86E6EF74504A").is_ok());
        assert!(normalize_build_id("").is_err());
        assert!(normalize_build_id("1234").is_err());
        assert!(normalize_build_id("../../etc/passwd").is_err());
        assert!(normalize_build_id("GGGGGGGGGGGGGGGG").is_err());
        assert!(normalize_build_id("0000000000000000").is_err());
    }

    #[test]
    fn tick_reports_per_cheat_errors_and_continues() {
        let dir = TempDir::new("tick-errors");
        let text = "\
[Bad]
82000001
04400000 00001234 00000063
20000000

[Good]
80000001
04400000 00001238 00000064
20000000
";
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut io = TestIo::default();
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let bad = manager.find_key("Bad").unwrap();
        let good = manager.find_key("Good").unwrap();
        manager.enable(bad, &mut io).unwrap();
        manager.enable(good, &mut io).unwrap();
        let report = manager.tick(&mut io, 1);
        assert_eq!(report.executed, 2);
        assert_eq!(report.failed, 0);
    }

    #[test]
    fn stale_journal_makes_the_restore_incomplete() {
        let dir = TempDir::new("journal-failure");
        dir.write(&format!("{BUILD}.txt"), &patch_file("Value"));
        let mut io = TestIo::with_u32(ADDRESS, 5);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Value").unwrap();
        manager.enable(key, &mut io).unwrap();

        // The sidecar cannot be updated (or removed) any more: the on-disk
        // restore record is stale, so the restore is not complete.
        let journal = manager.journal_path().to_path_buf();
        fs::remove_file(&journal).unwrap();
        fs::create_dir(&journal).unwrap();

        let report = manager.restore_all_backups(&mut io);
        assert_eq!(report.restored, 1);
        assert!(report.failed.is_empty());
        assert!(report.journal_error.is_some(), "{report:?}");
        assert!(
            !report.is_complete(),
            "a stale journal must not be reported as a complete restore"
        );
        assert!(!manager.dirty());
        assert!(manager.last_error().unwrap().contains("journal"));
    }

    #[test]
    fn failed_restore_is_incomplete_and_keeps_the_manager_dirty() {
        let dir = TempDir::new("restore-failure");
        let text = "\
[One]
04400000 00001234 00000063
04400000 00001238 00000064
";
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut io = TestIo::with_u32(ADDRESS, 5);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("One").unwrap();
        manager.enable(key, &mut io).unwrap();
        assert!(manager.dirty());
        assert_eq!(manager.backup_count(), 2);

        // The target refuses one of the two originals.
        io.fail_write_at = Some(ADDRESS + 4);
        let report = manager.restore_all_backups(&mut io);
        assert!(!report.is_complete(), "{report:?}");
        assert_eq!(report.restored, 1);
        assert_eq!(report.failed_addresses, 1);
        assert_eq!(report.failed_count(), 1);
        assert!(manager.dirty(), "a failed restore must not clear dirty");
        assert_eq!(manager.backup_count(), 1);
        assert!(manager.last_error().is_some());
        // The journal still describes the address that is not back yet.
        let journal = fs::read_to_string(manager.journal_path()).unwrap();
        assert!(journal.contains("addr="), "{journal}");
    }

    #[test]
    fn failed_disable_restore_is_reported_and_keeps_dirty() {
        let dir = TempDir::new("disable-failure");
        dir.write(&format!("{BUILD}.txt"), &patch_file("Value"));
        let mut io = TestIo::with_u32(ADDRESS, 5);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Value").unwrap();
        manager.enable(key, &mut io).unwrap();

        io.fail_write_at = Some(ADDRESS);
        let error = manager.disable(key, &mut io).unwrap_err();
        assert!(error.contains("restore failed"), "{error}");
        assert!(manager.dirty());
        assert_eq!(manager.backup_count(), 1);
        assert_eq!(io.value_u32(ADDRESS), 0x63);
        // The cheat stays marked ON: reporting it off while its bytes are
        // still patched is the silent failure this path must never have.
        assert!(manager.is_enabled(key));
    }

    #[test]
    fn save_failure_is_returned_as_an_error() {
        let dir = TempDir::new("save-failure");
        dir.write(&format!("{BUILD}.txt"), &patch_file("Value"));
        let mut io = TestIo::with_u32(ADDRESS, 5);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Value").unwrap();
        // Replace the cheat file with a directory: the atomic save has nowhere
        // to rename its temporary file to.
        let path = manager.path().to_path_buf();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();

        let error = manager.enable(key, &mut io).unwrap_err();
        assert!(error.contains("could not be saved"), "{error}");
        // The bytes are applied and the manager says so, instead of pretending
        // the toggle failed cleanly.
        assert!(manager.is_enabled(key));
        assert_eq!(io.value_u32(ADDRESS), 0x63);
        assert!(manager.dirty());
        assert!(manager.last_error().unwrap().contains("could not be saved"));
    }

    #[test]
    fn pause_opcode_is_released_after_the_block() {
        let dir = TempDir::new("pause-release");
        let text = "\
[Frozen]
FF000000
04400000 00001234 00000063
";
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut io = TestIo::with_u32(ADDRESS, 5);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Frozen").unwrap();
        manager.enable(key, &mut io).unwrap();
        assert_eq!(io.value_u32(ADDRESS), 0x63);
        assert!(
            !io.paused,
            "0xFF0 must not outlive the block; the console would stay frozen"
        );
    }

    #[test]
    fn budget_overrun_rolls_the_block_back() {
        let dir = TempDir::new("budget-rollback");
        let text = "\
[Slow]
04400000 00001234 00000063
04400000 00001238 00000064
";
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut io = TestIo::with_u32(ADDRESS, 5);
        // Simulate a slow console: the first write takes longer than the whole
        // budget, so the second instruction sees an expired deadline.
        io.slow_writes = Some((1, Duration::from_millis(30)));
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Slow").unwrap();
        let mut progress_calls = 0usize;
        let error = manager
            .enable_block(
                key,
                &mut io,
                Some(Duration::from_millis(1)),
                &mut |_, _| progress_calls += 1,
            )
            .unwrap_err();

        assert!(error.contains("timed out"), "{error}");
        assert!(progress_calls > 0);
        // The write that did land was written back...
        assert_eq!(io.value_u32(ADDRESS), 5);
        assert_eq!(io.value_u32(ADDRESS + 4), 0);
        // ...and nothing is left to restore.
        assert_eq!(manager.backup_count(), 0);
        assert!(!manager.dirty());
        assert!(!manager.is_enabled(key));
        assert!(manager.errors().contains_key(&key));
        assert!(
            !manager.journal_path().exists(),
            "an empty backup table must not leave a sidecar behind"
        );
    }

    #[test]
    fn explicit_off_failure_falls_back_to_the_original_bytes_and_saves_the_file() {
        let dir = TempDir::new("off-failure");
        let text = "\
[Value]
04400000 00001234 00000063
--off
B4000000 00000000
";
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut io = TestIo::with_u32(ADDRESS, 5);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Value").unwrap();
        manager.enable(key, &mut io).unwrap();

        let error = manager.disable(key, &mut io).unwrap_err();
        assert!(
            error.contains("unsupported") || error.contains("invalid"),
            "{error}"
        );
        // The broken OFF block must not leave the target patched.
        assert_eq!(io.value_u32(ADDRESS), 5);
        assert_eq!(manager.backup_count(), 0);
        assert!(!manager.dirty());
        assert!(!manager.is_enabled(key));
        // The file must record the disabled state, not just memory.
        let text = fs::read_to_string(manager.path()).unwrap();
        assert!(text.contains("@off"), "{text}");
    }

    // -- two-phase (plan/apply) writes -------------------------------------

    #[test]
    fn plan_applies_writes_in_descending_page_order() {
        let dir = TempDir::new("apply-order");
        let text = "\
[Order]
04400000 00001000 11111111
04400000 00002000 22222222
04400000 00001004 33333333
";
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut io = TestIo::default();
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Order").unwrap();
        manager.enable(key, &mut io).unwrap();

        // 0x2000 lives on a higher page and goes first; the two writes on page
        // 0x1000 keep the order the cheat author wrote them in.
        assert_eq!(
            io.written_addresses(),
            vec![0x2000, 0x1000, 0x1004],
            "cave pages must be written before the hook page"
        );
        assert_eq!(io.memory[&0x1000], 0x11);
        assert_eq!(io.memory[&0x2000], 0x22);
        assert_eq!(io.memory[&0x1004], 0x33);
    }

    #[test]
    fn preflight_failure_writes_nothing() {
        let dir = TempDir::new("preflight");
        let text = "\
[Two]
04400000 00001234 00000063
04400000 00001238 00000064
";
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut io = TestIo::with_u32(ADDRESS, 5);
        // The plan phase reads each new address once to record its original
        // bytes (2 reads); fail only the later preflight read of the first one.
        io.fail_read_at = Some(ADDRESS);
        io.fail_read_after = 2;
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Two").unwrap();
        let error = manager.enable(key, &mut io).unwrap_err();

        assert!(error.contains("preflight read failed at 0x1234"), "{error}");
        assert!(
            io.writes.is_empty(),
            "preflight must abort before the first byte: {:?}",
            io.writes
        );
        assert_eq!(io.value_u32(ADDRESS), 5);
        assert_eq!(io.value_u32(ADDRESS + 4), 0);
        assert_eq!(manager.backup_count(), 0);
        assert!(!manager.dirty());
        assert!(!manager.is_enabled(key));
        assert!(
            !manager.journal_path().exists(),
            "a plan that never applied must not leave a journal behind"
        );
    }

    #[test]
    fn read_back_mismatch_rolls_the_block_back() {
        let dir = TempDir::new("read-back");
        let text = "\
[Two]
04400000 00001234 00000063
04400000 00001238 00000064
";
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut io = TestIo::with_u32(ADDRESS, 5);
        // The target accepts the store but the byte never changes.
        io.ignore_write_at = Some(ADDRESS + 4);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Two").unwrap();
        let error = manager.enable(key, &mut io).unwrap_err();

        assert!(error.contains("read-back verification failed"), "{error}");
        assert!(error.contains("0x1238"), "{error}");
        // The accepted half of the block was written back.
        assert_eq!(io.value_u32(ADDRESS), 5);
        assert_eq!(io.value_u32(ADDRESS + 4), 0);
        assert_eq!(manager.backup_count(), 0);
        assert!(!manager.dirty());
        assert!(!manager.is_enabled(key));
    }

    #[test]
    fn target_gone_is_reported_once_and_never_rolled_back() {
        let dir = TempDir::new("target-gone");
        let text = "\
[Two]
04400000 00001234 00000063
04400000 00001238 00000064
";
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut io = TestIo::with_u32(ADDRESS, 5);
        // The first store lands, the second one discovers the process is gone.
        io.fail_write_at = Some(ADDRESS + 4);
        io.target_gone = true;
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Two").unwrap();
        let error = manager.enable(key, &mut io).unwrap_err();

        assert_eq!(
            error.lines().count(),
            1,
            "one line, not one per address: {error}"
        );
        assert!(
            error.contains("target is gone (console reports no process)"),
            "{error}"
        );
        assert!(
            error.contains("1 write(s) may have been applied"),
            "{error}"
        );
        assert_eq!(
            io.write_count(),
            1,
            "a dead process must not be asked to roll back: {:?}",
            io.writes
        );
        // The applied byte is still there; the process took it with it.
        assert_eq!(io.value_u32(ADDRESS), 0x63);
        assert_eq!(manager.backup_count(), 0);
        assert!(
            !manager.dirty(),
            "nothing can be restored in a process that no longer exists"
        );
        assert!(manager.errors().contains_key(&key));
    }

    #[test]
    fn pause_is_taken_for_small_rx_blocks_and_released_on_error() {
        let text = "\
[Two]
04400000 00001234 00000063
04400000 00001238 00000064
";
        let dir = TempDir::new("pause-success");
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut io = TestIo::with_u32(ADDRESS, 5);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Two").unwrap();
        manager.enable(key, &mut io).unwrap();
        assert_eq!(io.pause_calls, 1);
        assert_eq!(io.resume_calls, 1);
        assert!(!io.paused);

        // The same block failing mid-apply must release the pause as well.
        let dir = TempDir::new("pause-error");
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut io = TestIo::with_u32(ADDRESS, 5);
        io.fail_write_at = Some(ADDRESS + 4);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Two").unwrap();
        manager.enable(key, &mut io).unwrap_err();
        assert_eq!(io.pause_calls, 1, "the pause was taken before the stores");
        assert_eq!(io.resume_calls, 1, "an error path must still resume");
        assert!(!io.paused, "the console must never be left frozen");
    }

    #[test]
    fn pause_is_skipped_for_blocks_over_the_write_limit() {
        let dir = TempDir::new("pause-limit");
        let mut text = String::from("[Many]\n");
        for index in 0..=PAUSE_WRITE_LIMIT as u64 {
            text.push_str(&format!("04400000 {:08X} 00000001\n", 0x100 + index * 4));
        }
        dir.write(&format!("{BUILD}.txt"), &text);
        let mut io = TestIo::default();
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Many").unwrap();
        manager.enable(key, &mut io).unwrap();

        assert_eq!(io.write_count(), PAUSE_WRITE_LIMIT + 1);
        assert_eq!(
            io.pause_calls, 0,
            "a bulk write must not freeze the console for its whole duration"
        );
        assert!(!io.paused);
    }

    #[test]
    fn failed_pause_still_applies_and_is_reported() {
        let dir = TempDir::new("pause-fails");
        dir.write(&format!("{BUILD}.txt"), &patch_file("Value"));
        let mut io = TestIo::with_u32(ADDRESS, 5);
        io.pause_fails = true;
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Value").unwrap();
        manager.enable(key, &mut io).unwrap();

        assert_eq!(io.value_u32(ADDRESS), 0x63);
        assert_eq!(io.pause_calls, 1);
        assert_eq!(
            io.resume_calls, 0,
            "nothing was paused, so nothing to resume"
        );
        assert!(
            manager.last_error().unwrap().contains("pause"),
            "the failed pause must stay visible: {:?}",
            manager.last_error()
        );
    }

    #[test]
    fn plan_io_shadow_sees_pending_writes_and_keeps_the_last_value() {
        let dir = TempDir::new("shadow");
        dir.write(&format!("{BUILD}.txt"), &patch_file("Value"));
        let mut io = TestIo::with_u32(ADDRESS, 5);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Value").unwrap();
        {
            let mut planner = PlanIo {
                manager: &mut manager,
                io: &mut io,
                key,
                record_backups: true,
                writes: Vec::new(),
                plan: Vec::new(),
                shadow: BTreeMap::new(),
                journal_flushed: false,
            };
            planner
                .write_mem(ADDRESS, &[0xAA, 0xBB, 0xCC, 0xDD], true)
                .unwrap();
            // Reads overlapping the pending store see the new bytes...
            assert_eq!(
                planner.read_mem(ADDRESS, 4).unwrap(),
                vec![0xAA, 0xBB, 0xCC, 0xDD]
            );
            assert_eq!(planner.read_mem(ADDRESS + 1, 2).unwrap(), vec![0xBB, 0xCC]);
            // ...while bytes outside it still read the real memory.
            assert_eq!(planner.read_mem(ADDRESS + 4, 1).unwrap(), vec![0]);
            // A second store to the same address wins without a new entry.
            planner
                .write_mem(ADDRESS, &[0x11, 0x22, 0x33, 0x44], true)
                .unwrap();
            assert_eq!(planner.plan.len(), 1);
            assert_eq!(planner.plan[0].data, vec![0x11, 0x22, 0x33, 0x44]);
            assert_eq!(
                planner.read_mem(ADDRESS, 4).unwrap(),
                vec![0x11, 0x22, 0x33, 0x44]
            );
        }
        // Nothing reached the target: the plan is only applied after the block.
        assert_eq!(io.value_u32(ADDRESS), 5);
        assert_eq!(io.write_count(), 0);
        assert_eq!(manager.backup_count(), 1);
    }

    // -- コンソール実行モード ------------------------------------------------

    fn two_cheats(dir: &TempDir) -> String {
        let text = "\
[First]
04400000 00001234 00000063
[Second]
@loop
30050000 00000003
04400000 00001238 00000001
31050000
";
        dir.write(&format!("{BUILD}.txt"), text);
        text.to_string()
    }

    /// アップロードするバイト列は、そのまま `ir::build_program` の出力。
    ///
    /// PC が「コンソール用プログラム」を独自に組み立て始めると、リンカの
    /// 変更が片方にしか効かなくなる。同じ関数を通っていることを固定する。
    #[test]
    fn the_console_program_is_the_ir_linker_output_for_this_target() {
        let dir = TempDir::new("console-program");
        two_cheats(&dir);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let first = manager.find_key("First").unwrap();
        // ON にしたブロックは `BlockDesc::enabled` に載る（再アップロードで
        // 既存の ON が落ちない）。
        manager.note_console_toggle(first, true).unwrap();

        let program = manager.build_console_program().unwrap();
        let build_id = u64::from_str_radix(BUILD, 16).unwrap();
        let expected = ir::build_program(
            manager.document(),
            build_id,
            manager.identity().program_id,
            manager.enabled_keys(),
        )
        .unwrap();
        assert_eq!(program, expected, "must be the linker's own bytes");

        let header = ir::ProgramHeader::from_bytes(&program[..ir::HEADER_BYTES]).unwrap();
        assert_eq!(header.magic, ir::MAGIC);
        assert_eq!(header.build_id, build_id);
        assert_eq!(header.program_id, 0x0100_C380_0049_C000);
        assert_eq!(header.block_count, 2);
        assert_eq!(header.total_bytes as usize, program.len());

        // index はドキュメント順（`NxusCheatEnable.index` がそのまま使える）。
        assert_eq!(manager.block_index(first), Some(0));
        assert_eq!(
            manager.block_index(manager.find_key("Second").unwrap()),
            Some(1)
        );
        let second_desc = ir::BlockDesc::from_bytes(
            &program[ir::HEADER_BYTES + ir::BLOCK_BYTES..ir::HEADER_BYTES + 2 * ir::BLOCK_BYTES],
        )
        .unwrap();
        assert_eq!(second_desc.index, 1);
        assert_eq!(second_desc.enabled, 0);
        let first_desc =
            ir::BlockDesc::from_bytes(&program[ir::HEADER_BYTES..ir::HEADER_BYTES + ir::BLOCK_BYTES])
                .unwrap();
        assert_eq!(first_desc.enabled, 1);
    }

    /// 同じ内容は 2 度送らない。内容が変わった / コンソールがプログラムを
    /// 失ったときだけ送り直す。
    #[test]
    fn the_same_console_program_is_not_uploaded_twice() {
        let dir = TempDir::new("console-upload-cache");
        two_cheats(&dir);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();

        let program = manager.build_console_program().unwrap();
        assert!(manager.need_console_upload(&program), "nothing sent yet");
        assert!(manager.console_program().is_none());

        manager.note_console_upload(&program);
        assert!(
            !manager.need_console_upload(&program),
            "identical content must not be sent again"
        );
        assert_eq!(manager.console_program(), Some(program.as_slice()));

        // 内容が変われば（ブロックを ON にすると enabled が変わる）送り直す。
        let first = manager.find_key("First").unwrap();
        manager.note_console_toggle(first, true).unwrap();
        let changed = manager.build_console_program().unwrap();
        assert_ne!(changed, program);
        assert!(manager.need_console_upload(&changed));

        // コンソールが program_valid == 0 を返したら控えを捨て、次の ON で
        // 送り直す（「載っている」と思い込むと BAD_STATE になる）。
        manager.note_console_upload(&changed);
        manager.forget_console_upload();
        assert!(manager.need_console_upload(&changed));
        assert!(manager.console_program().is_none());
    }

    /// コンソール実行の ON/OFF は PC のメモリにもジャーナルにも触らない。
    ///
    /// 書き込みはコンソールのワーカーが自分の復元表で行うので、PC 側に
    /// バックアップを作ると「切断時に二重に書き戻す」事故になる。
    #[test]
    fn a_console_toggle_writes_nothing_from_the_pc() {
        let dir = TempDir::new("console-toggle");
        dir.write(&format!("{BUILD}.txt"), &patch_file("Value"));
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let key = manager.find_key("Value").unwrap();
        let mut io = TestIo::with_u32(ADDRESS, 5);

        manager.note_console_toggle(key, true).unwrap();
        assert_eq!(io.write_count(), 0, "the console does the writing");
        assert_eq!(manager.backup_count(), 0);
        assert!(!manager.dirty(), "the console owns the restore table");
        assert!(manager.is_enabled(key));
        assert!(manager.block(key).unwrap().enabled);

        manager.note_console_toggle(key, false).unwrap();
        assert_eq!(io.write_count(), 0);
        assert!(!manager.is_enabled(key));
        assert!(!manager.block(key).unwrap().enabled);

        // PC 側のジャーナル復元を走らせても書くものが無い（原本はコンソールが
        // 持っている）ので、コンソールの復元表を二重に触らない。
        let report = manager.restore_all_backups(&mut io);
        assert_eq!(report.restored, 0);
        assert_eq!(io.write_count(), 0);
    }

    /// 既定はコンソール実行。未対応のコンソールでは 1 回だけ通知して pc へ。
    #[test]
    fn cheats_run_on_the_console_by_default_and_fall_back_once() {
        let dir = TempDir::new("console-default");
        dir.write(&format!("{BUILD}.txt"), &patch_file("Value"));
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();

        assert_eq!(CheatExecution::default(), CheatExecution::Console);
        assert_eq!(manager.execution(), CheatExecution::Console);
        assert!(manager.is_console_mode());
        assert_eq!(CheatExecution::Console.label(), "console");
        assert_eq!(CheatExecution::Pc.label(), "pc");
        assert!(!CheatExecution::Pc.is_console());

        let notice = manager
            .fallback_to_pc("command 0x0082 failed (result=0x8003C801)")
            .expect("the first fallback is reported");
        assert!(notice.contains("does not implement"), "{notice}");
        assert_eq!(manager.execution(), CheatExecution::Pc);
        assert!(!manager.is_console_mode());
        assert!(manager.console_fallback().is_some());
        // 2 回目以降はログを溢れさせない。
        assert!(manager
            .fallback_to_pc("command 0x0082 failed (result=0x8003C801)")
            .is_none());
    }

    /// コンソールのワーカーが自分から止めたら、表示上も全部 OFF にする。
    #[test]
    fn a_console_fault_clears_every_enabled_block() {
        let dir = TempDir::new("console-fault");
        two_cheats(&dir);
        let mut manager =
            CheatManager::open_for_target_in(identity(100, 1), regions(), dir.path.clone())
                .unwrap();
        let first = manager.find_key("First").unwrap();
        let second = manager.find_key("Second").unwrap();
        manager.note_console_toggle(first, true).unwrap();
        manager.note_console_toggle(second, true).unwrap();
        assert_eq!(manager.enabled_keys().len(), 2);

        let off = manager.mark_all_off();
        assert_eq!(off, 2);
        assert!(manager.enabled_keys().is_empty());
        assert!(manager.blocks().iter().all(|block| !block.enabled));
        // 2 回目は何も OFF にしない（冪等）。
        assert_eq!(manager.mark_all_off(), 0);
    }
}
