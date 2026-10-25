# Nxus-ox (`v0.1.0-alpha`)

**Nxus-ox** is a headless remote memory scanner, pointer chain analyzer, and multi-core kernel hardware debugger & disassembler for **Nintendo Switch (Atmosphère CFW)**, paired with a unified **Rust PC Client (GUI + CLI)**.

Instead of transferring multi-gigabyte raw RAM dumps over Wi-Fi for every search, Nxus-ox runs a lightweight C sysmodule directly on the Switch (`pool_partition: System`: an 8 MiB inner heap, a measured `.bss` of `8.30 MiB` plus the `32 KiB` stack, and `system_resource_size=0` in the NPDM) that scans memory in 1 MiB chunks, coalesces sparse refinement windows, and streams compact hit lists and hardware debug events over TCP (default port `7332`).

---

## ⚠️ Alpha Release & Disclaimer (No Warranty)

> **IMPORTANT — PLEASE READ CAREFULLY BEFORE USE:**
>
> 1. **Alpha Testing Stage (`v0.1.0-alpha`)**: This software is in an early **Alpha testing phase**. Features, wire protocols, and configurations are experimental and may change or break without notice.
> 2. **No Warranty / No Guarantee of Operation**: This software is provided **"AS IS"**, without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. **There is no guarantee that this software will function correctly, safely, or at all on your hardware.**
> 3. **Limitation of Liability**: In no event shall the authors or contributors be liable for any claim, damages, data loss, save corruption, console ban, or other liability arising from the use of this software.
> 4. **Safe Usage Requirements**:
>    - Always run on **emuMMC** (never run custom debugging sysmodules on `sysMMC`).
>    - Maintain a verified **NAND backup** and **SD card backup**.
>    - Keep a recovery method ready (e.g., booting hekate UMS to remove `atmosphere/contents/4200000000004E58/flags/boot2.flag` if a session hangs).
>    - Strictly intended for **offline educational, debugging, and reverse-engineering research**.
> 5. **Network exposure**: the console protocol has **no authentication** — anyone who can
>    reach port `7332` can read/write the target's memory and take the debug handle. The
>    sysmodule therefore **only accepts connections from private/LAN addresses**
>    (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`, `100.64/10`) and closes
>    anything else, logging the refused peer. Do **not** port-forward `7332`.

---

## Version & Compatibility Matrix

| Component / Environment | Version / Specification | Notes |
|---|---|---|
| **Release Version** | **Alpha `v0.1.0` (`v0.1.0-alpha`)** | Wire Protocol `v1` (TCP port `7332`) |
| **Switch System Firmware** | Tested up to **HOS 23.0.1** | Built with FW 21.0.0+ TLS/ABI support |
| **Custom Firmware** | **Atmosphère 1.12.1+** / **hekate 6.5.4+** | Uses `dmnt:cht` for cheat VM & kernel `svcDebugActiveProcess` for hardware debugging |
| **Toolchain** | **devkitA64 r29.2-1** / **libnx 4.12.0-1** | Note: Homebrew/sysmodules built with `libnx < 4.10.0` crash on FW 21.0.0+ |
| **Target Title Architectures** | **AArch64 (64-bit)** & **AArch32 (32-bit ARM32 / Thumb)** | Full support for 32-bit titles (e.g., *Monster Hunter XX*) and 64-bit titles |
| **Sysmodule Title IDs** | `0x4200000000004E58` (`nxus`)<br>`0x4200000000004E59` (`probe`) | NPDM ACID/ACI0 patched with single-bit `ForceDebug` (`0x08`) |
| **PC Client (`nxus.exe`)** | **Windows x64** (Rust `eframe` / `egui` + CLI) | **Single unified executable** for both GUI and CLI |
| **`metadata.json` build stamp** | `build_utc` (ISO 8601 UTC) · `source_rev` (`git rev-parse --short HEAD`, or `unknown` when git is unavailable) · `dirty` (`true` when `git status --porcelain` was non-empty at build time) | Additive keys in every `dist/.../metadata.json`, so a folder on the SD card can be traced to the exact revision that built it; the older `built_utc` key keeps its value and meaning |

### PC ↔ console wire compatibility (mixed builds)

The wire protocol stays `v1`: newer fields are **appended**, never inserted, so every
structure keeps the offsets of its original fields. Each side therefore decides by
**frame length**, not by a version number, and the two directions degrade
differently:

| Wire change | Older console + this PC | This console + older PC |
|---|---|---|
| **20-byte `NxusPtrChainListHeader`** (`pointer_width` appended; chain records now start at offset 20) | ✔ Works. The 16-byte header is recognised from the reply length (it is not the `20 + count*48` shape); `pointer_width` reads `0`, so the PC falls back to its own width rule and the GUI reports *an unreported width* (its local cheat preview is disabled). Chain decoding is unaffected. | ⚠ The first 16 bytes (count / total / truncated) still decode, but the records now start at 20. A PC older than the field starts them at 16 and reads every record four bytes early — **the only silent mismatch in this table**. The length probe shipped in the same build as the field, so any PC from this release (or later) decodes both shapes; a build older than the field must be updated. |
| **40-byte `NxusDebugStatus`** (`stopped_thread` appended) | ✔ Works. A 32-byte reply is parsed through `stopped_thread_low`; `stopped_thread` is only read when the payload is at least 40 bytes, so a stopped thread id above 4 GiB can only be read truncated (the value the old console could express anyway). | ✔ Works. The 32-byte prefix keeps its offsets (offset 28 used to be `reserved`) and the trailing `u64` is ignored. |
| **`NXUS_RESULT_PTRSCAN_STARTED`** (`0x8003C808`) answered by `PtrScanBegin` | ✔ Works. An older console walks inside the command and answers with the chain list; the PC accepts both shapes and only starts polling `PtrScanGet` (250 ms, 150 s budget) after the new result. | ⚠ The result is unknown to it, so the command is reported as failed (`command 0x0030 failed` for the Rust CLI/GUI, `PtrScanBegin failed: result=0x8003C808` for the Python client) and the PC never polls: the walk keeps running on the console but its list is never collected. Nothing is corrupted — re-run with a current PC. |
| **Reason codes 10–13** (`HEAP_BUDGET`, `DEBUG_LOCKED`, `SLOT_FULL`, `RETRY_LATER`) | ✔ Works. The tail is optional: a console that sends no reason keeps the old `command 0x.... failed` text, every code 1–13 is named, and an unknown code is still printed as `(reason=N)`. | ⚠ Informational only. An older PC names the codes it knows (1–10 in the build before this one) and prints `(reason=11..13)` without text; one older than the reason word itself ignores the extra four bytes. The `Result` is unchanged, so only the guidance/retry policy is coarser (11/12 need a user action, 13 clears by itself). |
| **`NxusCmd_SnapshotRelease`** (`0x0072`) | ✔ Refused, loudly. The console answers `NXUS_ERR_UNSUPPORTED` (plus `NXUS_REASON_UNKNOWN_COMMAND` when it sends the tail), the CLI prints `command 0x0072 failed - unknown command: this console does not implement it (reason=6)`, and both snapshot slots stay resident — free them with `ScanReset`, or restart the module on a console that also predates the release-on-reset. | ✔ An older PC never sends `0x0072`; the console still frees both slots on `ScanReset`, so nothing changes for it. |

**No combination above fails silently, with one documented caveat.** All five changes
are append-only and self-describing by payload length, so a mismatch either works,
degrades visibly (unreported width, disabled preview, unknown command, unknown
result) or is refused with an explicit `Result` + `reason` — never by returning
plausible-looking data that belongs to another structure. The caveat is row 1: a
**pre-release** PC build (one compiled from the repository before the field existed,
so it is not shipped with any console) meeting the 20-byte chain header cannot detect
the tail and would read the records four bytes early. The probe and the field shipped
together, so keep the console and the PC on the same release — every officially
packaged pair does that by construction.

Two rules keep the table true: never insert a field into an existing structure
(append it and let the length decide), and never turn a success into an error — or an
error into a success — merely because a field is missing.

---

## Key Features

### 1. High-Speed On-Console Memory Scanner (`core/nxus_scan.c`)
- **Data Types**: `u8`, `u16`, `u32`, `u64`, `i8..i64` (`--signed`), `f32`, `f64` (with `±Inf` and epsilon support), `utf8`, `utf16`, raw byte arrays with wildcards (`AA ?? BB`), and `All` multi-type scan.
- **Comparisons**: `Equal`, `NotEqual`, `Greater`, `Less`, `GreaterOrEqual`, `LessOrEqual`, `Between`, `FuzzyEqual`, `Increased`, `Decreased`, `Changed`, `Unchanged`, `Different`, and `Unknown` initial state.
- **Type-Specialized Fast Paths**: Constant-width unrolled inner loops for 1st-pass and refinement scans, chunk-boundary overlap tracking (zero missed cross-boundary patterns), automatic read-halving fallback down to `4 KiB` pages, and zero-allocation 1-step **Undo**.
- **Uncapped Unknown Initial Scan (Dense Baseline + Zero-Block Skip + 16 KiB Hash Skip)**:
  - Instead of pushing every address into the hit list on Pass 1 (which would truncate at 150k hits), `Unknown` scans use a **2-stage Dense Baseline → Lazy Hit Materialization** pipeline on both the Switch (`sdmc:/nxus/scan_base.bin` + RAM hybrid) and the PC (`pcscan.rs`).
  - **Zero-Block Compression**: All-zero 16 KiB blocks are flagged in metadata without writing to the SD card, cutting SD I/O by 50–80%.
  - **O(1) 16 KiB Block-Hash Skip**: On the 1st refinement (`Changed`, `Increased`, `Decreased`, `Different`), unchanged 16 KiB blocks are skipped in `O(1)` via 64-bit FNV-1a fingerprints without reading from SD or comparing individual elements, and only surviving hits are materialized into the hit list (dynamically scaled up to `341k` hits for `u8`, `307k` for `u16`, `256k` for `u32`).
- **Strict 8 MiB Sysmodule Heap Budget**: Structure-of-Arrays (SoA) hit storage + zero-copy TCP socket transmission (`nxus_net.c`) keeps the working set inside the 8 MiB inner heap (`INNER_HEAP_SIZE`, `switch/source/main.c:48`); the host budget test's worst case — both snapshot slots held — is `6.93 MiB` against the `8.00 MiB` ceiling. The resident request is what the NPDM declares: `system_resource_size=0`, so the loader reserves the NSO's `.bss` (`8.30 MiB` = the 8 MiB heap + statics) plus the `0x8000` (`32 KiB`) main-thread stack, `8.33 MiB` in total, inside the Switch `System` pool partition.
- **Incomplete results are never silent**: three independent limits can cut a result
  short, and each one is reported instead of being presented as complete —
  - hit list full → `NxusHitBatchHeader.reserved & NXUS_HITBATCH_TRUNCATED` on every
    hit reply (the client surfaces it as `truncated` / `last_scan_truncated`),
  - pointer scan stopped on `max_results` or on the read budget →
    `NxusPtrChainListHeader.truncated` (plus `reads_blocked` in the stats),
  - snapshot diff blocked by a block-size mismatch → an explicit `BAD_STATE`
    error instead of "0 blocks changed".

  A read that fails because the *budget* ran out is never cached as "unmapped":
  the difference between a fault and a skipped read decides whether a pointer
  path is ruled out, so it is kept distinct internally.

### 2. Multi-Core Kernel Hardware Debugger (Watchpoints & Breakpoints) (`switch/source/nxus_debug.c`)
- **Seamless `dmnt:cht` Hand-off**: Automatically calls `ForceCloseCheatProcess` before attaching via `svcDebugActiveProcess`, and restores `ForceOpenCheatProcess` on detach.
- **All-Core Hardware Register Programming**: Programs ARMv8 `DBGBCR_EL1` and `DBGWCR_EL1` across **all 4 CPU cores (Cores 0–3)** via `svcSetThreadCoreMask` migration (`setHardwareBreakPointAllCores`), ensuring hits are captured regardless of which core the game thread runs on.
- **AArch32 & AArch64 Hardware Support**:
  - **ContextID Breakpoint** in slot `5` (`ctrl = 0x003001E1`, `BT = 0b0011`, linked to target PID).
  - **Linked Execution Breakpoints** in slots `0..3` (`ctrl = 0x001501E1` for ARM32/AArch64, `0x00150061`/`0x00150181` for Thumb halfwords).
  - **Linked Hardware Watchpoints** (`Write`, `Read`, `Access`) in slots `0x10..0x13` with automatic 8-byte `DBGWVR_EL1` alignment (`address & ~7ULL`) and byte-lane `BAS` selection.
  - **AArch32 Register Mapping**: Automatically maps `R13 (SP)`, `R14 (LR)`, and `R11 (FP)` from `cpu_gprs[11/13/14]` when debugging 32-bit titles.
  - **Non-Stop Stepping**: Automatically performs *disarm → `svcContinueDebugEvent` → 1 ms instruction retirement sleep → re-arm* on hit so the target game does not freeze in an infinite re-trap loop.
- **GDB-Style Stop on Hit (default)**: A watchpoint/breakpoint hit now *holds* the target stopped instead of silently resuming it — like `(gdb) continue` / `(gdb) stepi`.
  - The console publishes `NxusEvent_DebugStopped` (thread id, PC, address, slot), sets `NXUS_ST_DEBUG_STOPPED`, and waits for an explicit resume.
  - **CLI**: `nxus continue` (step over the trapping instruction, re-arm, resume), `nxus step [thread_id]` (single instruction), and `nxus watch <addr> --stop` / `nxus break <addr> --stop` which prints `STOPPED thread=… pc=… (main+0x…)`, the surrounding disassembly and all registers. `nxus config --auto-continue 0|1` switches back to the old auto-resume policy at runtime.
  - **GUI**: a `■ STOPPED` badge plus a banner with **[Continue] [Step]**; on every stop the GUI automatically fetches the stopped thread's registers and disassembles the code around its PC (`=>` highlight).
  - **Real freeze / pause**: `nxus pause` suspends every thread of the title. The preferred path is `dmnt:cht`'s `PauseCheatProcess` (`BreakDebugProcess` on dmnt's own debug handle, cmdid `65004`), which keeps the cheat session open so reads, scans and snapshot diffs keep working against the frozen title. If dmnt cannot stop it, the console falls back to opening its own debug session (`svcDebugActiveProcess`) and issuing `svcBreakDebugProcess`; reads/queries/mapping enumeration automatically switch to that handle. `nxus resume` mirrors whichever path was used. The GUI's *"pause target while scanning"* option drives the same mechanism.
  - **Automatic `dmnt:cht` recovery**: when the cheat process has been dropped (`0x0032C80D`), every `dmnt:cht` command re-issues `ForceOpenCheatProcess` once and retries, so a dropped session no longer turns into a permanent error.
- **Per-session hit history**: the breakpoint/watchpoint ring behind `nxus hits` and the GUI **Watch** tab belongs to one debug session. `DebugAttach` and `DebugDetach` both wipe it (the log line is `debug: hit ring cleared (attach/detach)`) and bump an internal epoch, so a hit that was still being recorded when the session changed is dropped instead of becoming hit #0 of the next title. A freshly attached title therefore starts with an empty list, and a hit from the previous title can never be presented as this session's.
- **Recovery matrix (what heals itself, what needs a reboot)**:
  | Situation | Behaviour |
  |---|---|
  | PC closes the CLI mid-debug (stop banner, GUI) | The debug session is released when the connection drops; the target resumes. |
  | PC disappears while paused | The pause watchdog resumes the target (~15 s). |
  | PC disappears while addresses are frozen | Nxus remembers what it froze and **releases them 30 s after the client is gone** (otherwise only a reboot would stop `dmnt` writing them). The release is reported with `NxusEvent_FrozenReleased`, so a reconnecting client drops them from its list instead of showing stale values. |
  | PC disappears in the middle of a scan | The scan keeps running for a minute so a quick reconnect can still read it, then it is **cancelled automatically** (previously it held the worker and the SCANNING flag until the process restarted). |
  | Wi-Fi drops / console sleeps | The listener is rebuilt automatically, and a boot-time network failure is retried every 3 s instead of parking the module. |
  | Hit list fills up | The reply is flagged `NXUS_HITBATCH_TRUNCATED`; refine further or raise the limit. |
  | Pointer scan is huge | It now runs on a worker thread: `PtrScanBegin` answers immediately, the client polls `PtrScanGet` (250 ms) while the console keeps serving other commands, and the walk stops after 90 s returning the partial chains flagged as truncated. |
  | SD card missing or full | The module still starts and serves over TCP (RAM only); the log lives in the RAM ring, readable with `nxus log`. A stale `scan_base.bin` from a previous boot is deleted at startup. |
  | Something is genuinely stuck | Hold `POWER` to force-off, then boot hekate and remove `atmosphere/contents/4200000000004E58/flags/boot2.flag` to stop the module from starting. |
 The console refreshes the cached `pid` / `title id` / `main NSO base` from `dmnt:cht` at most once per second (and right after `forceopen`), and `nxus status` reports that cache, so the target identity no longer stays at zero after the game is (re)started.

### 3. GDB-Style Disassembler & Live Code Patcher (CLI + GUI)
- **Built-in Multi-Architecture Decoder (`protocol.rs`)**: Decodes **AArch64**, **AArch32 (ARM32)**, and **Thumb (T16 / T32)** instructions with zero external DLL dependencies.
- **Context View (`--around` & GUI `Disasm` Tab)**: Displays instructions before and after any target address or hitting `PC` with `=>` markers, `<main+0x...>` module offsets, and full register state (`PC`, `LR`, `SP`, `CPSR`, `R0..R12` / `X0..X28`).
- **Live RX Code Patching**: Write directly to executable `.text` (`RX`) pages via `svcWriteDebugProcessMemory` (which performs full-system instruction cache invalidation across all cores). Includes 1-click **[NOP]** patching in the GUI (`00 00 A0 E1` for ARM32, `00 BF` / `AF F3 00 80` for Thumb, `1F 20 03 D5` for AArch64).

### 4. Pointer Scanner, Cross-Tool Dump Compatibility (`Jnoexs` & `EdiZon-SE`), & Snapshot Diff
- **Console & Offline PC Pointer Scanner**: Discovers multi-level pointer chains with `O(log M)` binary-searched memory mappings, **8-way set-associative Dead-End Subtree Memoization (`dead_set`) + 64-slot direct-mapped dereference window cache** (**~26× fewer IPC reads** (host diamond-graph test: 100 duplicate dereferences collapse to 4 reads) on shared heap graphs with zero false negatives), automatic **32-bit (4-byte)** vs **64-bit (8-byte)** pointer width detection, and direct Atmosphère `dmnt:cht` cheat code generation.
- **Full Jnoexs (`NDMP`) & EdiZon-SE / PointerSearcher-SE (`EDZN` / `eFZN`) Dump Interoperability**:
  - **Jnoexs (`NDMP` `.dmp`)**: 100% byte-for-byte compatible with Jnoexs (`MemoryDump.java`) and Takumi4685's PointerSearcher.
  - **EdiZon-SE / PointerSearcher-SE (`EDZN` / `eFZN` / `FDZN` / `fFZN` `.dmp*`)**: Directly loads and decompresses (LZ8) EdiZon-SE pointer dumps (`nxus dump info <file>`, `nxus ptrscan auto --dump <file>`, or via the GUI **Scan dump...** button), and can export/convert any `NDMP` dump into a PointerSearcher-SE compatible `EDZN` dump (`nxus dump export-edizon <in.dmp> <out.dmp1> --target <ADDR>`).
- **Block Snapshot Diff (`core/nxus_snapshot.c`)**: Hashes memory in 16 KiB blocks (`Capture A` → `Capture B` → `Diff`) to locate changed structures without dumping gigabytes over the network.

---

## Release Packages & Installation

In the **[GitHub Releases](https://github.com/Nexy451z/Nxus-ox/releases)** page, you will find:

| File | Description |
|---|---|
| **`Nxus-ox-v0.1.0-alpha-atmosphere.zip`** | **Switch Sysmodule Package**. Extract directly to the root of your Switch SD card (`SD:/atmosphere/contents/4200000000004E58/exefs.nsp` + `flags/boot2.flag`). |
| **`Nxus-ox-v0.1.0-alpha-windows-x64.zip`** | **Windows x64 PC Client Bundle**. Contains `nxus.exe` (unified GUI + CLI executable), `nxus-gui.bat` launcher, and documentation. |
| **`nxus.exe`** | Standalone Windows x64 executable (identical to the binary inside the Windows zip). Runs **GUI mode** when launched without subcommands, or **CLI mode** when invoked with subcommands. |
| **`Nxus-ox-v0.1.0-alpha-probe-atmosphere.zip`** | *(Optional)* Hardware diagnostic probe sysmodule (`0x4200000000004E59`). It ships **no** `flags/boot2.flag`; enable it only for a probe run, never together with `nxus` (see [Measuring the Diagnostic Probe](#3-measuring-the-diagnostic-probe-optional)). |

### 1. Switch Setup (Atmosphère / hekate)
1. Extract **`Nxus-ox-v0.1.0-alpha-atmosphere.zip`** to the root of your SD card so that the following files exist:
   ```text
   SD:/atmosphere/contents/4200000000004E58/exefs.nsp
   SD:/atmosphere/contents/4200000000004E58/flags/boot2.flag
   SD:/atmosphere/contents/4200000000004E58/README.txt      (identification)
   SD:/atmosphere/contents/4200000000004E58/metadata.json   (identification)
   ```

   **What are `README.txt` / `metadata.json` for?** A custom sysmodule's NPDM carries
   a title id and nothing else, so tools that simply list SD contents (DBI, homebrew
   file managers) show a bare `4200000000004E58` with no idea what it belongs to.
   These two files make the folder self-describing — name, version, role, TCP port,
   repository and the "no warranty" note — for humans, other tools, and other agents
   reading the card. They are inert: Atmosphère only reads `exefs.nsp` and `flags/`,
   so removing them changes nothing functionally.
2. To use **Hardware Watchpoints / Breakpoints**, enable kernel debug mode in Atmosphère / hekate:
   - In `SD:/bootloader/hekate_ipl.ini`: add `debugmode=1` to your boot entry, **and/or**
   - In `SD:/atmosphere/config/system_settings.ini`: ensure Atmosphère debug mode is enabled.
3. Reboot your Switch into **emuMMC**, connect to the same LAN/Wi-Fi network as your PC, and check your Switch's IP address under **System Settings → Internet → IP Address** (referred to below as `<SWITCH_IP>`).

### 2. PC Client Usage (GUI & CLI)

`nxus.exe` is a **single unified executable** containing both the graphical interface and the command-line tool.

#### Specifying Your Switch IP Address (`<SWITCH_IP>`)
Because every network assigns a different local IP address to the Switch (e.g., `192.168.x.x` or `10.0.x.x`), you can specify it in any of three flexible ways:
1. **In the GUI**: Type your Switch IP into the top **`host`** input field and click **Reconnect**. The GUI automatically saves your IP address and restores it on future launches.
2. **Via Environment Variable (`NXUS_HOST`)**: Set `NXUS_HOST` once in your terminal session so you do not have to pass `--host` on every CLI command:
   ```powershell
   $env:NXUS_HOST = "<SWITCH_IP>"   # PowerShell (e.g. "192.168.0.50")
   ```
3. **Via Command-Line Flag**: Pass `--host <SWITCH_IP>` (and optionally `--port 7332`) to any CLI or GUI invocation.

#### Launching the GUI
- **Double-click `nxus.exe`** (or `nxus-gui.bat`), or launch from a terminal:
  ```powershell
  .\nxus.exe
  # or pass an initial IP address:
  .\nxus.exe --gui --host <SWITCH_IP>
  ```
- Tabs available in the GUI:
  - **Results**: Filter, sort, edit, freeze, or bookmark scan hits.
  - **Hex editor**: Live memory inspection and byte patching.
  - **Disasm**: GDB-style AArch64 / ARM32 / Thumb disassembler, live CPU register bar, **[At Current PC (Regs)]**, **[BP]** (set hardware execution breakpoint), and 1-click **[NOP]** instruction patching.
  - **Snapshot**: Block-level memory diffing (`Capture A` / `Capture B` / `Diff A->B`).
  - **Watch**: Address book / bookmarks and hardware watchpoint/breakpoint hit table (click **[Disasm PC]** on any hit to jump straight to the offending instruction in the Disasm tab).
  - **Info**: Target process metadata (`title_id`, `pid`, `main_base`, memory mappings).

#### Using the CLI
```powershell
# Set your Switch IP once per terminal session (or pass --host <SWITCH_IP> per command)
$env:NXUS_HOST = "<SWITCH_IP>"

# Check connection and target process metadata
nxus status
nxus metadata

# 1. Scan & Refine a 4-byte value (e.g., money = 6440 -> 3940)
nxus scan reset
nxus scan begin 6440 --size 4 --scope writable
nxus scan refine 3940 --cmp eq
nxus scan hits

# 2. Hardware Watchpoint (find which instruction writes to a target address)
#    Automatically prints GDB-style disassembly around the hitting PC and R0..R12/SP/LR/CPSR!
nxus watch <TARGET_ADDR> --kind write --size 4 --seconds 60 --keep

# 3. GDB-style Disassembly around an address or current thread PC
nxus disasm <CODE_ADDR> 16 --around --arm32
nxus disasm pc 16 --around

# 4. Hardware Execution Breakpoint
nxus break <CODE_ADDR> --seconds 30 --keep

# 5. Live Code Patching (e.g., overwrite an ARM32 store/sub instruction with NOP E1A00000)
nxus write <CODE_ADDR> "00 00 A0 E1"
nxus detach
```

### 3. Measuring the Diagnostic Probe (optional)

`Nxus-ox-v0.1.0-alpha-probe-atmosphere.zip` contains the optional diagnostic probe
(`0x4200000000004E59`). It opens **no TCP port** and appends its verdict to
`sdmc:/nxus/probe.txt`; the PC client is not involved. It must **never** run at the
same time as the main module: both take the single `dmnt:cht` cheat process, so the
probe would report a wrong verdict instead of "unavailable" (the probe folder ships
`DO_NOT_BOOT_TOGETHER.txt` with the same warning).

```text
The probe folder ships NO flags/boot2.flag by default.  The release zip
deliberately contains none, so the two modules cannot both boot by accident.
To measure the probe, move the main module's flag aside and create this folder's
flag by hand:

  1. rename the main module's flag (do not delete it):
       sdmc:/atmosphere/contents/4200000000004E58/flags/boot2.flag
         -> sdmc:/atmosphere/contents/4200000000004E58/flags/boot2.flag.off
  2. create an EMPTY file:
       sdmc:/atmosphere/contents/4200000000004E59/flags/boot2.flag
  3. boot/reboot the console and start a game within 30 s (boot2 modules only
     run on boot, and the probe waits at most 30 s for a title)
  4. wait for a new "===== Nxus probe run ..." block at the end of
     sdmc:/nxus/probe.txt (each run is appended, never truncated; past 512 KiB
     the previous block is rotated to sdmc:/nxus/probe.txt.1), then delete the
     probe flag again and rename the main module's flag back:
       sdmc:/atmosphere/contents/4200000000004E59/flags/boot2.flag   must not exist
       sdmc:/atmosphere/contents/4200000000004E58/flags/boot2.flag.off
         -> sdmc:/atmosphere/contents/4200000000004E58/flags/boot2.flag

tools/build.sh stages the same split automatically:
  NXUS_STAGE_PROBE=1 tools/build.sh   probe gets boot2.flag, nxus does not
  tools/build.sh                      nxus gets boot2.flag, probe does not
```

`sdmc:/nxus/probe_started.txt` is rewritten on every probe run (the previous file
becomes `probe_started.txt.1`), so it proves the sysmodule actually started. If the
preferred report path is not writable, the report falls back to `sdmc:/probe.txt`
and then `sdmc:/switch/probe.txt`, and the block records the path it used.

## Repository Structure

```text
Nxus-ox/
  core/       Portable, libnx-independent C core (wire protocol, scanner, pointer scanner, snapshots)
  shared/     Switch shared modules (dmnt:cht IPC wrapper, zero-copy TCP server, HID hotkey, logging)
  switch/     Main Switch sysmodule (Title ID: 0x4200000000004E58, kernel debugger in nxus_debug.c)
  probe/      Hardware diagnostic probe sysmodule (Title ID: 0x4200000000004E59)
  pc/
    Nxus.Cli/ Unified Rust PC client (eframe/egui GUI + CLI + AArch64/ARM32/Thumb disassembler)
    nxus/     Python reference client & synthetic MockSwitch server for automated E2E testing
    tests/    Cross-language protocol parity & end-to-end test suite (116 tests)
  tests/      Host C unit test suite (1,633 checks across 8 test binaries)
  tools/      Build scripts, NPDM single-bit debug capability patcher, and PFS0/NSP verifier
```

---

## Building from Source & Running Tests

### Prerequisites
- **Switch Sysmodule**: [devkitPro](https://devkitpro.org/) with `devkitA64` (`r29.2-1+`) and `libnx` (`4.12.0-1+`), plus Python 3.10+.
- **PC Client**: Rust toolchain (`cargo` / `rustc` 1.80+ for `x86_64-pc-windows-msvc`).

### Build Commands
```bash
# 1. Build Switch sysmodules (nxus & probe) + patch NPDM + verify exefs.nsp
bash tools/build.sh

# 2. Build Windows x64 PC client (GUI + CLI) -> dist/pc/nxus.exe
bash tools/build_pc.sh
```

### Automated Test Suites (No Hardware Required)
```bash
# 1. Host C Core Tests (1,633 checks / 8 binaries: scan 797, ptrscan 45, snapshot 75, budget 39, scantypes 275, hotkey 11, session_view 189, snapshot_owner 202)
cd tests && bash run_tests.sh

# 2. Rust Unit Tests (117 tests: expression evaluator, AArch64/ARM32/Thumb disassembler, dense pcscan, Jnoexs NDMP & EdiZon-SE EDZN/eFZN)
cd pc/Nxus.Cli && cargo test --release

# 3. Python + Rust CLI End-to-End Tests against MockSwitch (116 tests)
cd pc && python -m unittest discover -s tests
```
