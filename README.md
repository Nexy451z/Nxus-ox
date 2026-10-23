# Nxus-ox (`v0.1.0-alpha`)

**Nxus-ox** is a headless remote memory scanner, pointer chain analyzer, and multi-core kernel hardware debugger & disassembler for **Nintendo Switch (Atmosphère CFW)**, paired with a unified **Rust PC Client (GUI + CLI)**.

Instead of transferring multi-gigabyte raw RAM dumps over Wi-Fi for every search, Nxus-ox runs a lightweight C sysmodule directly on the Switch (`pool_partition: System`, `< 6 MiB` peak heap) that scans memory in 1 MiB chunks, coalesces sparse refinement windows, and streams compact hit lists and hardware debug events over TCP (default port `7332`).

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
- **Strict 8 MiB Sysmodule Heap Budget**: Structure-of-Arrays (SoA) hit storage + zero-copy TCP socket transmission (`nxus_net.c`) keeps peak RAM usage well within the Switch `System` pool partition.

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
  - **Automatic `dmnt:cht` recovery**: when the cheat process has been dropped (`0x0032C80D`), every `dmnt:cht` command re-issues `ForceOpenCheatProcess` once and retries, so a dropped session no longer turns into a permanent error. `nxus status` also refreshes `pid` / `title id` / `main NSO base` once per second (and right after `forceopen`), so the reported target identity no longer stays at zero after the game is (re)started.

### 3. GDB-Style Disassembler & Live Code Patcher (CLI + GUI)
- **Built-in Multi-Architecture Decoder (`protocol.rs`)**: Decodes **AArch64**, **AArch32 (ARM32)**, and **Thumb (T16 / T32)** instructions with zero external DLL dependencies.
- **Context View (`--around` & GUI `Disasm` Tab)**: Displays instructions before and after any target address or hitting `PC` with `=>` markers, `<main+0x...>` module offsets, and full register state (`PC`, `LR`, `SP`, `CPSR`, `R0..R12` / `X0..X28`).
- **Live RX Code Patching**: Write directly to executable `.text` (`RX`) pages via `svcWriteDebugProcessMemory` (which performs full-system instruction cache invalidation across all cores). Includes 1-click **[NOP]** patching in the GUI (`00 00 A0 E1` for ARM32, `00 BF` / `AF F3 00 80` for Thumb, `1F 20 03 D5` for AArch64).

### 4. Pointer Scanner, Cross-Tool Dump Compatibility (`Jnoexs` & `EdiZon-SE`), & Snapshot Diff
- **Console & Offline PC Pointer Scanner**: Discovers multi-level pointer chains with `O(log M)` binary-searched memory mappings, **8-way set-associative Dead-End Subtree Memoization (`dead_set`) + 64-slot direct-mapped dereference window cache** (up to **132× fewer IPC reads** on shared heap graphs with zero false negatives), automatic **32-bit (4-byte)** vs **64-bit (8-byte)** pointer width detection, and direct Atmosphère `dmnt:cht` cheat code generation.
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
| **`Nxus-ox-v0.1.0-alpha-probe-atmosphere.zip`** | *(Optional)* Hardware diagnostic probe sysmodule (`0x4200000000004E59`). Do **not** enable `boot2.flag` on both `nxus` and `probe` simultaneously. |

### 1. Switch Setup (Atmosphère / hekate)
1. Extract **`Nxus-ox-v0.1.0-alpha-atmosphere.zip`** to the root of your SD card so that the following files exist:
   ```text
   SD:/atmosphere/contents/4200000000004E58/exefs.nsp
   SD:/atmosphere/contents/4200000000004E58/flags/boot2.flag
   ```
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
    tests/    Cross-language protocol parity & end-to-end test suite (75 tests)
  tests/      Host C unit test suite (1,010 assertions across 5 test binaries)
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
# 1. Host C Core Tests (1,083 checks: scanner, dense baseline, fast paths, chunk boundaries, ptrscan memoization, snapshot, hotkey)
cd tests && bash run_tests.sh

# 2. Rust Unit Tests (42 tests: expression evaluator, AArch64/ARM32/Thumb disassembler, dense pcscan, Jnoexs NDMP & EdiZon-SE EDZN/eFZN)
cd pc/Nxus.Cli && cargo test --release

# 3. Python + Rust CLI End-to-End Tests against MockSwitch (75 tests)
cd pc && python -m unittest discover -s tests
```
