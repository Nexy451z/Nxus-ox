//! nxus command line interface.
//!
//! Same protocol as the GUI; useful for scripting and for quick checks.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::client::{NxusClient, NxusError, ScanSpec};
use crate::protocol::*;

type Result<T> = std::result::Result<T, NxusError>;

const USAGE: &str = "nxus - PC client for the Nxus Switch sysmodule

usage: nxus [--host HOST] [--port PORT] <command> [args]

session
  status                          show the sysmodule / target status
  metadata                        process id, module base, build id
  modules                         list detected modules
  mappings [--count N]            list target memory mappings
  log                             dump the sysmodule log ring
  pause | resume                  freeze / unfreeze the target
  config [--hotkey COMBO] [--hold MS] [--watchdog MS] [--chunk N]
         [--watch-style N] [--auto-continue 0|1]
                                  set the controller hotkey (COMBO: plus, L+PLUS, off) and
                                  the debug policy (auto-continue 0 = a breakpoint hit
                                  holds the target)
  events [--seconds N] [--count N] listen for Switch-initiated events
  pids | processes                list running process IDs on the console
  attach [--pid PID]              attach kernel debugger (default: current game)
  detach                          leave debug mode (if attached)
  continue                        resume a target the console is holding (after --stop)
  step [thread_id]                single-step the held thread, then show its registers
                                  and the code at the new pc
  forceopen                       re-open dmnt's cheat process (recovery: only needed
                                  if it is stuck closed - normally detach restores it)
  threads                         list threads of the attached process
  regs [thread_id] [--set K=V]    show or modify 64-bit/32-bit CPU registers (x0..x28, r0..r12, pc, lr, sp, fp)
  disasm <address|pc> [count] [--arm32|--thumb] [--around]
                                  disassemble instructions at an address, or at the
                                  current pc (pc: first thread's pc, mode detected from
                                  CPSR).  --around marks that instruction with '=>' and
                                  appends its main+offset (GDB style)

memory
  read <address> <size>           hex dump
  write <address> <spec>          spec: hex bytes, u32:V, u64:V, i32:V
  dump <file.dmp> [--scope S]     save jnoexs-compatible NDMP RAM dump (default: writable)
  dump info <file>                inspect an NDMP or EdiZon-SE (EDZN/eFZN) dump offline
  dump export-edizon <in.dmp> <out.dmp> --target <address>
                                  convert an NDMP dump into a PointerSearcher-SE EDZN dump
  freeze <address> --width N      server-side freeze (no PC polling)
  unfreeze <address>

scanning
  scan begin <value|text|bytes> [--type VALUE-TYPE] [--cmp SCAN-TYPE] [--scope S]
                                  [--size N] [--hex] [--to VALUE] [--aligned]
                                  [--ignore-case] [--utf16]
                                  S: all main heap writable tls custom ranges
                                  --scope custom --range 0xA..0xB          (one range)
                                  --scope ranges --range 0xA..0xB,0xC..0xD (several at once)
                                  VALUE-TYPE: u8 u16 u32 u64 f32 f64 str bytes binary all
                                  SCAN-TYPE : equal not-equal greater less ge le between unknown
                                              increased decreased changed unchanged different fuzzy
                                              (fuzzy: within 10^-2 unless --to gives the epsilon)
  scan refine [value] [--cmp SCAN-TYPE] [--type VALUE-TYPE] [--to VALUE]
                 e.g. scan begin 12.5 --type f32
                      scan begin 'MASTER BALL' --type str
                      scan begin 'DE AD ?? EF' --type bytes
                      scan begin 100 --cmp between --to 200
  scan hits [--limit N] [--csv FILE]
  scan status | cancel | reset | undo [--load FILE] [--save FILE]
  scan unknown --size 4 [--scope main|custom] [--range A..B] [--max N] [--save FILE]
                 PC-side unknown-value scan: the candidate list lives in PC memory,
                 so the console's small heap is not a limit. Then:
  scan refine --cmp decreased [--load FILE] [--save FILE] [--limit N]
                 (with --load it refines the PC-side list, otherwise the console one)

snapshots (dump-free diffing)
  snapshot capture --slot a|b [--scope all] [--block 16384]
  snapshot diff [--from a] [--to b]
  snapshot changed [--limit N] [--csv FILE]

analysis
  ptrscan <address|auto> [--depth 3] [--max-offset 0x1000] [--module BASE] [--width 4]
                    [--pc] [--dump FILE] [--save-dump FILE] [--cheat-value N]
                    auto (or no address) with --dump FILE uses the target saved in
                    an EdiZon-SE (EDZN/eFZN) dump
  cheat <index> --value N [--width 4] [--64bit] [--out FILE]
  watch <address> [--kind write|read|exec|access] [--size 4] [--slot 0x10]
                  [--count N] [--seconds N] [--keep] [--stop]
                  on every hit: pc / lr / sp / r0-r3, then a disassembly window
                  around the pc (the hit instruction is marked with '=>') and the
                  whole 32-bit register set.
                  --stop holds the target on the hit (auto-continue 0): prints
                  STOPPED thread=... pc=... (main+0x...) with the code around the
                  pc and every register; 'nxus continue' resumes, 'nxus step' steps.
                  A stopped target is never left behind: without --keep nxus
                  detaches as soon as the last hit is printed (the game runs
                  again, armed breakpoints cleared); with --keep the session stays
                  alive, heartbeating, until --seconds expires and is then detached
                  too.  Arming only changes the debug settings: the controller
                  hotkey / watchdog applied from the GUI are left untouched.
  break <address> [--size 4] [--seconds S] [--keep] [--stop]
                  execute breakpoint (same as watch --kind exec), same hit context

addresses accept 0xHEX, decimal, bare hex, or expressions (e.g. main+0x80000+0x1000, (heap+0x1DC0)+4)
";

struct Opts {
    host: String,
    port: u16,
    positional: Vec<String>,
    flags: HashMap<String, String>,
}

impl Opts {
    fn parse(args: &[String]) -> Opts {
        let default_host = std::env::var("NXUS_HOST")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "127.0.0.1".into());
        let default_port = std::env::var("NXUS_PORT")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(DEFAULT_PORT);
        let mut opts = Opts {
            host: default_host,
            port: default_port,
            positional: Vec::new(),
            flags: HashMap::new(),
        };
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            if let Some(name) = arg.strip_prefix("--") {
                let (key, inline) = match name.split_once('=') {
                    Some((k, v)) => (k.to_string(), Some(v.to_string())),
                    None => (name.to_string(), None),
                };
                let value = match inline {
                    Some(v) => v,
                    None => {
                        let next = args.get(i + 1);
                        match next {
                            Some(v) if !v.starts_with("--") => {
                                i += 1;
                                v.clone()
                            }
                            _ => "true".to_string(),
                        }
                    }
                };
                match key.as_str() {
                    "host" => opts.host = value,
                    "port" => opts.port = value.parse().unwrap_or(DEFAULT_PORT),
                    _ => {
                        opts.flags.insert(key, value);
                    }
                }
            } else {
                opts.positional.push(arg.clone());
            }
            i += 1;
        }
        opts
    }

    fn flag(&self, name: &str) -> Option<&String> {
        self.flags.get(name)
    }

    fn num(&self, name: &str) -> Option<u64> {
        self.flags.get(name).and_then(|v| parse_number(v).ok())
    }

    fn has(&self, name: &str) -> bool {
        self.flags.contains_key(name)
    }
}

fn parse_number(text: &str) -> Result<u64> {
    let t = text.trim();
    let parsed = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(&hex.replace('_', ""), 16)
    } else {
        t.replace('_', "").parse::<u64>()
    };
    parsed.map_err(|_| NxusError { message: format!("not a number: {}", text), result: None })
}

fn parse_address(client: &NxusClient, text: &str) -> Result<u64> {
    let lower = text.to_ascii_lowercase();
    let (main_base, heap_base) = if lower.contains("main") || lower.contains("heap") {
        let md = client.metadata()?;
        (md.main_base, md.heap_base)
    } else {
        (0, 0)
    };
    if lower.contains("main") && main_base == 0 {
        return Err(NxusError {
            message: "main base is unknown (attach already reset it, or no scan/metadata was read yet): scan once without --debug, or attach without --pid".into(),
            result: None,
        });
    }
    if lower.contains("heap") && heap_base == 0 {
        return Err(NxusError {
            message: "heap base is unknown: read the metadata first (nxus metadata)".into(),
            result: None,
        });
    }
    if let Some(value) = eval_expr(text, main_base, heap_base) {
        return Ok(value);
    }
    Err(NxusError { message: format!("not an address: {}", text), result: None })
}

fn hexdump(data: &[u8], base: u64) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let address = base + (i * 16) as u64;
        let mut hex = String::new();
        let mut ascii = String::new();
        for (j, byte) in chunk.iter().enumerate() {
            hex.push_str(&format!("{:02x} ", byte));
            if j == 7 {
                hex.push(' ');
            }
            ascii.push(if *byte >= 32 && *byte < 127 { *byte as char } else { '.' });
        }
        println!("{:08x}  {:<49} |{}|", address, hex, ascii);
    }
}

pub fn run(args: &[String]) -> i32 {
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
        print!("{}", USAGE);
        return 0;
    }

    let opts = Opts::parse(args);
    match execute(&opts) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {}", e);
            1
        }
    }
}

fn execute(opts: &Opts) -> Result<()> {
    let command = opts.positional.first().map(|s| s.as_str()).unwrap_or("");

    // Offline commands that operate purely on a dump file on disk:
    if command == "dump" && opts.positional.get(1).map(|s| s.as_str()) == Some("info") {
        let path = opts.positional.get(2).ok_or_else(|| usage("dump info <file>"))?;
        if crate::edizon::is_edizon_file(path) {
            let dump = crate::edizon::EdizonDump::load(path)
                .map_err(|e| NxusError { message: e.to_string(), result: None })?;
            println!("format       : EdiZon-SE / PointerSearcher-SE (EDZN/eFZN)");
            println!("magic        : {:08X} ({})", dump.magic,
                     if dump.compressed { "LZ8 compressed" } else { "uncompressed" });
            println!("main         : {:08X} .. {:08X} ({} bytes)",
                     dump.main_base, dump.main_end,
                     dump.main_end.saturating_sub(dump.main_base));
            println!("heap         : {:08X} .. {:08X} ({} bytes)",
                     dump.heap_base, dump.heap_end,
                     dump.heap_end.saturating_sub(dump.heap_base));
            println!("target       : {:08X}", dump.target);
            println!("pairs        : {}", dump.pairs.len());
            return Ok(());
        }
        let dump = crate::dump::MemoryDump::load(path)
            .map_err(|e| NxusError { message: e.to_string(), result: None })?;
        let (main_base, main_size) = dump.infer_main_module();
        println!("format       : NDMP");
        println!("title id     : {:016X}", dump.tid);
        println!("main module  : {:08X} + {:X}", main_base, main_size);
        println!("mappings     : {}", dump.infos.len());
        println!("dumped blocks: {} ({} bytes)", dump.indices.len(), dump.total_bytes());
        for idx in dump.indices.iter().take(16) {
            println!("  {:08X} .. {:08X}  ({} bytes @ file+{:#x})",
                     idx.addr, idx.addr + idx.size, idx.size, idx.file_pos);
        }
        return Ok(());
    }
    if command == "dump" && opts.positional.get(1).map(|s| s.as_str()) == Some("export-edizon") {
        let usage_text = "dump export-edizon <in.dmp> <out.dmp> --target <address>";
        let in_path = opts.positional.get(2).ok_or_else(|| usage(usage_text))?;
        let out_path = opts.positional.get(3).ok_or_else(|| usage(usage_text))?;
        let target = opts.num("target").ok_or_else(|| usage(usage_text))?;
        let dump = crate::dump::MemoryDump::load(in_path)
            .map_err(|e| NxusError { message: e.to_string(), result: None })?;
        let pairs = crate::edizon::export_ndmp_to_edizon(&dump, target, None, None, out_path)
            .map_err(|e| NxusError { message: e.to_string(), result: None })?;
        println!("wrote EdiZon-SE pointer dump to {} ({} pairs, target {:08X})",
                 out_path, pairs, target);
        return Ok(());
    }
    if command == "ptrscan" {
        if let Some(dump_path) = opts.flag("dump") {
            let depth = opts.num("depth").unwrap_or(3) as u32;
            let max_offset = opts.num("max-offset").unwrap_or(0x1000) as u32;
            let max_results = opts.num("max").unwrap_or(64) as usize;
            let cancel = std::sync::atomic::AtomicBool::new(false);

            if crate::edizon::is_edizon_file(dump_path) {
                let dump = crate::edizon::EdizonDump::load(dump_path)
                    .map_err(|e| NxusError { message: e.to_string(), result: None })?;
                let module_base = opts.num("module").unwrap_or(dump.main_base);
                let raw_addr = opts.positional.get(1).map(|s| s.as_str()).unwrap_or("auto");
                let target = if raw_addr.eq_ignore_ascii_case("auto") {
                    dump.target
                } else if let Some(rest) = raw_addr.strip_prefix("main+") {
                    module_base + parse_number(rest)?
                } else {
                    parse_number(raw_addr).or_else(|_| {
                        let bare = raw_addr.trim().replace('_', "");
                        u64::from_str_radix(&bare, 16)
                            .map_err(|_| NxusError { message: format!("not an address: {}", raw_addr), result: None })
                    })?
                };
                let width = opts.num("width").unwrap_or(8) as u32;
                let res = crate::edizon::ptrscan_edizon(
                    &dump,
                    &crate::dump::PtrScanOptions {
                        target,
                        module_base,
                        module_size: dump.main_end.saturating_sub(dump.main_base),
                        max_depth: depth,
                        max_offset,
                        width,
                        max_results,
                    },
                    &cancel,
                );
                print_ptrscan_chains(&res.chains, res.truncated, "EdiZon dump", opts)?;
                return Ok(());
            }

            let dump = crate::dump::MemoryDump::load(dump_path)
                .map_err(|e| NxusError { message: e.to_string(), result: None })?;
            let (inferred_base, inferred_size) = dump.infer_main_module();
            let module_base = opts.num("module").unwrap_or(inferred_base);
            let raw_addr = opts.positional.get(1).ok_or_else(|| usage("ptrscan <address> --dump <file.dmp>"))?;
            let target = if let Some(rest) = raw_addr.strip_prefix("main+") {
                module_base + parse_number(rest)?
            } else {
                parse_number(raw_addr).or_else(|_| {
                    let bare = raw_addr.trim().replace('_', "");
                    u64::from_str_radix(&bare, 16)
                        .map_err(|_| NxusError { message: format!("not an address: {}", raw_addr), result: None })
                })?
            };
            let width = opts.num("width").unwrap_or(4) as u32;
            let res = crate::dump::ptrscan_dump(
                &dump,
                &crate::dump::PtrScanOptions {
                    target,
                    module_base,
                    module_size: inferred_size,
                    max_depth: depth,
                    max_offset,
                    width,
                    max_results,
                },
                &cancel,
            );
            print_ptrscan_chains(&res.chains, res.truncated, "PC dump", opts)?;
            return Ok(());
        }
    }

    let client = NxusClient::connect(&opts.host, opts.port)?;
    // One status round trip teaches the client the console's largest read (the
    // scan/chunk paths would otherwise stay at the conservative 64 KB default).
    let _ = client.status();

    match command {
        "status" => {
            let st = client.status()?;
            println!("proto        : v{}", st.proto_version);
            println!("target       : {:016X} (pid {})", st.program_id, st.process_id);
            println!("main         : {:08X} + {:X}", st.main_base, st.main_size);
            println!("process      : {}", if st.has_process() { "attached" } else { "none" });
            println!("paused       : {}", st.paused());
            // A --stop breakpoint hit leaves the target held: say so, and name the
            // thread (the status flags only carry the fact, NxusDebugStatus the id).
            if st.debug_stopped() {
                match client.debug_status().ok().and_then(|dbg| dbg.stopped_thread()) {
                    Some(tid) => println!("debug        : stopped (thread=0x{:X})", tid),
                    None => println!("debug        : stopped"),
                }
            } else if st.debug_attached() {
                println!("debug        : attached");
            }
            println!("scan         : {} ({} hits, {} permille)", scan_state_name(st.scan_state),
                     st.hit_count, st.progress_permille);
            println!("uptime       : {} ms", st.uptime_ms);
            if st.max_read > 0 {
                println!("read limit   : {} bytes", st.max_read);
            }
            if st.heap_total > 0 {
                println!("heap         : {} / {} bytes used", st.heap_used, st.heap_total);
            }
        }

        "metadata" => {
            let md = client.metadata()?;
            println!("pid          : {}", md.process_id);
            println!("title id     : {:016X}", md.program_id);
            println!("main nso     : {:08X} + {:X}", md.main_base, md.main_size);
            println!("heap         : {:08X} + {:X}", md.heap_base, md.heap_size);
            println!("alias        : {:08X} + {:X}", md.alias_base, md.alias_size);
            println!("aslr         : {:08X} + {:X}", md.aslr_base, md.aslr_size);
            println!("build id     : {}", md.build_id_hex());
        }

        "modules" => {
            let modules = client.modules()?;
            if modules.is_empty() {
                println!("(no modules detected - is a game running?)");
            }
            for m in modules {
                println!("{:08X} + {:<10X} {}", m.base, m.size, m.build_id);
            }
        }

        "mappings" => {
            let count = opts.num("count").unwrap_or(64) as u32;
            let maps = client.mappings(0, count)?;
            for m in maps {
                println!("{:08X} + {:<10X} {} type={}", m.base, m.size, m.perms(), m.memory_type);
            }
        }

        "log" => {
            print!("{}", client.log()?);
        }

        "pause" => {
            client.pause()?;
            println!("paused");
        }

        "resume" => {
            client.resume()?;
            println!("resumed");
        }

        "pids" | "processes" => {
            let pids = client.processes()?;
            for pid in &pids {
                println!("pid {} (0x{:X})", pid, pid);
            }
            println!("({} process(es))", pids.len());
        }

        "attach" => {
            let pid = opts.num("pid")
                .or_else(|| opts.positional.get(1).and_then(|s| parse_number(s).ok()))
                .unwrap_or(0);
            let st = client.debug_attach_pid(pid)?;
            println!("debug mode: attached={} watch_style={} breaks={} threads={}",
                     st.attached, st.watch_style, st.break_count, st.thread_count);
        }

        "detach" => {
            client.debug_detach()?;
            println!("detached (dmnt restored)");
        }

        // Resume a target that `watch/break --stop` left held at a breakpoint.
        "continue" => {
            client.debug_continue()?;
            println!("resumed");
        }

        // One instruction at a time.  The console holds the thread afterwards, so
        // show the same context a --stop hit shows: where we are and what changed.
        "step" => {
            let requested = match opts.positional.get(1) {
                Some(raw) => parse_number(raw)?,
                None => 0,
            };
            client.debug_step(requested)?;
            println!("stepped");
            let thread_id = if requested != 0 {
                Some(requested)
            } else {
                client.debug_stopped_thread().unwrap_or(None)
            }
            .or_else(|| client.thread_list().ok().and_then(|t| t.first().map(|t| t.thread_id)));
            if let Some(tid) = thread_id {
                let main_base = client.status().map(|st| st.main_base).unwrap_or(0);
                match client.regs_get(tid) {
                    Ok(ctx) => {
                        println!("thread 0x{:X}:", ctx.thread_id);
                        print_stopped_context(&client, &ctx, main_base);
                    }
                    Err(e) => eprintln!("warning: cannot read the registers of thread 0x{:X}: {}", tid, e),
                }
            }
        }

        // dmnt can be left closed (e.g. the console rebooted with a stale debugger, or a
        // crash skipped the detach): this is the only way back without a reboot.
        "forceopen" => {
            client.force_open()?;
            println!("dmnt cheat process opened");
        }

        "threads" => {
            let threads = client.thread_list()?;
            for t in &threads {
                println!("thread 0x{:X} ({})  state={} prio=0x{:X} core={}",
                         t.thread_id, t.thread_id, t.state, t.priority, t.core);
            }
            println!("({} thread(s))", threads.len());
        }

        "regs" => {
            let tid = match opts.positional.get(1) {
                Some(raw) => parse_number(raw)?,
                None => {
                    let threads = client.thread_list()?;
                    threads.first().map(|t| t.thread_id)
                        .ok_or_else(|| usage("regs <thread_id> (no threads reported)"))?
                }
            };
            let mut ctx = client.regs_get(tid)?;
            if let Some(assign) = opts.flag("set") {
                for pair in assign.split(',') {
                    let (k, v) = pair.split_once('=').ok_or_else(|| usage("regs <tid> --set x0=0x1234"))?;
                    let val = parse_number(v.trim())?;
                    let reg = k.trim().to_ascii_lowercase();
                    match reg.as_str() {
                        "pc" => ctx.pc = val,
                        "lr" | "x30" => ctx.lr = val,
                        "sp" => ctx.sp = val,
                        "fp" | "x29" => ctx.fp = val,
                        "cpsr" | "psr" => ctx.cpsr = val as u32,
                        _ if reg.starts_with('x') => {
                            let idx: usize = reg[1..].parse().map_err(|_| usage("x0..x28"))?;
                            if idx >= 29 { return Err(usage("x0..x28")); }
                            ctx.x[idx] = val;
                            if idx < 13 { ctx.r[idx] = (val & 0xFFFF_FFFF) as u32; }
                        }
                        _ if reg.starts_with('w') || reg.starts_with('r') => {
                            let idx: usize = reg[1..].parse().map_err(|_| usage("r0..r12 / w0..w28"))?;
                            if idx >= 29 { return Err(usage("w0..w28")); }
                            ctx.x[idx] = (ctx.x[idx] & !0xFFFF_FFFF) | (val & 0xFFFF_FFFF);
                            if idx < 13 { ctx.r[idx] = (val & 0xFFFF_FFFF) as u32; }
                        }
                        _ => return Err(usage("register name: x0..x28, r0..r12, pc, lr, sp, fp, cpsr")),
                    }
                }
                client.regs_set(&ctx)?;
                ctx = client.regs_get(tid)?;
            }
            println!("thread 0x{:X}:", ctx.thread_id);
            println!("  pc = {:016X}  lr = {:016X}  sp = {:016X}  fp = {:016X}  cpsr = {:08X}",
                     ctx.pc, ctx.lr, ctx.sp, ctx.fp, ctx.cpsr);
            for row in (0..29).step_by(4) {
                let mut line = String::from(" ");
                for i in row..(row + 4).min(29) {
                    line.push_str(&format!(" x{:<2} = {:016X}", i, ctx.x[i]));
                }
                println!("{}", line);
            }
        }

        "disasm" => {
            let raw = opts.positional.get(1).ok_or_else(|| usage("disasm <address|pc> [count]"))?;
            let count = opts.positional.get(2)
                .and_then(|s| parse_number(s).ok())
                .or_else(|| opts.num("count"))
                .unwrap_or(8) as u32;
            let around = opts.has("around");
            let explicit = if opts.has("thumb") {
                Some(DisasmMode::Thumb)
            } else if opts.has("arm32") || opts.has("32bit") || opts.has("arm") {
                Some(DisasmMode::Arm32)
            } else {
                None
            };
            // "pc" makes the CPU itself the target: the first reported thread supplies
            // both the address and, through its CPSR, the execution state.
            let key = raw.trim().to_ascii_lowercase();
            let (address, mode) = if key == "pc" || key == "$pc" || key == "regs.pc" {
                let threads = client.thread_list()?;
                let tid = threads.first().map(|t| t.thread_id).ok_or_else(|| {
                    usage("disasm pc (the console reports no threads - attach first)")
                })?;
                let ctx = client.regs_get(tid)?;
                let mode = explicit.unwrap_or_else(|| resolve_mode(&client, ctx.pc, ctx.cpsr));
                println!("pc = {:016X}  (thread 0x{:X}, {})", ctx.pc, ctx.thread_id, mode.label());
                (ctx.pc, mode)
            } else {
                (parse_address(&client, raw)?, explicit.unwrap_or(DisasmMode::Arm64))
            };
            let main_base = if around {
                client.metadata().map(|m| m.main_base).unwrap_or(0)
            } else {
                0
            };
            print_disassembly(&client, address, count, mode, around, main_base)?;
        }

        "read" => {
            let address = parse_address(&client, opts.positional.get(1).ok_or_else(|| usage("read <address> <size>"))?)?;
            let size = parse_number(opts.positional.get(2).ok_or_else(|| usage("read <address> <size>"))?)? as u32;
            let data = client.read(address, size)?;
            if data.len() < size as usize {
                // dmnt may accept only part of a read; say so instead of letting
                // the caller believe the region simply ends there
                eprintln!("warning: asked for {} byte(s), got {} (the console may cap a single read)",
                          size, data.len());
            }
            if let Some(path) = opts.flag("out") {
                std::fs::write(path, &data).map_err(|e| NxusError { message: e.to_string(), result: None })?;
                println!("wrote {} bytes to {}", data.len(), path);
            } else {
                hexdump(&data, address);
            }
        }

        "write" => {
            let address = parse_address(&client, opts.positional.get(1).ok_or_else(|| usage("write <address> <spec>"))?)?;
            let spec = opts.positional.get(2).ok_or_else(|| usage("write <address> <spec>"))?;
            let data = encode_write(spec)?;
            client.write(address, &data)?;
            println!("wrote {} byte(s) to {:08X}", data.len(), address);
        }

        "freeze" => {
            let address = parse_address(&client, opts.positional.get(1).ok_or_else(|| usage("freeze <address> --width N"))?)?;
            let width = opts.num("width").unwrap_or(4);
            let value = client.frozen_enable(address, width as u32)?;
            println!("freezing {:08X} (width {}), current value {}", address, width, value);
        }

        "unfreeze" => {
            let address = parse_address(&client, opts.positional.get(1).ok_or_else(|| usage("unfreeze <address>"))?)?;
            client.frozen_disable(address)?;
            println!("unfrozen {:08X}", address);
        }

        "config" => {
            let (mask, enabled) = match opts.flag("hotkey").map(|s| s.as_str()) {
                Some("off") | Some("none") | Some("0") => (0u64, 0u32),
                Some(combo) => (parse_combo(combo)?, 1u32),
                None => (0u64, 0u32),
            };
            let hold = opts.num("hold").unwrap_or(500) as u32;
            let watchdog = opts.num("watchdog").unwrap_or(15000) as u32;
            let chunk = opts.num("chunk").unwrap_or(0) as u32;
            let debug = match (opts.num("watch-style"), opts.num("auto-continue")) {
                (None, None) => None,
                (style, auto_continue) => Some((
                    style.unwrap_or(WATCH_STYLE_LINK5 as u64) as u32,
                    auto_continue.unwrap_or(1) as u32,
                )),
            };

            let body = client.set_config(mask, hold, enabled, chunk, watchdog, 5000, 1, debug)?;
            if body.len() >= 32 {
                println!("hotkey mask  : 0x{:X}{}", rd_u64(&body, 0),
                         if enabled == 0 { " (disabled)" } else { "" });
                println!("hotkey hold  : {} ms", rd_u32(&body, 8));
                println!("chunk size   : {} bytes", rd_u32(&body, 16));
                println!("watchdog     : {} ms", rd_u32(&body, 20));
            }
            if let Some(dbg) = debug {
                println!("debug config : watch style {} / auto-continue {}", dbg.0, dbg.1);
            }
            if enabled != 0 {
                println!("the hotkey now pauses the target from the controller");
            }
        }

        "events" => {
            let seconds = opts.num("seconds").unwrap_or(30);
            let want = opts.num("count").unwrap_or(0) as usize;
            let deadline = Instant::now() + Duration::from_secs(seconds);
            let start = Instant::now();
            let mut seen = 0usize;
            println!("listening for events ({}s) ...", seconds);
            while Instant::now() < deadline {
                if let Some(ev) = client.poll_event(Duration::from_millis(200)) {
                    let at = start.elapsed().as_secs_f32();
                    match ev.kind {
                        event::BREAK_HIT if ev.payload.len() >= BreakHit::SIZE => {
                            let hit = BreakHit::parse(&ev.payload);
                            println!("[{:6.2}s] break hit: {} to {:08X} pc={:08X}",
                                     at, break_kind_name(hit.kind), hit.address, hit.pc);
                        }
                        event::HOTKEY_PAUSED => println!("[{:6.2}s] hotkey: target paused", at),
                        event::AUTO_RESUME => println!("[{:6.2}s] watchdog: target auto-resumed", at),
                        event::DEBUG_STOPPED if ev.payload.len() >= DebugStop::SIZE => {
                            let stop = DebugStop::parse(&ev.payload);
                            println!("[{:6.2}s] stopped: thread=0x{:X} pc={:08X} ({} to {:08X})",
                                     at, stop.thread_id, stop.pc,
                                     break_kind_name(stop.kind), stop.address);
                        }
                        event::SCAN_PROGRESS => println!("[{:6.2}s] scan progress", at),
                        event::PROCESS_EVENT => println!("[{:6.2}s] process event", at),
                        other => println!("[{:6.2}s] event 0x{:04X} ({} bytes)", at, other, ev.payload.len()),
                    }
                    seen += 1;
                    if want > 0 && seen >= want {
                        break;
                    }
                }
            }
            println!("({} event(s))", seen);
        }

        "scan" => {
            let sub = opts.positional.get(1).map(|s| s.as_str()).unwrap_or("status");
            match sub {
                "begin" => {
                    let text = opts.positional.get(2).ok_or_else(|| usage("scan begin <value>"))?;
                    let spec = build_spec(opts, text, false)?;
                    client.scan_begin_spec(&spec)?;
                    let st = client.scan_wait(Duration::from_secs(900))?;
                    println!("first scan {} : {} hits ({} type)",
                             scan_state_name(st.scan_state), st.hit_count, spec.value_type.name());
                    print_scan_stats(&client);
                    print_scan_failure(&st);
                }
                "refine" => {
                    let compare = opts.flag("cmp").and_then(|c| Compare::parse(c)).unwrap_or(Compare::Decreased);
                    // --load switches to the PC-side candidate list
                    if let Some(path) = opts.flag("load") {
                        let mut scan = crate::pcscan::load(path)
                            .map_err(|e| NxusError { message: e.to_string(), result: None })?;
                        let bak_base = opts.flag("save").unwrap_or(path);
                        let _ = crate::pcscan::save(&format!("{}.bak", bak_base), &scan);
                        let target = opts.num("value")
                            .or_else(|| opts.positional.get(2).and_then(|s| parse_number(s).ok()))
                            .unwrap_or(0);
                        let target2 = opts.num("to").unwrap_or(0);
                        let flags = if matches!(compare, Compare::FuzzyEqual) { SCAN_F_FLOAT } else { 0 };
                        let cancel = std::sync::atomic::AtomicBool::new(false);
                        crate::pcscan::refine(&client, &mut scan, compare, target, target2, flags,
                                              &cancel, &mut |_, _| {})
                            .map_err(|e| NxusError { message: e, result: None })?;
                        println!("next scan: {} candidate(s)", scan.len());
                        let limit = opts.num("limit").unwrap_or(16) as usize;
                        for hit in scan.hits_page(0, limit) {
                            println!("{:08X}  {}", hit.address, hit.value);
                        }
                        if let Some(path) = opts.flag("save") {
                            crate::pcscan::save(path, &scan)
                                .map_err(|e| NxusError { message: e.to_string(), result: None })?;
                            println!("saved {}", path);
                        }
                        return Ok(());
                    }
                    let text = opts.positional.get(2).map(|s| s.as_str()).unwrap_or("");
                    let spec = build_spec(opts, text, true)?;
                    client.scan_next_spec(&spec)?;
                    let st = client.scan_wait(Duration::from_secs(900))?;
                    println!("next scan {} : {} hits", scan_state_name(st.scan_state), st.hit_count);
                    print_scan_stats(&client);
                    print_scan_failure(&st);
                }
                "hits" => {
                    let limit = opts.num("limit").unwrap_or(64) as usize;
                    let hits = client.scan_all_hits(4096)?;
                    let width = opts.num("size").unwrap_or(4) as u32;
                    for hit in hits.iter().take(limit) {
                        println!("{:08X}  {}", hit.address, hit.display_value(width));
                    }
                    println!("({} hit(s))", hits.len());
                    if let Some(path) = opts.flag("save") {
                        let scan = crate::pcscan::PcScan {
                            value_size: width.max(1),
                            hits: hits.iter()
                                .map(|hit| crate::pcscan::PcHit { address: hit.address, value: hit.value })
                                .collect(),
                            truncated: false,
                            bytes_read: 0,
                            reads: 0,
                            failed_reads: 0,
                            ..Default::default()
                        };
                        crate::pcscan::save(path, &scan)
                            .map_err(|e| NxusError { message: e.to_string(), result: None })?;
                        println!("saved {}", path);
                    }
                    if let Some(path) = opts.flag("csv") {
                        let mut text = String::from("address,value\n");
                        for hit in &hits {
                            text.push_str(&format!("{:08X},{}\n", hit.address, hit.value));
                        }
                        std::fs::write(path, text).map_err(|e| NxusError { message: e.to_string(), result: None })?;
                        println!("wrote {}", path);
                    }
                }
                "unknown" => {
                    // PC-side: the candidate list lives here, not on the console.
                    let value_size = opts.num("size").unwrap_or(4) as u32;
                    let scope = opts.flag("scope").and_then(|s| Scope::parse(s)).unwrap_or(Scope::Main);
                    let (begin, end) = parse_range_flag(opts);
                    let max_hits = opts.num("max").unwrap_or(crate::pcscan::DEFAULT_MAX_HITS as u64) as usize;
                    let regions = crate::pcscan::regions_for_scope(&client, scope, begin, end)
                        .map_err(|e| NxusError { message: e, result: None })?;
                    if regions.is_empty() {
                        return Err(usage("no readable memory for that scope"));
                    }
                    let total: u64 = regions.iter().map(|r| r.size).sum();
                    println!("reading {} MB in {} region(s) ...", total / (1024 * 1024), regions.len());
                    let cancel = std::sync::atomic::AtomicBool::new(false);
                    let mut last = Instant::now();
                    let scan = crate::pcscan::scan_unknown(&client, &regions, value_size, max_hits,
                                                           &cancel, &mut |done, total| {
                        if last.elapsed().as_millis() > 400 {
                            last = Instant::now();
                            eprintln!("  {} / {} MB", done / (1024 * 1024), total / (1024 * 1024));
                        }
                    }).map_err(|e| NxusError { message: e, result: None })?;
                    println!("unknown-value scan: {} candidate(s) from {} MB ({} reads){}",
                             scan.len(), scan.bytes_read / (1024 * 1024), scan.reads,
                             if scan.truncated { " [capped]" } else { "" });
                    if scan.is_empty() && scan.failed_reads > 0 {
                        println!("warning: {} read(s) failed - is the address range inside a mapping?",
                                 scan.failed_reads);
                    }
                    if let Some(path) = opts.flag("save") {
                        crate::pcscan::save(path, &scan).map_err(|e| NxusError { message: e.to_string(), result: None })?;
                        println!("saved {}", path);
                    }
                }
                "status" => {
                    let st = client.scan_status()?;
                    println!("{} : {} hits ({} permille)", scan_state_name(st.scan_state),
                             st.hit_count, st.progress_permille);
                }
                "cancel" => {
                    client.request(cmd::SCAN_CANCEL, &[])?;
                    println!("cancelled");
                }
                "reset" => {
                    client.scan_reset()?;
                    println!("scan session reset");
                }
                "undo" => {
                    if let Some(path) = opts.flag("load") {
                        let bak_path = format!("{}.bak", path);
                        let scan = crate::pcscan::load(&bak_path)
                            .map_err(|e| NxusError { message: format!("undo {}: {}", bak_path, e), result: None })?;
                        let out_path = opts.flag("save").unwrap_or(path);
                        crate::pcscan::save(out_path, &scan)
                            .map_err(|e| NxusError { message: e.to_string(), result: None })?;
                        println!("undo scan: {} candidate(s) restored", scan.len());
                        return Ok(());
                    }
                    let st = client.scan_undo()?;
                    println!("undo scan {} : {} hits", scan_state_name(st.scan_state), st.hit_count);
                }
                _ => return Err(usage("scan begin|refine|hits|status|cancel|reset|undo")),
            }
        }

        "dump" => {
            let path = opts.positional.get(1).ok_or_else(|| usage("dump <file.dmp> [--scope writable|all|heap|main|custom]"))?;
            let scope = opts.flag("scope").and_then(|s| Scope::parse(s)).unwrap_or(Scope::Writable);
            let (begin, end) = parse_range_flag(opts);
            let cancel = std::sync::atomic::AtomicBool::new(false);
            let mut last = Instant::now();
            let dump = crate::dump::MemoryDump::capture(&client, scope, begin, end, &cancel, &mut |done, total| {
                if last.elapsed().as_millis() > 400 {
                    last = Instant::now();
                    eprintln!("  {} / {} MB", done / (1024 * 1024), total / (1024 * 1024));
                }
            }).map_err(|e| NxusError { message: e, result: None })?;
            dump.save(path).map_err(|e| NxusError { message: e.to_string(), result: None })?;
            println!("saved NDMP dump to {} ({} blocks, {} bytes, tid {:016X})",
                     path, dump.indices.len(), dump.total_bytes(), dump.tid);
        }

        "ptrscan" => {
            let target = parse_address(&client, opts.positional.get(1).ok_or_else(|| usage("ptrscan <address>"))?)?;
            let metadata = client.metadata()?;
            let module_base = match opts.num("module") {
                Some(base) => base,
                None => metadata.main_base,
            };
            let depth = opts.num("depth").unwrap_or(3) as u32;
            let max_offset = opts.num("max-offset").unwrap_or(0x1000) as u32;
            let width = opts.num("width").unwrap_or(4) as u32;
            let max_results = opts.num("max").unwrap_or(64) as usize;

            if opts.has("pc") || opts.flag("save-dump").is_some() {
                let cancel = std::sync::atomic::AtomicBool::new(false);
                let mut last = Instant::now();
                let dump = crate::dump::MemoryDump::capture(
                    &client, Scope::Writable, 0, 0, &cancel, &mut |done, total| {
                        if last.elapsed().as_millis() > 400 {
                            last = Instant::now();
                            eprintln!("  dumping {} / {} MB", done / (1024 * 1024), total / (1024 * 1024));
                        }
                    },
                ).map_err(|e| NxusError { message: e, result: None })?;
                if let Some(save_path) = opts.flag("save-dump") {
                    dump.save(save_path).map_err(|e| NxusError { message: e.to_string(), result: None })?;
                    println!("saved NDMP dump to {}", save_path);
                }
                let res = crate::dump::ptrscan_dump(
                    &dump,
                    &crate::dump::PtrScanOptions {
                        target,
                        module_base,
                        module_size: metadata.main_size,
                        max_depth: depth,
                        max_offset,
                        width,
                        max_results,
                    },
                    &cancel,
                );
                print_ptrscan_chains(&res.chains, res.truncated, "PC", opts)?;
            } else {
                let (chains, truncated) = client.ptrscan_begin(target, module_base, depth, max_offset, max_results as u32, width)?;
                print_ptrscan_chains(&chains, truncated, "the console", opts)?;
            }
        }

        "cheat" => {
            let index = parse_number(opts.positional.get(1).ok_or_else(|| usage("cheat <index> --value N"))?)? as u32;
            let value = opts.num("value").ok_or_else(|| usage("cheat <index> --value N"))?;
            let width = opts.num("width").unwrap_or(4) as u32;
            let is_32bit = !opts.has("64bit");
            let text = client.cheat_export(index, value, width, is_32bit)?;
            match opts.flag("out") {
                Some(path) => {
                    std::fs::write(path, &text).map_err(|e| NxusError { message: e.to_string(), result: None })?;
                    println!("wrote {}", path);
                }
                None => print!("{}", text),
            }
        }

        "snapshot" => {
            let sub = opts.positional.get(1).map(|s| s.as_str()).unwrap_or("changed");
            match sub {
                "capture" => {
                    let slot = match opts.flag("slot").map(|s| s.as_str()) {
                        Some("b") | Some("B") | Some("1") => 1,
                        _ => 0,
                    };
                    let scope = opts.flag("scope").and_then(|s| Scope::parse(s)).unwrap_or(Scope::All);
                    let block = opts.num("block").unwrap_or(0) as u32;
                    let summary = client.snapshot_capture(slot, scope, block)?;
                    println!("captured slot {} : {} blocks of {} bytes ({} regions)",
                             if summary.slot == 0 { "A" } else { "B" }, summary.block_count,
                             summary.block_size, summary.region_count);
                }
                "diff" => {
                    let from = match opts.flag("from").map(|s| s.as_str()) {
                        Some("b") | Some("B") => 1,
                        _ => 0,
                    };
                    let to = match opts.flag("to").map(|s| s.as_str()) {
                        Some("a") | Some("A") => 0,
                        _ => 1,
                    };
                    let summary = client.snapshot_diff(from, to)?;
                    println!("{} block(s) changed{}", summary.changed_count,
                             if summary.truncated { " (truncated)" } else { "" });
                }
                "changed" => {
                    let limit = opts.num("limit").unwrap_or(64) as usize;
                    let blocks = client.snapshot_changed_all(1024)?;
                    for block in blocks.iter().take(limit) {
                        let kind = match block.flags {
                            CHANGE_VANISHED => "vanished",
                            CHANGE_APPEARED => "appeared",
                            _ => "changed",
                        };
                        println!("{:08X}  {:>6}  {}", block.address, block.size, kind);
                    }
                    println!("({} block(s))", blocks.len());
                    if let Some(path) = opts.flag("csv") {
                        let mut text = String::from("address,size,kind\n");
                        for block in &blocks {
                            text.push_str(&format!("{:08X},{},{}\n", block.address, block.size, block.flags));
                        }
                        std::fs::write(path, text).map_err(|e| NxusError { message: e.to_string(), result: None })?;
                        println!("wrote {}", path);
                    }
                }
                _ => return Err(usage("snapshot capture|diff|changed")),
            }
        }

        "watch" => {
            let address = parse_address(&client, opts.positional.get(1).ok_or_else(|| usage("watch <address>"))?)?;
            run_watch(&client, opts, address, break_kind::WRITE)?;
        }

        // The GDB spelling for an execute breakpoint: watch <addr> --kind exec.
        "break" => {
            let address = parse_address(&client, opts.positional.get(1)
                .ok_or_else(|| usage("break <address> [--size 4] [--seconds S] [--keep] [--stop]"))?)?;
            run_watch(&client, opts, address, break_kind::EXECUTE)?;
        }

        _ => {
            print!("{}", USAGE);
            return Err(usage("unknown command"));
        }
    }

    Ok(())
}

/// Arm a breakpoint / debug session and print every hit together with the code
/// that caused it.
///
/// `default_kind` is the only difference between the two spellings: `watch`
/// defaults to a write watchpoint, `break` to an execute breakpoint.  `--kind`
/// still overrides both, so `watch <addr> --kind exec` keeps working.
///
/// The session is always handed back: [`DebugSession`] detaches on every exit
/// path (including the `?` ones), and a `--stop` hit is never left holding the
/// game after this process exits - see the cleanup block at the end.
fn run_watch(client: &NxusClient, opts: &Opts, address: u64, default_kind: u32) -> Result<()> {
    let kind = opts.flag("kind").and_then(|k| break_kind::parse(k)).unwrap_or(default_kind);
    // --width is accepted as well: the docs and the GUI call it that, and an
    // unknown flag used to be ignored silently (so --width 2 watched 4 bytes)
    let size = opts.num("size").or_else(|| opts.num("width")).unwrap_or(4) as u32;
    let slot = opts.num("slot").unwrap_or(if kind == break_kind::EXECUTE { 0 } else { 0x10 }) as u32;
    let want = opts.num("count").unwrap_or(1) as usize;
    let seconds = opts.num("seconds").unwrap_or(60);
    let keep = opts.has("keep");
    // --stop is opt-in: without it a hit resumes the target (the historical
    // behaviour); with it the console holds the thread until `nxus continue`.
    let stop = opts.has("stop");

    // main_base must be read BEFORE attaching: dmnt is closed while we hold
    // the debug handle, so this call would fail (or return 0) afterwards.
    let metadata = client.metadata()?;
    if metadata.main_base == 0 {
        eprintln!("warning: main base is 0 - run one scan before attaching if you need main+off");
    }

    let status = client.debug_attach()?;
    println!("debug mode: attached={} watch_style={}", status.attached, status.watch_style);

    // dmnt is ours from this point on.  The guard hands it back on EVERY way out
    // of this function - a `?` on break_set/break_clear/hit_clear used to return
    // with the console still attached (the next scan then failed with BUSY until
    // the console's 20 s reaper noticed).
    let mut session = DebugSession::new(client);

    // The console's policy is explicit here, not assumed: --stop holds the target
    // on a hit, and without it a hit must resume the title exactly as before (the
    // switch defaults to the GDB-style hold, so "no flag" has to say so).
    // 16 bytes only: the hotkey/watchdog settings applied from the GUI survive.
    if stop {
        client.set_debug_auto_continue(status.watch_style, 0)?;
        println!("stop mode    : on (target held on a hit; nxus continue resumes)");
    } else {
        client.set_debug_auto_continue(status.watch_style, 1)?;
    }

    client.hit_clear()?;
    let breaks = client.break_set(address, kind, size, slot, 0)?;
    for b in &breaks {
        println!("breakpoint slot {:#x}: {} size {} at {:08X}", b.slot, break_kind_name(b.kind), b.size, b.address);
    }

    println!("waiting for {} hit(s) on {:08X} ...", want, address);
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut seen = 0usize;
    // The console parks the target at the LAST --stop hit on purpose (that is
    // the state `nxus continue` / `nxus step` inspect).  The cleanup below is
    // what guarantees it does not outlive this process.
    let mut held = false;
    let mut last_keepalive = Instant::now();
    while Instant::now() < deadline {
        // `--stop --keep` keeps the session (and the hold) alive until --seconds
        // expires instead of exiting on the first hit: leaving a held target
        // behind is the "hostage" state this command must never produce.
        if seen >= want && !(stop && keep) {
            break;
        }
        // The console detaches a debug session after 20 s with no command at
        // all, which clears the breakpoint: keep the session alive or this
        // loop reports "no hit observed" for a watchpoint that still works.
        if last_keepalive.elapsed() >= Duration::from_secs(4) {
            last_keepalive = Instant::now();
            let _ = client.heartbeat();
        }
        if let Some(event) = client.poll_event(Duration::from_millis(200)) {
            if stop {
                if event.kind == event::DEBUG_STOPPED && event.payload.len() >= DebugStop::SIZE {
                    let halt = DebugStop::parse(&event.payload);
                    print_stopped_line(client, &halt, metadata.main_base);
                    seen += 1;
                    // A held target cannot hit again, so release it for the next
                    // stop the caller asked for; the last one stays held.
                    held = seen >= want;
                    if !held {
                        let _ = client.debug_continue();
                    }
                }
                continue;
            }
            if event.kind == event::BREAK_HIT && event.payload.len() >= BreakHit::SIZE {
                let hit = BreakHit::parse(&event.payload);
                let offset = hit.pc.wrapping_sub(metadata.main_base);
                println!("hit #{}: {} to {:08X}", hit.index, break_kind_name(hit.kind), hit.address);
                println!("   pc = {:08X}  -> main+{:#x}", hit.pc, offset);
                println!("   lr = {:08X}  sp = {:08X}  r0-r3 = {:08X} {:08X} {:08X} {:08X}",
                         hit.lr, hit.sp, hit.regs[0], hit.regs[1], hit.regs[2], hit.regs[3]);
                // A pc alone does not tell an operator what happened: show the code
                // around it (=> on the hit instruction) and the rest of the registers.
                print_hit_context(client, &hit, metadata.main_base);
                seen += 1;
            }
        }
    }

    if seen == 0 {
        println!("no hit observed");
    }

    // ---- cleanup: never leave the console holding the game -------------------
    // `--stop` puts a hold policy on the console, so a session left behind would
    // freeze the title at the next hit with no PC around to continue it.  Both
    // a hit (`held`) and a kept `--stop` session therefore end with a detach -
    // the difference is only WHEN: immediately without --keep (after the loop
    // broke), or once --seconds expired with --keep.  A plain --keep (no --stop)
    // still leaves the watchpoint armed, exactly as before: nothing is held
    // then, the game keeps running.
    let detaching = !keep || stop;
    if detaching {
        // A detach clears every hardware breakpoint anyway; clear the slot first
        // so a failed detach still leaves nothing armed, and never `?` here: the
        // detach below must run even when the clear fails.
        if let Err(e) = client.break_clear(slot) {
            eprintln!("warning: cannot clear breakpoint slot {:#x}: {}", slot, e);
        }
        let _ = client.hit_clear();
        if stop {
            // Leave the console on the default policy: a later non-stop watch must
            // not freeze the title because this run configured a hold.
            let _ = client.set_debug_auto_continue(status.watch_style, 1);
        }
        if session.detach() {
            println!("detached (dmnt restored)");
            if held {
                println!("the game is running again (the stop was released, armed breakpoints cleared)");
            }
        } else {
            eprintln!("warning: detach failed - the console's reaper releases dmnt in ~20 s");
            if held {
                eprintln!("warning: the target is still held; run 'nxus continue' to resume it");
            }
        }
    } else {
        // Nothing is held (a plain --keep): the watchpoint may stay armed, so the
        // guard must not detach on the way out.
        session.leave_armed();
        println!("leaving the watchpoint armed (use: nxus detach)");
    }
    Ok(())
}

/// Detach-on-drop guard for the debug session `run_watch` owns.
///
/// Every early return (`?`) in that function has to give dmnt back: returning
/// with the console still attached takes the cheat process away from every other
/// client until the console's 20 s reaper notices.  A `Drop` cannot be
/// forgotten, a cleanup label can.
struct DebugSession<'a> {
    client: &'a NxusClient,
    /// True while this process still owes the console a detach.
    must_detach: bool,
}

impl<'a> DebugSession<'a> {
    fn new(client: &'a NxusClient) -> DebugSession<'a> {
        DebugSession { client, must_detach: true }
    }

    /// Give dmnt back.  Returns false when the console refused: the caller must
    /// not claim a state it has not reached, and `Drop` retries once.
    fn detach(&mut self) -> bool {
        if !self.must_detach {
            return true;
        }
        if self.client.debug_detach().is_ok() {
            self.must_detach = false;
            true
        } else {
            false
        }
    }

    /// Leave the session to whoever comes next (`--keep` on a target that is
    /// still running): nothing is held, so exiting with the watchpoint armed is
    /// what the user asked for.  The console reaps an idle session after 20 s.
    fn leave_armed(&mut self) {
        self.must_detach = false;
    }
}

impl Drop for DebugSession<'_> {
    fn drop(&mut self) {
        if self.must_detach {
            let _ = self.client.debug_detach();
        }
    }
}

/// The `--stop` counterpart of a hit: one STOPPED line, then the same context a
/// GDB stop prints - the code around the pc and every stopped register.
fn print_stopped_line(client: &NxusClient, halt: &DebugStop, main_base: u64) {
    if main_base != 0 {
        let offset = halt.pc.wrapping_sub(main_base);
        println!("STOPPED thread=0x{:X} pc={:08X} (main+{:#x})", halt.thread_id, halt.pc, offset);
    } else {
        println!("STOPPED thread=0x{:X} pc={:08X}", halt.thread_id, halt.pc);
    }
    match client.regs_get(halt.thread_id) {
        // The event's pc is the trapping instruction; a register read may already
        // look one instruction further, so the window stays centred on the event.
        Ok(ctx) => print_stop_body(client, halt.pc, ctx.cpsr, &ctx, main_base),
        Err(e) => {
            eprintln!("   (cannot read the registers of thread 0x{:X}: {})", halt.thread_id, e);
            let mode = resolve_mode(client, halt.pc, 0);
            println!("   ---------------- code around pc ({}) ----------------", mode.label());
            print_code_window(client, halt.pc, 8, 12, 32, mode, main_base);
        }
    }
}

/// Registers and code window for a thread the console is holding.
fn print_stopped_context(client: &NxusClient, ctx: &ThreadContext, main_base: u64) {
    print_stop_body(client, ctx.pc, ctx.cpsr, ctx, main_base);
}

fn print_stop_body(client: &NxusClient, pc: u64, cpsr: u32, ctx: &ThreadContext, main_base: u64) {
    let mode = resolve_mode(client, pc, cpsr);
    println!("   ---------------- code around pc ({}) ----------------", mode.label());
    print_code_window(client, pc, 8, 12, 32, mode, main_base);
    // "every register" (r0-r12 / sp / lr / pc / cpsr) is what a stopped debugger
    // shows; the 32-bit view is the one a hit reports, and the alias a 32-bit
    // title uses.  Same row shape as print_hit_context, but complete.
    println!("   r0-r3  = {:08X} {:08X} {:08X} {:08X}", ctx.r[0], ctx.r[1], ctx.r[2], ctx.r[3]);
    println!("   r4-r12 = {:08X} {:08X} {:08X} {:08X} {:08X} {:08X} {:08X} {:08X} {:08X}",
             ctx.r[4], ctx.r[5], ctx.r[6], ctx.r[7], ctx.r[8],
             ctx.r[9], ctx.r[10], ctx.r[11], ctx.r[12]);
    println!("   sp     = {:08X}   lr = {:08X}   pc = {:08X}", ctx.sp, ctx.lr, ctx.pc);
    println!("   cpsr   = {:08X}", ctx.cpsr);
}

/// GDB-style context for a hit: a few instructions around the pc plus the
/// registers (`r0..r12`, sp, lr, pc, cpsr).  A failed code read never aborts the
/// watch - the hit itself (reported above) is still valid.
fn print_hit_context(client: &NxusClient, hit: &BreakHit, main_base: u64) {
    let mode = resolve_mode(client, hit.pc, hit.cpsr);
    println!("   ---------------- code around pc ({}) ----------------", mode.label());
    print_code_window(client, hit.pc, 8, 12, 32, mode, main_base);
    println!("   r4-r12 = {:08X} {:08X} {:08X} {:08X} {:08X} {:08X} {:08X} {:08X} {:08X}",
             hit.regs[4], hit.regs[5], hit.regs[6], hit.regs[7], hit.regs[8],
             hit.regs[9], hit.regs[10], hit.regs[11], hit.regs[12]);
    println!("   cpsr = {:08X}", hit.cpsr);
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DisasmMode {
    Arm64,
    Arm32,
    Thumb,
}

impl DisasmMode {
    fn instr_size(self) -> u64 {
        match self {
            DisasmMode::Thumb => 2,
            _ => 4,
        }
    }

    fn label(self) -> &'static str {
        match self {
            DisasmMode::Arm64 => "AArch64",
            DisasmMode::Arm32 => "AArch32/ARM",
            DisasmMode::Thumb => "AArch32/Thumb",
        }
    }
}

/// Detect the execution state of a context from its pc / CPSR pair.
///
/// A pc above 4 GiB can only be AArch64, and the T bit (0x20) is authoritative:
/// Atmosphère's CPSR mask (`0xFE0FFE20`) keeps bit 5, so a set T bit always
/// means Thumb.  The M bits cannot be trusted on hardware: that same mask clears
/// M[4] (0x10) for AArch32 threads, so a running 32-bit ARM title such as MHXX
/// reports `cpsr = 0x60000000` - the same shape as AArch64 PSTATE.  This
/// function therefore only reports what the context itself proves;
/// [`resolve_mode`] refines the guess with the bytes at the pc and with the
/// 32-bit address space.
///
/// This is deliberately local to the CLI: protocol.rs stays the single owner of
/// the wire format, and the CLI must not depend on a helper the library may not
/// export.
fn mode_from_context(pc: u64, cpsr: u32) -> DisasmMode {
    if pc > 0xFFFF_FFFF {
        return DisasmMode::Arm64;
    }
    if (cpsr & 0x20) != 0 {
        return DisasmMode::Thumb;
    }
    match cpsr & 0x1F {
        0x10 | 0x11 | 0x12 | 0x13 | 0x16 | 0x17 | 0x1a | 0x1b | 0x1f => DisasmMode::Arm32,
        _ => DisasmMode::Arm64,
    }
}

/// Is `pc` inside the 32-bit (AArch32) process address space?
///
/// Atmosphère maps 32-bit titles high in the address space - MHXX runs from
/// 0x1B004000 up to about 0x1F000000 - while 64-bit application code lives
/// below 0x0800_0000 (MockSwitch's `MAIN_BASE` is 0x00700000).  Only consulted
/// when the bytes at the pc cannot settle the question.
fn in_aarch32_space(pc: u64) -> bool {
    (0x0800_0000..0x8000_0000).contains(&pc)
}

/// Decide between the two 32-bit encodings from the words found at the pc.
///
/// Two independent tells, neither of which needs the (masked) CPSR M bits:
///   * a word whose top nibble is 0xE is a classic AArch32 instruction with
///     condition AL.  AArch64 does not use that encoding space, so an ARM-AL
///     word is solid evidence of ARM32 (MHXX's code is full of them);
///   * a word that decodes as a real AArch64 instruction (anything but
///     `.word`) and is *not* an ARM-AL word is evidence of AArch64
///     (MockSwitch's 0x00700000 image, or any 64-bit title).
///
/// ARM32 wins a tie: an AArch32 stream contains conditional (non-AL) words that
/// the AArch64 decoder can occasionally accept, whereas an AArch64 stream
/// practically never contains an ARM-AL word.  When nothing decodes at all
/// (zeros, data, an unreadable hole) the address space decides, then the CPSR
/// shape.
fn mode_from_words(pc: u64, words: &[u32], fallback: DisasmMode) -> DisasmMode {
    let mut arm_known = 0usize;
    let mut arm64_known = 0usize;
    for (i, &word) in words.iter().enumerate() {
        if (word >> 28) == 0xE {
            arm_known += 1;
        } else if !disasm_arm(pc + (i as u64) * 4, word, false).starts_with('.') {
            arm64_known += 1;
        }
    }
    if arm_known == 0 && arm64_known == 0 {
        return if in_aarch32_space(pc) { DisasmMode::Arm32 } else { fallback };
    }
    if arm_known >= arm64_known {
        DisasmMode::Arm32
    } else {
        DisasmMode::Arm64
    }
}

/// Auto-detected mode with a byte-level sanity check and the 32-bit address
/// space as the last resort.
///
/// dmnt reports the same CPSR shape (e.g. 0x60000000) for both execution states
/// because Atmosphère masks M[4] away, so CPSR alone cannot tell a 32-bit ARM
/// title from AArch64.  Thumb is never re-decided (its T bit is exact); the
/// words at the pc decide the rest, and if they are unreadable the address
/// space does.
fn resolve_mode(client: &NxusClient, pc: u64, cpsr: u32) -> DisasmMode {
    let mode = mode_from_context(pc, cpsr);
    if mode == DisasmMode::Thumb || pc > 0xFFFF_FFFF {
        return mode;
    }
    let aligned = pc & !3;
    let Ok(data) = client.read(aligned, 16) else {
        return if in_aarch32_space(pc) { DisasmMode::Arm32 } else { mode };
    };
    if data.len() < 4 {
        return if in_aarch32_space(pc) { DisasmMode::Arm32 } else { mode };
    }
    let words: Vec<u32> = data
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    mode_from_words(aligned, &words, mode)
}

/// Print `count` instructions at `target`.  With `around` the listing starts
/// `count/2` instructions earlier and the instruction containing `target` gets
/// the "=>" marker plus its `<main+offset>` (when main_base is known).
fn print_disassembly(client: &NxusClient, target: u64, count: u32, mode: DisasmMode,
                     around: bool, main_base: u64) -> Result<()> {
    let count = count.max(1) as u64;
    let size = mode.instr_size();
    let before = if around { count / 2 } else { 0 };
    let aligned = target & !(size - 1);
    let start = aligned.saturating_sub(before * size) & !(size - 1);
    // Thumb instructions are 2 or 4 bytes: ask for the widest possible packing.
    let ask = if mode == DisasmMode::Thumb { (count * 4).max(4) } else { count * size };
    let ask = ask.min(u32::MAX as u64) as u32;

    let mut used_start = start;
    let mut data = match client.read(start, ask) {
        Ok(data) if !data.is_empty() => data,
        Ok(_) => Vec::new(),                  // fall back to the aligned address
        Err(e) => {
            if start == aligned {
                return Err(e);
            }
            Vec::new()
        }
    };
    if data.is_empty() && start != aligned {
        data = client.read(aligned, ask)?;
        used_start = aligned;
    }
    if data.is_empty() {
        return Err(NxusError { message: format!("no readable data at {:08X}", aligned), result: None });
    }

    let mut printed = 0u64;
    walk_instructions(used_start, &data, mode, |pc, word, len, text| {
        print_instruction_line(pc, word, len, &text, target, main_base, around);
        printed += 1;
        printed >= count
    });
    Ok(())
}

/// Read `back` bytes before and `forward` bytes after `center` and print every
/// instruction in that window, marking the one that contains `center`.
///
/// Used after a watchpoint hit (`hit.pc - 8 .. hit.pc + 12`, GDB's `x/i` view).
fn print_code_window(client: &NxusClient, center: u64, back: u64, forward: u64,
                     max_bytes: u32, mode: DisasmMode, main_base: u64) {
    let size = mode.instr_size();
    let aligned = center & !(size - 1);
    let start = aligned.saturating_sub(back) & !(size - 1);
    let end = center.saturating_add(forward);
    let data = match client.read(start, max_bytes) {
        Ok(data) if !data.is_empty() => data,
        Ok(_) => {
            eprintln!("   (the console returned no bytes at {:08X})", start);
            return;
        }
        Err(e) => {
            eprintln!("   (cannot read the code at {:08X}: {})", start, e);
            return;
        }
    };
    let mut any = false;
    walk_instructions(start, &data, mode, |pc, word, len, text| {
        if pc >= end {
            return true;
        }
        print_instruction_line(pc, word, len, &text, center, main_base, true);
        any = true;
        false
    });
    if !any {
        eprintln!("   (no instruction could be decoded at {:08X})", center);
    }
}

/// Decode `data` starting at `start`, calling `emit(pc, word, length, text)` for
/// every instruction.  Returning `true` from `emit` stops the walk.
fn walk_instructions<F>(start: u64, data: &[u8], mode: DisasmMode, mut emit: F)
where
    F: FnMut(u64, u32, u64, String) -> bool,
{
    let mut pc = start;
    let mut offset = 0usize;
    while offset < data.len() {
        if mode == DisasmMode::Thumb {
            if offset + 2 > data.len() {
                break;
            }
            let hw = u16::from_le_bytes([data[offset], data[offset + 1]]);
            if thumb_is_32bit(hw) && offset + 4 <= data.len() {
                let hw2 = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
                let word = ((hw as u32) << 16) | hw2 as u32;
                let text = thumb32_text(pc, word);
                if emit(pc, word, 4, text) {
                    break;
                }
                pc = pc.wrapping_add(4);
                offset += 4;
                continue;
            }
            let text = thumb16_text(pc, hw);
            if emit(pc, hw as u32, 2, text) {
                break;
            }
            pc = pc.wrapping_add(2);
            offset += 2;
        } else {
            if offset + 4 > data.len() {
                break;
            }
            let word = u32::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            ]);
            let text = disasm_arm(pc, word, mode == DisasmMode::Arm32);
            if emit(pc, word, 4, text) {
                break;
            }
            pc = pc.wrapping_add(4);
            offset += 4;
        }
    }
}

/// One listing line.  The default (no --around) format is unchanged from the
/// original tool: `ADDR  WORD  TEXT`.
fn print_instruction_line(pc: u64, word: u32, len: u64, text: &str, target: u64,
                          main_base: u64, around: bool) {
    if !around {
        if len == 2 {
            println!("{:08X}  {:04X}      {}", pc, word & 0xFFFF, text);
        } else {
            println!("{:08X}  {:08X}  {}", pc, word, text);
        }
        return;
    }
    let marker = target >= pc && target < pc.saturating_add(len.max(1));
    let main = if main_base != 0 && pc >= main_base {
        format!("  <main+{:#x}>", pc - main_base)
    } else {
        String::new()
    };
    if len == 2 {
        println!("{} {:08X}  {:04X}      {}{}", if marker { "=>" } else { "  " },
                 pc, word & 0xFFFF, text, main);
    } else {
        println!("{} {:08X}  {:08X}  {}{}", if marker { "=>" } else { "  " },
                 pc, word, text, main);
    }
}

/// A 32-bit Thumb instruction is signalled by the top five bits of its first
/// halfword (11101, 11110, 11111).
fn thumb_is_32bit(hw: u16) -> bool {
    matches!(hw >> 11, 0b11101 | 0b11110 | 0b11111)
}

fn thumb_cond(cond: u16) -> &'static str {
    match cond & 0xF {
        0x0 => "eq", 0x1 => "ne", 0x2 => "cs", 0x3 => "cc", 0x4 => "mi", 0x5 => "pl",
        0x6 => "vs", 0x7 => "vc", 0x8 => "hi", 0x9 => "ls", 0xA => "ge", 0xB => "lt",
        0xC => "gt", 0xD => "le", _ => "nv",
    }
}

/// Thumb (AArch32 T32) 16-bit decoder for the instructions seen around
/// watchpoints.  Unknown encodings print as `.hword`, never as a wrong mnemonic.
fn thumb16_text(pc: u64, hw: u16) -> String {
    let rd = (hw & 7) as u32;
    let rs = ((hw >> 3) & 7) as u32;
    let imm5 = ((hw >> 6) & 0x1F) as u32;

    // Format 1/2: shift by immediate, add/subtract register or 3-bit immediate.
    if (hw & 0xE000) == 0x0000 {
        if (hw & 0x1800) == 0x0000 {
            let op = (hw >> 11) & 3;
            return match op {
                0 => if imm5 == 0 { format!("movs r{}, r{}", rd, rs) }
                     else { format!("lsls r{}, r{}, #{}", rd, rs, imm5) },
                1 => if imm5 == 0 { format!("movs r{}, r{}", rd, rs) }
                     else { format!("lsrs r{}, r{}, #{}", rd, rs, imm5) },
                2 => if imm5 == 0 { format!("movs r{}, r{}", rd, rs) }
                     else { format!("asrs r{}, r{}, #{}", rd, rs, imm5) },
                _ => format!("adds r{}, r{}, #{}", rd, rs, imm5),
            };
        }
        let sub = (hw & 0x0200) != 0;
        let imm_form = (hw & 0x0400) != 0;
        let rd2 = (hw & 7) as u32;
        let rs2 = ((hw >> 3) & 7) as u32;
        let operand = ((hw >> 6) & 7) as u32;
        let mnem = if sub { "subs" } else { "adds" };
        return if imm_form {
            format!("{} r{}, r{}, #{}", mnem, rd2, rs2, operand)
        } else {
            format!("{} r{}, r{}, r{}", mnem, rd2, rs2, operand)
        };
    }

    // Format 3: mov/cmp/add/sub with an 8-bit immediate.
    if (hw & 0xE000) == 0x2000 {
        let op = (hw >> 11) & 3;
        let r = ((hw >> 8) & 7) as u32;
        let mnem = match op {
            0 => "movs",
            1 => "cmp",
            2 => "adds",
            _ => "subs",
        };
        return format!("{} r{}, #{}", mnem, r, hw & 0xFF);
    }

    // Format 4: data-processing register.
    if (hw & 0xFC00) == 0x4000 {
        let op = ((hw >> 6) & 0xF) as u32;
        let rdn = (hw & 7) as u32;
        let rm = ((hw >> 3) & 7) as u32;
        let mnem = match op {
            0 => "ands", 1 => "eors", 2 => "lsls", 3 => "lsrs", 4 => "asrs",
            5 => "adcs", 6 => "sbcs", 7 => "rors", 8 => "tst", 9 => "rsbs",
            10 => "cmp", 11 => "cmn", 12 => "orrs", 13 => "muls", 14 => "bics",
            _ => "mvns",
        };
        return match op {
            8 | 10 | 11 => format!("{} r{}, r{}", mnem, rdn, rm),
            9 => format!("rsbs r{}, r{}, #0", rdn, rm),
            13 => format!("muls r{}, r{}, r{}", rdn, rm, rdn),
            _ => format!("{} r{}, r{}", mnem, rdn, rm),
        };
    }

    // Format 5: special data processing (hi registers) / BX / BLX.
    if (hw & 0xFC00) == 0x4400 {
        let op = (hw >> 8) & 3;
        let h1 = ((hw >> 7) & 1) as u32;
        let h2 = ((hw >> 6) & 1) as u32;
        let rdn = (h1 << 3) | (hw & 7) as u32;
        let rm = (h2 << 3) | ((hw >> 3) & 7) as u32;
        return match op {
            3 => {
                let rm_text = match rm {
                    14 => "lr".to_string(),
                    15 => "pc".to_string(),
                    _ => format!("r{}", rm),
                };
                if (hw & 0x0080) != 0 { format!("blx {}", rm_text) } else { format!("bx {}", rm_text) }
            }
            0 => format!("add r{}, r{}", rdn, rm),
            1 => format!("cmp r{}, r{}", rdn, rm),
            _ => format!("mov r{}, r{}", rdn, rm),
        };
    }

    // Format 6: PC-relative load.
    if (hw & 0xF800) == 0x4800 {
        let r = ((hw >> 8) & 7) as u32;
        let off = ((hw & 0xFF) as u64) * 4;
        let addr = (pc.wrapping_add(4) & !3).wrapping_add(off);
        return format!("ldr r{}, [pc, #{}]  ; {:#x}", r, off, addr);
    }

    // Format 7/8/9: load/store with register offset.
    if (hw & 0xF000) == 0x5000 {
        let op = ((hw >> 9) & 7) as u32;
        let mnem = match op {
            0 => "str", 1 => "strh", 2 => "strb", 3 => "ldrsb",
            4 => "ldr", 5 => "ldrh", 6 => "ldrb", _ => "ldrsh",
        };
        let r = (hw & 7) as u32;
        let base = ((hw >> 3) & 7) as u32;
        let ro = ((hw >> 6) & 7) as u32;
        return format!("{} r{}, [r{}, r{}]", mnem, r, base, ro);
    }

    // Format 10/11/12/13: load/store with immediate offset.
    let top = hw >> 12;
    if (0x6..=0x9).contains(&top) {
        let load = (hw & 0x0800) != 0;
        let off5 = ((hw >> 6) & 0x1F) as u32;
        let r = (hw & 7) as u32;
        let base = ((hw >> 3) & 7) as u32;
        let (mnem, off, base_text) = match top {
            0x6 => (if load { "ldr" } else { "str" }, off5 * 4, format!("r{}", base)),
            0x7 => (if load { "ldrb" } else { "strb" }, off5, format!("r{}", base)),
            0x8 => (if load { "ldrh" } else { "strh" }, off5 * 2, format!("r{}", base)),
            _ => (if load { "ldr" } else { "str" }, off5 * 4, "sp".to_string()),
        };
        return if off == 0 {
            format!("{} r{}, [{}]", mnem, r, base_text)
        } else {
            format!("{} r{}, [{}, #{}]", mnem, r, base_text, off)
        };
    }

    // Format 14: ADR / ADD Rd, SP.
    if (hw & 0xF000) == 0xA000 {
        let r = ((hw >> 8) & 7) as u32;
        let off = ((hw & 0xFF) as u64) * 4;
        if (hw & 0x0800) != 0 {
            return format!("add r{}, sp, #{}", r, off);
        }
        return format!("adr r{}, {:#x}", r, (pc.wrapping_add(4) & !3).wrapping_add(off));
    }

    // Format 15: adjust SP / hints.
    if (hw & 0xF000) == 0xB000 {
        if hw == 0xBF00 {
            return "nop".to_string();
        }
        if (hw & 0xFF00) == 0xB000 || (hw & 0xFF00) == 0xB080 {
            let sub = (hw & 0x0080) != 0;
            let off = ((hw & 0x7F) as u32) * 4;
            return format!("{} sp, #{}", if sub { "sub" } else { "add" }, off);
        }
        return format!(".hword 0x{:04X}", hw);
    }

    // Format 16: LDM / STM.
    if (hw & 0xF000) == 0xC000 {
        let load = (hw & 0x0800) != 0;
        let base = ((hw >> 8) & 7) as u32;
        let list = hw & 0xFF;
        let mut regs = String::new();
        for i in 0..8 {
            if list & (1 << i) != 0 {
                if !regs.is_empty() {
                    regs.push(',');
                }
                regs.push_str(&format!("r{}", i));
            }
        }
        if regs.is_empty() {
            regs.push_str("(none)");
        }
        return format!("{}{} r{}!, {{{}}}", if load { "ldm" } else { "stm" },
                       if load { "ia" } else { "ia" }, base, regs);
    }

    // Format 17: conditional branch / svc.
    if (hw & 0xF000) == 0xD000 {
        let cond = (hw >> 8) & 0xF;
        if cond == 0xF {
            return format!("svc #{}", hw & 0xFF);
        }
        if cond == 0xE {
            return format!("udf #{}", hw & 0xFF);
        }
        let v = (((hw & 0xFF) as i32) << 1) << 20 >> 20;    // sign-extend imm8*2
        let target = pc.wrapping_add(4).wrapping_add(v as i64 as u64);
        return format!("b{} {:#x}", thumb_cond(cond), target);
    }

    // Format 18: unconditional branch.
    if (hw & 0xF800) == 0xE000 {
        let v = (((hw & 0x7FF) as i32) << 1) << 20 >> 20;   // sign-extend imm11*2
        let target = pc.wrapping_add(4).wrapping_add(v as i64 as u64);
        return format!("b {:#x}", target);
    }

    format!(".hword 0x{:04X}", hw)
}

/// Thumb-2 32-bit instructions: BL / B.W are decoded; everything else falls
/// back to the shared AArch32 decoder (which prints `.word` when it does not
/// know the encoding, instead of inventing a mnemonic).
fn thumb32_text(pc: u64, word: u32) -> String {
    let hw1 = (word >> 16) as u16;
    let hw2 = word as u16;
    if (hw1 & 0xF800) == 0xF000 && (hw2 & 0xD000) == 0xD000 {
        let s = ((hw1 >> 10) & 1) as i64;
        let j1 = ((hw2 >> 13) & 1) as i64;
        let j2 = ((hw2 >> 11) & 1) as i64;
        let i1 = (!(j1 ^ s)) & 1;
        let i2 = (!(j2 ^ s)) & 1;
        let imm10 = (hw1 & 0x3FF) as i64;
        let imm11 = (hw2 & 0x7FF) as i64;
        let mut offset = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
        if s != 0 {
            offset -= 1i64 << 25;
        }
        let target = pc.wrapping_add((offset as i32) as i64 as u64).wrapping_add(4);
        return format!("{} {:#x}", if (hw2 & 0x4000) != 0 { "bl" } else { "b.w" }, target);
    }
    disasm_arm(pc, word, true)
}

/// Build a scan spec from the CLI flags (value type, patterns, hex, ...).
fn build_spec(opts: &Opts, text: &str, refine: bool) -> Result<ScanSpec> {
    let value_type = opts.flag("type").and_then(|t| ValueType::parse(t)).unwrap_or(ValueType::U32);
    let compare = if refine {
        opts.flag("cmp").and_then(|c| Compare::parse(c)).unwrap_or(Compare::Increased)
    } else {
        opts.flag("cmp").and_then(|c| Compare::parse(c)).unwrap_or(Compare::Equal)
    };

    let mut spec = ScanSpec::new(value_type, compare);
    spec.scope = opts.flag("scope").and_then(|s| Scope::parse(s)).unwrap_or(Scope::All);
    spec.value_size = opts.num("size").unwrap_or(value_type.size() as u64) as u32;
    // The custom scope needs the range in the request; without this the console built
    // zero regions and rejected the scan (BadInput).
    let ranges = parse_ranges_flag(opts)?;
    if opts.flag("range").is_some() && ranges.is_empty() {
        // A mistyped range used to be dropped, leaving the default scope in place -
        // i.e. a silent full-memory scan.  Refuse instead.
        return Err(usage("--range 0xBEGIN..0xEND (several: 0xA..0xB,0xC..0xD)"));
    }
    if ranges.len() > crate::protocol::MAX_SCAN_RANGES {
        return Err(usage("at most 16 ranges"));
    }
    if !ranges.is_empty() {
        // several ranges are a scope of their own; a single one stays "custom" so the
        // existing command lines keep behaving the same
        if ranges.len() > 1 || spec.scope == Scope::Ranges {
            spec.scope = Scope::Ranges;
            spec.ranges = ranges;
        } else {
            spec.scope = Scope::Custom;
            spec.range_begin = ranges[0].0;
            spec.range_end = ranges[0].1;
        }
    } else if spec.scope == Scope::Custom || spec.scope == Scope::Ranges {
        return Err(usage("--scope custom needs --range 0xBEGIN..0xEND (scope ranges: 0xA..0xB,0xC..0xD)"));
    }
    if opts.has("aligned") {
        spec.flags |= SCAN_F_ALIGNED;
    }
    if opts.has("hex") {
        spec.flags |= SCAN_F_HEX;
    }

    if value_type.is_pattern() {
        if text.is_empty() {
            return Err(usage("scan begin <text|bytes> --type str|bytes"));
        }
        if value_type == ValueType::Str {
            spec.pattern = text.as_bytes().to_vec();
            if opts.has("ignore-case") {
                spec.flags |= SCAN_F_CASE_INSENS;
            }
            if opts.has("utf16") {
                spec.flags |= SCAN_F_UTF16;
            }
        } else {
            let (pattern, mask) = parse_byte_pattern(text)?;
            spec.pattern = pattern;
            if mask.iter().any(|m| *m != 0xFF) {
                spec.flags |= SCAN_F_WILDCARD;
                spec.mask = mask;
            }
        }
    } else if !text.is_empty() {
        spec.value = match value_type {
            ValueType::F32 => text.parse::<f32>().map_err(|_| usage("float value"))?.to_bits() as u64,
            ValueType::F64 => text.parse::<f64>().map_err(|_| usage("double value"))?.to_bits(),
            _ => parse_number(text)?,
        };
        if value_type.is_float() {
            spec.flags |= SCAN_F_FLOAT;
        } else {
            spec.flags &= !SCAN_F_FLOAT;
        }
        if let Some(second) = opts.flag("to") {
            spec.target2 = match value_type {
                ValueType::F32 => second.parse::<f32>().map_err(|_| usage("--to float"))?.to_bits() as u64,
                ValueType::F64 => second.parse::<f64>().map_err(|_| usage("--to double"))?.to_bits(),
                _ => parse_number(second)?,
            };
        }
    }
    Ok(spec)
}

/// "DE AD ?? EF" -> (bytes, mask); "?" means "any byte".
fn parse_byte_pattern(text: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let cleaned = text.replace([' ', ',', '-'], "");
    if cleaned.is_empty() || cleaned.len() % 2 != 0 {
        return Err(usage("byte pattern like 'DE AD ?? EF'"));
    }
    let mut pattern = Vec::new();
    let mut mask = Vec::new();
    for i in (0..cleaned.len()).step_by(2) {
        let pair = &cleaned[i..i + 2];
        if pair == "??" || pair == "?" {
            pattern.push(0);
            mask.push(0);
        } else {
            pattern.push(u8::from_str_radix(pair, 16).map_err(|_| usage("hex bytes"))?);
            mask.push(0xFF);
        }
    }
    if pattern.len() > SCAN_MAX_PATTERN {
        return Err(usage("pattern too long (max 64 bytes)"));
    }
    Ok((pattern, mask))
}

/// --range 0x1000..0x2000,0x3000..0x4000 - one or more ranges (custom / ranges scope).
///
/// Every element must be valid: a silently dropped entry would turn "scan these two
/// areas" into "scan one area" (or, with an empty result, into a full-memory scan).
fn parse_ranges_flag(opts: &Opts) -> Result<Vec<(u64, u64)>> {
    let mut out = Vec::new();
    let Some(text) = opts.flag("range") else { return Ok(out) };
    for part in text.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;                       // tolerate ",A,,B" and trailing commas
        }
        let (a, b) = part
            .split_once("..")
            .ok_or_else(|| usage(&format!("--range: '{}' is not BEGIN..END", part)))?;
        let begin = parse_number(a.trim())
            .map_err(|_| usage(&format!("--range: '{}' is not a number", a.trim())))?;
        let end = parse_number(b.trim())
            .map_err(|_| usage(&format!("--range: '{}' is not a number", b.trim())))?;
        if end <= begin {
            return Err(usage(&format!("--range: '{}' is empty or reversed", part)));
        }
        out.push((begin, end));
    }
    Ok(out)
}

/// --range 0x1000..0x2000 (used by the custom scope).
fn parse_range_flag(opts: &Opts) -> (u64, u64) {
    match opts.flag("range").and_then(|text| {
        let (a, b) = text.split_once("..")?;
        Some((parse_number(a).ok()?, parse_number(b).ok()?))
    }) {
        Some(range) => range,
        None => (0, 0),
    }
}

fn usage(what: &str) -> NxusError {
    NxusError { message: format!("usage: {}", what), result: None }
}

fn encode_write(spec: &str) -> Result<Vec<u8>> {
    if let Some(rest) = spec.strip_prefix("u32:") {
        let v = parse_number(rest)? as u32;
        return Ok(v.to_le_bytes().to_vec());
    }
    if let Some(rest) = spec.strip_prefix("i32:") {
        let v: i32 = rest.parse().map_err(|_| usage("i32:VALUE"))?;
        return Ok(v.to_le_bytes().to_vec());
    }
    if let Some(rest) = spec.strip_prefix("u64:") {
        let v = parse_number(rest)?;
        return Ok(v.to_le_bytes().to_vec());
    }
    if let Some(rest) = spec.strip_prefix("u16:") {
        let v = parse_number(rest)? as u16;
        return Ok(v.to_le_bytes().to_vec());
    }
    if let Some(rest) = spec.strip_prefix("u8:") {
        let v = parse_number(rest)? as u8;
        return Ok(vec![v]);
    }

    let cleaned = spec.replace([' ', ',', '-'], "");
    if cleaned.len() % 2 != 0 {
        return Err(usage("hex bytes like 'DE AD BE EF'"));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[i..i + 2], 16)
            .map_err(|_| usage("hex bytes like 'DE AD BE EF'"))?;
        out.push(byte);
    }
    if out.is_empty() {
        return Err(usage("nothing to write"));
    }
    Ok(out)
}

/// Parse "plus", "L+PLUS", "zl+zr+plus" or a raw mask into a HidNpadButton bitmask.
fn parse_combo(text: &str) -> Result<u64> {
    if let Ok(value) = parse_number(text) {
        return Ok(value);
    }
    let mut mask = 0u64;
    for part in text.split('+') {
        let bit = match part.trim().to_ascii_lowercase().as_str() {
            "a" => 1u64 << 0,
            "b" => 1u64 << 1,
            "x" => 1u64 << 2,
            "y" => 1u64 << 3,
            "lstick" | "ls" => 1u64 << 4,
            "rstick" | "rs" => 1u64 << 5,
            "l" => 1u64 << 6,
            "r" => 1u64 << 7,
            "zl" => 1u64 << 8,
            "zr" => 1u64 << 9,
            "plus" | "start" => 1u64 << 10,
            "minus" | "select" => 1u64 << 11,
            "" => continue,
            other => return Err(usage(&format!("unknown button: {}", other))),
        };
        mask |= bit;
    }
    Ok(mask)
}

fn format_value(value: u64, width: u32) -> String {
    match width {
        1 => format!("{} (0x{:02X})", value as u8, value as u8),
        2 => format!("{} (0x{:04X})", value as u16, value as u16),
        8 => format!("{} (0x{:016X})", value, value),
        _ => format!("{} (0x{:08X})", value as u32, value as u32),
    }
}

/// The console logs how many regions it could not read ("dropped") and how many
/// reads it had to retry smaller; without this a 0-hit scan looks like a missing
/// value even when nothing was actually examined.
/// Explains a failed scan: the two causes an operator can act on are "more hits
/// than the console can hold" and "the console could not read that memory".
fn print_scan_failure(st: &crate::protocol::Status) {
    if st.scan_state != scan_state::ERROR {
        return;
    }
    eprintln!("scan failed (result=0x{:08X})", st.last_result);
    eprintln!("  - too many hits for the console (it keeps ~150k): narrow the range");
    eprintln!("    e.g. --scope custom --range 0x<heap>..0x<heap_end>, or use the PC-side scan:");
    eprintln!("    'nxus scan unknown --size 4 --scope custom --range ...'");
    eprintln!("  - or the memory could not be read: check the 'dropped=' line above");
}

fn print_scan_stats(client: &NxusClient) {
    if let Ok(log) = client.log() {
        if let Some(line) = log.lines().rev().find(|l| l.contains("scan done")) {
            println!("console: {}", line.trim());
        }
    }
}

fn scan_state_name(state: u32) -> &'static str {
    match state {
        scan_state::IDLE => "idle",
        scan_state::RUNNING => "running",
        scan_state::DONE => "done",
        scan_state::ERROR => "error",
        scan_state::CANCELLED => "cancelled",
        _ => "unknown",
    }
}

fn break_kind_name(kind: u32) -> &'static str {
    break_kind::name(kind)
}

fn print_ptrscan_chains(chains: &[PtrChain], truncated: bool, source: &str, opts: &Opts) -> Result<()> {
    if chains.is_empty() {
        println!("no pointer chain found (try --depth 4, a larger --max-offset, or --pc)");
        return Ok(());
    }
    if truncated {
        println!("({} chains - TRUNCATED by {}; narrow --max-offset or raise --max)", chains.len(), source);
    }
    for (i, chain) in chains.iter().enumerate() {
        let steps: String = chain.steps.iter().map(|s| format!(" +{:#x}", s)).collect();
        println!("[{}] main+{:#x}{} +{:#x}", i, chain.root_offset, steps, chain.final_offset);
    }
    if let Some(value) = opts.num("cheat-value") {
        let width = opts.num("width").unwrap_or(4) as u32;
        let is_32bit = !opts.has("64bit");
        let text = crate::dump::format_cheat(&chains[0], value, width, is_32bit, "Nxus pointer chain");
        if let Some(path) = opts.flag("out") {
            std::fs::write(path, &text).map_err(|e| NxusError { message: e.to_string(), result: None })?;
            println!("wrote {}", path);
        } else {
            print!("{}", text);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    }

    /// The 32-bit ASLR window that Atmosphère gives an AArch32 title.
    #[test]
    fn aarch32_space_is_the_high_half_below_2gib() {
        assert!(!in_aarch32_space(0x0070_0000)); // MockSwitch MAIN_BASE (64-bit)
        assert!(!in_aarch32_space(0x07FF_FFFF));
        assert!(in_aarch32_space(0x0800_0000));
        assert!(in_aarch32_space(0x1B00_4000)); // MHXX
        assert!(in_aarch32_space(0x1F00_0000 - 4));
        assert!(!in_aarch32_space(0x8000_0000)); // 64-bit ppc/heap space
    }

    /// Atmosphère masks M[4] away, so MHXX's context alone looks like AArch64;
    /// the T bit survives, so a Thumb thread is still identified exactly.
    #[test]
    fn masked_cpsr_needs_the_bytes_to_identify_arm32() {
        assert_eq!(mode_from_context(0x1B00_4000, 0x6000_0000), DisasmMode::Arm64);
        assert_eq!(mode_from_context(0x1B00_4000, 0x6000_0020), DisasmMode::Thumb);
        assert_eq!(mode_from_context(0x1_0000_0000, 0x6000_0000), DisasmMode::Arm64);
        // An unmasked AArch32 context is still recognised on its own.
        assert_eq!(mode_from_context(0x1B00_4000, 0x6000_0010), DisasmMode::Arm32);
    }

    /// MHXX-style AArch32/ARM code: every word carries an AL condition nibble,
    /// which AArch64 never uses - even though the CPSR says nothing useful.
    #[test]
    fn arm32_code_is_recognised_from_the_0xe_nibble() {
        // push {r11,lr}; mov r0,r0; ldr r0,[pc,#-4]; bx lr
        let code = words(&[
            0x00, 0x48, 0x2D, 0xE9,
            0x00, 0x00, 0xA0, 0xE1,
            0x04, 0xF0, 0x1F, 0xE5,
            0x1E, 0xFF, 0x2F, 0xE1,
        ]);
        assert_eq!(mode_from_words(0x1B00_4000, &code, DisasmMode::Arm64), DisasmMode::Arm32);
        // ... and the address space alone is enough when the bytes cannot tell.
        let zeros = words(&[0u8; 16]);
        assert_eq!(mode_from_words(0x1B00_4000, &zeros, DisasmMode::Arm64), DisasmMode::Arm32);
    }

    /// MockSwitch's 0x00700000 image is AArch64 code: no word has an AL
    /// condition nibble, and each one decodes as a real AArch64 instruction.
    #[test]
    fn aarch64_code_is_recognised_from_the_decoder() {
        // str w1,[x0,#4]; add x0,x0,#1; nop; ret
        let code = words(&[
            0x01, 0x04, 0x00, 0xB9,
            0x00, 0x04, 0x00, 0x91,
            0x1F, 0x20, 0x03, 0xD5,
            0xC0, 0x03, 0x5F, 0xD6,
        ]);
        assert_eq!(mode_from_words(0x0070_0000, &code, DisasmMode::Arm64), DisasmMode::Arm64);
        // The bytes beat both the masked CPSR and the address space.
        assert_eq!(mode_from_words(0x1B00_4000, &code, DisasmMode::Arm32), DisasmMode::Arm64);
        // All-zero words (the mock's padding) keep the CPSR-derived answer.
        let zeros = words(&[0u8; 16]);
        assert_eq!(mode_from_words(0x0071_2344, &zeros, DisasmMode::Arm32), DisasmMode::Arm32);
        assert_eq!(mode_from_words(0x0071_2344, &zeros, DisasmMode::Arm64), DisasmMode::Arm64);
    }
}

