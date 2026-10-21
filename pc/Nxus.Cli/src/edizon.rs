//! EdiZon-SE / PointerSearcher-SE dump (`EDZN` / `eFZN`) support.
//!
//! EdiZon-SE writes two kinds of files with the same 135-byte `data_header_t`
//! (`include/types.h`):
//!   - address/value dumps (`dumpType = 'A'` / `'D'`), and
//!   - pointer-search dumps (`dumpType = 'P'`), which `MemoryDump.java`-style
//!     tools and PointerSearcher-SE read as a flat array of
//!     `(u64 source_address, u64 target_value)` pairs.
//!
//! This module understands the pointer-search flavour used by
//! PointerSearcher-SE's `NoexsDumpDataReader.cs`:
//!
//! ```text
//!   0x00 .. 0x87 : 135-byte EdiZon data_header_t (magic is the only fixed part)
//!   0x87 .. 0xAF : 40-byte prefix, little-endian u64 x 5:
//!                  main_base, main_end, heap_base, heap_end, target
//!   0xAF .. EOF  : (u64 src_addr, u64 val) pairs, or LZ8-compressed bytes
//! ```
//!
//! Magic values (little-endian u32 at offset 0):
//!   * `EDZN` = 0x4E5A4445 - uncompressed
//!   * `eFZN` = 0x4E5A4665 - LZ8 compressed
//!   * `FDZN` = 0x4E5A4446 - uncompressed with extra data
//!   * `fFZN` = 0x4E5A4666 - LZ8 compressed with extra data
//!
//! The LZ8 codec is the exact one from EdiZon-SE `source/guis/lz.cpp` (also
//! re-implemented in `NoexsDumpDataReader.cs`): each token byte splits into a
//! 4-bit `front` (literal count) and `back` (block distance - 1), describing an
//! 8-byte output block.
//!
//! Everything here is read-only with respect to the console: these files are
//! produced by `MemoryDump::save` / `export_ndmp_to_edizon`, so the whole
//! PointerSearcher-SE interop path works offline.

use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::dump::{MemoryDump, PtrScanOptions, PtrScanResult};
use crate::protocol::{PtrChain, MEMTYPE_HEAP, PERM_R, PERM_W};

pub const MAGIC_EDZN: u32 = 0x4E5A_4445; // "EDZN", uncompressed
pub const MAGIC_EFZN: u32 = 0x4E5A_4665; // "eFZN", LZ8 compressed
pub const MAGIC_FDZN: u32 = 0x4E5A_4446; // "FDZN", uncompressed + extra data
pub const MAGIC_FFZN: u32 = 0x4E5A_4666; // "fFZN", LZ8 compressed + extra data

/// EdiZon-SE `data_header_t` size (see `include/types.h`, `__attribute__((packed))`).
pub const EDIZON_HEADER_SIZE: u64 = 135;
/// The five base addresses EdiZon/PointerSearcher write right after the header.
pub const EDIZON_PREFIX_SIZE: u64 = 40;
/// First byte of the pair table.
pub const EDIZON_DATA_OFFSET: u64 = EDIZON_HEADER_SIZE + EDIZON_PREFIX_SIZE;

#[inline]
fn is_edizon_magic(magic: u32) -> bool {
    matches!(magic, MAGIC_EDZN | MAGIC_EFZN | MAGIC_FDZN | MAGIC_FFZN)
}

/// True when `path` starts with one of the four EdiZon/PointerSearcher magics.
///
/// A missing or unreadable file is simply "not an EdiZon dump"; the caller falls
/// back to the NDMP loader which reports the real I/O error.
pub fn is_edizon_file(path: &str) -> bool {
    let mut head = [0u8; 4];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut head))
        .map(|_| is_edizon_magic(u32::from_le_bytes(head)))
        .unwrap_or(false)
}

/// Decompress an LZ8 stream, never producing more than `max_out` bytes.
///
/// Mirrors `LZ_Uncompress()` in EdiZon-SE (`source/guis/lz.cpp:77-101`) and
/// `NoexsDumpDataReader.LZ_Uncompress()` (`NoexsDumpDataReader.cs:294-317`),
/// but every read is bounds-checked:
///   * a `front == 8` token is followed by 8 literal bytes;
///   * otherwise `front` literal bytes are copied and the remaining
///     `8 - front` bytes are copied from `out.len() - (back + 1) * 8`;
///   * when that history is not available yet (a truncated or corrupt stream)
///     the missing bytes are zero-filled instead of reading out of bounds.
pub fn lz8_decompress(input: &[u8], max_out: usize) -> Vec<u8> {
    // Only reserve a modest amount up front: `max_out` can be the 8x worst-case
    // bound of a large compressed file, and reserving that eagerly would OOM
    // long before the real output size is known.
    let mut out: Vec<u8> = Vec::with_capacity(max_out.min(1 << 20).max(8));
    let mut ip = 0usize;

    while ip < input.len() && out.len() < max_out {
        let token = input[ip];
        ip += 1;
        let front = (token >> 4) as usize;
        let back = (token & 0x0F) as usize;
        let block_start = out.len();

        if front >= 8 {
            // Literal 8-byte block (the canonical `0x80` token).
            let avail = (input.len() - ip).min(8);
            out.extend_from_slice(&input[ip..ip + avail]);
            ip += avail;
            if avail < 8 {
                break; // truncated stream: keep what we decoded
            }
        } else {
            let avail = (input.len() - ip).min(front);
            out.extend_from_slice(&input[ip..ip + avail]);
            ip += avail;
            if avail < front {
                break; // truncated literal
            }
            let distance = (back + 1) * 8;
            for i in front..8 {
                let from = block_start as isize - distance as isize + i as isize;
                let byte = if from >= 0 {
                    let from = from as usize;
                    // `from` always stays below `block_start` for a valid
                    // distance >= 8, but the check keeps corrupt streams safe.
                    if from < out.len() { out[from] } else { 0 }
                } else {
                    0
                };
                out.push(byte);
            }
        }
    }

    out.truncate(max_out);
    out
}

/// A parsed EdiZon-SE / PointerSearcher-SE pointer dump.
#[derive(Debug, Clone, Default)]
pub struct EdizonDump {
    pub magic: u32,
    pub compressed: bool,
    pub main_base: u64,
    pub main_end: u64,
    pub heap_base: u64,
    pub heap_end: u64,
    pub target: u64,
    /// `(source address, value)` pairs exactly as stored in the file.
    pub pairs: Vec<(u64, u64)>,
}

impl EdizonDump {
    /// Load an `EDZN` / `eFZN` / `FDZN` / `fFZN` pointer dump from disk.
    pub fn load(path: &str) -> std::io::Result<EdizonDump> {
        let mut file = File::open(path)?;
        let file_len = file.metadata()?.len();
        if file_len < EDIZON_DATA_OFFSET {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("EdiZon dump too short ({} bytes)", file_len),
            ));
        }

        let mut header = [0u8; EDIZON_HEADER_SIZE as usize];
        file.read_exact(&mut header)?;
        let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
        if !is_edizon_magic(magic) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("not an EdiZon-SE dump (magic={:#010x})", magic),
            ));
        }
        let compressed = matches!(magic, MAGIC_EFZN | MAGIC_FFZN);

        // The 40-byte prefix uses the order PointerSearcher-SE expects,
        // regardless of the order of the fields in the EdiZon header itself.
        file.seek(SeekFrom::Start(EDIZON_HEADER_SIZE))?;
        let mut prefix = [0u8; EDIZON_PREFIX_SIZE as usize];
        file.read_exact(&mut prefix)?;
        let main_base = u64::from_le_bytes(prefix[0..8].try_into().unwrap());
        let main_end = u64::from_le_bytes(prefix[8..16].try_into().unwrap());
        let heap_base = u64::from_le_bytes(prefix[16..24].try_into().unwrap());
        let heap_end = u64::from_le_bytes(prefix[24..32].try_into().unwrap());
        let target = u64::from_le_bytes(prefix[32..40].try_into().unwrap());

        let payload_len = (file_len - EDIZON_DATA_OFFSET) as usize;
        let mut payload = vec![0u8; payload_len];
        file.read_exact(&mut payload)?;

        let mut table = if compressed {
            // `dataSize` (header offset 5) holds the *uncompressed* byte count;
            // EdiZon rewrites it before flushing every compressed chunk.  Fall
            // back to the theoretical LZ8 worst case (8 output bytes for a
            // one-byte back-reference token) when the header is not usable.
            let declared = u32::from_le_bytes(header[5..9].try_into().unwrap()) as usize;
            let hard_cap = payload_len.saturating_mul(8).saturating_add(8);
            // The pair table is a whole number of 16-byte records, so a header
            // size that is not a multiple of 16 is not describing the
            // uncompressed byte count (e.g. `fFZN` extra data overlaps it).
            let max_out = if declared >= 16 && declared % 16 == 0 && declared <= hard_cap {
                declared
            } else {
                hard_cap
            };
            lz8_decompress(&payload, max_out)
        } else {
            payload
        };

        // Ignore a trailing partial record instead of failing the whole dump.
        table.truncate(table.len() - table.len() % 16);
        let mut pairs = Vec::with_capacity(table.len() / 16);
        for record in table.chunks_exact(16) {
            let src = u64::from_le_bytes(record[0..8].try_into().unwrap());
            let val = u64::from_le_bytes(record[8..16].try_into().unwrap());
            pairs.push((src, val));
        }

        Ok(EdizonDump {
            magic,
            compressed,
            main_base,
            main_end,
            heap_base,
            heap_end,
            target,
            pairs,
        })
    }
}

#[inline]
fn in_range(value: u64, base: u64, end: u64) -> bool {
    base != end && value >= base && value < end
}

/// Reverse pointer scan over an EdiZon dump.
///
/// EdiZon already stores only `(source, value)` pointer pairs, so the index is
/// the pairs themselves.  Sorting by value allows the same binary-searched
/// backward DFS as `dump::ptrscan_dump`, reaching static roots in
/// `[module_base, module_end)` (defaults to the dump's `main` range).
///
/// `opts.target == 0` means "use the target address saved in the dump", which
/// is what makes `nxus ptrscan auto --dump game.dmp` work.
pub fn ptrscan_edizon(
    dump: &EdizonDump,
    opts: &PtrScanOptions,
    cancel: &AtomicBool,
) -> PtrScanResult {
    let target = if opts.target != 0 { opts.target } else { dump.target };
    let module_base = if opts.module_base != 0 { opts.module_base } else { dump.main_base };
    let module_size = if opts.module_size != 0 {
        opts.module_size
    } else {
        dump.main_end.saturating_sub(dump.main_base)
    };
    let module_end = module_base.saturating_add(module_size);

    let max_depth = opts.max_depth.clamp(1, 8);
    let max_offset = opts.max_offset as u64;

    let mut ptrs: Vec<(u64, u64)> = dump
        .pairs
        .iter()
        .map(|&(src, val)| (val, src))
        .collect();
    ptrs.sort_unstable();
    let pointers_indexed = ptrs.len();

    let mut chains: Vec<PtrChain> = Vec::new();
    let mut truncated = false;
    if target == 0 || cancel.load(Ordering::Relaxed) {
        return PtrScanResult { chains, truncated, pointers_indexed };
    }

    let mut rev_steps: Vec<u32> = Vec::new();
    let mut visited: Vec<u64> = vec![target];

    walk_back(
        &ptrs,
        target,
        1,
        max_depth,
        max_offset,
        module_base,
        module_end,
        0,
        &mut rev_steps,
        &mut visited,
        &mut chains,
        opts.max_results.max(1),
        &mut truncated,
        cancel,
    );

    chains.sort_by(|a, b| {
        a.steps
            .len()
            .cmp(&b.steps.len())
            .then_with(|| a.root_offset.cmp(&b.root_offset))
            .then_with(|| a.steps.cmp(&b.steps))
            .then_with(|| a.final_offset.cmp(&b.final_offset))
    });

    PtrScanResult {
        chains,
        truncated,
        pointers_indexed,
    }
}

/// Identical traversal to the nested `walk_back` in `dump::ptrscan_dump`.
///
/// Kept as a copy instead of shared code so the existing NDMP scanner stays
/// byte-for-byte unchanged; the two only differ in where the pointer index
/// comes from.
#[allow(clippy::too_many_arguments)]
fn walk_back(
    ptrs: &[(u64, u64)],
    cur_addr: u64,
    depth: u32,
    max_depth: u32,
    max_offset: u64,
    module_base: u64,
    module_end: u64,
    final_offset: u32,
    rev_steps: &mut Vec<u32>,
    visited: &mut Vec<u64>,
    chains: &mut Vec<PtrChain>,
    max_results: usize,
    truncated: &mut bool,
    cancel: &AtomicBool,
) {
    if *truncated || cancel.load(Ordering::Relaxed) {
        return;
    }
    let low = cur_addr.saturating_sub(max_offset);
    let start_idx = ptrs.partition_point(|&(target_val, _)| target_val < low);
    let end_idx = ptrs.partition_point(|&(target_val, _)| target_val <= cur_addr);

    for &(target_val, src_addr) in &ptrs[start_idx..end_idx] {
        if chains.len() >= max_results {
            *truncated = true;
            return;
        }
        let off = (cur_addr - target_val) as u32;
        let cur_final = if depth == 1 { off } else { final_offset };
        if depth > 1 {
            rev_steps.push(off);
        }

        if src_addr >= module_base && src_addr < module_end {
            let mut steps = rev_steps.clone();
            steps.reverse();
            chains.push(PtrChain {
                root_offset: (src_addr - module_base) as u32,
                final_offset: cur_final,
                steps,
            });
        } else if depth < max_depth && !visited.contains(&src_addr) {
            visited.push(src_addr);
            walk_back(
                ptrs,
                src_addr,
                depth + 1,
                max_depth,
                max_offset,
                module_base,
                module_end,
                cur_final,
                rev_steps,
                visited,
                chains,
                max_results,
                truncated,
                cancel,
            );
            visited.pop();
        }

        if depth > 1 {
            rev_steps.pop();
        }
    }
}

/// Find the heap range to store in the 40-byte prefix.
///
/// Prefer real `MEMTYPE_HEAP` mappings; when the dump has none (older captures,
/// hand-built test dumps) fall back to every readable+writable mapping that does
/// not overlap `[main_base, main_end)`.
fn infer_heap_range(ndmp: &MemoryDump, main_base: u64, main_end: u64) -> (u64, u64) {
    let mut lo = u64::MAX;
    let mut hi = 0u64;
    for info in &ndmp.infos {
        if info.memory_type == MEMTYPE_HEAP && info.size != 0 {
            lo = lo.min(info.base);
            hi = hi.max(info.base.saturating_add(info.size));
        }
    }
    if lo != u64::MAX {
        return (lo, hi);
    }

    lo = u64::MAX;
    hi = 0u64;
    for info in &ndmp.infos {
        if info.size == 0 || (info.perm & PERM_R) == 0 || (info.perm & PERM_W) == 0 {
            continue;
        }
        let end = info.base.saturating_add(info.size);
        if end <= main_base || info.base >= main_end {
            lo = lo.min(info.base);
            hi = hi.max(end);
        }
    }
    if lo == u64::MAX {
        (0, 0)
    } else {
        (lo, hi)
    }
}

#[inline]
fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[inline]
fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Convert a Nxus/jnoexs `NDMP` dump into a PointerSearcher-SE / EdiZon-SE
/// compatible uncompressed `EDZN` file.
///
/// `main` comes from `main_override` or `MemoryDump::infer_main_module()`, and
/// `heap` from `heap_override` or the dump's heap mappings.  Pointer candidates
/// are the 32-bit and 64-bit values stored inside those ranges whose value also
/// lands inside them, which covers both 32-bit and 64-bit titles without a
/// width guess.
///
/// Returns the number of `(source, value)` pairs written.
pub fn export_ndmp_to_edizon(
    ndmp: &MemoryDump,
    target: u64,
    main_override: Option<(u64, u64)>,
    heap_override: Option<(u64, u64)>,
    out_path: &str,
) -> std::io::Result<usize> {
    let (main_base, main_size) = main_override.unwrap_or_else(|| ndmp.infer_main_module());
    let main_end = main_base.saturating_add(main_size);
    let (heap_base, heap_end) = heap_override.unwrap_or_else(|| infer_heap_range(ndmp, main_base, main_end));

    // Collect every pointer-looking value stored in main/heap.  A 4-byte pass
    // finds 32-bit titles; the 8-byte pass finds 64-bit pointers (including
    // 64-bit titles whose main module happens to sit below 4 GiB).
    let mut pairs: Vec<(u64, u64)> = Vec::new();
    for idx in &ndmp.indices {
        let start = (idx.file_pos - ndmp.data_base) as usize;
        let len = idx.size as usize;
        let slice = match ndmp.data.get(start..start + len) {
            Some(slice) => slice,
            None => continue,
        };
        let mut off = 0usize;
        while off + 4 <= slice.len() {
            let src = idx.addr + off as u64;
            if in_range(src, main_base, main_end) || in_range(src, heap_base, heap_end) {
                let val32 = u32::from_le_bytes(slice[off..off + 4].try_into().unwrap()) as u64;
                if val32 != 0
                    && (in_range(val32, main_base, main_end) || in_range(val32, heap_base, heap_end))
                {
                    pairs.push((src, val32));
                }
                if off + 8 <= slice.len() {
                    let val64 = u64::from_le_bytes(slice[off..off + 8].try_into().unwrap());
                    if val64 != 0
                        && (in_range(val64, main_base, main_end)
                            || in_range(val64, heap_base, heap_end))
                    {
                        pairs.push((src, val64));
                    }
                }
            }
            off += 4;
        }
    }
    // PointerSearcher-SE binary-searches this table by source address.
    pairs.sort_unstable();
    pairs.dedup();

    let table_bytes = pairs.len().checked_mul(16).filter(|&n| n <= u32::MAX as usize);
    let table_bytes = match table_bytes {
        Some(n) => n,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "too many pointer pairs for the EdiZon header",
            ))
        }
    };

    let mut header = [0u8; EDIZON_HEADER_SIZE as usize];
    put_u32(&mut header, 0, MAGIC_EDZN);
    header[4] = b'D';
    put_u32(&mut header, 5, table_bytes as u32);
    put_u64(&mut header, 37, heap_base); // heapBaseAddress
    put_u64(&mut header, 45, heap_end.saturating_sub(heap_base)); // heapSize
    put_u64(&mut header, 53, main_base); // mainBaseAddress
    put_u64(&mut header, 61, main_size); // mainSize
    header[134] = b'@';

    let mut prefix = [0u8; EDIZON_PREFIX_SIZE as usize];
    put_u64(&mut prefix, 0, main_base);
    put_u64(&mut prefix, 8, main_end);
    put_u64(&mut prefix, 16, heap_base);
    put_u64(&mut prefix, 24, heap_end);
    put_u64(&mut prefix, 32, target);

    let mut out = BufWriter::new(File::create(out_path)?);
    out.write_all(&header)?;
    out.write_all(&prefix)?;
    for &(src, val) in &pairs {
        out.write_all(&src.to_le_bytes())?;
        out.write_all(&val.to_le_bytes())?;
    }
    out.flush()?;

    Ok(pairs.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dump::{DumpIndex, NDMP_DATA_OFFSET};
    use crate::protocol::{MemoryInfo, PERM_X};

    fn tmp_path(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("nxus_edizon_{}_{}.dmp", std::process::id(), name))
            .to_string_lossy()
            .to_string()
    }

    fn info(base: u64, size: u64, memory_type: u32, perm: u32) -> MemoryInfo {
        MemoryInfo { base, size, memory_type, attr: 0, perm }
    }

    /// main+0x10 -> heap+0x100 -> heap+0x200, with `target = heap+0x204`.
    fn sample_ndmp() -> (MemoryDump, u64, u64, u64) {
        let main_base = 0x1_0000_0000u64;
        let heap_base = 0x2_0000_0000u64;
        let target = heap_base + 0x204;

        let mut main_seg = vec![0u8; 0x1000];
        let mut heap_seg = vec![0u8; 0x1000];
        main_seg[0x10..0x18].copy_from_slice(&(heap_base + 0x100).to_le_bytes());
        heap_seg[0x100..0x108].copy_from_slice(&(heap_base + 0x200).to_le_bytes());

        let mut data = Vec::new();
        let pos_main = NDMP_DATA_OFFSET;
        data.extend_from_slice(&main_seg);
        let pos_heap = NDMP_DATA_OFFSET + data.len() as u64;
        data.extend_from_slice(&heap_seg);

        let dump = MemoryDump {
            tid: 0x0100_0000_0000_0000,
            infos: vec![
                info(main_base, 0x1000, 3, PERM_R | PERM_X),
                info(heap_base, 0x1000, MEMTYPE_HEAP, PERM_R | PERM_W),
            ],
            indices: vec![
                DumpIndex { addr: main_base, file_pos: pos_main, size: 0x1000 },
                DumpIndex { addr: heap_base, file_pos: pos_heap, size: 0x1000 },
            ],
            data_base: NDMP_DATA_OFFSET,
            data,
        };
        (dump, main_base, heap_base, target)
    }

    #[test]
    fn export_ndmp_to_edzn_round_trips_through_the_loader() {
        let (ndmp, main_base, heap_base, target) = sample_ndmp();
        let path = tmp_path("roundtrip");

        let written = export_ndmp_to_edizon(&ndmp, target, None, None, &path)
            .expect("export EDZN");
        assert!(written >= 2, "main and heap pointers must be exported");
        assert!(is_edizon_file(&path));
        assert!(!is_edizon_file(&tmp_path("does_not_exist")));

        let dump = EdizonDump::load(&path).expect("load EDZN");
        let _ = std::fs::remove_file(&path);

        assert_eq!(dump.magic, MAGIC_EDZN);
        assert!(!dump.compressed);
        assert_eq!(dump.main_base, main_base);
        assert_eq!(dump.main_end, main_base + 0x1000);
        assert_eq!(dump.heap_base, heap_base);
        assert_eq!(dump.heap_end, heap_base + 0x1000);
        assert_eq!(dump.target, target);
        assert!(dump.pairs.contains(&(main_base + 0x10, heap_base + 0x100)));
        assert!(dump.pairs.contains(&(heap_base + 0x100, heap_base + 0x200)));

        // PointerSearcher-SE binary-searches by source address.
        assert!(dump.pairs.windows(2).all(|w| w[0].0 <= w[1].0));
    }

    /// Exact LZ8 encoder from EdiZon-SE `lz.cpp` / `NoexsDumpDataReader.cs`,
    /// used only to create realistic `eFZN` fixtures.
    fn lz8_compress_reference(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut inpos = 0usize;
        while inpos + 8 <= input.len() {
            let mut front = 8usize;
            let mut back = 0usize;
            'search: for frnt in 0..=8usize {
                for bak in 1..=16usize {
                    if inpos < bak * 8 {
                        break;
                    }
                    let mut matched = true;
                    for i in frnt..8 {
                        if input[inpos - bak * 8 + i] != input[inpos + i] {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        front = frnt;
                        back = bak - 1;
                        break 'search;
                    }
                }
            }
            out.push(((front as u8) << 4) | back as u8);
            out.extend_from_slice(&input[inpos..inpos + front]);
            inpos += 8;
        }
        out
    }

    #[test]
    fn recognises_every_edizon_magic_but_not_ndmp() {
        for (magic, name) in [
            (MAGIC_EDZN, "magic_edzn"),
            (MAGIC_EFZN, "magic_efzn"),
            (MAGIC_FDZN, "magic_fdzn"),
            (MAGIC_FFZN, "magic_ffzn"),
        ] {
            let mut bytes = [0u8; EDIZON_DATA_OFFSET as usize];
            put_u32(&mut bytes, 0, magic);
            let path = tmp_path(name);
            std::fs::write(&path, &bytes).expect("write magic fixture");
            assert!(is_edizon_file(&path));
            let dump = EdizonDump::load(&path).expect("load magic fixture");
            let _ = std::fs::remove_file(&path);
            assert_eq!(dump.magic, magic);
            assert_eq!(dump.compressed, matches!(magic, MAGIC_EFZN | MAGIC_FFZN));
            assert!(dump.pairs.is_empty());
        }

        // jnoexs NDMP uses the opposite byte order and must not be mistaken
        // for an EdiZon dump.
        let path = tmp_path("magic_ndmp");
        std::fs::write(&path, crate::dump::NDMP_MAGIC.to_be_bytes()).expect("write NDMP magic");
        assert!(!is_edizon_file(&path));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn lz8_decompress_matches_the_edizon_codec() {
        // A literal token followed by a back-reference to the previous block.
        let literal: [u8; 9] = [0x80, 1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(lz8_decompress(&literal, 8), vec![1, 2, 3, 4, 5, 6, 7, 8]);

        let mut stream = literal.to_vec();
        stream.push(0x00); // front=0, back=0 => repeat the 8 bytes before outpos
        assert_eq!(
            lz8_decompress(&stream, 16),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]
        );

        // Round-trip a realistic pair table (>= 16 blocks so the encoder's
        // refill window is exercised as well).
        let mut raw = Vec::new();
        for i in 0..64u64 {
            raw.extend_from_slice(&(0x1_0000_0000u64 + i * 0x40).to_le_bytes());
            raw.extend_from_slice(&(0x2_0000_0000u64 + i * 0x20).to_le_bytes());
        }
        let compressed = lz8_compress_reference(&raw);
        assert_eq!(lz8_decompress(&compressed, raw.len()), raw);

        // A truncated stream must not panic or over-read.
        assert!(lz8_decompress(&[0x80, 1, 2], 64).len() <= 64);
    }

    #[test]
    fn loads_an_efzn_dump_through_lz8() {
        let mut table = Vec::new();
        for i in 0..32u64 {
            table.extend_from_slice(&(0x1_0000_0000u64 + i * 0x10).to_le_bytes());
            table.extend_from_slice(&(0x2_0000_0000u64 + i * 0x20).to_le_bytes());
        }
        let compressed = lz8_compress_reference(&table);

        let mut file = Vec::new();
        let mut header = [0u8; EDIZON_HEADER_SIZE as usize];
        put_u32(&mut header, 0, MAGIC_EFZN);
        header[4] = b'P';
        put_u32(&mut header, 5, table.len() as u32); // uncompressed size
        header[134] = b'@';
        file.extend_from_slice(&header);

        let mut prefix = [0u8; EDIZON_PREFIX_SIZE as usize];
        put_u64(&mut prefix, 0, 0x1_0000_0000);
        put_u64(&mut prefix, 8, 0x1_0000_1000);
        put_u64(&mut prefix, 16, 0x2_0000_0000);
        put_u64(&mut prefix, 24, 0x2_0000_1000);
        put_u64(&mut prefix, 32, 0x2_0000_0020);
        file.extend_from_slice(&prefix);
        file.extend_from_slice(&compressed);

        let path = tmp_path("efzn");
        std::fs::write(&path, &file).expect("write eFZN fixture");
        let dump = EdizonDump::load(&path).expect("load eFZN");
        let _ = std::fs::remove_file(&path);

        assert_eq!(dump.magic, MAGIC_EFZN);
        assert!(dump.compressed);
        assert_eq!(dump.target, 0x2_0000_0020);
        assert_eq!(dump.pairs.len(), 32);
        assert_eq!(dump.pairs[0], (0x1_0000_0000, 0x2_0000_0000));
        assert_eq!(dump.pairs[31], (0x1_0000_0000 + 31 * 0x10, 0x2_0000_0000 + 31 * 0x20));
    }

    #[test]
    fn ptrscan_edizon_finds_the_same_chain_as_ptrscan_dump() {
        let main_base = 0x1_0000_0000u64;
        let heap_base = 0x2_0000_0000u64;
        let target = heap_base + 0x204;
        let dump = EdizonDump {
            magic: MAGIC_EDZN,
            compressed: false,
            main_base,
            main_end: main_base + 0x1000,
            heap_base,
            heap_end: heap_base + 0x1000,
            target,
            pairs: vec![
                (main_base + 0x10, heap_base + 0x100),
                (heap_base + 0x100, heap_base + 0x200),
            ],
        };

        let cancel = AtomicBool::new(false);
        let res = ptrscan_edizon(
            &dump,
            &PtrScanOptions {
                target,
                module_base: main_base,
                module_size: 0x1000,
                max_depth: 3,
                max_offset: 0x80,
                width: 8,
                max_results: 16,
            },
            &cancel,
        );
        assert_eq!(res.pointers_indexed, 2);
        assert!(!res.chains.is_empty(), "the exported chain must be found");
        assert_eq!(res.chains[0].root_offset, 0x10);
        assert_eq!(res.chains[0].steps, vec![0]);
        assert_eq!(res.chains[0].final_offset, 4);

        // target == 0 means "use the target saved in the dump".
        let auto = ptrscan_edizon(
            &dump,
            &PtrScanOptions {
                target: 0,
                module_base: 0,
                module_size: 0,
                max_depth: 3,
                max_offset: 0x80,
                width: 0,
                max_results: 16,
            },
            &cancel,
        );
        assert_eq!(auto.chains.len(), res.chains.len());
        assert_eq!(auto.chains[0].root_offset, 0x10);

        // An already-cancelled scan must return immediately.
        let cancelled = AtomicBool::new(true);
        let none = ptrscan_edizon(&dump, &PtrScanOptions {
            target,
            module_base: main_base,
            module_size: 0x1000,
            max_depth: 3,
            max_offset: 0x80,
            width: 8,
            max_results: 16,
        }, &cancelled);
        assert!(none.chains.is_empty());
    }

    #[test]
    fn export_ndmp_to_edizon_uses_overrides_and_reports_the_header() {
        let (ndmp, _main_base, heap_base, target) = sample_ndmp();
        let path = tmp_path("override");
        let main_override = (0x1_0000_0000u64, 0x1000u64);

        let written = export_ndmp_to_edizon(
            &ndmp,
            target,
            Some(main_override),
            Some((heap_base, heap_base + 0x1000)),
            &path,
        )
        .expect("export with overrides");
        let bytes = std::fs::read(&path).expect("read exported file");
        let _ = std::fs::remove_file(&path);

        assert_eq!(&bytes[0..4], b"EDZN");
        assert_eq!(bytes[4], b'D');
        assert_eq!(bytes[134], b'@');
        assert_eq!(u32::from_le_bytes(bytes[5..9].try_into().unwrap()) as usize, written * 16);
        assert_eq!(bytes.len(), EDIZON_DATA_OFFSET as usize + written * 16);
        assert_eq!(
            u64::from_le_bytes(bytes[135..143].try_into().unwrap()),
            main_override.0
        );
        assert_eq!(
            u64::from_le_bytes(bytes[167..175].try_into().unwrap()),
            target
        );
    }
}
