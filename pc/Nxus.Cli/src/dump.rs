//! Full RAM dump (jnoexs `NDMP` compatible) and PC-side pointer scanner.
//!
//! Why both live here:
//!   * On the Switch, `nxusPtrScan` has to work inside the sysmodule's 8 MB heap
//!     and over `dmnt:cht` IPC, so intermediate dereference windows are capped at
//!     `0x400` bytes and 20,000 reads (`switch/source/nxus_server.c:241-242`).
//!   * On the PC, we can dump all readable/writable memory (or load a saved `.dmp`
//!     file) and build a sorted reverse-pointer index in RAM. Every hop then uses
//!     binary search (`O(log N)`), allowing arbitrary `--max-offset` (e.g. `0x4000+`)
//!     and depth at every level, and working completely offline.
//!
//! File format (`NDMP`):
//!   Byte-for-byte compatible with jnoexs `MemoryDump.java`:
//!   - `0x00`: u32 BE `0x4E444D50` ("NDMP")
//!   - `0x04`: u64 BE `tid` (Program ID / Title ID)
//!   - `0x0C`: u32 BE `info_count`
//!   - `0x10`: u64 BE `info_ptr` (file offset of MemoryInfo table)
//!   - `0x18`: u32 BE `idx_count`
//!   - `0x1C`: u64 BE `idx_ptr`  (file offset of DumpIndex table)
//!   - `0x24..0x32`: zero padding (raw memory data starts at `0x32`, matching
//!                   `MemoryDump.java:62` `dump.seek(0x32)`)
//!   - `0x32..idx_ptr`: raw little-endian target memory bytes
//!   - `idx_ptr..info_ptr`: `idx_count` × 24B `(addr: u64 BE, file_pos: u64 BE, size: u64 BE)`
//!   - `info_ptr..EOF`: `info_count` × 24B `(addr: u64 BE, size: u64 BE, type: u32 BE, perm: u32 BE)`

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::client::NxusClient;
use crate::pcscan::regions_for_scope;
use crate::protocol::{MemoryInfo, PtrChain, Scope, PERM_R, PERM_X};

pub const NDMP_MAGIC: u32 = 0x4E444D50; // "NDMP"
pub const NDMP_DATA_OFFSET: u64 = 0x32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpIndex {
    pub addr: u64,
    pub file_pos: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct MemoryDump {
    pub tid: u64,
    pub infos: Vec<MemoryInfo>,
    pub indices: Vec<DumpIndex>,
    /// Raw memory bytes concatenated in the same order as `indices`.
    /// For an index `idx`, its slice in `data` starts at `(idx.file_pos - data_base)`.
    pub data_base: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PtrScanOptions {
    pub target: u64,
    pub module_base: u64,
    pub module_size: u64,
    pub max_depth: u32,
    pub max_offset: u32,
    pub width: u32,
    pub max_results: usize,
}

#[derive(Debug, Clone)]
pub struct PtrScanResult {
    pub chains: Vec<PtrChain>,
    pub truncated: bool,
    pub pointers_indexed: usize,
}

impl MemoryDump {
    /// Capture a live memory dump from the console into memory.
    pub fn capture(
        client: &NxusClient,
        scope: Scope,
        begin: u64,
        end: u64,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<MemoryDump, String> {
        let md = client.metadata().map_err(|e| e.to_string())?;
        let count = client.mapping_count().map_err(|e| e.to_string())?;
        let mut offset = 0u64;
        let mut infos = Vec::new();
        while offset < count {
            let page = client.mappings(offset, 512).map_err(|e| e.to_string())?;
            if page.is_empty() {
                break;
            }
            offset += page.len() as u64;
            infos.extend(page);
        }

        let regions = regions_for_scope(client, scope, begin, end)?;
        if regions.is_empty() {
            return Err("no readable memory regions for the requested scope".into());
        }

        let chunk = client.max_read().min(1 << 20).max(4096);

        let total_bytes: u64 = regions.iter().map(|r| r.size).sum();
        let mut done_bytes = 0u64;
        let mut indices = Vec::new();
        let mut data = Vec::new();

        for reg in &regions {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let mut pos = reg.base;
            let reg_end = reg.base + reg.size;
            let mut seg_start_addr = reg.base;
            let mut seg_file_pos = NDMP_DATA_OFFSET + data.len() as u64;
            let mut seg_len = 0u64;

            while pos < reg_end && !cancel.load(Ordering::Relaxed) {
                let want = ((reg_end - pos).min(chunk as u64)) as u32;
                match client.read(pos, want) {
                    Ok(bytes) if !bytes.is_empty() => {
                        let got = bytes.len() as u64;
                        if seg_len == 0 {
                            seg_start_addr = pos;
                            seg_file_pos = NDMP_DATA_OFFSET + data.len() as u64;
                        }
                        data.extend_from_slice(&bytes);
                        seg_len += got;
                        pos += got;
                        done_bytes += got;
                    }
                    _ => {
                        if seg_len > 0 {
                            indices.push(DumpIndex {
                                addr: seg_start_addr,
                                file_pos: seg_file_pos,
                                size: seg_len,
                            });
                            seg_len = 0;
                        }
                        // Retry the failed range in smaller pieces before giving up on
                        // it: advancing by the whole (up to 1 MB) chunk would silently
                        // drop every readable page behind a single unmapped one.
                        let mut step = (want as u64).max(4096);
                        let mut retried = false;
                        while step > 4096 {
                            step /= 2;
                            let mut off = 0u64;
                            let mut progress_made = false;
                            while off < step {
                                let sub = (step - off).min(u32::MAX as u64) as u32;
                                match client.read(pos + off, sub) {
                                    Ok(b) if !b.is_empty() => {
                                        if seg_len == 0 {
                                            seg_start_addr = pos + off;
                                            seg_file_pos = NDMP_DATA_OFFSET + data.len() as u64;
                                        }
                                        data.extend_from_slice(&b);
                                        seg_len += b.len() as u64;
                                        done_bytes += b.len() as u64;
                                        off += b.len() as u64;
                                        progress_made = true;
                                    }
                                    _ => break,     // still failing: keep halving
                                }
                            }
                            if progress_made {
                                retried = true;
                                pos += off;
                                break;
                            }
                        }
                        if !retried {
                            if seg_len > 0 {
                                indices.push(DumpIndex {
                                    addr: seg_start_addr,
                                    file_pos: seg_file_pos,
                                    size: seg_len,
                                });
                                seg_len = 0;
                            }
                            pos = (pos + step).min(reg_end);
                            done_bytes += step.min(reg_end.saturating_sub(pos));
                        }
                    }
                }
                progress(done_bytes, total_bytes);
            }

            if seg_len > 0 {
                indices.push(DumpIndex {
                    addr: seg_start_addr,
                    file_pos: seg_file_pos,
                    size: seg_len,
                });
            }
        }

        indices.sort_by_key(|idx| idx.addr);
        // `is_mapped()` binary-searches `infos`, so keep them ordered by base
        // whatever order the mapping table happened to arrive in.
        infos.sort_by_key(|info| info.base);

        Ok(MemoryDump {
            tid: md.program_id,
            infos,
            indices,
            data_base: NDMP_DATA_OFFSET,
            data,
        })
    }

    /// Write this dump to disk in jnoexs `NDMP` format.
    pub fn save(&self, path: &str) -> std::io::Result<()> {
        let mut file = File::create(path)?;

        // Reserve 0x32 bytes for the header (matches MemoryDump.java:62)
        file.write_all(&[0u8; NDMP_DATA_OFFSET as usize])?;
        file.write_all(&self.data)?;

        let idx_ptr = file.stream_position()?;
        for idx in &self.indices {
            file.write_all(&idx.addr.to_be_bytes())?;
            file.write_all(&idx.file_pos.to_be_bytes())?;
            file.write_all(&idx.size.to_be_bytes())?;
        }

        let info_ptr = file.stream_position()?;
        for info in &self.infos {
            file.write_all(&info.base.to_be_bytes())?;
            file.write_all(&info.size.to_be_bytes())?;
            file.write_all(&info.memory_type.to_be_bytes())?;
            file.write_all(&info.perm.to_be_bytes())?;
        }

        // Write header at offset 0
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&NDMP_MAGIC.to_be_bytes())?;
        file.write_all(&self.tid.to_be_bytes())?;
        file.write_all(&(self.infos.len() as u32).to_be_bytes())?;
        file.write_all(&info_ptr.to_be_bytes())?;
        file.write_all(&(self.indices.len() as u32).to_be_bytes())?;
        file.write_all(&idx_ptr.to_be_bytes())?;
        file.flush()
    }

    /// Load a jnoexs `NDMP` dump file from disk.
    pub fn load(path: &str) -> std::io::Result<MemoryDump> {
        let mut file = File::open(path)?;
        let mut head = [0u8; 36];
        file.read_exact(&mut head)?;

        let magic = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        if magic != NDMP_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("not an NDMP dump (magic={:#010x})", magic),
            ));
        }

        let tid = u64::from_be_bytes(head[4..12].try_into().unwrap());
        let info_count = u32::from_be_bytes(head[12..16].try_into().unwrap()) as usize;
        let info_ptr = u64::from_be_bytes(head[16..24].try_into().unwrap());
        let idx_count = u32::from_be_bytes(head[24..28].try_into().unwrap()) as usize;
        let idx_ptr = u64::from_be_bytes(head[28..36].try_into().unwrap());

        // Bound everything by the real file length: a truncated or corrupted dump must
        // not make us allocate (or read) far beyond the file.
        let file_len = file.metadata()?.len();
        let max_entries = ((file_len / 24) as usize).min(1 << 20);
        if idx_count > max_entries || info_count > max_entries {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("NDMP index out of range ({} indices, {} infos, {} bytes)",
                        idx_count, info_count, file_len),
            ));
        }

        file.seek(SeekFrom::Start(idx_ptr))?;
        let mut indices = Vec::with_capacity(idx_count.min(65536));
        for _ in 0..idx_count {
            let mut buf = [0u8; 24];
            file.read_exact(&mut buf)?;
            let addr = u64::from_be_bytes(buf[0..8].try_into().unwrap());
            let file_pos = u64::from_be_bytes(buf[8..16].try_into().unwrap());
            let size = u64::from_be_bytes(buf[16..24].try_into().unwrap());
            if file_pos.saturating_add(size) > file_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("NDMP entry outside the file (pos={:#x} size={:#x} len={:#x})",
                            file_pos, size, file_len),
                ));
            }
            indices.push(DumpIndex { addr, file_pos, size });
        }

        file.seek(SeekFrom::Start(info_ptr))?;
        let mut infos = Vec::with_capacity(info_count.min(65536));
        for _ in 0..info_count {
            let mut buf = [0u8; 24];
            file.read_exact(&mut buf)?;
            let base = u64::from_be_bytes(buf[0..8].try_into().unwrap());
            let size = u64::from_be_bytes(buf[8..16].try_into().unwrap());
            let memory_type = u32::from_be_bytes(buf[16..20].try_into().unwrap());
            let perm = u32::from_be_bytes(buf[20..24].try_into().unwrap());
            infos.push(MemoryInfo {
                base,
                size,
                memory_type,
                attr: 0,
                perm,
            });
        }

        // `is_mapped()` binary-searches the table: guarantee the sorted order
        // even for files written by an older/hand-rolled encoder.
        infos.sort_by_key(|info| info.base);

        // Load each index's byte range into a contiguous buffer and normalize file_pos
        let total_data: u64 = indices.iter().map(|i| i.size).sum();
        // Individually in-range entries can still overlap and together claim more
        // bytes than the file holds; allocating that would either OOM or fail with
        // a confusing read error.  Reject the file instead.
        let max_data = file_len.saturating_sub(NDMP_DATA_OFFSET);
        if total_data > max_data {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("NDMP data size out of range ({} bytes claimed, {} available)",
                        total_data, max_data),
            ));
        }
        let mut data = vec![0u8; total_data as usize];
        let mut cursor = 0usize;
        let mut norm_indices = Vec::with_capacity(indices.len());
        for idx in &indices {
            file.seek(SeekFrom::Start(idx.file_pos))?;
            let len = idx.size as usize;
            file.read_exact(&mut data[cursor..cursor + len])?;
            norm_indices.push(DumpIndex {
                addr: idx.addr,
                file_pos: NDMP_DATA_OFFSET + cursor as u64,
                size: idx.size,
            });
            cursor += len;
        }
        norm_indices.sort_by_key(|i| i.addr);

        Ok(MemoryDump {
            tid,
            infos,
            indices: norm_indices,
            data_base: NDMP_DATA_OFFSET,
            data,
        })
    }

    pub fn total_bytes(&self) -> u64 {
        self.data.len() as u64
    }

    /// Find the DumpIndex containing `[addr, addr + size)`.
    pub fn find_index(&self, addr: u64, size: u64) -> Option<&DumpIndex> {
        let pos = self.indices.partition_point(|idx| idx.addr <= addr);
        if pos == 0 {
            return None;
        }
        let idx = &self.indices[pos - 1];
        if addr >= idx.addr && addr.saturating_add(size) <= idx.addr.saturating_add(idx.size) {
            Some(idx)
        } else {
            None
        }
    }

    pub fn read(&self, addr: u64, size: usize) -> Option<&[u8]> {
        let idx = self.find_index(addr, size as u64)?;
        let rel = (addr - idx.addr) as usize;
        let start = (idx.file_pos - self.data_base) as usize + rel;
        self.data.get(start..start + size)
    }

    /// True when `[addr, addr + size)` lies inside a readable mapping.
    ///
    /// `ptrscan_dump` calls this once per candidate word (tens of millions of
    /// times), so the mapping table is binary-searched instead of scanned:
    /// `O(M)` per call made the scan quadratic.  `infos` is stored sorted by
    /// base (see `capture`/`load`), which allows an `O(1)` bounds reject plus
    /// a `partition_point` (`O(log M)`) lookup.  A cheap monotonicity probe
    /// keeps hand-built tables that are not sorted on the old linear path, so
    /// they can never suffer a false negative.
    pub fn is_mapped(&self, addr: u64, size: u64) -> bool {
        if self.find_index(addr, size).is_some() {
            return true;
        }
        if self.infos.is_empty() {
            return false;
        }
        let end = addr.saturating_add(size);
        if !self.infos_look_sorted() {
            return self.infos.iter().any(|info| Self::info_contains(info, addr, end));
        }
        // Nothing can be covered below the lowest mapping base.
        if addr < self.infos[0].base {
            return false;
        }
        let pos = self.infos.partition_point(|info| info.base <= addr);
        if pos == 0 {
            return false;
        }
        // Console mapping tables are disjoint, so the entry with the greatest
        // base <= addr is the only candidate.  A few entries are still checked
        // backwards so slightly overlapping tables (aliases, guard pages)
        // behave like the old linear scan while the common miss stays cheap.
        const BACK_STEPS: usize = 4;
        let low = pos.saturating_sub(BACK_STEPS);
        self.infos[low..pos]
            .iter()
            .rev()
            .any(|info| Self::info_contains(info, addr, end))
    }

    #[inline]
    fn info_contains(info: &MemoryInfo, addr: u64, end: u64) -> bool {
        (info.perm & PERM_R) != 0
            && addr >= info.base
            && end <= info.base.saturating_add(info.size)
    }

    /// O(1) monotonicity probe for the binary-search fast path.
    ///
    /// A full `O(M)` sortedness check cannot run in `is_mapped`'s hot path.
    /// Dumps produced by `capture`/`load` are always sorted; this probe only
    /// has to notice the rare hand-built table that is not, in which case the
    /// caller falls back to the linear scan.
    fn infos_look_sorted(&self) -> bool {
        let n = self.infos.len();
        if n < 2 {
            return true;
        }
        let step = ((n - 1) / 4).max(1);
        let mut i = 0usize;
        while i + 1 < n {
            if self.infos[i].base > self.infos[i + 1].base {
                return false;
            }
            i += step;
        }
        self.infos[n - 2].base <= self.infos[n - 1].base
    }

    /// Infer `(main_base, main_size)` from `MemoryInfo` entries when offline.
    pub fn infer_main_module(&self) -> (u64, u64) {
        // Look for the first executable CodeStatic (type=3) or PERM_X mapping,
        // and include immediately following CodeMutable (type=4) segments belonging
        // to the same module.
        let mut main_base = 0u64;
        let mut main_end = 0u64;
        for info in &self.infos {
            if main_base == 0 {
                if (info.perm & PERM_X) != 0 || info.memory_type == 3 {
                    main_base = info.base;
                    main_end = info.base + info.size;
                }
            } else if info.memory_type == 3 || info.memory_type == 4 {
                // Only extend if within a reasonable module span (e.g. 64 MB)
                if info.base + info.size <= main_base + 0x0400_0000 {
                    main_end = main_end.max(info.base + info.size);
                }
            } else if info.perm != 0 {
                break;
            }
        }
        if main_base == 0 {
            if let Some(first) = self.indices.first() {
                return (first.addr, first.size);
            }
        }
        (main_base, main_end.saturating_sub(main_base))
    }
}

/// Run a multi-depth pointer scan on a `MemoryDump` in PC RAM.
///
/// Unlike the console-side scanner (`window_size = 0x400`), this indexes all
/// valid pointers across dumped memory and uses binary search on each backward
/// hop, so `max_offset` applies at EVERY depth without extra reads.
pub fn ptrscan_dump(
    dump: &MemoryDump,
    opts: &PtrScanOptions,
    cancel: &AtomicBool,
) -> PtrScanResult {
    let max_depth = opts.max_depth.clamp(1, 8);
    let max_offset = opts.max_offset as u64;
    let (inferred_base, inferred_size) = dump.infer_main_module();
    let module_base = if opts.module_base != 0 { opts.module_base } else { inferred_base };
    let module_size = if opts.module_size != 0 {
        opts.module_size
    } else if inferred_base == module_base && inferred_size != 0 {
        inferred_size
    } else {
        0x0400_0000
    };
    let module_end = module_base.saturating_add(module_size);

    // Pointer width.  An explicit 4/8 always wins; anything else (notably the
    // CLI default of 0) is inferred: a module base below 4 GiB belongs to a
    // 32-bit title (MHXX etc.), everything else is a 64-bit one.  Guessing
    // wrong used to produce chains that could never resolve.
    let width = match opts.width {
        4 => 4usize,
        8 => 8usize,
        _ => {
            if module_base != 0 && module_base < 0x1_0000_0000 {
                4
            } else {
                8
            }
        }
    };

    // 1. Collect all valid aligned pointer pairs `(target_val, src_addr)`
    let mut ptrs: Vec<(u64, u64)> = Vec::new();
    for idx in &dump.indices {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let start = (idx.file_pos - dump.data_base) as usize;
        let len = idx.size as usize;
        let slice = match dump.data.get(start..start + len) {
            Some(s) => s,
            None => continue,
        };
        if slice.len() < width {
            continue;
        }
        let mut off = 0usize;
        while off + width <= slice.len() {
            let val = if width == 8 {
                u64::from_le_bytes(slice[off..off + 8].try_into().unwrap())
            } else {
                u32::from_le_bytes(slice[off..off + 4].try_into().unwrap()) as u64
            };
            let src_addr = idx.addr + off as u64;
            // 4-byte alignment is accepted even in 64-bit mode: structure
            // members sit on 4-byte boundaries and their address is still a
            // perfectly valid pointer target.
            if val != 0 && val != src_addr && (val % 4 == 0 || (val <= opts.target && opts.target - val <= max_offset)) {
                if dump.is_mapped(val, width as u64) || (val <= opts.target && opts.target - val <= max_offset) {
                    ptrs.push((val, src_addr));
                }
            }
            off += width;
        }
    }

    ptrs.sort_unstable();
    let pointers_indexed = ptrs.len();

    // 2. Backward DFS from `opts.target` down to static roots in `[module_base, module_end)`
    let mut chains: Vec<PtrChain> = Vec::new();
    let mut truncated = false;
    let mut rev_steps: Vec<u32> = Vec::new();
    let mut visited: Vec<u64> = vec![opts.target];

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

    walk_back(
        &ptrs,
        opts.target,
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

/// Format an Atmosphère cheat code block directly on the PC (matches `nxusCheatGenerate` in C).
pub fn format_cheat(chain: &PtrChain, value: u64, value_width: u32, is_32bit: bool, label: &str) -> String {
    let load = if is_32bit { "540F" } else { "580F" };
    let width_nibble = match value_width {
        1 => 1,
        2 => 2,
        4 => 4,
        _ => 8,
    };
    let mut out = format!("[{}]\n", if label.is_empty() { "Nxus pointer chain" } else { label });
    out.push_str(&format!("{}0000 {:08X}\n", load, chain.root_offset));
    for &step in &chain.steps {
        out.push_str(&format!("{}1000 {:08X}\n", load, step));
    }
    if chain.final_offset != 0 {
        out.push_str(&format!("780F0000 {:08X}\n", chain.final_offset));
    }
    out.push_str(&format!(
        "6{:X}0F0000 {:08X} {:08X}\n",
        width_nibble,
        (value >> 32) as u32,
        (value & 0xFFFF_FFFF) as u32
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::PERM_W;

    #[test]
    fn ndmp_round_trip_and_large_offset_ptrscan() {
        let main_base = 0x0070_0000u64;
        let data_base = 0x0078_0000u64;
        let heap_base = 0x3600_0000u64;
        let rec_base = 0x42CA_0000u64;

        let mut data_seg = vec![0u8; 0x2000];
        let mut heap_seg = vec![0u8; 0x4000];
        let mut rec_seg = vec![0u8; 0x3000];

        // Chain: main+0x81000 -> heap+0x100 (+0x2500, > 0x400!) -> rec+0x1DC0 (+4) = 0x42CA1DC4
        let ptr1 = (heap_base + 0x100) as u32;
        data_seg[0x1000..0x1004].copy_from_slice(&ptr1.to_le_bytes());

        let ptr2 = (rec_base + 0x1DC0) as u32;
        heap_seg[0x100 + 0x2500..0x100 + 0x2504].copy_from_slice(&ptr2.to_le_bytes());

        rec_seg[0x1DC4..0x1DC8].copy_from_slice(&6440u32.to_le_bytes());

        let mut all_data = Vec::new();
        let pos0 = NDMP_DATA_OFFSET;
        all_data.extend_from_slice(&data_seg);
        let pos1 = NDMP_DATA_OFFSET + all_data.len() as u64;
        all_data.extend_from_slice(&heap_seg);
        let pos2 = NDMP_DATA_OFFSET + all_data.len() as u64;
        all_data.extend_from_slice(&rec_seg);

        let dump = MemoryDump {
            tid: 0x0100_C380_0049_C000,
            infos: vec![
                MemoryInfo { base: main_base, size: 0x80000, memory_type: 3, attr: 0, perm: PERM_R | PERM_X },
                MemoryInfo { base: data_base, size: 0x2000, memory_type: 4, attr: 0, perm: PERM_R | PERM_W },
                MemoryInfo { base: heap_base, size: 0x4000, memory_type: 5, attr: 0, perm: PERM_R | PERM_W },
                MemoryInfo { base: rec_base, size: 0x3000, memory_type: 5, attr: 0, perm: PERM_R | PERM_W },
            ],
            indices: vec![
                DumpIndex { addr: data_base, file_pos: pos0, size: 0x2000 },
                DumpIndex { addr: heap_base, file_pos: pos1, size: 0x4000 },
                DumpIndex { addr: rec_base, file_pos: pos2, size: 0x3000 },
            ],
            data_base: NDMP_DATA_OFFSET,
            data: all_data,
        };

        let tmp = std::env::temp_dir().join("nxus_test_dump.dmp");
        let path = tmp.to_string_lossy().to_string();
        dump.save(&path).expect("save NDMP");
        let loaded = MemoryDump::load(&path).expect("load NDMP");
        let _ = std::fs::remove_file(&path);

        assert_eq!(loaded.tid, 0x0100_C380_0049_C000);
        assert_eq!(loaded.infos.len(), 4);
        assert_eq!(loaded.indices.len(), 3);
        assert_eq!(loaded.read(rec_base + 0x1DC4, 4), Some(&6440u32.to_le_bytes()[..]));

        let cancel = AtomicBool::new(false);
        let res = ptrscan_dump(
            &loaded,
            &PtrScanOptions {
                target: rec_base + 0x1DC4,
                module_base: main_base,
                module_size: 0x82000,
                max_depth: 3,
                max_offset: 0x3000,
                width: 4,
                max_results: 64,
            },
            &cancel,
        );
        assert!(!res.chains.is_empty(), "should find chain with +0x2500 step");
        assert_eq!(res.chains[0].root_offset, 0x81000);
        assert_eq!(res.chains[0].steps, vec![0x2500]);
        assert_eq!(res.chains[0].final_offset, 4);

        let cheat = format_cheat(&res.chains[0], 9999999, 4, true, "Nxus");
        assert!(cheat.contains("540F0000 00081000"));
        assert!(cheat.contains("540F1000 00002500"));
        assert!(cheat.contains("780F0000 00000004"));
        assert!(cheat.contains("640F0000 00000000 0098967F"));

        // width == 0 means "infer"; the low module base selects the 32-bit layout.
        let auto = ptrscan_dump(
            &loaded,
            &PtrScanOptions {
                target: rec_base + 0x1DC4,
                module_base: main_base,
                module_size: 0x82000,
                max_depth: 3,
                max_offset: 0x3000,
                width: 0,
                max_results: 64,
            },
            &cancel,
        );
        assert!(!auto.chains.is_empty(), "width=0 must infer 4-byte pointers from a <4 GiB module base");
        assert_eq!(auto.chains[0].steps, vec![0x2500]);
    }

    fn info(base: u64, size: u64, memory_type: u32, perm: u32) -> MemoryInfo {
        MemoryInfo { base, size, memory_type, attr: 0, perm }
    }

    #[test]
    fn is_mapped_binary_search_matches_the_linear_result() {
        let infos = vec![
            info(0x1000, 0x1000, 5, PERM_R | PERM_W),
            info(0x4000, 0x1000, 5, PERM_R),
            info(0x8000, 0x1000, 5, PERM_W), // write-only: not readable
            info(0x1_0000, 0x1000, 3, PERM_R | PERM_X),
        ];
        let dump = MemoryDump {
            tid: 1,
            infos: infos.clone(),
            indices: vec![],
            data_base: NDMP_DATA_OFFSET,
            data: vec![],
        };
        assert!(dump.is_mapped(0x1000, 4));
        assert!(dump.is_mapped(0x1FFC, 4));
        assert!(dump.is_mapped(0x4000, 8));
        assert!(dump.is_mapped(0x1_0FF8, 8));
        assert!(dump.infos_look_sorted(), "sorted table must take the binary-search path");
        assert!(!dump.is_mapped(0x2000, 4), "gap between mappings");
        assert!(!dump.is_mapped(0x1FFE, 4), "straddles the mapping end");
        assert!(!dump.is_mapped(0x8000, 4), "mapping is not readable");
        assert!(!dump.is_mapped(0, 4));
        assert!(!dump.is_mapped(0x2_0000, 4));
        assert!(!dump.is_mapped(0x1_1000, 4));

        // A table that is not sorted must fall back to the linear scan instead
        // of silently reporting a false negative.
        let mut shuffled = infos;
        shuffled.reverse();
        let unsorted = MemoryDump {
            tid: 1,
            infos: shuffled,
            indices: vec![],
            data_base: NDMP_DATA_OFFSET,
            data: vec![],
        };
        assert!(unsorted.is_mapped(0x1000, 4));
        assert!(unsorted.is_mapped(0x1_0000, 4));
        assert!(!unsorted.is_mapped(0x2000, 4));
        assert!(!unsorted.is_mapped(0x8000, 4));
        assert!(!unsorted.infos_look_sorted(), "unsorted table must fall back to the linear scan");
    }

    #[test]
    fn ptrscan_autodetects_64bit_width() {
        let main_base = 0x1_0000_0000u64;
        let heap_base = 0x2_0000_0000u64;
        let rec_base = 0x3_0000_0000u64;

        let mut main_seg = vec![0u8; 0x1000];
        let mut heap_seg = vec![0u8; 0x1000];
        let rec_seg = vec![0u8; 0x1000];
        main_seg[0x10..0x18].copy_from_slice(&(heap_base + 0x100).to_le_bytes());
        heap_seg[0x100..0x108].copy_from_slice(&(rec_base + 0x20).to_le_bytes());

        let mut data = Vec::new();
        let pos_main = NDMP_DATA_OFFSET;
        data.extend_from_slice(&main_seg);
        let pos_heap = NDMP_DATA_OFFSET + data.len() as u64;
        data.extend_from_slice(&heap_seg);
        let pos_rec = NDMP_DATA_OFFSET + data.len() as u64;
        data.extend_from_slice(&rec_seg);

        let dump = MemoryDump {
            tid: 0x0100_0000_0000_0000,
            infos: vec![
                info(main_base, 0x1000, 3, PERM_R | PERM_X),
                info(heap_base, 0x1000, 5, PERM_R | PERM_W),
                info(rec_base, 0x1000, 5, PERM_R | PERM_W),
            ],
            indices: vec![
                DumpIndex { addr: main_base, file_pos: pos_main, size: 0x1000 },
                DumpIndex { addr: heap_base, file_pos: pos_heap, size: 0x1000 },
                DumpIndex { addr: rec_base, file_pos: pos_rec, size: 0x1000 },
            ],
            data_base: NDMP_DATA_OFFSET,
            data,
        };

        let cancel = AtomicBool::new(false);
        let res = ptrscan_dump(
            &dump,
            &PtrScanOptions {
                target: rec_base + 0x20,
                module_base: main_base,
                module_size: 0x1000,
                max_depth: 3,
                max_offset: 0x1000,
                width: 0,
                max_results: 16,
            },
            &cancel,
        );
        assert!(!res.chains.is_empty(), "width=0 must infer 8-byte pointers for a 64-bit module base");
        assert_eq!(res.chains[0].root_offset, 0x10);
        assert_eq!(res.chains[0].steps, vec![0]);
    }

    #[test]
    fn ptrscan_keeps_4_byte_aligned_pointers_in_64bit_mode() {
        let main_base = 0x1_0000_0000u64;
        let heap_base = 0x2_0000_0000u64;
        let rec_base = 0x3_0000_0000u64;

        let mut main_seg = vec![0u8; 0x1000];
        let mut heap_seg = vec![0u8; 0x1000];
        let rec_seg = vec![0u8; 0x1000];
        // main+0x10 -> heap+0xFC: the pointer VALUE is 4-byte aligned but not
        // 8-byte aligned, and it is further from the target than max_offset, so
        // the old `val % width == 0` filter would have dropped it.
        main_seg[0x10..0x18].copy_from_slice(&(heap_base + 0xFC).to_le_bytes());
        heap_seg[0x100..0x108].copy_from_slice(&(rec_base + 0x20).to_le_bytes());

        let mut data = Vec::new();
        let pos_main = NDMP_DATA_OFFSET;
        data.extend_from_slice(&main_seg);
        let pos_heap = NDMP_DATA_OFFSET + data.len() as u64;
        data.extend_from_slice(&heap_seg);
        let pos_rec = NDMP_DATA_OFFSET + data.len() as u64;
        data.extend_from_slice(&rec_seg);

        let dump = MemoryDump {
            tid: 0x0100_0000_0000_0000,
            infos: vec![
                info(main_base, 0x1000, 3, PERM_R | PERM_X),
                info(heap_base, 0x1000, 5, PERM_R | PERM_W),
                info(rec_base, 0x1000, 5, PERM_R | PERM_W),
            ],
            indices: vec![
                DumpIndex { addr: main_base, file_pos: pos_main, size: 0x1000 },
                DumpIndex { addr: heap_base, file_pos: pos_heap, size: 0x1000 },
                DumpIndex { addr: rec_base, file_pos: pos_rec, size: 0x1000 },
            ],
            data_base: NDMP_DATA_OFFSET,
            data,
        };

        let cancel = AtomicBool::new(false);
        let res = ptrscan_dump(
            &dump,
            &PtrScanOptions {
                target: rec_base + 0x20,
                module_base: main_base,
                module_size: 0x1000,
                max_depth: 3,
                max_offset: 0x1000,
                width: 8,
                max_results: 16,
            },
            &cancel,
        );
        assert!(!res.chains.is_empty(), "4-byte aligned intermediate pointers must be indexed");
        assert_eq!(res.chains[0].root_offset, 0x10);
        assert_eq!(res.chains[0].steps, vec![0x4]); // heap+0xFC -> heap+0x100
        assert_eq!(res.chains[0].final_offset, 0);
    }

    #[test]
    fn load_rejects_indices_claiming_more_data_than_the_file_holds() {
        let data_len = 0x100u64;
        let idx_ptr = NDMP_DATA_OFFSET + data_len;
        let mut blob = Vec::new();
        blob.extend_from_slice(&NDMP_MAGIC.to_be_bytes());
        blob.extend_from_slice(&0x100u64.to_be_bytes()); // tid
        blob.extend_from_slice(&0u32.to_be_bytes()); // info_count
        blob.extend_from_slice(&(idx_ptr + 2 * 24).to_be_bytes()); // info_ptr
        blob.extend_from_slice(&2u32.to_be_bytes()); // idx_count
        blob.extend_from_slice(&idx_ptr.to_be_bytes()); // idx_ptr
        assert_eq!(blob.len(), 36);
        blob.resize(NDMP_DATA_OFFSET as usize, 0);
        blob.resize(blob.len() + data_len as usize, 0);
        // Both entries sit inside the file on their own, but together they claim
        // twice the data the file can hold.
        for addr in [0x1000u64, 0x2000] {
            blob.extend_from_slice(&addr.to_be_bytes());
            blob.extend_from_slice(&NDMP_DATA_OFFSET.to_be_bytes());
            blob.extend_from_slice(&data_len.to_be_bytes());
        }

        let path = std::env::temp_dir().join("nxus_ndmp_overlap.dmp");
        let path = path.to_string_lossy().to_string();
        std::fs::write(&path, &blob).expect("write corrupt dump");
        let err = MemoryDump::load(&path).expect_err("overlapping data ranges must be rejected");
        let _ = std::fs::remove_file(&path);
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
