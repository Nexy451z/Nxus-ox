//! PC-side scanning.
//!
//! The console only has a few megabytes of heap, so an "unknown initial value"
//! scan (which has to remember a value for every candidate address) cannot live
//! there.  The PC has gigabytes: this module reads the target's memory over the
//! wire once, keeps the candidates locally and refines them without ever asking
//! the console to remember anything.
//!
//! ## Dense baseline
//!
//! Remembering a `PcHit` (16 bytes) for every candidate explodes on big scopes:
//! a 512 MB heap stepped in 4-byte words is 134 M candidates = 2.1 GB, which is
//! why the old code bailed out at `DEFAULT_MAX_HITS`.  The first pass therefore
//! no longer turns values into hits at all: it keeps the raw bytes it read plus
//! one FNV-1a hash per 16 KiB block ([`BaselineSegment`]).  That is 4x-16x
//! smaller than the hit vector, so the first pass is effectively uncapped.
//!
//! The candidate values are materialised lazily by the first [`refine`]:
//!   * every segment is re-read and hashed block by block;
//!   * for the change-based comparisons (`Changed` / `Increased` / `Decreased`
//!     and `Different` with a non-zero target) a block whose hash still matches
//!     the baseline cannot contain a matching candidate, so the whole 16 KiB
//!     block is skipped in O(1);
//!   * only the surviving candidates become [`PcHit`] entries, and the baseline
//!     bytes are released immediately afterwards.
//!
//! Reads are chunked and coalesced so a whole-module pass is a few dozen round
//! trips instead of millions.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::client::NxusClient;
use crate::protocol::*;

/// Fallback chunk; the real limit comes from the server (client.max_read()).
const READ_CHUNK_FALLBACK: u32 = 64 * 1024;
/// Coalesced refine window.  The console engine uses 1 MB (NXUS_SESSION_DEFAULT_CHUNK
/// in switch/include/nxus_session.h); keeping the same value here makes both scanners
/// behave alike and cuts one request per 64 KB down to one per MB.
const WINDOW_MAX: u32 = 1024 * 1024;
const GAP_MAX: u32 = 16 * 1024;

pub const DEFAULT_MAX_HITS: usize = 8_000_000;

/// Block granularity of the dense baseline.  16 KiB keeps the hash overhead at
/// 8 bytes per 16 KiB (0.05 %) while still skipping large untouched spans.
pub const BASELINE_BLOCK: usize = 16 * 1024;

/// Scans at or below this many candidates are materialised immediately.
///
/// Callers that walk `PcScan::hits` directly (the CLI candidate list, the GUI
/// hit view) need the vector to be there, and for a small scope the hit vector
/// is cheaper than keeping both representations.  Bigger scans stay dense and
/// are materialised by the first refine, which is where the memory win lives.
pub const EAGER_MATERIALIZE_CANDIDATES: usize = 16_000_000;

#[derive(Clone, Copy, Debug)]
pub struct Region {
    pub base: u64,
    pub size: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct PcHit {
    pub address: u64,
    pub value: u64,
}

/// One raw chunk of the target's memory captured by the first pass.
///
/// `address` is the absolute address the chunk was read from; `data` is exactly
/// what came back over the wire and `block_hashes` is [`fnv1a`] over each
/// [`BASELINE_BLOCK`]-sized slice of `data` (the last block may be shorter).
#[derive(Debug, Clone)]
pub struct BaselineSegment {
    /// Index of the scan region this chunk came from (not the mapping index:
    /// the region list is what the caller asked for).
    pub map_idx: u16,
    /// Offset of this chunk inside its scan region.
    pub base_offset: u32,
    /// Absolute address the chunk was read from (needed to re-read it).
    pub address: u64,
    pub data: Vec<u8>,
    pub block_hashes: Vec<u64>, // 16KB ブロックごとの FNV-1a ハッシュ
}

#[derive(Clone, Debug, Default)]
pub struct PcScan {
    pub value_size: u32,
    pub hits: Vec<PcHit>,
    pub truncated: bool,
    pub bytes_read: u64,
    pub reads: u64,
    pub failed_reads: u64,
    /// Dense candidate storage; empty once the candidates are materialised.
    pub baseline: Vec<BaselineSegment>,
    /// Number of candidates held in `baseline` (0 when `hits` is authoritative).
    pub baseline_candidates: usize,
}

/// FNV-1a (64 bit): the same hash the snapshot engine uses, cheap enough to run
/// over every byte of the scan and stable across builds.
pub fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xCBF2_9CE4_8422_2325u64;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

#[inline]
fn align_up(value: u64, step: u64) -> u64 {
    if step <= 1 {
        return value;
    }
    let remainder = value % step;
    if remainder == 0 {
        value
    } else {
        value + (step - remainder)
    }
}

/// Number of candidates a chunk of `len` bytes read at `address` yields.
fn candidate_count(address: u64, len: usize, value_size: u32) -> usize {
    let size = value_size as usize;
    if size == 0 || len < size {
        return 0;
    }
    let first = (align_up(address, size as u64) - address) as usize;
    if first + size > len {
        return 0;
    }
    (len - first - size) / size + 1
}

/// Index of the first candidate inside a chunk read at `address`.
fn first_candidate_index(address: u64, size: usize) -> usize {
    if size == 0 {
        return 0;
    }
    (align_up(address, size as u64) - address) as usize
}

/// Walks the candidates of one dense segment.
struct BaselineHits<'a> {
    segment: &'a BaselineSegment,
    size: usize,
    index: usize,
    address: u64,
}

impl<'a> BaselineHits<'a> {
    fn new(segment: &'a BaselineSegment, value_size: u32) -> Self {
        let size = value_size as usize;
        BaselineHits {
            segment,
            size,
            index: first_candidate_index(segment.address, size),
            address: align_up(segment.address, size.max(1) as u64),
        }
    }
}

impl Iterator for BaselineHits<'_> {
    type Item = PcHit;

    fn next(&mut self) -> Option<PcHit> {
        if self.size == 0 || self.index + self.size > self.segment.data.len() {
            return None;
        }
        let hit = PcHit {
            address: self.address,
            value: load_value(&self.segment.data[self.index..], self.size as u32),
        };
        self.index += self.size;
        self.address += self.size as u64;
        Some(hit)
    }
}

impl PcScan {
    /// Candidate count, whichever representation currently holds them.
    pub fn len(&self) -> usize {
        if !self.baseline.is_empty() {
            self.baseline_candidates
        } else {
            self.hits.len()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// True while the candidates live in the dense baseline.
    pub fn is_dense(&self) -> bool {
        !self.baseline.is_empty()
    }

    /// Every candidate, in scan order, without materialising the baseline.
    ///
    /// This is the allocation-free-of-hits view: a dense scan is walked segment
    /// by segment, a materialised one straight out of `hits`.
    pub fn iter(&self) -> Box<dyn Iterator<Item = PcHit> + '_> {
        if self.baseline.is_empty() {
            Box::new(self.hits.iter().copied())
        } else {
            let value_size = self.value_size;
            Box::new(
                self.baseline
                    .iter()
                    .flat_map(move |segment| BaselineHits::new(segment, value_size)),
            )
        }
    }

    /// Page over the candidates without materialising anything.
    pub fn hits_page(&self, offset: usize, count: usize) -> Vec<PcHit> {
        self.iter().skip(offset).take(count).collect()
    }

    /// Drop the dense baseline without turning it into hits.
    pub fn drop_baseline(&mut self) {
        self.baseline.clear();
        self.baseline.shrink_to_fit();
        self.baseline_candidates = 0;
    }

    /// Turn the dense baseline into a `Vec<PcHit>` and release the raw bytes.
    ///
    /// Used by the small-scan compatibility path and by callers that need the
    /// full vector; [`refine`] and [`save`] never need it.
    pub fn ensure_materialized(&mut self) {
        if self.baseline.is_empty() {
            return;
        }
        let hits: Vec<PcHit> = self.iter().collect();
        self.hits = hits;
        self.drop_baseline();
    }
}

pub struct Progress<'a> {
    pub done: u64,
    pub total: u64,
    pub on_step: &'a mut dyn FnMut(u64, u64),
}

/// Regions to scan for a scope, taken from the live mapping table.
pub fn regions_for_scope(client: &NxusClient, scope: Scope, begin: u64, end: u64) -> Result<Vec<Region>, String> {
    let metadata = client.metadata().map_err(|e| e.to_string())?;
    let mut regions = Vec::new();

    let count = client.mapping_count().map_err(|e| e.to_string())?;
    let mut offset = 0u64;
    let mut all: Vec<MemoryInfo> = Vec::new();
    while offset < count {
        let page = client.mappings(offset, 512).map_err(|e| e.to_string())?;
        if page.is_empty() {
            break;
        }
        offset += page.len() as u64;
        all.extend(page);
    }

    // Mirrors buildRegions() in switch/source/nxus_session.c: same scope rules,
    // same clipping, no extra rounding.  If the two ever disagree, a PC-side
    // scan and a console-side scan of the "same" scope see different memory.
    for map in all {
        let perms = map.perms();
        if !perms.contains('r') || map.size == 0 {
            continue;
        }
        let mut base = map.base;
        let mut end_at = map.base + map.size;

        match scope {
            // A range list is a server-side feature (the request carries it to the
            // console).  Returning every readable mapping here silently scanned the
            // whole memory instead of the ranges the user picked.
            Scope::Ranges => {
                return Err("scope 'ranges' is console-side only - use --scope custom, or drop --pc".into());
            }
            Scope::Main => {
                if metadata.main_size == 0 {
                    continue;
                }
                let main_end = metadata.main_base + metadata.main_size;
                if end_at <= metadata.main_base || base >= main_end {
                    continue;
                }
                base = base.max(metadata.main_base);
                end_at = end_at.min(main_end);
            }
            Scope::Heap => {
                if !perms.contains('w') {
                    continue;
                }
                if map.memory_type != 0 && map.memory_type != crate::protocol::MEMTYPE_HEAP {
                    continue;
                }
            }
            Scope::Writable => {
                if !perms.contains('w') {
                    continue;
                }
            }
            Scope::Tls => {
                if map.memory_type != crate::protocol::MEMTYPE_TLS {
                    continue;
                }
            }
            Scope::Custom => {
                if end <= begin {
                    continue;
                }
                if end_at <= begin || base >= end {
                    continue;
                }
                base = base.max(begin);
                end_at = end_at.min(end);
            }
            Scope::All => {}
        }

        if end_at <= base {
            continue;
        }
        regions.push(Region { base, size: end_at - base });
    }

    Ok(regions)
}

fn load_value(bytes: &[u8], size: u32) -> u64 {
    let mut value = 0u64;
    for i in 0..size.min(8) as usize {
        value |= (bytes[i] as u64) << (8 * i);
    }
    value
}

fn bits_to_f64(bits: u64, size: u32) -> f64 {
    if size == 8 {
        f64::from_bits(bits)
    } else {
        f32::from_bits(bits as u32) as f64
    }
}

/// Mirrors the console engine's comparison so both agree on the semantics.
pub fn compare_value(cur: u64, prev: u64, size: u32, compare: Compare, target: u64,
                     target2: u64, flags: u32) -> bool {
    if flags & SCAN_F_FLOAT != 0 {
        let c = bits_to_f64(cur, size);
        let t = bits_to_f64(target, size);
        let p = bits_to_f64(prev, size);
        let hi = bits_to_f64(target2, size);
        // Exact parity with nxus_scan.c:nxusCompareBytes(): the epsilon comes
        // from the target2 bits and falls back to 1e-2 for "unspecified".  It
        // is applied as two one-sided deltas (no libm fabs, NaN-safe ordering),
        // and `Equal` is an epsilon compare just like `FuzzyEqual` in C.
        let eps = if target2 != 0 { hi.abs() } else { 1e-2 };
        let close = |a: f64, b: f64| (a == b) || ((a - b) <= eps && (b - a) <= eps);
        return match compare {
            Compare::Equal | Compare::FuzzyEqual => close(c, t),
            Compare::NotEqual => !close(c, t),
            Compare::Greater => c > t,
            Compare::Less => c < t,
            Compare::GreaterOrEqual => c >= t,
            Compare::LessOrEqual => c <= t,
            Compare::Between => c >= t && c <= hi,
            Compare::Increased => c > p,
            Compare::Decreased => c < p,
            Compare::Changed => c != p,
            Compare::Unchanged => c == p,
            Compare::Different => close((c - p).abs(), t.abs()),
            _ => false,
        };
    }

    if flags & SCAN_F_SIGNED != 0 {
        let sign = |v: u64| -> i64 {
            match size {
                1 => v as u8 as i8 as i64,
                2 => v as u16 as i16 as i64,
                4 => v as u32 as i32 as i64,
                _ => v as i64,
            }
        };
        let (c, t, p) = (sign(cur), sign(target), sign(prev));
        let hi = sign(target2);
        return match compare {
            Compare::Equal => c == t,
            Compare::NotEqual => c != t,
            Compare::Greater => c > t,
            Compare::Less => c < t,
            Compare::GreaterOrEqual => c >= t,
            Compare::LessOrEqual => c <= t,
            Compare::Between => c >= t && c <= hi,
            Compare::Increased => c > p,
            Compare::Decreased => c < p,
            Compare::Changed => c != p,
            Compare::Unchanged => c == p,
            Compare::Different => c.abs_diff(p) == t.unsigned_abs(),
            _ => false,
        };
    }

    match compare {
        Compare::Equal => cur == target,
        Compare::NotEqual => cur != target,
        Compare::Greater => cur > target,
        Compare::Less => cur < target,
        Compare::GreaterOrEqual => cur >= target,
        Compare::LessOrEqual => cur <= target,
        Compare::Between => cur >= target && cur <= target2,
        Compare::Increased => cur > prev,
        Compare::Decreased => cur < prev,
        Compare::Changed => cur != prev,
        Compare::Unchanged => cur == prev,
        Compare::Different => cur.abs_diff(prev) == target,
        _ => false,
    }
}

const FILE_MAGIC: &[u8; 8] = b"NXUSPC01";

/// Save / load the candidate list so the CLI can refine across invocations.
///
/// A dense scan is streamed straight out of the baseline: nothing is
/// materialised, so saving a 134 M candidate scan does not build a hit vector.
pub fn save(path: &str, scan: &PcScan) -> std::io::Result<()> {
    use std::io::{BufWriter, Write};
    let total = scan.len();
    debug_assert_eq!(scan.iter().count(), total, "baseline_candidates must match the stored candidates");

    let mut header = [0u8; 24];
    header[0..8].copy_from_slice(FILE_MAGIC);
    header[8..12].copy_from_slice(&scan.value_size.to_le_bytes());
    header[12..20].copy_from_slice(&(total as u64).to_le_bytes());
    header[20..24].copy_from_slice(&(scan.truncated as u32).to_le_bytes());

    let file = std::fs::File::create(path)?;
    let mut out = BufWriter::with_capacity(1 << 20, file);
    out.write_all(&header)?;

    // 16 bytes per record, batched so a dense scan does not cost one syscall
    // (or even one BufWriter call) per candidate.
    let mut batch: Vec<u8> = Vec::with_capacity(1 << 20);
    for hit in scan.iter() {
        batch.extend_from_slice(&hit.address.to_le_bytes());
        batch.extend_from_slice(&hit.value.to_le_bytes());
        if batch.len() >= (1 << 20) {
            out.write_all(&batch)?;
            batch.clear();
        }
    }
    out.write_all(&batch)?;
    out.flush()
}

pub fn load(path: &str) -> std::io::Result<PcScan> {
    let data = std::fs::read(path)?;
    if data.len() < 24 || &data[0..8] != FILE_MAGIC {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not a Nxus candidate file"));
    }
    let value_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let count = u64::from_le_bytes([data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19]]) as usize;
    let truncated = u32::from_le_bytes([data[20], data[21], data[22], data[23]]) != 0;
    // A corrupt header can claim billions of hits.  The file length bounds how
    // many records can really exist, so clamp the pre-allocation instead of
    // aborting the process on an impossible `with_capacity` (OOM abort).
    let max_hits = data.len().saturating_sub(24) / 16;
    let mut hits = Vec::with_capacity(count.min(max_hits));
    let mut at = 24;
    for _ in 0..count {
        if at + 16 > data.len() {
            break;
        }
        let address = u64::from_le_bytes(data[at..at + 8].try_into().unwrap());
        let value = u64::from_le_bytes(data[at + 8..at + 16].try_into().unwrap());
        hits.push(PcHit { address, value });
        at += 16;
    }
    Ok(PcScan { value_size, hits, truncated, bytes_read: 0, reads: 0, failed_reads: 0, ..Default::default() })
}

/// First pass: read every region and keep the raw bytes as a dense baseline.
///
/// No `PcHit` is created here (except for small scans, see
/// [`EAGER_MATERIALIZE_CANDIDATES`]), which is what removes the old
/// `max_hits` truncation: the baseline costs `value_size`-free raw bytes plus
/// 8 bytes per 16 KiB block instead of 16 bytes per candidate.
pub fn scan_unknown(client: &NxusClient, regions: &[Region], value_size: u32, max_hits: usize,
                    cancel: &AtomicBool, progress: &mut dyn FnMut(u64, u64)) -> Result<PcScan, String> {
    if value_size == 0 || value_size > 8 {
        return Err("value size must be 1, 2, 4 or 8".into());
    }
    // Kept for API/source compatibility.  The dense baseline is intentionally
    // uncapped: the cap only ever existed to bound the old hit vector.
    let _ = max_hits;
    let total: u64 = regions.iter().map(|r| r.size).sum();
    let mut done = 0u64;
    let mut scan = PcScan { value_size, ..Default::default() };
    let read_chunk = client.max_read().min(1 << 20).max(4096);

    for (region_index, region) in regions.iter().enumerate() {
        let mut pos = region.base;
        let end = region.base + region.size;
        while pos < end {
            if cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            let todo = ((end - pos).min(read_chunk as u64)) as u32;
            let data = match client.read(pos, todo) {
                Ok(data) => data,
                Err(_) => {
                    // dmnt may refuse a large read (the accepted size is not
                    // documented).  Halve the request down to 4 KiB before
                    // giving up, exactly like the dump reader and
                    // nxus_scan.c do, so a read-size limit cannot silently drop
                    // a whole 1 MB window.
                    let mut retry = todo / 2;
                    let mut salvaged: Option<Vec<u8>> = None;
                    while retry >= 4096 {
                        match client.read(pos, retry) {
                            Ok(data) => {
                                salvaged = Some(data);
                                break;
                            }
                            Err(_) => retry /= 2,
                        }
                    }
                    match salvaged {
                        Some(data) => {
                            scan.failed_reads += 1;
                            data
                        }
                        None => {
                            // genuinely unreadable range: skip it, keep going
                            scan.failed_reads += 1;
                            pos += todo as u64;
                            done += todo as u64;
                            progress(done, total);
                            continue;
                        }
                    }
                }
            };
            scan.reads += 1;
            scan.bytes_read += data.len() as u64;

            // Advance by what was actually returned: a short read would
            // otherwise skip the unread tail of this chunk.
            let got = data.len() as u64;

            let candidates = candidate_count(pos, data.len(), value_size);
            if candidates > 0 {
                let block_hashes: Vec<u64> = data.chunks(BASELINE_BLOCK).map(fnv1a).collect();
                scan.baseline_candidates += candidates;
                scan.baseline.push(BaselineSegment {
                    map_idx: region_index.min(u16::MAX as usize) as u16,
                    base_offset: (pos - region.base).min(u32::MAX as u64) as u32,
                    address: pos,
                    data,
                    block_hashes,
                });
            }

            if got == 0 {
                break;                                  // nothing more readable here
            }
            pos += got;
            done += got;
            progress(done, total);
        }
    }

    Ok(scan)
}

/// Whether an unchanged 16 KiB block can be skipped outright.
///
/// Only comparisons that an unchanged value can never satisfy qualify: with
/// `Different` and a target of 0 the very opposite is true (`|cur - prev| == 0`
/// matches every unchanged candidate), so that one is excluded.
fn block_skip_applies(compare: Compare, target: u64) -> bool {
    match compare {
        Compare::Changed | Compare::Increased | Compare::Decreased => true,
        Compare::Different => target != 0,
        _ => false,
    }
}

/// Append every remaining candidate of `segment` with its baseline value.
fn keep_baseline_candidates(hits: &mut Vec<PcHit>, segment: &BaselineSegment, value_size: u32,
                            mut index: usize, processed: &mut u64) {
    let size = value_size as usize;
    if size == 0 {
        return;
    }
    while index + size <= segment.data.len() {
        hits.push(PcHit {
            address: segment.address + index as u64,
            value: load_value(&segment.data[index..], value_size),
        });
        *processed += 1;
        index += size;
    }
}

/// The dense half of [`refine`]: re-read each baseline segment, skip unchanged
/// 16 KiB blocks by hash and materialise only the surviving candidates.
///
/// `compared` reports how many candidate values were actually compared, which is
/// what proves the block skip really skipped (tests assert on it).
fn dense_refine_core(
    scan: &mut PcScan,
    compare: Compare,
    target: u64,
    target2: u64,
    flags: u32,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(u64, u64),
    compared: &mut u64,
    mut read: impl FnMut(u64, u32) -> Result<Vec<u8>, ()>,
) -> Result<(), String> {
    let value_size = scan.value_size;
    let size = value_size as usize;
    let total = scan.baseline_candidates as u64;
    let skip_blocks = block_skip_applies(compare, target);
    let segments = std::mem::take(&mut scan.baseline);
    let mut hits: Vec<PcHit> = Vec::new();
    let mut processed = 0u64;
    let mut failed = 0u64;
    let mut cancelled = false;
    let mut stopped = false;

    for segment in &segments {
        let len = segment.data.len();
        if size == 0 || len < size {
            continue;
        }
        let mut index = first_candidate_index(segment.address, size);
        if stopped {
            keep_baseline_candidates(&mut hits, segment, value_size, index, &mut processed);
            continue;
        }

        let current = match read(segment.address, len as u32) {
            Ok(data) => data,
            Err(_) => {
                // A transient read failure must not look like "no longer
                // matches": keep the candidates with their baseline values.
                failed += 1;
                keep_baseline_candidates(&mut hits, segment, value_size, index, &mut processed);
                progress(processed, total);
                continue;
            }
        };
        let current = &current[..current.len().min(len)];
        if current.len() < len {
            // Short reply: compare what came back, keep the unread tail.
            failed += 1;
        }

        while index + size <= len {
            if cancel.load(Ordering::Relaxed) {
                cancelled = true;
                stopped = true;
                break;
            }

            let block = index / BASELINE_BLOCK;
            let block_start = block * BASELINE_BLOCK;
            let block_end = (block_start + BASELINE_BLOCK).min(len);
            let complete = block_end <= current.len();
            let unchanged = complete
                && segment
                    .block_hashes
                    .get(block)
                    .map_or(false, |old| *old == fnv1a(&current[block_start..block_end]));

            if skip_blocks && unchanged {
                // O(1): every candidate starting in this block still holds its
                // baseline value, so none of them can match a change compare.
                let last_start = len - size;                     // inclusive
                let take_end = block_end.min(last_start + 1);     // exclusive
                let count = if index >= take_end { 0 } else { (take_end - 1 - index) / size + 1 };
                if count > 0 {
                    index += count * size;
                    processed += count as u64;
                    continue;
                }
                // Defensive: never spin without consuming a candidate.
            }

            if index + size > current.len() {
                // Beyond the short reply: keep the baseline value for a retry.
                hits.push(PcHit {
                    address: segment.address + index as u64,
                    value: load_value(&segment.data[index..], value_size),
                });
                index += size;
                processed += 1;
                continue;
            }

            let value = load_value(&current[index..], value_size);
            *compared += 1;
            if compare_value(value, load_value(&segment.data[index..], value_size), value_size,
                             compare, target, target2, flags) {
                hits.push(PcHit { address: segment.address + index as u64, value });
            }
            index += size;
            processed += 1;
        }

        if stopped {
            keep_baseline_candidates(&mut hits, segment, value_size, index, &mut processed);
        }
        progress(processed, total);
    }

    scan.hits = hits;
    scan.failed_reads += failed;
    scan.truncated = false;
    // Release the baseline as soon as it has been turned into hits: the whole
    // point is not to hold both representations at once.
    scan.baseline.clear();
    scan.baseline.shrink_to_fit();
    scan.baseline_candidates = 0;

    if cancelled {
        return Err("cancelled".into());
    }
    Ok(())
}

/// Refine pass.
///
/// A dense scan (right after [`scan_unknown`]) goes through
/// [`dense_refine_core`], which is where the baseline is materialised.  Every
/// later pass sees a normal `hits` vector and uses the sparse windowed reader
/// below.
pub fn refine(client: &NxusClient, scan: &mut PcScan, compare: Compare, target: u64,
              target2: u64, flags: u32, cancel: &AtomicBool,
              progress: &mut dyn FnMut(u64, u64)) -> Result<(), String> {
    if !scan.baseline.is_empty() {
        let mut compared = 0u64;
        return dense_refine_core(scan, compare, target, target2, flags, cancel, progress, &mut compared,
                                 |address, size| client.read(address, size).map_err(|_| ()));
    }

    let size = scan.value_size;
    let total = scan.hits.len() as u64;
    let mut keep = 0usize;
    let mut i = 0usize;
    // reads return fresh buffers, so no scratch window is needed here
    let mut processed = 0u64;

    while i < scan.hits.len() {
        if cancel.load(Ordering::Relaxed) {
            // keep the untouched tail, like the console engine does
            let tail = scan.hits.len() - i;
            if tail > 0 {
                scan.hits.copy_within(i..i + tail, keep);
            }
            scan.hits.truncate(keep + tail);
            return Err("cancelled".into());
        }

        let start = scan.hits[i].address;
        let mut end = start + size as u64;
        let batch_start = i;
        i += 1;
        while i < scan.hits.len() {
            let next = scan.hits[i].address;
            if next < end {
                end = end.max(next + size as u64);
                i += 1;
                continue;
            }
            if (next + size as u64 - start) <= WINDOW_MAX as u64 && (next - end) <= GAP_MAX as u64 {
                end = next + size as u64;
                i += 1;
            } else {
                break;
            }
        }
        let batch_end = i;

        let win_size = (end - start) as usize;
        if win_size > WINDOW_MAX as usize {
            // window too large: process the batch one by one via small reads
            for j in batch_start..batch_end {
                let address = scan.hits[j].address;
                match client.read(address, size) {
                    Ok(data) => {
                        let cur = load_value(&data, size);
                        if compare_value(cur, scan.hits[j].value, size, compare, target, target2, flags) {
                            scan.hits[keep] = PcHit { address, value: cur };
                            keep += 1;
                        }
                    }
                    Err(_) => {
                        scan.hits[keep] = scan.hits[j];   // keep it for a retry
                        scan.failed_reads += 1;
                        keep += 1;
                    }
                }
                processed += 1;
            }
            progress(processed, total);
            continue;
        }

        let data = match client.read(start, win_size as u32) {
            Ok(data) => data,
            Err(_) => {
                // A transient read failure must not look like "no longer
                // matches": keep the candidates (with their previous values) and
                // count the failure so the caller can retry the pass.
                for j in batch_start..batch_end {
                    scan.hits[keep] = scan.hits[j];
                    keep += 1;
                }
                scan.failed_reads += 1;
                processed += (batch_end - batch_start) as u64;
                progress(processed, total);
                continue;
            }
        };

        for j in batch_start..batch_end {
            let address = scan.hits[j].address;
            let offset = (address - start) as usize;
            if offset + size as usize > data.len() {
                // short read: keep the candidate for the next pass instead of
                // treating the missing bytes as "no longer matches"
                scan.hits[keep] = scan.hits[j];
                keep += 1;
                scan.failed_reads += 1;
                continue;
            }
            let cur = load_value(&data[offset..], size);
            if compare_value(cur, scan.hits[j].value, size, compare, target, target2, flags) {
                scan.hits[keep] = PcHit { address, value: cur };
                keep += 1;
            }
        }

        processed += (batch_end - batch_start) as u64;
        progress(processed, total);
    }

    scan.hits.truncate(keep);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Compare, SCAN_F_FLOAT, SCAN_F_SIGNED};
    use std::sync::atomic::AtomicBool;

    fn s32_bits(v: i32) -> u64 {
        v as u32 as u64
    }

    fn f32_bits(v: f32) -> u64 {
        v.to_bits() as u64
    }

    fn f64_bits(v: f64) -> u64 {
        v.to_bits()
    }

    #[test]
    fn compare_unsigned_integers() {
        assert!(compare_value(100, 0, 4, Compare::Equal, 100, 0, 0));
        assert!(!compare_value(100, 0, 4, Compare::Equal, 101, 0, 0));
        assert!(compare_value(100, 0, 4, Compare::NotEqual, 101, 0, 0));
        assert!(compare_value(100, 0, 4, Compare::GreaterOrEqual, 100, 0, 0));
        assert!(compare_value(101, 0, 4, Compare::GreaterOrEqual, 100, 0, 0));
        assert!(!compare_value(99, 0, 4, Compare::GreaterOrEqual, 100, 0, 0));
        assert!(compare_value(100, 0, 4, Compare::LessOrEqual, 100, 0, 0));
        assert!(compare_value(99, 0, 4, Compare::LessOrEqual, 100, 0, 0));
        assert!(!compare_value(101, 0, 4, Compare::LessOrEqual, 100, 0, 0));
        assert!(compare_value(150, 0, 4, Compare::Between, 100, 200, 0));
        assert!(compare_value(100, 0, 4, Compare::Between, 100, 200, 0));
        assert!(!compare_value(201, 0, 4, Compare::Between, 100, 200, 0));
        // Different: |cur - prev| == target (unsigned)
        assert!(compare_value(140, 100, 4, Compare::Different, 40, 0, 0));
        assert!(compare_value(100, 140, 4, Compare::Different, 40, 0, 0));
        assert!(!compare_value(140, 100, 4, Compare::Different, 41, 0, 0));
        assert!(compare_value(u32::MAX as u64, 0, 4, Compare::Equal, u32::MAX as u64, 0, 0));
        assert!(compare_value(5, 7, 4, Compare::Changed, 0, 0, 0));
        assert!(compare_value(5, 5, 4, Compare::Unchanged, 0, 0, 0));
    }

    #[test]
    fn compare_signed_integers() {
        let f = SCAN_F_SIGNED;
        // -5 < 3 only when interpreted as signed.
        assert!(compare_value(s32_bits(-5), 0, 4, Compare::Less, s32_bits(3), 0, f));
        assert!(!compare_value(s32_bits(-5), 0, 4, Compare::Greater, s32_bits(3), 0, f));
        // ... and the unsigned interpretation really does differ.
        assert!(compare_value(s32_bits(-5), 0, 4, Compare::Greater, s32_bits(3), 0, 0));
        assert!(compare_value(s32_bits(-5), 0, 4, Compare::Equal, s32_bits(-5), 0, f));
        assert!(compare_value(s32_bits(-5), 0, 4, Compare::LessOrEqual, s32_bits(-5), 0, f));
        assert!(compare_value(s32_bits(-5), 0, 4, Compare::GreaterOrEqual, s32_bits(-5), 0, f));
        assert!(compare_value(s32_bits(-2), 0, 4, Compare::GreaterOrEqual, s32_bits(-5), 0, f));
        assert!(!compare_value(s32_bits(-5), 0, 4, Compare::GreaterOrEqual, s32_bits(-2), 0, f));
        assert!(compare_value(s32_bits(0), 0, 4, Compare::Between, s32_bits(-10), s32_bits(0), f));
        assert!(!compare_value(s32_bits(1), 0, 4, Compare::Between, s32_bits(-10), s32_bits(0), f));
        assert!(compare_value(s32_bits(-3), s32_bits(-5), 4, Compare::Different, 2, 0, f));
        assert!(!compare_value(s32_bits(-3), s32_bits(-5), 4, Compare::Different, 3, 0, f));
        // Size 8 uses the raw i64 interpretation.
        assert!(compare_value((-7i64) as u64, 0, 8, Compare::Less, 7, 0, f));
    }

    #[test]
    fn compare_float_equal_and_fuzzy_use_c_epsilon() {
        let f = SCAN_F_FLOAT;
        // Equal is an epsilon compare in the C engine; with target2 == 0 the
        // default epsilon is 1e-2.
        assert!(compare_value(f32_bits(1.25), 0, 4, Compare::Equal, f32_bits(1.25), 0, f));
        assert!(compare_value(f32_bits(1.254), 0, 4, Compare::Equal, f32_bits(1.25), 0, f));
        assert!(!compare_value(f32_bits(1.30), 0, 4, Compare::Equal, f32_bits(1.25), 0, f));
        assert!(compare_value(f32_bits(1.30), 0, 4, Compare::NotEqual, f32_bits(1.25), 0, f));
        assert!(!compare_value(f32_bits(1.25), 0, 4, Compare::NotEqual, f32_bits(1.25), 0, f));

        // FuzzyEqual with an explicit epsilon (target2 bits of 1e-3).
        let eps = f32_bits(1e-3);
        assert!(compare_value(f32_bits(1.2505), 0, 4, Compare::FuzzyEqual, f32_bits(1.25), eps, f));
        // A tighter epsilon from the caller must reject the same delta.
        assert!(!compare_value(f32_bits(1.2505), 0, 4, Compare::FuzzyEqual, f32_bits(1.25), f32_bits(1e-4), f));

        // f64 path (size 8) behaves the same, with f64 epsilon bits.
        assert!(compare_value(f64_bits(0.1 + 0.2), 0, 8, Compare::Equal, f64_bits(0.3), 0, f));
        assert!(compare_value(f64_bits(1.0 + 1e-9), 0, 8, Compare::Equal, f64_bits(1.0), 0, f));
        assert!(!compare_value(f64_bits(1.0 + 1e-3), 0, 8, Compare::FuzzyEqual, f64_bits(1.0), f64_bits(1e-6), f));
        assert!(compare_value(f64_bits(1.0 + 1e-9), 0, 8, Compare::FuzzyEqual, f64_bits(1.0), f64_bits(1e-6), f));
    }

    #[test]
    fn compare_float_ordering_and_different() {
        let f = SCAN_F_FLOAT;
        assert!(compare_value(f32_bits(0.5), 0, 4, Compare::LessOrEqual, f32_bits(0.5), 0, f));
        assert!(compare_value(f32_bits(0.25), 0, 4, Compare::LessOrEqual, f32_bits(0.5), 0, f));
        assert!(!compare_value(f32_bits(0.75), 0, 4, Compare::LessOrEqual, f32_bits(0.5), 0, f));
        assert!(compare_value(f32_bits(2.0), 0, 4, Compare::GreaterOrEqual, f32_bits(1.5), 0, f));
        assert!(compare_value(f32_bits(1.5), 0, 4, Compare::GreaterOrEqual, f32_bits(1.5), 0, f));
        assert!(!compare_value(f32_bits(1.4), 0, 4, Compare::GreaterOrEqual, f32_bits(1.5), 0, f));
        assert!(compare_value(f32_bits(1.5), 0, 4, Compare::Between, f32_bits(1.0), f32_bits(2.0), f));
        assert!(!compare_value(f32_bits(2.5), 0, 4, Compare::Between, f32_bits(1.0), f32_bits(2.0), f));
        assert!(compare_value(f32_bits(1.75), f32_bits(1.5), 4, Compare::Increased, 0, 0, f));
        assert!(compare_value(f32_bits(1.5), f32_bits(1.75), 4, Compare::Decreased, 0, 0, f));

        // Different compares |cur - prev| against |target|.
        assert!(compare_value(f32_bits(1.75), f32_bits(1.5), 4, Compare::Different, f32_bits(0.25), 0, f));
        assert!(!compare_value(f32_bits(1.75), f32_bits(1.5), 4, Compare::Different, f32_bits(0.5), 0, f));
        assert!(compare_value(f64_bits(3.0), f64_bits(1.5), 8, Compare::Different, f64_bits(1.5), 0, f));
    }

    #[test]
    fn load_clamps_impossible_hit_count() {
        let mut blob = Vec::new();
        blob.extend_from_slice(FILE_MAGIC);
        blob.extend_from_slice(&4u32.to_le_bytes());
        blob.extend_from_slice(&(1u64 << 40).to_le_bytes()); // ~1 T claimed hits
        blob.extend_from_slice(&0u32.to_le_bytes());

        let path = std::env::temp_dir().join("nxus_pcscan_huge_count.bin");
        let path = path.to_string_lossy().to_string();
        std::fs::write(&path, &blob).expect("write candidate file");
        let scan = load(&path).expect("corrupt header must still load (clamped)");
        let _ = std::fs::remove_file(&path);

        assert_eq!(scan.value_size, 4);
        assert!(scan.hits.is_empty());
    }

    #[test]
    fn save_load_round_trip() {
        let scan = PcScan {
            value_size: 4,
            hits: vec![PcHit { address: 0x1000, value: 7 }, PcHit { address: 0x2000, value: 9 }],
            truncated: true,
            bytes_read: 0,
            reads: 0,
            failed_reads: 0,
            ..Default::default()
        };
        let path = std::env::temp_dir().join("nxus_pcscan_round_trip.bin");
        let path = path.to_string_lossy().to_string();
        save(&path, &scan).expect("save");
        let loaded = load(&path).expect("load");
        let _ = std::fs::remove_file(&path);

        assert_eq!(loaded.value_size, 4);
        assert_eq!(loaded.hits.len(), 2);
        assert!(loaded.truncated);
        assert_eq!(loaded.hits[0].address, 0x1000);
        assert_eq!(loaded.hits[1].value, 9);
    }

    // ---- dense baseline --------------------------------------------------

    /// Build the state `scan_unknown` leaves behind for a linear memory image.
    fn dense_scan_from_image(image: &[u8], base: u64, value_size: u32, chunk: usize) -> PcScan {
        let mut scan = PcScan { value_size, ..Default::default() };
        let mut at = 0usize;
        while at < image.len() {
            let end = (at + chunk).min(image.len());
            let data = image[at..end].to_vec();
            let block_hashes: Vec<u64> = data.chunks(BASELINE_BLOCK).map(fnv1a).collect();
            let address = base + at as u64;
            scan.baseline_candidates += candidate_count(address, data.len(), value_size);
            scan.baseline.push(BaselineSegment {
                map_idx: 0,
                base_offset: at as u32,
                address,
                data,
                block_hashes,
            });
            at = end;
        }
        scan
    }

    /// n consecutive little-endian u32 values 0, 1, 2, ...
    fn u32_image(count: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(count * 4);
        for value in 0..count {
            out.extend_from_slice(&(value as u32).to_le_bytes());
        }
        out
    }

    #[test]
    fn dense_baseline_skips_unchanged_16k_blocks_on_changed() {
        let base = 0x3600_0000u64;
        let mut image = u32_image(8192);                       // 32 KiB = two blocks
        let mut scan = dense_scan_from_image(&image, base, 4, 32 * 1024);

        // The first pass must not have built a hit vector.
        assert!(scan.hits.is_empty(), "scan_unknown must not materialise PcHit");
        assert!(scan.is_dense());
        assert_eq!(scan.len(), 8192);
        assert_eq!(scan.baseline.len(), 1);
        assert_eq!(scan.baseline[0].block_hashes.len(), 2);

        let changed_at = 16 * 1024 + 0x10;
        image[changed_at..changed_at + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

        let cancel = AtomicBool::new(false);
        let mut compared = 0u64;
        let mut processed = 0u64;
        {
            let mut progress = |done: u64, _total: u64| {
                processed = done;
            };
            let mut read = |address: u64, size: u32| -> Result<Vec<u8>, ()> {
                let offset = (address - base) as usize;
                Ok(image[offset..offset + size as usize].to_vec())
            };
            dense_refine_core(&mut scan, Compare::Changed, 0, 0, 0, &cancel,
                              &mut progress, &mut compared, &mut read)
                .expect("dense refine");
        }

        assert_eq!(scan.hits.len(), 1, "only the changed value survives");
        assert_eq!(scan.hits[0].address, base + changed_at as u64);
        assert_eq!(scan.hits[0].value, 0xDEAD_BEEF);
        // 4096 candidates live in the touched block; the untouched 16 KiB block
        // was skipped by hash, so only one block was ever compared.
        assert_eq!(compared, 4096, "the unchanged 16 KiB block must be skipped O(1)");
        assert_eq!(processed, 8192);
        assert!(scan.baseline.is_empty(), "the baseline memory must be released");
        assert_eq!(scan.baseline_candidates, 0);
        assert_eq!(scan.len(), 1);
    }

    #[test]
    fn dense_baseline_increased_materialises_lazily_and_pages_from_the_baseline() {
        let base = 0x3600_0000u64;
        let mut image = u32_image(8192);
        let mut scan = dense_scan_from_image(&image, base, 4, 0x4000);   // two segments

        assert_eq!(scan.baseline.len(), 2);
        assert!(scan.hits.is_empty());
        assert_eq!(scan.len(), 8192);

        // Paging works straight out of the baseline, without materialising.
        let page = scan.hits_page(4092, 8);
        assert_eq!(page.len(), 8);
        assert_eq!(page[0].address, base + 4092 * 4);
        assert_eq!(page[0].value, 4092);
        assert!(scan.hits.is_empty());

        // Bump one value in the second segment.
        let raised_at = 0x4000 + 0x20;
        image[raised_at..raised_at + 4].copy_from_slice(&0x0001_0000u32.to_le_bytes());

        let cancel = AtomicBool::new(false);
        let mut compared = 0u64;
        {
            let mut read = |address: u64, size: u32| -> Result<Vec<u8>, ()> {
                let offset = (address - base) as usize;
                Ok(image[offset..offset + size as usize].to_vec())
            };
            dense_refine_core(&mut scan, Compare::Increased, 0, 0, 0, &cancel,
                              &mut |_, _| {}, &mut compared, &mut read)
                .expect("dense refine");
        }

        assert_eq!(scan.hits.len(), 1);
        assert_eq!(scan.hits[0].address, base + raised_at as u64);
        assert_eq!(scan.hits[0].value, 0x0001_0000);
        assert_eq!(compared, 4096, "only the touched 16 KiB block is compared");
        assert!(!scan.is_dense());
        assert_eq!(scan.len(), 1);
    }

    #[test]
    fn dense_baseline_different_with_zero_target_does_not_skip() {
        // |cur - prev| == 0 matches every unchanged candidate, so the block skip
        // must stay off or all of them would be lost.
        let base = 0x3600_0000u64;
        let image = u32_image(8192);
        let mut scan = dense_scan_from_image(&image, base, 4, 32 * 1024);

        let cancel = AtomicBool::new(false);
        let mut compared = 0u64;
        {
            let mut read = |address: u64, size: u32| -> Result<Vec<u8>, ()> {
                let offset = (address - base) as usize;
                Ok(image[offset..offset + size as usize].to_vec())
            };
            dense_refine_core(&mut scan, Compare::Different, 0, 0, 0, &cancel,
                              &mut |_, _| {}, &mut compared, &mut read)
                .expect("dense refine");
        }

        assert_eq!(compared, 8192, "a zero Different target must compare every candidate");
        assert_eq!(scan.hits.len(), 8192);
    }

    #[test]
    fn dense_baseline_read_failure_keeps_candidates_for_a_retry() {
        let base = 0x3600_0000u64;
        let image = u32_image(8192);
        let mut scan = dense_scan_from_image(&image, base, 4, 0x8000);

        let cancel = AtomicBool::new(false);
        let mut compared = 0u64;
        {
            let mut read = |_address: u64, _size: u32| -> Result<Vec<u8>, ()> { Err(()) };
            dense_refine_core(&mut scan, Compare::Changed, 0, 0, 0, &cancel,
                              &mut |_, _| {}, &mut compared, &mut read)
                .expect("dense refine");
        }

        assert_eq!(compared, 0);
        assert_eq!(scan.hits.len(), 8192, "a failed read must not drop candidates");
        assert_eq!(scan.hits[0].value, 0);
        assert_eq!(scan.failed_reads, 1);
        assert!(!scan.is_dense());
    }

    #[test]
    fn dense_baseline_save_streams_without_materialising() {
        let base = 0x3600_0000u64;
        let image = u32_image(2048);
        let scan = dense_scan_from_image(&image, base, 4, 0x1000);
        assert!(scan.hits.is_empty());
        assert_eq!(scan.len(), 2048);

        let path = std::env::temp_dir().join("nxus_pcscan_dense.bin");
        let path = path.to_string_lossy().to_string();
        save(&path, &scan).expect("save dense scan");
        let loaded = load(&path).expect("load");
        let _ = std::fs::remove_file(&path);

        assert_eq!(loaded.hits.len(), 2048);
        assert!(loaded.baseline.is_empty());
        assert_eq!(loaded.hits[0].address, base);
        assert_eq!(loaded.hits[0].value, 0);
        assert_eq!(loaded.hits[2047].address, base + 2047 * 4);
        assert_eq!(loaded.hits[2047].value, 2047);
    }

    #[test]
    fn ensure_materialized_expands_and_releases_the_baseline() {
        let base = 0x3600_0000u64;
        let image = u32_image(4096);
        let mut scan = dense_scan_from_image(&image, base, 4, 0x4000);
        assert_eq!(scan.len(), 4096);

        scan.ensure_materialized();
        assert!(!scan.is_dense());
        assert_eq!(scan.baseline_candidates, 0);
        assert_eq!(scan.hits.len(), 4096);
        assert_eq!(scan.hits[4095].address, base + 4095 * 4);
        assert_eq!(scan.hits[4095].value, 4095);
    }

    #[test]
    fn block_skip_only_for_change_comparisons() {
        assert!(block_skip_applies(Compare::Changed, 0));
        assert!(block_skip_applies(Compare::Increased, 0));
        assert!(block_skip_applies(Compare::Decreased, 0));
        assert!(block_skip_applies(Compare::Different, 5));
        assert!(!block_skip_applies(Compare::Different, 0));
        assert!(!block_skip_applies(Compare::Unchanged, 0));
        assert!(!block_skip_applies(Compare::Equal, 0));
        assert!(!block_skip_applies(Compare::NotEqual, 0));
    }

    #[test]
    fn candidate_count_matches_the_iterator() {
        for value_size in [1u32, 2, 4, 8] {
            for misalign in 0..value_size as u64 {
                let base = 0x1000 + misalign;
                let len = 64 + misalign as usize;
                let image = vec![0u8; len];
                let scan = dense_scan_from_image(&image, base, value_size, len);
                assert_eq!(scan.baseline_candidates, scan.iter().count(),
                           "value_size {} misalign {}", value_size, misalign);
            }
        }
    }
}
