//! PC-side scanning.
//!
//! The console only has a few megabytes of heap, so an "unknown initial value"
//! scan (which has to remember a value for every candidate address) cannot live
//! there.  The PC has gigabytes: this module reads the target's memory over the
//! wire once, keeps the candidates locally and refines them without ever asking
//! the console to remember anything.
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

#[derive(Clone, Debug)]
pub struct PcScan {
    pub value_size: u32,
    pub hits: Vec<PcHit>,
    pub truncated: bool,
    pub bytes_read: u64,
    pub reads: u64,
    pub failed_reads: u64,
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
pub fn save(path: &str, scan: &PcScan) -> std::io::Result<()> {
    use std::io::Write;
    let mut out = Vec::with_capacity(24 + scan.hits.len() * 16);
    out.extend_from_slice(FILE_MAGIC);
    out.extend_from_slice(&scan.value_size.to_le_bytes());
    out.extend_from_slice(&(scan.hits.len() as u64).to_le_bytes());
    out.extend_from_slice(&(scan.truncated as u32).to_le_bytes());
    for hit in &scan.hits {
        out.extend_from_slice(&hit.address.to_le_bytes());
        out.extend_from_slice(&hit.value.to_le_bytes());
    }
    let mut file = std::fs::File::create(path)?;
    file.write_all(&out)
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
    Ok(PcScan { value_size, hits, truncated, bytes_read: 0, reads: 0, failed_reads: 0 })
}

/// First pass: read every region and remember each candidate value.
pub fn scan_unknown(client: &NxusClient, regions: &[Region], value_size: u32, max_hits: usize,
                    cancel: &AtomicBool, progress: &mut dyn FnMut(u64, u64)) -> Result<PcScan, String> {
    if value_size == 0 || value_size > 8 {
        return Err("value size must be 1, 2, 4 or 8".into());
    }
    let step = value_size as u64;
    let total: u64 = regions.iter().map(|r| r.size).sum();
    let mut done = 0u64;
    // One allocation instead of 7.9M pushes growing it (41.7 -> 19.2 ms for 30 MB)
    let planned: u64 = regions.iter().map(|r| r.size / step.max(1)).sum();
    let mut scan = PcScan {
        value_size,
        hits: Vec::with_capacity(planned.min(max_hits as u64) as usize),
        truncated: false,
        bytes_read: 0,
        reads: 0,
        failed_reads: 0,
    };
    let read_chunk = client.max_read().min(1 << 20).max(4096);

    'outer: for region in regions {
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

            let aligned = (pos + step - 1) & !(step - 1);
            let mut address = aligned;
            let mut index = (aligned - pos) as usize;
            while index + value_size as usize <= data.len() {
                let value = load_value(&data[index..], value_size);
                scan.hits.push(PcHit { address, value });
                if scan.hits.len() >= max_hits {
                    scan.truncated = true;
                    break 'outer;
                }
                address += step;
                index += step as usize;
            }

            // Advance by what was actually returned: a short read would
            // otherwise skip the unread tail of this chunk.
            let got = data.len() as u64;
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

/// Refine pass: read only the surviving addresses (coalesced) and drop the ones
/// that no longer match.
pub fn refine(client: &NxusClient, scan: &mut PcScan, compare: Compare, target: u64,
              target2: u64, flags: u32, cancel: &AtomicBool,
              progress: &mut dyn FnMut(u64, u64)) -> Result<(), String> {
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
}
