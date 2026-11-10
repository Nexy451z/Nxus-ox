//! Atmosphere cheat-file parser, instruction decoder and writer.
//!
//! The parser is deliberately forgiving about formatting but strict about
//! instruction shape: every code line must decode to exactly one instruction
//! and the conditional/loop structure must balance.  A block with any decode
//! issue stays loadable and visible, but the manager refuses to enable it.

use std::fs;
use std::path::Path;

use super::model::{
    ArithmeticOp, ArithmeticOperand, CheatBlock, CheatCode, CheatDocument, CheatExecMode, CheatKey,
    CheatKind, CodeLine, Comparison, ConditionalOperand, Instruction, JumpInfo, MemoryRegion,
    ModeSource, OffStyle, ParseIssue, SaveRestoreOp, StoreOffset, MAX_PROGRAM_OPCODES,
    MAX_WORDS_PER_CODE_LINE,
};

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Parse an in-memory cheat file.  `build_id` is stored on the document.
pub fn parse_document(text: &str, build_id: &str) -> CheatDocument {
    let mut document = CheatDocument::new(build_id);
    document.raw_text = text.to_string();

    let normalized = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut current: Option<Current> = None;
    let mut line_number = 0usize;

    for raw_line in normalized.split('\n') {
        line_number += 1;
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);

        // A header starts a new section, closes the previous one and is never
        // added to code bodies.
        if let Some(header) = try_parse_header(line, line_number, &mut document.issues) {
            finish_current(&mut current, &mut document);
            if header.off_section {
                let attach_index = document.blocks.len().checked_sub(1).filter(|index| {
                    document.blocks[*index]
                        .name
                        .eq_ignore_ascii_case(&header.name)
                });
                if let Some(index) = attach_index {
                    let block = &mut document.blocks[index];
                    if let Some(mode) = header.mode {
                        block.mode_source = ModeSource::explicit(mode);
                        block.mode = mode;
                    }
                    current = Some(Current::AttachedOff {
                        index,
                        lines: Vec::new(),
                    });
                    continue;
                }
                // A `[Name:OFF]` with no preceding match is a restore-only
                // section.  It is shown, disabled, and never auto-enabled.
                let mut pending = PendingBlock::new(header);
                pending.explicit_off = true;
                pending.off_style = OffStyle::SeparateSection;
                pending.in_off = true;
                pending.source_line = line_number;
                current = Some(Current::Block(pending));
                continue;
            }

            let mut pending = PendingBlock::new(header);
            pending.source_line = line_number;
            current = Some(Current::Block(pending));
            continue;
        }

        match current.as_mut() {
            None => document.preamble.push(line.to_string()),
            Some(Current::Block(pending)) => {
                if apply_body_line(pending, line, line_number) {
                    continue;
                }
            }
            Some(Current::AttachedOff { lines, .. }) => {
                if let Some(rest) = directive(line) {
                    if let Some(mode) = rest {
                        if let Some(block) = document.blocks.last_mut() {
                            block.mode_source = ModeSource::explicit(mode);
                            block.mode = mode;
                        }
                    }
                    continue;
                }
                lines.push(CodeLine::new(line.to_string(), line_number));
            }
        }
    }

    finish_current(&mut current, &mut document);
    document
}

/// Read and parse `<path>`.
pub fn parse_file(path: &Path, build_id: &str) -> Result<CheatDocument, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("failed to stat {}: {error}", path.display()))?;
    if metadata.len() > super::model::MAX_CHEAT_FILE_BYTES {
        return Err(format!(
            "{} is {} bytes; the maximum is {} bytes",
            path.display(),
            metadata.len(),
            super::model::MAX_CHEAT_FILE_BYTES
        ));
    }
    let text = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let mut document = parse_document(&text, build_id);
    document.path = Some(path.to_path_buf());
    Ok(document)
}

/// Decode a standalone list of code lines (used by tests and editors).
pub fn parse_code_lines(lines: &[String], first_source_line: usize) -> CheatCode {
    let code_lines: Vec<CodeLine> = lines
        .iter()
        .enumerate()
        .map(|(index, text)| {
            CodeLine::new(
                text.clone(),
                if first_source_line > 0 {
                    first_source_line + index
                } else {
                    0
                },
            )
        })
        .collect();
    parse_code(&code_lines)
}

/// Decode already source-mapped body lines.
pub fn parse_code(lines: &[CodeLine]) -> CheatCode {
    let mut code = CheatCode {
        lines: lines.to_vec(),
        ..CheatCode::default()
    };
    let mut decoded_lines: Vec<usize> = Vec::new();

    for line in lines {
        let without_comment = strip_comment(&line.text);
        let trimmed = without_comment.trim();
        if trimmed.is_empty() {
            continue;
        }
        let words = match parse_words(trimmed) {
            Ok(words) => words,
            Err(message) => {
                code.issues.push(ParseIssue::new(line.source_line, message));
                continue;
            }
        };
        if words.len() > MAX_WORDS_PER_CODE_LINE {
            code.issues.push(ParseIssue::new(
                line.source_line,
                format!(
                    "code line has {} words; at most {MAX_WORDS_PER_CODE_LINE} are allowed",
                    words.len()
                ),
            ));
            continue;
        }

        match decode_words(&words) {
            Ok(instruction) => {
                if matches!(instruction, Instruction::Unsupported { .. }) {
                    code.issues.push(ParseIssue::new(
                        line.source_line,
                        format!("unsupported opcode 0x{:X}", instruction.opcode()),
                    ));
                }
                code.instructions.push(instruction);
                decoded_lines.push(line.source_line);
                if code.instructions.len() > MAX_PROGRAM_OPCODES {
                    code.issues.push(ParseIssue::new(
                        line.source_line,
                        format!("program exceeds the {MAX_PROGRAM_OPCODES} opcode limit"),
                    ));
                    break;
                }
            }
            Err(message) => {
                code.issues.push(ParseIssue::new(line.source_line, message));
                code.instructions.push(Instruction::Unsupported {
                    opcode: decode_opcode(words[0]),
                    words: words.clone(),
                });
                decoded_lines.push(line.source_line);
            }
        }
    }

    if code.issues.is_empty() {
        match compile_control_flow(&code.instructions) {
            Ok(jumps) => code.jumps = jumps,
            Err((index, message)) => {
                let source_line = decoded_lines.get(index).copied().unwrap_or(0);
                code.issues.push(ParseIssue::new(source_line, message));
            }
        }
    }

    code
}

// ---------------------------------------------------------------------------
// Header and body line handling
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Header {
    name: String,
    kind: CheatKind,
    off_section: bool,
    /// `true` when the header carried an explicit `:ON` marker.
    ///
    /// The marker is remembered as "what the file said" (`CheatBlock::
    /// saved_enabled`) for display only: it never enables the block.
    on_marker: bool,
    mode: Option<CheatExecMode>,
    extra: String,
}

enum Current {
    Block(PendingBlock),
    AttachedOff { index: usize, lines: Vec<CodeLine> },
}

struct PendingBlock {
    header: Header,
    on_lines: Vec<CodeLine>,
    off_lines: Vec<CodeLine>,
    /// What the file says about this block's state, starting with the `:ON`
    /// marker on its header.  This is **not** applied: a cheat file never
    /// starts a block ON, and the manager is the only thing that can.
    saved_enabled: bool,
    in_off: bool,
    explicit_off: bool,
    off_style: OffStyle,
    mode_source: ModeSource,
    source_line: usize,
}

impl PendingBlock {
    fn new(header: Header) -> Self {
        let saved_enabled = header.on_marker;
        PendingBlock {
            saved_enabled,
            mode_source: header
                .mode
                .map(ModeSource::explicit)
                .unwrap_or(ModeSource::Auto),
            header,
            on_lines: Vec::new(),
            off_lines: Vec::new(),
            in_off: false,
            explicit_off: false,
            off_style: OffStyle::None,
            source_line: 0,
        }
    }

    fn has_on_code(&self) -> bool {
        self.on_lines
            .iter()
            .any(|line| !strip_comment(&line.text).trim().is_empty())
    }
}

fn finish_current(current: &mut Option<Current>, document: &mut CheatDocument) {
    match current.take() {
        None => {}
        Some(Current::AttachedOff { index, lines }) => {
            if let Some(block) = document.blocks.get_mut(index) {
                block.explicit_off = true;
                block.off_style = OffStyle::SeparateSection;
                let mut combined = block.off.take().map(|code| code.lines).unwrap_or_default();
                combined.extend(lines);
                block.off = Some(parse_code(&combined));
            }
        }
        Some(Current::Block(pending)) => {
            let mut block = finalize_block(pending);
            let occurrence = document.occurrence_count(&block.name);
            block.key = CheatKey::from_name(&block.name, occurrence);
            document.blocks.push(block);
        }
    }
}

fn finalize_block(pending: PendingBlock) -> CheatBlock {
    let on = parse_code(&pending.on_lines);
    let off = if pending.explicit_off {
        Some(parse_code(&pending.off_lines))
    } else {
        None
    };

    let mut block = CheatBlock::new(CheatKey(0), pending.header.name, pending.header.kind);
    block.mode_source = pending.mode_source;
    // Loading a file never applies anything: the ON state is the manager's to
    // own, and a marker on disk only survives as `saved_enabled` for display.
    // Otherwise a restart of the title (the bytes are gone) would still show
    // every cheat of the last session as ON.
    block.enabled = false;
    // An orphan `[Name:OFF]` restore-only section has no runnable ON half, so a
    // state marker on it means nothing either.
    let restore_only = pending.explicit_off && on.instructions.is_empty();
    block.saved_enabled = pending.saved_enabled && !restore_only;
    block.on = on;
    block.off = off;
    block.explicit_off = pending.explicit_off;
    block.off_style = pending.off_style;
    block.header_extra = pending.header.extra;
    block.source_line = pending.source_line;
    block.refresh_mode();
    block
}

fn apply_body_line(pending: &mut PendingBlock, line: &str, line_number: usize) -> bool {
    let trimmed = line.trim();

    if trimmed.is_empty() {
        push_body_line(pending, line, line_number);
        return true;
    }

    if is_comment(trimmed) {
        push_body_line(pending, line, line_number);
        return true;
    }

    let compact = trimmed.to_ascii_lowercase().replace(' ', "");
    match compact.as_str() {
        "@loop" | "[loop]" | ":loop" => {
            pending.mode_source = ModeSource::ExplicitLoop;
            return true;
        }
        "@patch" | "[patch]" | ":patch" => {
            pending.mode_source = ModeSource::ExplicitPatch;
            return true;
        }
        "@on" => {
            // Remembered for display only; nothing is applied at load time.
            pending.saved_enabled = true;
            return true;
        }
        "@off" => {
            if !pending.in_off && !pending.has_on_code() {
                // `@off` at the top of a block is the disabled-by-default
                // marker, not a divider.
                pending.saved_enabled = false;
            } else {
                start_off_block(pending, OffStyle::Inline);
            }
            return true;
        }
        "--off" | ":off" => {
            start_off_block(pending, OffStyle::Inline);
            return true;
        }
        _ => {}
    }

    // A trailing marker on an instruction line is accepted for compatibility.
    let (cleaned, marker) = strip_trailing_markers(trimmed);
    if let Some(CheatExecMode::Loop) = marker.mode {
        pending.mode_source = ModeSource::ExplicitLoop;
    }
    if let Some(CheatExecMode::Patch) = marker.mode {
        pending.mode_source = ModeSource::ExplicitPatch;
    }
    if marker.disabled {
        pending.saved_enabled = false;
    }
    if marker.off_block {
        start_off_block(pending, OffStyle::Inline);
    }

    if cleaned.is_empty() {
        return true;
    }

    // Preserve the original line when no marker was stripped; otherwise store
    // the cleaned code so re-saving does not reintroduce a stale directive.
    if cleaned == trimmed {
        push_body_line(pending, line, line_number);
    } else {
        push_body_line(pending, &cleaned, line_number);
    }
    true
}

fn push_body_line(pending: &mut PendingBlock, line: &str, line_number: usize) {
    if pending.in_off {
        pending.off_lines.push(CodeLine::new(line, line_number));
    } else {
        pending.on_lines.push(CodeLine::new(line, line_number));
    }
}

fn start_off_block(pending: &mut PendingBlock, style: OffStyle) {
    if !pending.explicit_off {
        pending.explicit_off = true;
        pending.off_style = style;
    }
    pending.in_off = true;
}

/// Returns `Some(None)` for a directive with no mode, `Some(Some(mode))` for a
/// mode directive, and `None` when the line is not a directive.
fn directive(line: &str) -> Option<Option<CheatExecMode>> {
    let compact = line.trim().to_ascii_lowercase().replace(' ', "");
    match compact.as_str() {
        "@loop" | "[loop]" | ":loop" => Some(Some(CheatExecMode::Loop)),
        "@patch" | "[patch]" | ":patch" => Some(Some(CheatExecMode::Patch)),
        "@off" | "--off" | ":off" | "@on" | ":on" => Some(None),
        _ => None,
    }
}

fn try_parse_header(
    line: &str,
    line_number: usize,
    issues: &mut Vec<ParseIssue>,
) -> Option<Header> {
    let trimmed = line.trim_start();
    let (open, close, kind) = match trimmed.chars().next()? {
        '[' => ('[', ']', CheatKind::Regular),
        '{' => ('{', '}', CheatKind::Master),
        _ => return None,
    };

    // `[loop]` / `[patch]` are body directives, not cheat names.
    let compact = trimmed.to_ascii_lowercase().replace(' ', "");
    if matches!(compact.as_str(), "[loop]" | "[patch]") {
        return None;
    }

    let start = trimmed.find(open)?;
    let end = match trimmed[start + 1..].find(close) {
        Some(offset) => start + 1 + offset,
        None => {
            issues.push(ParseIssue::new(
                line_number,
                format!("section header is missing '{close}'"),
            ));
            return None;
        }
    };

    let mut inner = trimmed[start + 1..end].trim().to_string();
    let extra = trimmed[end + 1..].to_string();
    let mut off_section = false;
    let mut on_marker = false;
    let mut mode = None;

    // Repeatedly peel trailing state/mode annotations.  Names may contain
    // UTF-8; suffix matching is ASCII-only and therefore byte-safe here
    // because every marker is ASCII.
    loop {
        let lower = inner.to_ascii_lowercase();
        if let Some(stripped) = strip_suffix(&inner, &lower, ":off") {
            off_section = true;
            inner = stripped;
            continue;
        }
        if let Some(stripped) = strip_suffix(&inner, &lower, ":on") {
            on_marker = true;
            inner = stripped;
            continue;
        }
        let mut found = false;
        for (tag, found_mode) in [
            ("@loop", CheatExecMode::Loop),
            ("[loop]", CheatExecMode::Loop),
            ("@patch", CheatExecMode::Patch),
            ("[patch]", CheatExecMode::Patch),
        ] {
            if let Some(stripped) = strip_suffix(&inner, &lower, tag) {
                mode = Some(found_mode);
                inner = stripped;
                found = true;
                break;
            }
        }
        if !found {
            break;
        }
    }

    let extra_lower = extra.to_ascii_lowercase();
    if extra_lower.contains("@loop") || extra_lower.contains("[loop]") {
        mode = Some(CheatExecMode::Loop);
    } else if extra_lower.contains("@patch") || extra_lower.contains("[patch]") {
        mode = Some(CheatExecMode::Patch);
    }
    let extra = if mode.is_some()
        && (extra_lower.contains("@loop")
            || extra_lower.contains("[loop]")
            || extra_lower.contains("@patch")
            || extra_lower.contains("[patch]"))
    {
        // Drop the tag so the writer does not emit it twice.
        String::new()
    } else {
        extra
    };

    let name = inner.trim().to_string();
    if name.is_empty() {
        issues.push(ParseIssue::new(
            line_number,
            "section header has an empty name",
        ));
    }

    Some(Header {
        name,
        kind,
        off_section,
        on_marker,
        mode,
        extra,
    })
}

/// Rewrite every ON marker so a saved cheat file never describes a block as ON.
///
/// The structured writer ([`crate::cheat::CheatDocument::to_text`]) always
/// emits `@off`, but the raw editor stores exactly what the user typed.  A
/// `[Name:ON]` / `{Name:ON}` header or a standalone `@on` line would come back
/// as a saved ON state on the next load (while the bytes it described are long
/// gone), so they are rewritten to the OFF spelling before the file reaches the
/// disk:
///
/// * `[Name:ON]` becomes `[Name]` followed by an explicit `@off`,
/// * `{Name:ON}` becomes `{Name}` followed by an explicit `@off`,
/// * a bare `@on` / `:on` directive becomes `@off`.
///
/// Everything else — code lines, comments (even ones that mention `@on`),
/// spacing and line endings — is preserved byte for byte.  The function is
/// idempotent.
pub fn sanitize_on_markers(text: &str) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out = String::with_capacity(text.len() + 8);
    for (index, raw) in lines.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        let (line, carriage_return) = match raw.strip_suffix('\r') {
            Some(line) => (line, true),
            None => (*raw, false),
        };
        let trimmed = line.trim_start();
        let leading = &line[..line.len() - trimmed.len()];
        let compact = trimmed.to_ascii_lowercase().replace(' ', "");

        if compact == "@on" || compact == ":on" {
            // A bare ON directive becomes the unambiguous OFF directive.
            out.push_str(leading);
            out.push_str("@off");
            if carriage_return {
                out.push('\r');
            }
            continue;
        }

        if let Some(header) = header_without_on_marker(trimmed) {
            out.push_str(leading);
            out.push_str(&header);
            if carriage_return {
                out.push('\r');
            }
            // An explicit `@off` directly below the header already is the OFF
            // spelling, so it is not duplicated.
            if !next_line_is_off_directive(&lines, index + 1) {
                out.push('\n');
                out.push_str("@off");
                if carriage_return {
                    out.push('\r');
                }
            }
            continue;
        }

        out.push_str(line);
        if carriage_return {
            out.push('\r');
        }
    }
    out
}

fn next_line_is_off_directive(lines: &[&str], index: usize) -> bool {
    lines
        .get(index)
        .map(|line| line.trim().to_ascii_lowercase().replace(' ', "") == "@off")
        .unwrap_or(false)
}

/// `[Name:ON]` / `{Name:ON}` -> `[Name]` / `{Name}`; `None` for every other
/// line.  Mode tags and trailing text after the closing bracket are kept.
fn header_without_on_marker(trimmed: &str) -> Option<String> {
    let mut issues = Vec::new();
    let header = try_parse_header(trimmed, 0, &mut issues)?;
    if !header.on_marker {
        return None;
    }
    let (open, close) = match header.kind {
        CheatKind::Master => ('{', '}'),
        CheatKind::Regular => ('[', ']'),
    };
    // A restore-only `[Name:OFF]` section keeps its OFF spelling; only the
    // state marker is dropped so the block cannot come back as ON.
    let mut line = if header.off_section {
        format!("{open}{}:OFF", header.name)
    } else {
        format!("{open}{}", header.name)
    };
    if let Some(mode) = header.mode {
        line.push_str(match mode {
            CheatExecMode::Loop => " @loop",
            CheatExecMode::Patch => " @patch",
        });
    }
    line.push(close);
    line.push_str(&header.extra);
    Some(line)
}

fn strip_suffix(text: &str, lower: &str, suffix: &str) -> Option<String> {
    if lower.ends_with(suffix) {
        let cut = text.len().checked_sub(suffix.len())?;
        Some(text[..cut].trim_end().to_string())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tokenising and decode
// ---------------------------------------------------------------------------

fn is_comment(trimmed: &str) -> bool {
    trimmed.starts_with(';') || trimmed.starts_with('#') || trimmed.starts_with("//")
}

fn strip_comment(line: &str) -> &str {
    let mut end = line.len();
    if let Some(index) = line.find(';') {
        end = end.min(index);
    }
    if let Some(index) = line.find('#') {
        end = end.min(index);
    }
    if let Some(index) = line.find("//") {
        end = end.min(index);
    }
    &line[..end]
}

fn parse_words(code: &str) -> Result<Vec<u32>, String> {
    let mut words = Vec::new();
    for token in code.split_whitespace() {
        let token = token.trim_end_matches(',');
        let token = token
            .strip_prefix("0x")
            .or_else(|| token.strip_prefix("0X"))
            .unwrap_or(token);
        if token.is_empty() || token.len() > 8 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("invalid code word '{token}'"));
        }
        let value =
            u32::from_str_radix(token, 16).map_err(|_| format!("invalid code word '{token}'"))?;
        words.push(value);
    }
    if words.is_empty() {
        return Err("empty code line".to_string());
    }
    Ok(words)
}

struct Reader<'a> {
    words: &'a [u32],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(words: &'a [u32]) -> Self {
        Reader { words, position: 1 }
    }

    fn next(&mut self) -> Result<u32, String> {
        let word = self
            .words
            .get(self.position)
            .copied()
            .ok_or_else(|| "instruction is missing an operand word".to_string())?;
        self.position += 1;
        Ok(word)
    }

    fn next_vm_int(&mut self, width: u8) -> Result<u64, String> {
        if width == 8 {
            // 64-bit values are stored high dword first.
            let high = self.next()?;
            let low = self.next()?;
            Ok((u64::from(high) << 32) | u64::from(low))
        } else {
            Ok(u64::from(self.next()?))
        }
    }

    fn finish(&self) -> Result<(), String> {
        if self.position == self.words.len() {
            Ok(())
        } else {
            Err(format!(
                "instruction has {} unused word(s)",
                self.words.len() - self.position
            ))
        }
    }
}

fn decode_opcode(first: u32) -> u16 {
    let mut opcode = ((first >> 28) & 0xF) as u16;
    if opcode >= 0xC {
        opcode = (opcode << 4) | ((first >> 24) & 0xF) as u16;
        // 0xFF >= 0xF0: fold the third nibble for FF0/FF1/FFF.
        if opcode >= 0xF0 {
            opcode = (opcode << 4) | ((first >> 20) & 0xF) as u16;
        }
    }
    opcode
}

fn width(bits: u32) -> Result<u8, String> {
    match bits {
        1 => Ok(1),
        2 => Ok(2),
        4 => Ok(4),
        8 => Ok(8),
        other => Err(format!(
            "invalid access width {other} (expected 1, 2, 4 or 8)"
        )),
    }
}

fn register(bits: u32) -> Result<u8, String> {
    if bits < 16 {
        Ok(bits as u8)
    } else {
        Err(format!("invalid register r{bits} (expected r0..r15)"))
    }
}

fn region(bits: u32) -> Result<MemoryRegion, String> {
    MemoryRegion::from_bits(bits)
        .ok_or_else(|| format!("invalid memory region {bits} (expected 0..4)"))
}

fn rel40(high_nibble_or_byte: u32, low: u32) -> u64 {
    (u64::from(high_nibble_or_byte) << 32) | u64::from(low)
}

fn decode_words(words: &[u32]) -> Result<Instruction, String> {
    let first = words[0];
    let opcode = decode_opcode(first);
    let mut reader = Reader::new(words);

    let instruction = match opcode {
        0x0 => {
            let access_width = width((first >> 24) & 0xF)?;
            let memory_region = region((first >> 20) & 0xF)?;
            let offset_register = register((first >> 16) & 0xF)?;
            let low = reader.next()?;
            let rel_address = rel40(first & 0xFF, low);
            let value = reader.next_vm_int(access_width)?;
            Instruction::StoreStatic {
                width: access_width,
                region: memory_region,
                offset_register,
                rel_address,
                value,
            }
        }
        0x1 => {
            let access_width = width((first >> 24) & 0xF)?;
            let memory_region = region((first >> 20) & 0xF)?;
            let comparison = Comparison::from_bits((first >> 16) & 0xF)
                .ok_or_else(|| "invalid comparison type".to_string())?;
            let include_offset_register = ((first >> 12) & 0xF) != 0;
            let offset_register = register((first >> 8) & 0xF)?;
            let low = reader.next()?;
            let rel_address = rel40(first & 0xFF, low);
            let value = reader.next_vm_int(access_width)?;
            Instruction::BeginConditional {
                width: access_width,
                region: memory_region,
                comparison,
                include_offset_register,
                offset_register,
                rel_address,
                value,
            }
        }
        0x2 => {
            let marker = (first >> 24) & 0xF;
            if marker > 1 {
                return Err(format!("invalid conditional terminator 0x{first:08X}"));
            }
            Instruction::EndConditional {
                is_else: marker == 1,
            }
        }
        0x3 => {
            let marker = (first >> 24) & 0xF;
            let loop_register = register((first >> 16) & 0xF)?;
            match marker {
                0 => Instruction::LoopStart {
                    register: loop_register,
                    count: reader.next()?,
                },
                1 => Instruction::LoopEnd {
                    register: loop_register,
                },
                other => return Err(format!("invalid loop marker {other}")),
            }
        }
        0x4 => {
            let target_register = register((first >> 16) & 0xF)?;
            let high = reader.next()?;
            let low = reader.next()?;
            Instruction::LoadRegisterImmediate {
                register: target_register,
                value: (u64::from(high) << 32) | u64::from(low),
            }
        }
        0x5 => {
            let access_width = width((first >> 24) & 0xF)?;
            let memory_region = region((first >> 20) & 0xF)?;
            let target_register = register((first >> 16) & 0xF)?;
            let load_from_register = (first >> 12) & 0xF;
            if load_from_register > 3 {
                return Err(format!(
                    "invalid load-from-register mode {load_from_register}"
                ));
            }
            let offset_register = register((first >> 8) & 0xF)?;
            let low = reader.next()?;
            Instruction::LoadRegisterMemory {
                width: access_width,
                region: memory_region,
                register: target_register,
                load_from_register: load_from_register as u8,
                offset_register,
                rel_address: rel40(first & 0xFF, low),
            }
        }
        0x6 => {
            let access_width = width((first >> 24) & 0xF)?;
            let target_register = register((first >> 16) & 0xF)?;
            let increment = ((first >> 12) & 0xF) != 0;
            let add_offset_register = ((first >> 8) & 0xF) != 0;
            let offset_register = register((first >> 4) & 0xF)?;
            let high = reader.next()?;
            let low = reader.next()?;
            Instruction::StoreStaticToRegister {
                width: access_width,
                register: target_register,
                increment,
                add_offset_register,
                offset_register,
                value: (u64::from(high) << 32) | u64::from(low),
            }
        }
        0x7 => {
            let access_width = width((first >> 24) & 0xF)?;
            let target_register = register((first >> 16) & 0xF)?;
            let operation = ArithmeticOp::from_bits((first >> 12) & 0xF)
                .ok_or_else(|| "invalid arithmetic type".to_string())?;
            if !matches!(
                operation,
                ArithmeticOp::Add
                    | ArithmeticOp::Sub
                    | ArithmeticOp::Multiply
                    | ArithmeticOp::LeftShift
                    | ArithmeticOp::RightShift
            ) {
                return Err("legacy arithmetic only supports +, -, *, << and >>".to_string());
            }
            Instruction::LegacyArithmetic {
                width: access_width,
                register: target_register,
                operation,
                value: reader.next()?,
            }
        }
        0x8 => Instruction::KeypressConditional {
            key_mask: first & 0x0FFF_FFFF,
        },
        0x9 => {
            let access_width = width((first >> 24) & 0xF)?;
            let operation = ArithmeticOp::from_bits((first >> 20) & 0xF)
                .ok_or_else(|| "invalid register arithmetic type".to_string())?;
            let destination_register = register((first >> 16) & 0xF)?;
            let source_register_1 = register((first >> 12) & 0xF)?;
            let has_immediate = ((first >> 8) & 0xF) != 0;
            let operand = if has_immediate {
                ArithmeticOperand::Immediate(reader.next_vm_int(access_width)?)
            } else {
                ArithmeticOperand::Register(register((first >> 4) & 0xF)?)
            };
            Instruction::RegisterArithmetic {
                width: access_width,
                operation,
                destination_register,
                source_register_1,
                operand,
            }
        }
        0xA => {
            let access_width = width((first >> 24) & 0xF)?;
            let source_register = register((first >> 20) & 0xF)?;
            let address_register = register((first >> 16) & 0xF)?;
            let increment = ((first >> 12) & 0xF) != 0;
            let offset_type = (first >> 8) & 0xF;
            let x = (first >> 4) & 0xF;
            let offset = match offset_type {
                0 => StoreOffset::None,
                1 => StoreOffset::Register(register(x)?),
                2 => {
                    let low = reader.next()?;
                    StoreOffset::Immediate(rel40(first & 0xF, low))
                }
                3 => StoreOffset::MemoryRegister(region(x)?),
                4 => {
                    let memory_region = region(x)?;
                    let low = reader.next()?;
                    StoreOffset::MemoryImmediate {
                        region: memory_region,
                        rel_address: rel40(first & 0xF, low),
                    }
                }
                5 => {
                    let memory_region = region(x)?;
                    let low = reader.next()?;
                    StoreOffset::MemoryImmediateRegister {
                        region: memory_region,
                        rel_address: rel40(first & 0xF, low),
                    }
                }
                other => return Err(format!("invalid store offset type {other}")),
            };
            Instruction::StoreRegisterToMemory {
                width: access_width,
                source_register,
                address_register,
                increment,
                offset,
            }
        }
        0xC0 => {
            let access_width = width((first >> 20) & 0xF)?;
            let comparison = Comparison::from_bits((first >> 16) & 0xF)
                .ok_or_else(|| "invalid register comparison type".to_string())?;
            let value_register = register((first >> 12) & 0xF)?;
            let compare_type = (first >> 8) & 0xF;
            let x = (first >> 4) & 0xF;
            let operand = match compare_type {
                0 => {
                    let memory_region = region(x)?;
                    let low = reader.next()?;
                    ConditionalOperand::MemoryRelative {
                        region: memory_region,
                        rel_address: rel40(first & 0xF, low),
                    }
                }
                1 => ConditionalOperand::MemoryOffset {
                    region: region(x)?,
                    offset_register: register(first & 0xF)?,
                },
                2 => {
                    let address_register = register(x)?;
                    let low = reader.next()?;
                    ConditionalOperand::RegisterRelative {
                        address_register,
                        rel_address: rel40(first & 0xF, low),
                    }
                }
                3 => ConditionalOperand::RegisterOffset {
                    address_register: register(x)?,
                    offset_register: register(first & 0xF)?,
                },
                4 => ConditionalOperand::Immediate(reader.next_vm_int(access_width)?),
                5 => ConditionalOperand::Register(register(x)?),
                other => return Err(format!("invalid register comparison operand {other}")),
            };
            Instruction::RegisterConditional {
                width: access_width,
                comparison,
                value_register,
                operand,
            }
        }
        0xC1 => {
            let destination = register((first >> 16) & 0xF)?;
            let source = register((first >> 8) & 0xF)?;
            let operation = SaveRestoreOp::from_bits((first >> 4) & 0xF)
                .ok_or_else(|| "invalid save/restore operation".to_string())?;
            Instruction::SaveRestoreRegister {
                destination,
                source,
                operation,
            }
        }
        0xC2 => {
            let operation = SaveRestoreOp::from_bits((first >> 20) & 0xF)
                .ok_or_else(|| "invalid save/restore mask operation".to_string())?;
            Instruction::SaveRestoreRegisterMask {
                operation,
                mask: (first & 0xFFFF) as u16,
            }
        }
        0xC3 => Instruction::StaticRegister {
            static_index: ((first >> 4) & 0xFF) as u8,
            register: register(first & 0xF)?,
        },
        0xFF0 => Instruction::PauseProcess,
        0xFF1 => Instruction::ResumeProcess,
        _ => Instruction::Unsupported {
            opcode,
            words: words.to_vec(),
        },
    };

    if matches!(instruction, Instruction::Unsupported { .. }) {
        return Ok(instruction);
    }
    reader.finish()?;
    Ok(instruction)
}

// ---------------------------------------------------------------------------
// Control-flow validation
// ---------------------------------------------------------------------------

fn compile_control_flow(instructions: &[Instruction]) -> Result<Vec<JumpInfo>, (usize, String)> {
    let mut jumps = vec![JumpInfo::default(); instructions.len()];
    let mut conditionals: Vec<(usize, Option<usize>)> = Vec::new();
    let mut loops: Vec<(usize, u8)> = Vec::new();

    for (index, instruction) in instructions.iter().enumerate() {
        match instruction {
            Instruction::BeginConditional { .. }
            | Instruction::KeypressConditional { .. }
            | Instruction::RegisterConditional { .. } => {
                conditionals.push((index, None));
            }
            Instruction::EndConditional { is_else } => {
                if *is_else {
                    let Some((_, else_slot)) = conditionals.last_mut() else {
                        return Err((index, "else without a matching condition".to_string()));
                    };
                    if else_slot.is_some() {
                        return Err((index, "condition has more than one else".to_string()));
                    }
                    *else_slot = Some(index);
                } else {
                    let Some((begin, else_index)) = conditionals.pop() else {
                        return Err((index, "conditional end without a begin".to_string()));
                    };
                    let exit = index + 1;
                    jumps[begin].false_target = Some(match else_index {
                        Some(else_index) => {
                            jumps[else_index].else_target = Some(exit);
                            else_index + 1
                        }
                        None => exit,
                    });
                }
            }
            Instruction::LoopStart { register, .. } => loops.push((index, *register)),
            Instruction::LoopEnd { register } => {
                let Some((start, start_register)) = loops.pop() else {
                    return Err((index, "loop end without a loop start".to_string()));
                };
                if start_register != *register {
                    return Err((
                        index,
                        format!(
                            "loop end uses r{register} but the matching start uses r{start_register}"
                        ),
                    ));
                }
                jumps[index].loop_start = Some(start);
                jumps[start].loop_end = Some(index);
            }
            _ => {}
        }
    }

    if let Some((index, _)) = conditionals.first() {
        return Err((*index, "conditional block is never closed".to_string()));
    }
    if let Some((index, _)) = loops.first() {
        return Err((*index, "loop is never closed".to_string()));
    }
    Ok(jumps)
}

// ---------------------------------------------------------------------------
// Trailing line markers
// ---------------------------------------------------------------------------

#[derive(Default)]
struct TrailingMarkers {
    mode: Option<CheatExecMode>,
    disabled: bool,
    off_block: bool,
}

fn strip_trailing_markers(line: &str) -> (String, TrailingMarkers) {
    let mut markers = TrailingMarkers::default();
    let mut text = line.trim_end().to_string();

    loop {
        let lower = text.to_ascii_lowercase();
        let mut changed = false;
        for (tag, mode) in [
            ("@loop", Some(CheatExecMode::Loop)),
            ("[loop]", Some(CheatExecMode::Loop)),
            ("@patch", Some(CheatExecMode::Patch)),
            ("[patch]", Some(CheatExecMode::Patch)),
        ] {
            if lower.ends_with(tag) {
                markers.mode = mode;
                text.truncate(text.len() - tag.len());
                text = text.trim_end().to_string();
                changed = true;
                break;
            }
        }
        if changed {
            continue;
        }
        if lower.ends_with("--off") {
            markers.off_block = true;
            text.truncate(text.len() - "--off".len());
            text = text.trim_end().to_string();
            continue;
        }
        if lower.ends_with(":off") || lower.ends_with("@off") {
            markers.disabled = true;
            text.truncate(text.len() - 4);
            text = text.trim_end().to_string();
            continue;
        }
        break;
    }

    (text, markers)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(text: &str) -> CheatDocument {
        parse_document(text, "0123456789ABCDEF")
    }

    fn code(lines: &[&str]) -> CheatCode {
        let lines: Vec<String> = lines.iter().map(|line| (*line).to_string()).collect();
        parse_code_lines(&lines, 1)
    }

    #[test]
    fn parses_regular_and_master_sections() {
        let text = "\
; header comment
[Cheat A]
04000000 10000000 00000001

{Master Code}
04000000 20000000 00000002
";
        let document = doc(text);
        assert_eq!(document.blocks.len(), 2);
        assert_eq!(document.blocks[0].name, "Cheat A");
        assert_eq!(document.blocks[0].kind, CheatKind::Regular);
        // A section without a state marker is OFF, and a file never applies
        // anything on load.
        assert!(!document.blocks[0].enabled);
        assert!(!document.blocks[0].saved_enabled);
        assert_eq!(document.blocks[1].name, "Master Code");
        assert_eq!(document.blocks[1].kind, CheatKind::Master);
        assert_eq!(document.preamble, vec!["; header comment"]);
        assert_eq!(document.blocks[0].on.instructions.len(), 1);
    }

    #[test]
    fn parses_at_off_as_disabled_default() {
        let document = doc("[Money]\n@off\n04000000 30000000 00000003\n");
        assert_eq!(document.blocks.len(), 1);
        assert!(!document.blocks[0].enabled);
        assert!(!document.blocks[0].saved_enabled);
        assert_eq!(document.blocks[0].name, "Money");
        assert!(!document.blocks[0].explicit_off);
    }

    #[test]
    fn parses_inline_at_off_divider() {
        let document =
            doc("[Money]\n04000000 30000000 00000003\n@off\n04000000 30000000 00000000\n");
        let block = &document.blocks[0];
        assert!(block.explicit_off);
        assert_eq!(block.off_style, OffStyle::Inline);
        assert_eq!(block.on.instructions.len(), 1);
        assert_eq!(block.off.as_ref().unwrap().instructions.len(), 1);
    }

    #[test]
    fn parses_dash_off_divider() {
        let document =
            doc("[Money]\n04000000 30000000 00000003\n--off\n04000000 30000000 00000000\n");
        let block = &document.blocks[0];
        assert!(block.explicit_off);
        assert_eq!(block.off_style, OffStyle::Inline);
        assert_eq!(block.off.as_ref().unwrap().instructions.len(), 1);
    }

    #[test]
    fn parses_separate_off_section() {
        let document =
            doc("[Money]\n04000000 30000000 00000003\n\n[Money:OFF]\n04000000 30000000 00000000\n");
        assert_eq!(document.blocks.len(), 1);
        let block = &document.blocks[0];
        assert!(block.explicit_off);
        assert_eq!(block.off_style, OffStyle::SeparateSection);
        // The restore section does not apply anything either.
        assert!(!block.enabled);
        assert!(!block.saved_enabled);
        assert_eq!(block.off.as_ref().unwrap().instructions.len(), 1);
    }

    #[test]
    fn orphan_off_section_is_restore_only() {
        let document = doc("[Money:OFF]\n04000000 30000000 00000000\n");
        assert_eq!(document.blocks.len(), 1);
        assert!(document.blocks[0].is_restore_only());
        assert!(!document.blocks[0].is_enableable());
        assert!(!document.blocks[0].enabled);
        assert!(!document.blocks[0].saved_enabled);
    }

    /// An ON marker on disk is remembered for display, never applied.
    #[test]
    fn on_markers_are_remembered_but_never_enable_a_block() {
        let text = "\
[A:ON]
04000000 10000000 00000001

[B]
04000000 10000000 00000002

[C:OFF]
04000000 10000000 00000003

[D]
@on
04000000 10000000 00000004
";
        let document = doc(text);
        assert_eq!(document.blocks.len(), 4);
        for block in &document.blocks {
            assert!(!block.enabled, "{} must start OFF", block.name);
        }
        assert!(document.blocks[0].saved_enabled, "the file said ON for A");
        assert!(!document.blocks[1].saved_enabled);
        assert!(!document.blocks[2].saved_enabled);
        assert!(document.blocks[3].saved_enabled, "`@on` is an ON marker");
    }

    /// Every save path funnels through this: a file must never say ON.
    #[test]
    fn sanitizer_rewrites_on_markers_and_keeps_comments() {
        let text = "\
; [Commented:ON] and @on mentions must stay
[A:ON]
04000000 10000000 00000001
; @on in a comment stays too
[B]
@on
04000000 10000000 00000002
{C:ON}
04000000 10000000 00000003
";
        let clean = sanitize_on_markers(text);
        assert!(
            !clean.contains("[A:ON]") && !clean.contains("{C:ON}"),
            "header markers must be removed:\n{clean}"
        );
        assert!(
            !clean.lines().any(|line| line.trim().eq_ignore_ascii_case("@on")),
            "a bare @on must be rewritten:\n{clean}"
        );
        assert!(clean.contains("; [Commented:ON] and @on mentions must stay"));
        assert!(clean.contains("; @on in a comment stays too"));
        assert!(clean.contains("[A]\n@off\n04000000"), "{clean}");
        assert!(clean.contains("[B]\n@off\n04000000"), "{clean}");
        assert!(clean.contains("{C}\n@off\n04000000"), "{clean}");
        // The result is the OFF side for every block ...
        let document = doc(&clean);
        assert_eq!(document.blocks.len(), 3);
        for block in &document.blocks {
            assert!(!block.enabled && !block.saved_enabled, "{} is ON", block.name);
        }
        // ... and sanitizing it again changes nothing.
        assert_eq!(sanitize_on_markers(&clean), clean);
    }

    /// A header that already has an explicit `@off` below it is not doubled.
    #[test]
    fn sanitizer_does_not_duplicate_an_existing_off_directive() {
        let clean = sanitize_on_markers("[A:ON]\n@off\n04000000 10000000 00000001\n");
        assert_eq!(clean, "[A]\n@off\n04000000 10000000 00000001\n");
        // CRLF files keep their line endings.
        let crlf = sanitize_on_markers("[A:ON]\r\n04000000 10000000 00000001\r\n");
        assert_eq!(crlf, "[A]\r\n@off\r\n04000000 10000000 00000001\r\n");
    }

    /// The structured writer emits an OFF marker for every block, even when the
    /// in-memory state says ON: a save must never write a lie to disk.
    #[test]
    fn the_writer_always_saves_every_block_off() {
        let mut document = doc("[A]\n04000000 10000000 00000001\n");
        assert_eq!(document.blocks.len(), 1);
        // Simulate "the block is applied right now".
        document.blocks[0].enabled = true;
        document.blocks[0].saved_enabled = true;
        let text = document.to_text();
        assert!(text.contains("[A]\n@off\n04000000"), "{text}");
        assert!(!text.to_ascii_lowercase().contains(":on"), "{text}");
        assert!(
            !text.lines().any(|line| line.trim().eq_ignore_ascii_case("@on")),
            "{text}"
        );
        let reparsed = doc(&text);
        assert!(!reparsed.blocks[0].enabled);
        assert!(!reparsed.blocks[0].saved_enabled);
    }

    #[test]
    fn mode_auto_detects_keypress_opcode_8() {
        let document = doc("[Keys]\n80000001\n04000000 30000000 00000001\n20000000\n");
        let block = &document.blocks[0];
        assert_eq!(block.mode, CheatExecMode::Loop);
        assert_eq!(block.mode_source, ModeSource::Auto);
    }

    #[test]
    fn mode_auto_defaults_to_patch() {
        let document = doc("[Plain]\n04000000 30000000 00000001\n");
        assert_eq!(document.blocks[0].mode, CheatExecMode::Patch);
    }

    #[test]
    fn explicit_patch_overrides_opcode_8() {
        let document = doc("[Keys]\n@patch\n80000001\n04000000 30000000 00000001\n20000000\n");
        assert_eq!(document.blocks[0].mode, CheatExecMode::Patch);
        assert_eq!(document.blocks[0].mode_source, ModeSource::ExplicitPatch);
    }

    #[test]
    fn bracketed_mode_tag_and_header_tag_are_accepted() {
        let document = doc("[Keys] [loop]\n04000000 30000000 00000001\n[Plain @patch]\n04000000 30000000 00000001\n");
        assert_eq!(document.blocks[0].mode, CheatExecMode::Loop);
        assert_eq!(document.blocks[1].mode, CheatExecMode::Patch);
    }

    #[test]
    fn comments_and_round_trip_are_preserved() {
        let text = "\
; file preamble
[One] ; trailing
  ; inside comment
04000000 10000000 00000001 ; inline

[Two]
04000000 10000000 00000002

";
        let document = doc(text);
        let rendered = document.to_text();
        assert!(rendered.contains("; file preamble"));
        assert!(rendered.contains("[One] ; trailing"));
        assert!(rendered.contains("  ; inside comment"));
        assert!(rendered.contains("04000000 10000000 00000001 ; inline"));
        let reparsed = doc(&rendered);
        assert_eq!(reparsed.blocks.len(), 2);
        assert_eq!(
            reparsed.blocks[0].on.instructions,
            document.blocks[0].on.instructions
        );
    }

    #[test]
    fn duplicate_names_get_distinct_keys_and_survive_round_trip() {
        let text = "[Same]\n04000000 10000000 00000001\n[Same]\n04000000 10000000 00000002\n";
        let document = doc(text);
        assert_eq!(document.blocks.len(), 2);
        assert_ne!(document.blocks[0].key, document.blocks[1].key);
        let reparsed = doc(&document.to_text());
        assert_eq!(reparsed.blocks[0].key, document.blocks[0].key);
        assert_eq!(reparsed.blocks[1].key, document.blocks[1].key);
    }

    #[test]
    fn removing_one_duplicate_rekeys_the_survivor() {
        let text = "[Same]\n04000000 10000000 00000001\n[Same]\n04000000 10000000 00000002\n";
        let mut document = doc(text);
        let first = document.blocks[0].key;
        document.remove_block(first).unwrap();
        assert_eq!(document.blocks.len(), 1);
        assert_eq!(document.blocks[0].key, CheatKey::from_name("Same", 0));
        let reparsed = doc(&document.to_text());
        assert_eq!(reparsed.blocks[0].key, document.blocks[0].key);
    }

    #[test]
    fn decodes_store_static_widths_and_regions() {
        let code = code(&[
            "01000000 00001000 0000002A",
            "02000000 00001000 00002A2A",
            "04000000 00001000 11223344",
            "08000000 00001000 11223344 55667788",
            "04400000 00001000 11223344",
        ]);
        assert!(code.is_valid(), "{:?}", code.issues);
        assert_eq!(
            code.instructions[0],
            Instruction::StoreStatic {
                width: 1,
                region: MemoryRegion::Main,
                offset_register: 0,
                rel_address: 0x1000,
                value: 0x2A
            }
        );
        assert_eq!(
            code.instructions[4],
            Instruction::StoreStatic {
                width: 4,
                region: MemoryRegion::Absolute,
                offset_register: 0,
                rel_address: 0x1000,
                value: 0x1122_3344
            }
        );
    }

    #[test]
    fn decodes_40_bit_relative_address() {
        let code = code(&["044000AB 12345678 00000001"]);
        assert!(code.is_valid(), "{:?}", code.issues);
        match code.instructions[0] {
            Instruction::StoreStatic { rel_address, .. } => {
                assert_eq!(rel_address, 0xAB_1234_5678);
            }
            ref other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn decodes_conditional_and_else_structure() {
        let code = code(&[
            "14050000 00001000 00000001",
            "04000000 00002000 000000AA",
            "21000000",
            "04000000 00002000 000000BB",
            "20000000",
        ]);
        assert!(code.is_valid(), "{:?}", code.issues);
        assert_eq!(code.jumps[0].false_target, Some(3));
        assert_eq!(code.jumps[2].else_target, Some(5));
    }

    #[test]
    fn rejects_unbalanced_conditionals() {
        let code = code(&["14050000 00001000 00000001"]);
        assert!(!code.is_valid());
        assert!(code.issues[0].message.contains("never closed"));
    }

    #[test]
    fn decodes_nested_conditionals() {
        let code = code(&[
            "14050000 00001000 00000001",
            "14050000 00001000 00000002",
            "04000000 00002000 000000AA",
            "20000000",
            "20000000",
        ]);
        assert!(code.is_valid(), "{:?}", code.issues);
        assert_eq!(code.jumps[0].false_target, Some(5));
        assert_eq!(code.jumps[1].false_target, Some(4));
    }

    #[test]
    fn decodes_loops_and_pairs_them() {
        let code = code(&[
            "30000000 00000003",
            "04000000 00001000 00000001",
            "31000000",
        ]);
        assert!(code.is_valid(), "{:?}", code.issues);
        assert_eq!(code.jumps[0].loop_end, Some(2));
        assert_eq!(code.jumps[2].loop_start, Some(0));
    }

    #[test]
    fn rejects_loop_register_mismatch() {
        let code = code(&["30010000 00000003", "31020000"]);
        assert!(!code.is_valid());
        assert!(code.issues[0].message.contains("matching start"));
    }

    #[test]
    fn decodes_register_load_and_arithmetic() {
        let code = code(&[
            "40010000 11223344 55667788",
            "98020100 00000000 00000005",
            "91010A00 00000003",
            "98910070",
            "94A10100 3F800000",
        ]);
        assert!(code.is_valid(), "{:?}", code.issues);
        assert_eq!(
            code.instructions[0],
            Instruction::LoadRegisterImmediate {
                register: 1,
                value: 0x1122_3344_5566_7788
            }
        );
        assert!(matches!(
            code.instructions[1],
            Instruction::RegisterArithmetic {
                width: 8,
                operation: ArithmeticOp::Add,
                ..
            }
        ));
        assert!(matches!(
            code.instructions[4],
            Instruction::RegisterArithmetic {
                operation: ArithmeticOp::FloatAdd,
                ..
            }
        ));
    }

    #[test]
    fn decodes_load_register_memory_modes() {
        let code = code(&[
            "54010000 00001000",
            "54011000 00000010",
            "54012100 00000010",
            "54013100 00000010",
        ]);
        assert!(code.is_valid(), "{:?}", code.issues);
        for (index, mode) in [0u8, 1, 2, 3].iter().enumerate() {
            match code.instructions[index] {
                Instruction::LoadRegisterMemory {
                    load_from_register, ..
                } => assert_eq!(load_from_register, *mode),
                ref other => panic!("unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn decodes_store_static_to_register() {
        let code = code(&["64011010 11223344 55667788"]);
        assert!(code.is_valid(), "{:?}", code.issues);
        match code.instructions[0] {
            Instruction::StoreStaticToRegister {
                width,
                register,
                increment,
                add_offset_register,
                offset_register,
                value,
            } => {
                assert_eq!(width, 4);
                assert_eq!(register, 1);
                assert!(increment);
                assert!(!add_offset_register);
                assert_eq!(offset_register, 1);
                assert_eq!(value, 0x1122_3344_5566_7788);
            }
            ref other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn decodes_keypress_mask() {
        let code = code(&["8ABCDEF0", "20000000"]);
        assert!(code.is_valid(), "{:?}", code.issues);
        assert_eq!(
            code.instructions[0],
            Instruction::KeypressConditional {
                key_mask: 0x0ABC_DEF0
            }
        );
    }

    #[test]
    fn decodes_store_register_offset_types() {
        let code = code(&[
            "A4100000",
            "A4100130",
            "A4100200 00001000",
            "A4100300",
            "A4100400 00001000",
            "A4100500 00001000",
        ]);
        assert!(code.is_valid(), "{:?}", code.issues);
        assert_eq!(
            code.instructions[0],
            Instruction::StoreRegisterToMemory {
                width: 4,
                source_register: 1,
                address_register: 0,
                increment: false,
                offset: StoreOffset::None
            }
        );
        assert!(matches!(
            code.instructions[4],
            Instruction::StoreRegisterToMemory {
                offset: StoreOffset::MemoryImmediate {
                    region: MemoryRegion::Main,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn decodes_register_conditional_all_operand_types() {
        let code = code(&[
            "C0410000 00001000",
            "C0410100",
            "C0410200 00001000",
            "C0410300",
            "C0410400 0000002A",
            "C0410550",
            "20000000",
            "20000000",
            "20000000",
            "20000000",
            "20000000",
            "20000000",
        ]);
        assert!(code.is_valid(), "{:?}", code.issues);
        assert!(matches!(
            code.instructions[0],
            Instruction::RegisterConditional {
                operand: ConditionalOperand::MemoryRelative { .. },
                ..
            }
        ));
        assert!(matches!(
            code.instructions[5],
            Instruction::RegisterConditional {
                operand: ConditionalOperand::Register(5),
                ..
            }
        ));
    }

    #[test]
    fn decodes_save_restore_and_static_registers() {
        let code = code(&[
            "C1010000", "C21000FF", "C30000A0", "C30008A1", "FF000000", "FF100000",
        ]);
        assert!(code.is_valid(), "{:?}", code.issues);
        assert_eq!(
            code.instructions[0],
            Instruction::SaveRestoreRegister {
                destination: 1,
                source: 0,
                operation: SaveRestoreOp::Restore
            }
        );
        assert_eq!(
            code.instructions[1],
            Instruction::SaveRestoreRegisterMask {
                operation: SaveRestoreOp::Save,
                mask: 0x00FF
            }
        );
        assert_eq!(
            code.instructions[2],
            Instruction::StaticRegister {
                static_index: 0x0A,
                register: 0
            }
        );
        assert_eq!(code.instructions[4], Instruction::PauseProcess);
        assert_eq!(code.instructions[5], Instruction::ResumeProcess);
    }

    #[test]
    fn unsupported_opcode_keeps_file_loadable_but_invalid() {
        let code = code(&["B4000000 00000000"]);
        assert!(!code.is_valid());
        assert!(matches!(
            code.instructions[0],
            Instruction::Unsupported { opcode: 0xB, .. }
        ));
        assert!(code.issues[0].message.contains("unsupported opcode"));
    }

    #[test]
    fn malformed_word_and_extra_words_are_reported() {
        let code = code(&["04000000 00000000 00000001 00000002", "ZZZZ"]);
        assert!(!code.is_valid());
        assert_eq!(code.issues.len(), 2);
    }

    #[test]
    fn instruction_encode_round_trips_through_decoder() {
        let original = code(&[
            "04000000 00001000 11223344",
            "18050000 00001000 00000000 00000001",
            "04000000 00002000 00000001",
            "21000000",
            "04000000 00002000 00000002",
            "20000000",
            "30020000 00000002",
            "74010000 00000001",
            "31020000",
            "40030000 11223344 55667788",
            "54041000 00002000",
            "64051110 11223344 55667788",
            "74060000 00000002",
            "8ABCDEF0",
            "04000000 00002000 00000003",
            "20000000",
            "98020100 00000000 00000005",
            "A4081200 00001000",
            "C0410000 00001000",
            "20000000",
            "C1A0B010",
            "C22000FF",
            "C3300F00",
            "FF000000",
            "FF100000",
        ]);
        assert!(original.is_valid(), "{:?}", original.issues);
        for instruction in &original.instructions {
            let words = instruction.encode();
            let decoded = decode_words(&words).unwrap();
            assert_eq!(&decoded, instruction);
        }
    }

    #[test]
    fn add_edit_delete_and_save_round_trip() {
        let mut document = doc("[A]\n04000000 10000000 00000001\n");
        let key = document.add_cheat("B", &["04000000 20000000 00000002".to_string()], None);
        assert_eq!(document.blocks.len(), 2);
        document
            .replace_on_code(key, &["04000000 20000000 00000003".to_string()])
            .unwrap();
        assert_eq!(document.blocks[1].on.instructions.len(), 1);
        let removed = document.remove_block(document.blocks[0].key).unwrap();
        assert_eq!(removed.name, "A");
        assert_eq!(document.blocks.len(), 1);
    }
}
