//! Hex editor pane.
//!
//! Supports the things a memory editor actually needs: click / shift-click
//! selection, keyboard navigation, typing hex digits to overwrite memory,
//! undo, clipboard copy/paste, value interpretation and a one-click freeze.
//! Scrolls far enough to page through memory without leaving the keyboard.

use eframe::egui;
use egui::{Align2, Color32, FontId, Rect, Sense, Stroke, Vec2};

use std::fmt::Write as _;
use std::sync::mpsc::Sender;

use super::{Cmd, Prefs, State};

pub const PAGE: u64 = 0x4000;          // bytes held in the view at once
const ROW: usize = 16;                  // bytes per row

#[derive(Default)]
pub struct Undo {
    pub address: u64,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

pub struct HexView {
    pub base: u64,
    pub data: Vec<u8>,
    pub cursor: u64,
    pub anchor: Option<u64>,
    pub nibble: Option<u8>,             // high nibble typed first
    pub go_to: String,
    pub undo: Vec<Undo>,
    pub pending: u64,                   // address of the last write (flash)
    pub pending_until: f64,
    pub scroll_row: usize,
    pub value_input: String,
    pub value_type: usize,
    pub ascii_focus: bool,
    pub status: String,
    pub focused: bool,
    visible_rows: usize,
}

pub const VALUE_TYPES: [(&str, usize); 10] = [
    ("u8", 1), ("i8", 1), ("u16", 2), ("i16", 2), ("u32", 4),
    ("i32", 4), ("u64", 8), ("i64", 8), ("f32", 4), ("f64", 8),
];

impl HexView {
    pub fn new() -> HexView {
        HexView {
            base: 0x42CA1DC0,
            data: Vec::new(),
            cursor: 0x42CA1DC4,
            anchor: None,
            nibble: None,
            go_to: String::new(),
            undo: Vec::new(),
            pending: 0,
            pending_until: 0.0,
            scroll_row: 0,
            value_input: String::new(),
            value_type: 4,
            ascii_focus: false,
            status: String::new(),
            focused: false,
            visible_rows: 16,
        }
    }

    /// Parse "0x1234", "4660", "main+0x20", or full arithmetic/bitwise expressions.
    pub fn parse_address(text: &str, main_base: u64) -> Option<u64> {
        crate::protocol::eval_expr(text, main_base, 0)
    }

    pub fn parse_address_ex(text: &str, main_base: u64, heap_base: u64) -> Option<u64> {
        crate::protocol::eval_expr(text, main_base, heap_base)
    }

    pub fn set_data(&mut self, address: u64, data: Vec<u8>) {
        self.base = address;
        self.data = data;
        self.scroll_row = 0;
    }

    pub fn patch(&mut self, address: u64, bytes: &[u8]) {
        for (i, byte) in bytes.iter().enumerate() {
            let at = address + i as u64;
            if at >= self.base && at < self.base + self.data.len() as u64 {
                self.data[(at - self.base) as usize] = *byte;
            }
        }
    }

    pub fn byte(&self, address: u64) -> Option<u8> {
        if address >= self.base && address < self.base + self.data.len() as u64 {
            Some(self.data[(address - self.base) as usize])
        } else {
            None
        }
    }

    pub fn selection(&self) -> Option<(u64, u64)> {
        let anchor = self.anchor?;
        let (a, b) = if anchor <= self.cursor { (anchor, self.cursor) } else { (self.cursor, anchor) };
        Some((a, b))
    }

    pub fn jump_to(&mut self, address: u64, fetch: bool, st: &mut super::State,
                   tx: &std::sync::mpsc::Sender<Cmd>) {
        self.jump_to_inner(address, fetch, false, st, tx);
    }

    /// Re-read the current page.  Unlike jump_to() this always sends the request:
    /// jump_to() only fetches when the page changes, so the Refresh button was a
    /// no-op on the page already displayed.
    pub fn reload(&mut self, st: &mut super::State, tx: &std::sync::mpsc::Sender<Cmd>) {
        let address = self.cursor;
        self.jump_to_inner(address, true, true, st, tx);
    }

    fn jump_to_inner(&mut self, address: u64, fetch: bool, force: bool,
                     st: &mut super::State, tx: &std::sync::mpsc::Sender<Cmd>) {
        self.cursor = address;
        self.anchor = Some(address);
        self.nibble = None;
        if fetch && st.connected {
            let page = address & !(PAGE - 1);
            if force || page != self.base || self.data.is_empty() {
                let _ = tx.send(Cmd::Read { address: page, size: PAGE as u32 });
            }
        }
        self.scroll_to_cursor();
    }

    fn scroll_to_cursor(&mut self) {
        let row = ((self.cursor.saturating_sub(self.base)) / ROW as u64) as usize;
        let visible = self.visible_rows.max(1);
        if row < self.scroll_row {
            self.scroll_row = row;
        } else if row >= self.scroll_row + visible {
            self.scroll_row = row + 1 - visible;
        }
    }

    pub fn write_bytes(&mut self, st: &mut super::State, tx: &std::sync::mpsc::Sender<Cmd>,
                       address: u64, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        let before: Vec<u8> = (0..bytes.len())
            .map(|i| self.byte(address + i as u64).unwrap_or(0))
            .collect();
        self.undo.push(Undo { address, before, after: bytes.clone() });
        if self.undo.len() > 128 {
            self.undo.remove(0);
        }
        self.patch(address, &bytes);
        self.pending = address;
        self.pending_until = st.started.elapsed().as_secs_f64() + 0.6;
        st.busy = true;
        let _ = tx.send(Cmd::Write { address, data: bytes });
    }

    fn undo_last(&mut self, st: &mut super::State, tx: &std::sync::mpsc::Sender<Cmd>) {
        if let Some(entry) = self.undo.pop() {
            let before = entry.before.clone();
            self.patch(entry.address, &before);
            st.busy = true;
            let _ = tx.send(Cmd::Write { address: entry.address, data: before });
            self.cursor = entry.address;
            st.log(format!("undo write at {:08X}", entry.address));
        }
    }

    pub fn decode_at(&self, address: u64, size: usize, signed: bool) -> Option<f64> {
        let mut bytes = [0u8; 8];
        for i in 0..size {
            bytes[i] = self.byte(address + i as u64)?;
        }
        Some(match (size, signed) {
            (1, false) => bytes[0] as f64,
            (1, true) => bytes[0] as i8 as f64,
            (2, false) => u16::from_le_bytes([bytes[0], bytes[1]]) as f64,
            (2, true) => i16::from_le_bytes([bytes[0], bytes[1]]) as f64,
            (4, false) => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64,
            (4, true) => i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64,
            (8, _) => u64::from_le_bytes(bytes) as f64,
            _ => return None,
        })
    }

    pub fn read_value(&self, address: u64) -> String {
        let (_, size) = VALUE_TYPES[self.value_type];
        let signed = VALUE_TYPES[self.value_type].0.starts_with('i');
        let name = VALUE_TYPES[self.value_type].0;
        let mut bytes = [0u8; 8];
        let mut ok = true;
        for i in 0..size.min(8) {
            match self.byte(address + i as u64) {
                Some(byte) => bytes[i] = byte,
                None => ok = false,
            }
        }
        if !ok {
            return "-".into();
        }
        match name {
            "f32" => format!("{}", f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
            "f64" => format!("{}", f64::from_le_bytes(bytes)),
            _ => match self.decode_at(address, size, signed) {
                Some(value) => format!("{}", value as i64),
                None => "-".into(),
            },
        }
    }

    fn encode_value(&self) -> Option<Vec<u8>> {
        let (name, size) = VALUE_TYPES[self.value_type];
        let text = self.value_input.trim();
        if text.is_empty() {
            return None;
        }
        let mut out = Vec::with_capacity(size);
        let parsed: f64 = if name.starts_with('f') {
            text.parse().ok()?
        } else if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()? as f64
        } else {
            text.parse().ok()?
        };
        match name {
            "u8" | "i8" => out.push(parsed as i64 as u8),
            "u16" | "i16" => out.extend_from_slice(&(parsed as i64 as u16).to_le_bytes()),
            "u32" | "i32" => out.extend_from_slice(&(parsed as i64 as u32).to_le_bytes()),
            "u64" | "i64" => out.extend_from_slice(&(parsed as i64 as u64).to_le_bytes()),
            "f32" => out.extend_from_slice(&(parsed as f32).to_le_bytes()),
            "f64" => out.extend_from_slice(&parsed.to_le_bytes()),
            _ => return None,
        }
        Some(out)
    }

    pub fn ui(&mut self, st: &mut State, prefs: &mut Prefs, tx: &Sender<Cmd>, ui: &mut egui::Ui) {
        // ---- toolbar ----
        ui.horizontal(|ui| {
            ui.label("Go to:");
            let edit = ui.add(egui::TextEdit::singleline(&mut self.go_to)
                .desired_width(120.0)
                .hint_text("42CA1DC4"));
            if edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                self.apply_goto(st, tx);
            }
            if ui.button("Go").clicked() {
                self.apply_goto(st, tx);
            }
            if ui.button("-4K").clicked() {
                let target = self.base.saturating_sub(PAGE);
                self.jump_to(target, true, st, tx);
            }
            if ui.button("+4K").clicked() {
                let target = self.base + PAGE;
                self.jump_to(target, true, st, tx);
            }
            ui.separator();
            if ui.button("Undo").on_hover_text("Ctrl+Z").clicked() {
                self.undo_last(st, tx);
            }
            if ui.button("Copy").on_hover_text("copy selection as hex").clicked() {
                let text = self.selection_text();
                ui.ctx().copy_text(text);
                self.status = "selection copied".into();
            }
            if ui.button("Refresh").on_hover_text("re-read this page").clicked() {
                self.reload(st, tx);
            }
            ui.separator();
            ui.label("write-protect");
            ui.checkbox(&mut prefs.write_protect, "");
            if prefs.write_protect {
                ui.colored_label(Color32::from_rgb(0xF0, 0xB2, 0x32), "ON (typing is ignored)");
            } else {
                ui.colored_label(Color32::from_rgb(0xFF, 0x6B, 0x6B), "off - edits go to the console");
            }
        });

        ui.horizontal(|ui| {
            ui.label("cursor:");
            ui.monospace(format!("{:08X}", self.cursor));
            if let Some((start, end)) = self.selection() {
                ui.label("selection:");
                ui.monospace(format!("{:08X}-{:08X} ({} bytes)", start, end, end - start + 1));
            }
            ui.separator();
            ui.label("value:");
            ui.monospace(self.read_value(self.cursor));
            if ui.button("Freeze").on_hover_text("let the console keep this value pinned").clicked() {
                let width = VALUE_TYPES[self.value_type].1 as u32;
                let address = self.cursor;
                st.busy = true;
                st.last_message = "freezing".into();
                let _ = tx.send(Cmd::Freeze { address, width });
            }
            if ui.button("Unfreeze").clicked() {
                let address = self.cursor;
                st.busy = true;
                st.last_message = "unfreezing".into();
                let _ = tx.send(Cmd::Unfreeze { address });
            }
        });

        ui.separator();

        // ---- value writer ----
        ui.horizontal(|ui| {
            ui.label("write value:");
            egui::ComboBox::from_id_salt("hex-value-type")
                .selected_text(VALUE_TYPES[self.value_type].0)
                .width(60.0)
                .show_ui(ui, |ui| {
                    for (index, (name, _)) in VALUE_TYPES.iter().enumerate() {
                        ui.selectable_value(&mut self.value_type, index, *name);
                    }
                });
            let edit = ui.add(egui::TextEdit::singleline(&mut self.value_input)
                .desired_width(140.0)
                .hint_text("9999999 or 0x98967F"));
            let submit = ui.button("Write").clicked()
                || (edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
            if submit {
                if let Some(bytes) = self.encode_value() {
                    if prefs.write_protect {
                        self.status = "write-protect is ON - value not written".into();
                    } else {
                        let address = self.cursor;
                        self.write_bytes(st, tx, address, bytes);
                        self.status = format!("wrote {}", self.value_input);
                    }
                } else {
                    self.status = "cannot parse that value".into();
                }
            }
            if !self.status.is_empty() {
                ui.colored_label(Color32::from_rgb(0x9A, 0xA3, 0xB0), &self.status);
            }
        });

        ui.separator();

        // ---- the grid ----
        let font = FontId::monospace(14.0);
        let char_w = ui.painter().layout_no_wrap("0".into(), font.clone(), Color32::WHITE).size().x;
        let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 4.0;
        let gutter = char_w * 10.0;
        let hex_x = gutter + char_w;
        let byte_w = char_w * 3.0;
        let ascii_x = hex_x + byte_w * ROW as f32 + char_w * 2.0;

        let available = ui.available_size();
        let rows_visible = (((available.y - 8.0) / row_h).floor() as usize).max(1);
        self.visible_rows = rows_visible;

        let (rect, response) = ui.allocate_exact_size(
            Vec2::new(available.x, row_h * rows_visible as f32 + 8.0),
            Sense::click_and_drag(),
        );
        let painter = ui.painter_at(rect);
        let origin = rect.left_top() + Vec2::new(4.0, 4.0);

        painter.rect_filled(rect, 2.0, Color32::from_rgb(0x14, 0x16, 0x1A));

        let total_rows = (self.data.len() + ROW - 1) / ROW;
        let selection = self.selection();
        let flash = st.started.elapsed().as_secs_f64() < self.pending_until;

        // Reused scratch buffers for the cell text.  Formatting each cell with
        // `format!` / `to_string()` meant ~1960 short-lived `String`s per frame on
        // a 960-cell page (16 hex + 16 ascii cells per row); clearing and
        // refilling one buffer per kind produces byte-identical text with no
        // allocation of our own.
        let mut row_addr_text = String::with_capacity(8);
        let mut hex_text = String::with_capacity(2);
        let mut ascii_text = String::with_capacity(1);

        for row in 0..rows_visible {
            let index = self.scroll_row + row;
            let y = origin.y + row as f32 * row_h;
            let row_address = self.base + (index * ROW) as u64;
            if index >= total_rows {
                continue;
            }
            row_addr_text.clear();
            let _ = write!(row_addr_text, "{:08X}", row_address);
            painter.text(egui::pos2(origin.x, y), Align2::LEFT_TOP,
                         row_addr_text.as_str(), font.clone(),
                         Color32::from_rgb(0x8A, 0x92, 0xA0));

            for col in 0..ROW {
                let at = index * ROW + col;
                let address = row_address + col as u64;
                let x_hex = origin.x + hex_x + col as f32 * byte_w;
                let x_ascii = origin.x + ascii_x + col as f32 * char_w;

                let selected = match selection {
                    Some((start, end)) => address >= start && address <= end,
                    None => false,
                };
                if selected {
                    painter.rect_filled(Rect::from_min_size(egui::pos2(x_hex - 2.0, y - 1.0),
                                                            Vec2::new(byte_w, row_h - 2.0)),
                                        1.0, Color32::from_rgb(0x2E, 0x44, 0x74));
                    painter.rect_filled(Rect::from_min_size(egui::pos2(x_ascii - 1.0, y - 1.0),
                                                            Vec2::new(char_w, row_h - 2.0)),
                                        1.0, Color32::from_rgb(0x2E, 0x44, 0x74));
                }
                if address == self.cursor {
                    painter.rect_filled(Rect::from_min_size(egui::pos2(x_hex - 2.0, y - 1.0),
                                                            Vec2::new(byte_w, row_h - 2.0)),
                                        1.0, Color32::from_rgb(0x4C, 0x8D, 0xFF));
                }
                if flash && address >= self.pending && address < self.pending + 4 {
                    painter.rect_filled(Rect::from_min_size(egui::pos2(x_hex - 2.0, y - 1.0),
                                                            Vec2::new(byte_w, row_h - 2.0)),
                                        1.0, Color32::from_rgb(0x2F, 0x6B, 0x45));
                }

                let byte = self.data.get(at).copied().unwrap_or(0);
                let hex_color = if address == self.cursor {
                    Color32::from_rgb(0x0B, 0x10, 0x18)
                } else {
                    Color32::from_rgb(0xE6, 0xE9, 0xEE)
                };
                hex_text.clear();
                let _ = write!(hex_text, "{:02X}", byte);
                painter.text(egui::pos2(x_hex, y), Align2::LEFT_TOP, hex_text.as_str(),
                             font.clone(), hex_color);
                let printable = byte >= 32 && byte < 127;
                ascii_text.clear();
                let _ = write!(ascii_text, "{}", if printable { byte as char } else { '.' });
                painter.text(egui::pos2(x_ascii, y), Align2::LEFT_TOP, ascii_text.as_str(),
                             font.clone(),
                             if printable { Color32::from_rgb(0x5A, 0xD0, 0x8A) }
                             else { Color32::from_rgb(0x55, 0x5B, 0x66) });
            }
        }

        // ---- mouse ----
        if let Some(pos) = response.interact_pointer_pos() {
            if response.clicked() || response.dragged() {
                let row = (((pos.y - origin.y) / row_h).floor() as i64).clamp(0, rows_visible as i64 - 1) as usize;
                let index = self.scroll_row + row;
                let address = if pos.x >= origin.x + ascii_x {
                    let col = ((pos.x - origin.x - ascii_x) / char_w).floor().max(0.0) as usize;
                    self.base + (index * ROW + col.min(ROW - 1)) as u64
                } else {
                    let col = ((pos.x - origin.x - hex_x) / byte_w).floor();
                    let col = col.clamp(0.0, (ROW - 1) as f32) as usize;
                    self.base + (index * ROW + col) as u64
                };
                let address = address.min(self.base + self.data.len().saturating_sub(1) as u64);
                let shift = ui.input(|i| i.modifiers.shift);
                self.cursor = address;
                if !shift {
                    self.anchor = Some(address);
                }
                self.nibble = None;
                self.scroll_to_cursor();
            }
        }

        // ---- wheel / keyboard ----
        if response.hovered() {
            let delta = ui.input(|i| i.smooth_scroll_delta.y);
            if delta.abs() > 0.5 {
                let lines = (-delta / row_h).round() as i64;
                let max_row = total_rows.saturating_sub(rows_visible) as i64;
                self.scroll_row = (self.scroll_row as i64 + lines).clamp(0, max_row.max(0)) as usize;
            }
        }

        let (keys, text, paste, scroll) = ui.input(|i| {
            let keys: Vec<egui::Key> = i.events.iter().filter_map(|e| match e {
                egui::Event::Key { key, pressed: true, .. } => Some(*key),
                _ => None,
            }).collect();
            let mut text = String::new();
            let mut paste = false;
            for event in &i.events {
                match event {
                    egui::Event::Text(t) => text.push_str(t),
                    egui::Event::Paste(_) => paste = true,
                    _ => {}
                }
            }
            (keys, text, paste, i.modifiers)
        });
        let _ = scroll;

        if response.clicked() {
            self.focused = true;
        } else if response.clicked_elsewhere() {
            self.focused = false;
        }
        if response.hovered() || self.focused {
            let shift = ui.input(|i| i.modifiers.shift);
            let ctrl = ui.input(|i| i.modifiers.command);
            for key in keys {
                match key {
                    egui::Key::ArrowLeft => self.move_cursor(-1, shift),
                    egui::Key::ArrowRight => self.move_cursor(1, shift),
                    egui::Key::ArrowUp => self.move_cursor(-(ROW as i64), shift),
                    egui::Key::ArrowDown => self.move_cursor(ROW as i64, shift),
                    egui::Key::PageUp => self.move_cursor(-((rows_visible * ROW) as i64), shift),
                    egui::Key::PageDown => self.move_cursor((rows_visible * ROW) as i64, shift),
                    egui::Key::Home => {
                        self.cursor = self.base;
                        self.anchor = if shift { self.anchor } else { Some(self.cursor) };
                    }
                    egui::Key::End => {
                        self.cursor = self.base + self.data.len().saturating_sub(1) as u64;
                        self.anchor = if shift { self.anchor } else { Some(self.cursor) };
                    }
                    egui::Key::Backspace if !prefs.write_protect => {
                        let address = self.cursor;
                        self.write_bytes(st, tx, address, vec![0]);
                        self.move_cursor(1, false);
                    }
                    egui::Key::Delete if !prefs.write_protect => {
                        let address = self.cursor;
                        self.write_bytes(st, tx, address, vec![0]);
                    }
                    egui::Key::Z if ctrl => self.undo_last(st, tx),
                    egui::Key::C if ctrl => {
                        let text = self.selection_text();
                        ui.ctx().copy_text(text);
                        self.status = "selection copied".into();
                    }
                    _ => {}
                }
            }

            if !prefs.write_protect {
                for ch in text.chars() {
                    if let Some(digit) = ch.to_digit(16) {
                        self.type_nibble(digit as u8, st, tx);
                    }
                }
            } else if !text.is_empty() {
                self.status = "write-protect is ON - typing is ignored".into();
            }
            let _ = paste;
        }
        self.scroll_to_cursor();
        let _ = rect;
        let _ = Stroke::NONE;
    }

    fn move_cursor(&mut self, delta: i64, extend: bool) {
        let limit = self.base + self.data.len().saturating_sub(1) as u64;
        let next = (self.cursor as i64 + delta).clamp(self.base as i64, limit as i64) as u64;
        self.cursor = next;
        if !extend {
            self.anchor = Some(next);
        }
        self.nibble = None;
        self.scroll_to_cursor();
    }

    /// Classic hex-editor typing: first digit is the high nibble, the second one
    /// commits the byte and moves on.
    fn type_nibble(&mut self, digit: u8, st: &mut super::State, tx: &Sender<Cmd>) {
        let value = match self.nibble {
            None => {
                self.nibble = Some(digit);
                return;
            }
            Some(high) => {
                self.nibble = None;
                (high << 4) | digit
            }
        };
        let address = self.cursor;
        self.write_bytes(st, tx, address, vec![value]);
        self.move_cursor(1, false);
    }

    pub fn selection_text(&self) -> String {
        match self.selection() {
            Some((start, end)) => {
                let mut out = String::new();
                let mut address = start;
                while address <= end {
                    match self.byte(address) {
                        Some(byte) => out.push_str(&format!("{:02X} ", byte)),
                        None => out.push_str("?? "),
                    }
                    address += 1;
                }
                out.trim_end().to_string()
            }
            None => String::new(),
        }
    }

    fn apply_goto(&mut self, st: &mut State, tx: &Sender<Cmd>) {
        let text = self.go_to.trim().to_string();
        if text.is_empty() {
            return;
        }
        let address = HexView::parse_address_ex(&text, st.main_base(), st.heap_base());
        match address {
            Some(address) => {
                self.jump_to(address, true, st, tx);
                self.status.clear();
            }
            None => self.status = format!("cannot parse {}", text),
        }
    }

}