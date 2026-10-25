//! Panels and windows for the Nxus GUI.

use eframe::egui;
use egui::{Color32, RichText};
use egui_extras::{Column, TableBuilder};

use super::{auto_continue_for, App, Cmd, Tab, DISASM_PAGE, SCOPE_NAMES, WATCH_KINDS};
use crate::protocol::VALUE_TYPE_NAMES;

const ACCENT: Color32 = Color32::from_rgb(0x4C, 0x8D, 0xFF);
const GREEN: Color32 = Color32::from_rgb(0x5A, 0xD0, 0x8A);
const YELLOW: Color32 = Color32::from_rgb(0xFF, 0xC8, 0x66);
const DIM: Color32 = Color32::from_rgb(0x9A, 0xA3, 0xB0);
const RED: Color32 = Color32::from_rgb(0xFF, 0x6B, 0x6B);

/// "The hit list is incomplete" badge, built the same way as the STOPPED badge in
/// the top bar: a marker square plus strong coloured text, with the explanation
/// on hover.
///
/// The console reports a capped hit list with `NXUS_HITBATCH_TRUNCATED`
/// (`NxusClient::last_scan_truncated`); without a visible marker a cut-off result
/// reads exactly like a complete one, which is how a scan that never saw a match
/// was silently taken as final.
fn truncated_badge(ui: &mut egui::Ui) {
    ui.label(RichText::new("■ TRUNCATED").strong().color(YELLOW))
        .on_hover_text("hit list full: the console kept as many hits as it could and more \
                        may exist - refine the scan or raise the limit");
}

pub fn parse_value(text: &str, size: u32) -> u64 {
    let text = text.trim();
    let value = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex.replace('_', "").as_str(), 16).unwrap_or(0)
    } else {
        text.replace('_', "").parse::<u64>().unwrap_or_else(|_| {
            u64::from_str_radix(&text.replace('_', ""), 16).unwrap_or(0)
        })
    };
    match size {
        1 => value & 0xFF,
        2 => value & 0xFFFF,
        4 => value & 0xFFFF_FFFF,
        _ => value,
    }
}

pub fn parse_range(begin: &str, end: &str) -> (u64, u64) {
    parse_range_ex(begin, end, 0, 0)
}

pub fn parse_range_ex(begin: &str, end: &str, main_base: u64, heap_base: u64) -> (u64, u64) {
    let b = if begin.trim().is_empty() {
        0
    } else {
        crate::protocol::eval_expr(begin, main_base, heap_base).unwrap_or_else(|| parse_value(begin, 8))
    };
    let e = if end.trim().is_empty() {
        0
    } else {
        crate::protocol::eval_expr(end, main_base, heap_base).unwrap_or_else(|| parse_value(end, 8))
    };
    (b, e)
}

// ---------------------------------------------------------------- top bar

pub fn top_bar(app: &mut App, ui: &mut egui::Ui) {
    egui::Panel::top("top").show(ui, |ui| {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Nxus").heading().color(ACCENT));
            ui.separator();
            ui.label("host");
            ui.add(egui::TextEdit::singleline(&mut app.prefs.host).desired_width(140.0));
            ui.label("port");
            ui.add(egui::TextEdit::singleline(&mut app.prefs.port).desired_width(60.0));

            let connect_label = if app.st.connected { "Reconnect" } else { "Connect" };
            if ui.add(egui::Button::new(RichText::new(connect_label).strong())).clicked() {
                let host = app.prefs.host.clone();
                let port = app.prefs.port.trim().parse().unwrap_or(7332);
                app.send(Cmd::Connect { host, port }, "connecting");
            }
            if app.st.connected {
                if ui.button("Disconnect").clicked() {
                    app.cancel_work("disconnecting");
                    app.send(Cmd::Disconnect, "disconnecting");
                }
                ui.separator();
                if ui.button("Pause").on_hover_text("freeze the game").clicked() {
                    app.send(Cmd::Pause, "pausing");
                }
                if ui.button("Resume").clicked() {
                    app.send(Cmd::Resume, "resuming");
                }
            }
            ui.separator();
            if ui.button("Refresh").on_hover_text("re-read status (F5 in the scan panel does a scan)").clicked() {
                app.send(Cmd::Refresh, "refreshing");
            }
            if ui.button("Settings").clicked() {
                app.show_settings = true;
            }
            ui.checkbox(&mut app.prefs.auto_connect, "auto-connect")
                .on_hover_text("connect to the remembered address when Nxus starts");
            if ui.button("Info").clicked() {
                app.show_modules = true;
                app.tab = Tab::Info;
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // GDB style: "connected" is still true while the target is held, so
                // the STOPPED badge sits next to it instead of replacing it.
                let stopped = app.st.is_stopped();
                let (text, color) = if !app.st.connected {
                    ("OFFLINE".to_string(), DIM)
                } else if stopped {
                    ("CONNECTED".to_string(), GREEN)
                } else if app.st.status.as_ref().map(|s| s.paused()).unwrap_or(false) {
                    ("PAUSED".to_string(), YELLOW)
                } else {
                    ("CONNECTED".to_string(), GREEN)
                };
                if stopped && app.st.connected {
                    ui.label(RichText::new("■ STOPPED").strong().color(RED));
                }
                ui.label(RichText::new(text).strong().color(color));
            });
        });
        ui.add_space(4.0);
    });
}

// ---------------------------------------------------------------- status bar

pub fn status_bar(app: &mut App, ui: &mut egui::Ui) {
    egui::Panel::bottom("status").show(ui, |ui| {
        ui.horizontal(|ui| {
            if app.st.busy {
                ui.spinner();
            }
            ui.label(RichText::new(&app.st.last_message).color(DIM));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let target = match (&app.st.status, &app.st.metadata) {
                    (Some(status), Some(md)) => format!(
                        "{:016X}   main {:08X}   pid {}   {} hit(s)",
                        status.program_id, status.main_base, md.process_id, app.st.hits.len()),
                    (Some(status), None) => format!(
                        "{:016X}   main {:08X}   {} hit(s)",
                        status.program_id, status.main_base, app.st.hits.len()),
                    _ => "F5 scan  F6 refine  F7 reset  F8 attach/detach  F9 watch  Ctrl+Z undo".to_string(),
                };
                ui.label(RichText::new(target).monospace().color(DIM));
            });
        });
    });
}

// ---------------------------------------------------------------- log

pub fn log_panel(app: &mut App, ui: &mut egui::Ui) {
    egui::Panel::bottom("log")
        .resizable(true)
        .default_size(120.0)
        .min_size(60.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("LOG").strong());
                if ui.small_button("clear").clicked() {
                    app.st.log.clear();
                }
                if ui.small_button("console log")
                    .on_hover_text("fetch the console's log (scan statistics: dropped regions, retried reads)")
                    .clicked()
                {
                    app.send(Cmd::FetchConsoleLog, "fetching console log");
                }
                ui.label(RichText::new(format!("{} line(s)", app.st.log.len())).color(DIM));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    for hit in app.st.break_hits.iter().take(1) {
                        ui.label(RichText::new(format!(
                            "last watch hit: {:08X}  pc=main+{:#x}", hit.address,
                            app.st.module_offset(hit.pc))).color(YELLOW));
                    }
                });
            });
            if !app.console_log.is_empty() {
                ui.label(RichText::new("console").strong().size(12.0));
                egui::ScrollArea::vertical().id_salt("console_log").max_height(90.0)
                    .stick_to_bottom(true).show(ui, |ui| {
                    for line in &app.console_log {
                        let color = if line.contains("dropped") || line.contains("retr") { YELLOW }
                                    else { DIM };
                        ui.label(RichText::new(line).monospace().size(11.0).color(color));
                    }
                });
                ui.separator();
            }
            egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                for line in &app.st.log {
                    let color = if line.contains("error") { RED }
                                else if line.contains("STOPPED") { RED }
                                else if line.contains("watch hit") || line.contains("hotkey") { YELLOW }
                                else { DIM };
                    ui.label(RichText::new(line).monospace().size(12.0).color(color));
                }
            });
        });
}

// ---------------------------------------------------------------- side panel

pub fn side_panel(app: &mut App, ui: &mut egui::Ui) {
    egui::Panel::left("side")
        .resizable(true)
        .default_size(370.0)
        .size_range(300.0..=560.0)
        .show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                scan_section(app, ui);
                ui.add_space(6.0);
                snapshot_section(app, ui);
                ui.add_space(6.0);
                pointer_section(app, ui);
                ui.add_space(6.0);
                watch_section(app, ui);
            });
        });
}

fn scan_section(app: &mut App, ui: &mut egui::Ui) {
    egui::CollapsingHeader::new(RichText::new("SCAN").strong())
        .default_open(true)
        .id_salt("sec-scan")
        .show(ui, |ui| {
        ui.group(|ui| {
            let compare = super::SCAN_TYPE_COMPARE[app.prefs.compare.min(super::SCAN_TYPE_NAMES.len() - 1)];
            ui.horizontal(|ui| {
                ui.label("Scan Type");
                egui::ComboBox::from_id_salt("scan-type")
                    .selected_text(super::SCAN_TYPE_NAMES[app.prefs.compare.min(super::SCAN_TYPE_NAMES.len() - 1)])
                    .width(170.0)
                    .show_ui(ui, |ui| {
                        for (index, name) in super::SCAN_TYPE_NAMES.iter().enumerate() {
                            ui.selectable_value(&mut app.prefs.compare, index, *name);
                        }
                    });
            });
            ui.horizontal(|ui| {
                ui.label("Value Type");
                egui::ComboBox::from_id_salt("value-type")
                    .selected_text(VALUE_TYPE_NAMES[app.prefs.value_type.min(VALUE_TYPE_NAMES.len() - 1)].0)
                    .width(130.0)
                    .show_ui(ui, |ui| {
                        for (index, (name, _)) in VALUE_TYPE_NAMES.iter().enumerate() {
                            ui.selectable_value(&mut app.prefs.value_type, index, *name);
                        }
                    });
                let value_type = VALUE_TYPE_NAMES[app.prefs.value_type.min(VALUE_TYPE_NAMES.len() - 1)].1;
                if !value_type.is_pattern() {
                    ui.checkbox(&mut app.prefs.hex_input, "Hex");
                }
            });

            let value_type = VALUE_TYPE_NAMES[app.prefs.value_type.min(VALUE_TYPE_NAMES.len() - 1)].1;
            ui.horizontal(|ui| {
                if value_type.is_pattern() {
                    ui.label(if value_type == crate::protocol::ValueType::Str { "Text" } else { "Bytes" });
                    ui.add(egui::TextEdit::singleline(&mut app.prefs.scan_value)
                        .desired_width(180.0)
                        .hint_text(if value_type == crate::protocol::ValueType::Str { "MASTER BALL" } else { "DE AD ?? EF" }));
                } else {
                    ui.label("Value");
                    ui.add(egui::TextEdit::singleline(&mut app.prefs.scan_value)
                        .desired_width(110.0)
                        .hint_text(if value_type.is_float() { "100.25" } else { "6440 / 0x1928" }));
                    if compare == crate::protocol::Compare::Between {
                        ui.label("to");
                        ui.add(egui::TextEdit::singleline(&mut app.prefs.scan_value2)
                            .desired_width(80.0));
                    }
                }
            });

            if value_type == crate::protocol::ValueType::Str {
                ui.horizontal(|ui| {
                    ui.checkbox(&mut app.prefs.case_insensitive, "ignore case");
                    ui.checkbox(&mut app.prefs.utf16, "UTF-16");
                });
            }

            ui.horizontal(|ui| {
                ui.label("Scope");
                egui::ComboBox::from_id_salt("scan-scope")
                    .selected_text(SCOPE_NAMES[app.prefs.scope.min(SCOPE_NAMES.len() - 1)])
                    .width(90.0)
                    .show_ui(ui, |ui| {
                        for (index, name) in SCOPE_NAMES.iter().enumerate() {
                            ui.selectable_value(&mut app.prefs.scope, index, *name);
                        }
                    });
                ui.checkbox(&mut app.prefs.aligned, "aligned")
                    .on_hover_text("numeric scans always step by the value size (absolute alignment), so an unaligned value will NOT be found - use a byte pattern for those");
            });
            if app.prefs.scope == 3 {
                ui.horizontal(|ui| {
                    ui.label("range");
                    ui.add(egui::TextEdit::singleline(&mut app.st.scan_range_begin)
                        .desired_width(110.0).hint_text("begin"));
                    ui.add(egui::TextEdit::singleline(&mut app.st.scan_range_end)
                        .desired_width(110.0).hint_text("end"));
                });
            }

            ui.checkbox(&mut app.prefs.scan_pause, "pause target while scanning")
                .on_hover_text("freeze the game for the duration of the scan so no value \
                                changes under the reads; resumed automatically when the scan \
                                ends (needs debug attach - plain dmnt scans keep running)");

            ui.horizontal(|ui| {
                if ui.add(egui::Button::new(RichText::new("First Scan").strong())).on_hover_text("F5").clicked() {
                    app.start_scan(false);
                }
                if ui.add(egui::Button::new(RichText::new("Next Scan").strong())).on_hover_text("F6").clicked() {
                    app.start_scan(true);
                }
                if ui.button("Undo").on_hover_text("restore candidate list from before the last Next Scan").clicked() {
                    app.send(Cmd::ScanUndo, "undoing scan");
                }
                if ui.button("New Scan").on_hover_text("F7 - forget this scan session").clicked() {
                    app.send(Cmd::ScanReset, "reset");
                }
                if ui.button("Cancel").on_hover_text("stop the running scan now").clicked() {
                    app.cancel_work("cancelling");
                }
            });
            if app.st.busy {
                ui.add(egui::ProgressBar::new(app.st.scan_progress).show_percentage());
                if app.st.scan_hits > 0 {
                    // The console's live count while it walks: the hit LIST only
                    // arrives with the finished result, and the polled count is the
                    // only sign of progress besides the bar.
                    ui.label(RichText::new(format!("{} found so far", app.st.scan_hits)).color(DIM));
                }
            }
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{} hit(s)", app.st.hits.len())).color(GREEN));
                if app.st.hits_truncated {
                    truncated_badge(ui);
                }
            });
            if compare == crate::protocol::Compare::Unknown {
                ui.label(RichText::new("Unknown initial value: the candidate list is kept in THIS PC's \
                                        memory (the console heap is far too small), so a whole-module \
                                        scan is fine. Then refine with Increased / Decreased / Changed.").color(YELLOW));
            }
        });
        });
}

fn snapshot_section(app: &mut App, ui: &mut egui::Ui) {
    egui::CollapsingHeader::new(RichText::new("SNAPSHOT (find what changed)").strong())
        .default_open(true)
        .id_salt("sec-snapshot")
        .show(ui, |ui| {
        ui.group(|ui| {
        ui.label(RichText::new("capture A, play, capture B, then diff - no full dump needed").color(DIM));
        ui.horizontal(|ui| {
            if ui.button("Capture A").clicked() {
                app.send(Cmd::SnapshotCapture { slot: 0, scope: app.prefs.scope as u32 }, "capturing A");
            }
            if ui.button("Capture B").clicked() {
                app.send(Cmd::SnapshotCapture { slot: 1, scope: app.prefs.scope as u32 }, "capturing B");
            }
            if ui.button("Diff A->B").clicked() {
                app.send(Cmd::SnapshotDiff { from: 0, to: 1 }, "diffing");
            }
        });
        if let Some(summary) = &app.st.snapshot.summary {
            ui.label(RichText::new(format!("slot {}: {} blocks x {} bytes",
                                           if summary.slot == 0 { "A" } else { "B" },
                                           summary.block_count, summary.block_size)).color(DIM));
            if summary.truncated {
                // the capture hit the block limit: the diff under-reports changes,
                // and without this line that looks like "nothing changed"
                ui.colored_label(Color32::from_rgb(0xF0, 0xB2, 0x32),
                                 "INCOMPLETE capture (block limit) - raise the block size and retake");
            }
            if summary.changed_count > 0 {
                ui.label(RichText::new(format!("{} changed block(s)", summary.changed_count)).color(YELLOW));
                let changed = app.st.snapshot.changed.clone();
                egui::ScrollArea::vertical().max_height(140.0).show(ui, |ui| {
                    for block in changed.iter().take(200) {
                        let label = format!("{:08X}  {:>6} bytes  {}", block.address, block.size,
                                            if block.flags == 2 { "appeared" } else { "changed" });
                        if ui.small_button(label).clicked() {
                            app.goto(block.address);
                            app.tab = Tab::Hex;
                        }
                    }
                });
            }
        }
        });
    });
}

fn pointer_section(app: &mut App, ui: &mut egui::Ui) {
    egui::CollapsingHeader::new(RichText::new("POINTER CHAIN + CHEAT CODE").strong())
        .default_open(false)
        .id_salt("sec-pointer")
        .show(ui, |ui| {
        ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.label("depth");
            ui.add(egui::DragValue::new(&mut app.prefs.ptr_depth).range(1..=8));
            ui.label("max offset");
            ui.add(egui::DragValue::new(&mut app.prefs.ptr_max_offset).range(0x10..=0x100000).speed(16.0));
            ui.checkbox(&mut app.prefs.ptr_pc_mode, "PC scan")
                .on_hover_text("Dump writable memory to PC RAM and scan with unlimited intermediate offsets");
        });
        ui.horizontal(|ui| {
            if ui.button("Find pointer to cursor").clicked() {
                let target = app.hex.cursor;
                let module_base = app.st.main_base();
                if app.prefs.ptr_pc_mode {
                    app.send(Cmd::PtrScanPc {
                        target, module_base,
                        depth: app.prefs.ptr_depth,
                        max_offset: app.prefs.ptr_max_offset,
                        dump_path: None,
                    }, "scanning for pointers (PC)");
                } else {
                    app.send(Cmd::PtrScan {
                        target, module_base,
                        depth: app.prefs.ptr_depth,
                        max_offset: app.prefs.ptr_max_offset,
                    }, "scanning for pointers");
                }
            }
            if ui.button("Save NDMP...").on_hover_text("Save jnoexs-compatible .dmp file").clicked() {
                if let Some(path) = rfd::FileDialog::new().set_file_name("dump.dmp").save_file() {
                    let (begin, end) = parse_range(&app.st.scan_range_begin, &app.st.scan_range_end);
                    app.send(Cmd::SaveDump {
                        path: path.to_string_lossy().to_string(),
                        scope: app.prefs.scope as u32,
                        begin, end,
                    }, "saving NDMP dump");
                }
            }
            if ui.button("Scan dump...").on_hover_text(
                "Run pointer scan offline on a saved dump: Nxus NDMP or EdiZon-SE / PointerSearcher-SE EDZN/eFZN").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    app.send(Cmd::PtrScanPc {
                        target: app.hex.cursor,
                        module_base: app.st.main_base(),
                        depth: app.prefs.ptr_depth,
                        max_offset: app.prefs.ptr_max_offset,
                        dump_path: Some(path.to_string_lossy().to_string()),
                    }, "scanning dump");
                }
            }
        });
        let chains = app.st.chains.clone();
        if app.st.chains_truncated {
            // authoritative console flag: a capped list must not look complete
            ui.colored_label(egui::Color32::from_rgb(0xE0, 0xA0, 0x40),
                             format!("{} chains - TRUNCATED (narrow the offset range or use PC scan)", chains.len()));
        }
        for (_index, chain) in chains.iter().enumerate().take(8) {
            let steps: String = chain.steps.iter().map(|s| format!(" +{:#x}", s)).collect();
            ui.horizontal(|ui| {
                if ui.selectable_label(false, format!("main+{:#x}{} +{:#x}",
                                                      chain.root_offset, steps, chain.final_offset)).clicked() {
                    let val = parse_value(&app.prefs.cheat_value, 4);
                    app.st.cheat_text = crate::dump::format_cheat(chain, val, 4, true, "Nxus");
                }
            });
        }
        ui.horizontal(|ui| {
            ui.label("value for cheat");
            ui.add(egui::TextEdit::singleline(&mut app.prefs.cheat_value).desired_width(90.0));
            if ui.button("Generate code").clicked() {
                let val = parse_value(&app.prefs.cheat_value, 4);
                if let Some(first) = chains.first() {
                    app.st.cheat_text = crate::dump::format_cheat(first, val, 4, true, "Nxus");
                } else {
                    app.send(Cmd::Cheat { index: 0, value: val }, "generating cheat");
                }
            }
            if !app.st.cheat_text.is_empty() && ui.button("Copy").clicked() {
                ui.ctx().copy_text(app.st.cheat_text.clone());
            }
        });
        if !app.st.cheat_text.is_empty() {
            ui.label(RichText::new(&app.st.cheat_text).monospace().size(12.0).color(GREEN));
        }
        });
    });
}

fn watch_section(app: &mut App, ui: &mut egui::Ui) {
    egui::CollapsingHeader::new(RichText::new("WATCHPOINT (who writes this value?)").strong())
        .default_open(true)
        .id_salt("sec-watch")
        .show(ui, |ui| {
        ui.group(|ui| {
        ui.label(RichText::new("needs debug mode; dmnt is handed over and restored on detach").color(DIM));
        ui.horizontal(|ui| {
            ui.label("kind");
            egui::ComboBox::from_id_salt("watch-kind")
                .selected_text(WATCH_KINDS[app.prefs.watch_kind.min(WATCH_KINDS.len() - 1)].0)
                .width(90.0)
                .show_ui(ui, |ui| {
                    for (index, (name, _)) in WATCH_KINDS.iter().enumerate() {
                        ui.selectable_value(&mut app.prefs.watch_kind, index, *name);
                    }
                });
            ui.label("size");
            egui::ComboBox::from_id_salt("watch-size")
                .selected_text(format!("{}", app.prefs.watch_size))
                .width(46.0)
                .show_ui(ui, |ui| {
                    for size in [1u32, 2, 4, 8] {
                        ui.selectable_value(&mut app.prefs.watch_size, size, format!("{}", size));
                    }
                });
        });
        ui.horizontal(|ui| {
            if ui.add(egui::Button::new(RichText::new("Attach debug").strong())).clicked() {
                app.send(Cmd::Attach, "attaching debugger");
            }
            if ui.button("Detach").clicked() {
                app.send(Cmd::Detach, "detaching");
                app.st.watch_armed = None;
            }
        });
        if ui.checkbox(&mut app.prefs.watch_stop_on_hit, "stop on hit (GDB style)")
            .on_hover_text("hold the target at the hit and open the disassembly at the PC \
                            (auto_continue=0, sent BEFORE arming); off = record the hit and \
                            resume the game immediately")
            .changed()
        {
            // an armed breakpoint must follow a policy change right away, not
            // only from the next arm
            app.apply_stop_on_hit();
        }
        ui.horizontal(|ui| {
            if ui.add(egui::Button::new(RichText::new("Arm on cursor").strong())).clicked() {
                app.arm_watchpoint();
            }
            if ui.button("Disarm").on_hover_text("clear both breakpoint slots (exec = 0, watch = 0x10)").clicked() {
                // execute breakpoints live in slot 0, watchpoints in slot 0x10: the
                // panel does not know which one is armed, so clear both
                app.send(Cmd::BreakClear { slot: 0 }, "disarming exec");
                app.send(Cmd::BreakClear { slot: 0x10 }, "disarming");
                app.st.watch_armed = None;
            }
            if ui.button("Clear hits").clicked() {
                app.send(Cmd::HitClear, "clearing hits");
            }
            if ui.button("Fetch hits").clicked() {
                app.send(Cmd::HitGet, "fetching hits");
            }
        });
        if let Some(address) = app.st.watch_armed {
            ui.label(RichText::new(format!("armed at {:08X}", address)).color(YELLOW));
        }
        let recent = app.st.break_hits.clone();
        for hit in recent.iter().take(3) {
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{} {:08X}  pc=main+{:#x}",
                                               crate::protocol::break_kind::name(hit.kind),
                                               hit.address, app.st.module_offset(hit.pc)))
                    .monospace().size(12.0).color(GREEN));
                if ui.small_button("goto").clicked() {
                    app.goto(hit.address);
                    app.tab = Tab::Hex;
                }
            });
        }
        });
    });
}

// ---------------------------------------------------------------- central

/// GDB-style stop banner: a hit is a stop, so the first thing on screen is which
/// thread is parked, where the PC is, what was hit, and the two actions that make
/// sense (Continue / Step).  It sits above the tab bar so it is visible whichever
/// tab the hit interrupted.
fn stop_banner(app: &mut App, ui: &mut egui::Ui) {
    // The console's status bit is the only truth for "the target is held": the
    // DebugStopped event sets it early (that is the instant refresh), but a
    // status reply that no longer reports the stop must take the banner away.
    if !app.st.is_stopped() {
        return;
    }
    // Only a stop with details is a "hit": a manual break (the Pause button, the
    // scan pause) is shown by the STOPPED badge in the top bar instead, because
    // there is no hitting instruction to jump to.
    let Some(stop) = app.st.debug_stop.clone() else {
        return;
    };
    let main_base = app.st.main_base();
    let mut do_continue = false;
    let mut do_step = false;
    let mut goto_pc = false;

    egui::Frame::new()
        .fill(Color32::from_rgb(0x3A, 0x17, 0x1B))
        .stroke(egui::Stroke::new(1.0, RED))
        .corner_radius(egui::CornerRadius::same(3))
        .inner_margin(egui::Margin::symmetric(8, 5))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("■ STOPPED").heading().strong().color(RED));
                ui.label(RichText::new(format!("thread {}", stop.thread_id))
                    .strong().color(YELLOW));
                let pc = RichText::new(format!("PC={:08X} (main+{:#x})", stop.pc,
                                               stop.pc.wrapping_sub(main_base)))
                    .monospace().color(GREEN);
                if ui.add(egui::Label::new(pc).sense(egui::Sense::click()))
                    .on_hover_text("open the PC in the hex editor")
                    .clicked()
                {
                    goto_pc = true;
                }
                ui.label(RichText::new(format!("— hit {} on {:08X} (slot {:#x})",
                                               crate::protocol::break_kind::name(stop.kind),
                                               stop.address, stop.slot))
                    .color(DIM));
                ui.separator();
                if ui.add(egui::Button::new(RichText::new("Continue").strong()))
                    .on_hover_text("resume the held threads (F10)")
                    .clicked()
                {
                    do_continue = true;
                }
                if ui.button("Step")
                    .on_hover_text("single step and refresh the listing at the new PC")
                    .clicked()
                {
                    do_step = true;
                }
            });
        });
    ui.add_space(4.0);

    if do_continue {
        app.debug_continue();
    }
    if do_step {
        app.debug_step();
    }
    if goto_pc {
        let pc = stop.pc;
        app.goto(pc);
        app.tab = Tab::Hex;
    }
}

pub fn central(app: &mut App, ui: &mut egui::Ui) {
    egui::CentralPanel::default().show(ui, |ui| {
        stop_banner(app, ui);
        ui.horizontal(|ui| {
            for (tab, name) in [(Tab::Results, "Results"), (Tab::Hex, "Hex editor"),
                                (Tab::Disasm, "Disasm"), (Tab::Snapshot, "Snapshot"),
                                (Tab::Watch, "Watch"), (Tab::Info, "Info")] {
                if ui.selectable_label(app.tab == tab, RichText::new(name).strong()).clicked() {
                    app.tab = tab;
                }
            }
        });
        ui.separator();
        match app.tab {
            Tab::Results => results_tab(app, ui),
            Tab::Hex => {
                let super::App { hex, st, prefs, cmd_tx, .. } = app;
                hex.ui(st, prefs, cmd_tx, ui);
            }
            Tab::Disasm => disasm_tab(app, ui),
            Tab::Snapshot => snapshot_tab(app, ui),
            Tab::Watch => watch_tab(app, ui),
            Tab::Info => info_tab(app, ui),
        }
    });
}

fn results_tab(app: &mut App, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.label("filter");
        ui.add(egui::TextEdit::singleline(&mut app.st.filter).desired_width(160.0)
            .hint_text("address or value"));
        ui.checkbox(&mut app.st.sort_desc, "descending");
        ui.checkbox(&mut app.prefs.follow_selection, "follow selection in hex view");
        ui.separator();
        if ui.button("Save list").on_hover_text("write the current results to a file").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_file_name("nxus-results.bin")
                .save_file()
            {
                let scan = crate::pcscan::PcScan {
                    value_size: app.st.value_size.max(1),
                    hits: app.st.hits.iter()
                        .map(|hit| crate::pcscan::PcHit { address: hit.address, value: hit.value })
                        .collect(),
                    truncated: false,
                    bytes_read: 0,
                    reads: 0,
                    failed_reads: 0,
                    ..Default::default()
                };
                let count = scan.hits.len();
                match crate::pcscan::save(&path.to_string_lossy(), &scan) {
                    Ok(()) => app.st.log(format!("saved {} result(s) to {}", count, path.display())),
                    Err(e) => app.st.log(format!("save failed: {}", e)),
                }
            }
        }
        if ui.button("Load list").on_hover_text("reload a saved table and keep refining it").clicked() {
            if let Some(path) = rfd::FileDialog::new().pick_file() {
                match crate::pcscan::load(&path.to_string_lossy()) {
                    Ok(scan) => {
                        let value_type = match scan.value_size {
                            1 => crate::protocol::ValueType::U8,
                            2 => crate::protocol::ValueType::U16,
                            8 => crate::protocol::ValueType::U64,
                            _ => crate::protocol::ValueType::U32,
                        };
                        app.st.value_size = scan.value_size;
                        app.st.hits = scan.hits.iter()
                            .map(|hit| crate::protocol::Hit {
                                address: hit.address,
                                mapping_idx: 0,
                                value_type: value_type as u16,
                                value: hit.value,
                            })
                            .collect();
                        app.st.selected = None;
                        app.st.hits_generation = app.st.hits_generation.wrapping_add(1);
                        app.pc_scan_active = true;   // Next Scan refines the loaded table
                        let count = app.st.hits.len();
                        app.st.log(format!("loaded {} result(s) from {}", count, path.display()));
                    }
                    Err(e) => app.st.log(format!("load failed: {}", e)),
                }
            }
        }
    });
    let rows = app.st.visible_hits();
    let filter_note = if app.st.hits.len() > super::FILTER_LIMIT && !app.st.filter.trim().is_empty() {
        "  (filter disabled above 2M rows - refine first)"
    } else {
        ""
    };
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{} of {} hit(s){}", rows.len(), app.st.hits.len(), filter_note))
                     .color(DIM));
        if app.st.hits_truncated {
            truncated_badge(ui);
        }
    });

    let value_size = app.st.value_size as usize;
    let mut pending: Option<(usize, u64)> = None;
    // (address, width): the width must come from the hit's own value type.  A
    // fixed 4 bytes made dmnt rewrite 4 bytes every frame for a byte/2-byte value,
    // corrupting the neighbouring fields.
    let mut freeze: Option<(u64, u32)> = None;
    let mut watch: Option<u64> = None;
    let mut bookmark: Option<crate::protocol::Hit> = None;
    let frozen = app.st.frozen.clone();
    let main_base = app.st.main_base();
    let selected = app.st.selected;

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(110.0).at_least(90.0))
        .column(Column::initial(90.0).at_least(70.0))
        .column(Column::initial(130.0).at_least(100.0))
        .column(Column::remainder())
        .header(22.0, |mut header| {
            header.col(|ui| { ui.strong("ADDRESS"); });
            header.col(|ui| { ui.strong("VALUE"); });
            header.col(|ui| { ui.strong("MODULE OFFSET"); });
            header.col(|ui| { ui.strong("ACTIONS"); });
        })
        .body(|body| {
            body.rows(20.0, rows.len(), |mut row| {
                let index = row.index();
                let (hit_index, hit) = rows[index].clone();
                let is_selected = selected == Some(hit_index);
                let address = hit.address;
                let offset = address.wrapping_sub(main_base);

                row.col(|ui| {
                    if ui.selectable_label(is_selected, RichText::new(format!("{:08X}", address)).monospace())
                        .clicked() {
                        pending = Some((hit_index, address));
                    }
                });
                row.col(|ui| {
                    let text = hit.display_value(value_size as u32);
                    ui.label(RichText::new(text).monospace().color(GREEN));
                });
                row.col(|ui| {
                    ui.label(RichText::new(format!("main+{:#x}", offset)).monospace().color(DIM));
                });
                row.col(|ui| {
                    ui.horizontal(|ui| {
                        if ui.small_button("hex").on_hover_text("open in hex editor").clicked() {
                            pending = Some((hit_index, address));
                        }
                        if ui.small_button("+book").on_hover_text("add to watchlist / address book").clicked() {
                            bookmark = Some(hit.clone());
                        }
                        if ui.small_button("watch").on_hover_text("trap writes here").clicked() {
                            // this used to only move the hex cursor: the watchpoint
                            // was never armed, yet the panel said "armed"
                            pending = Some((hit_index, address));
                            watch = Some(address);
                        }
                        if ui.small_button("freeze").clicked() {
                            freeze = Some((address, hit_width(hit.value_type, app.st.value_size)));
                        }
                        if ui.small_button("copy").clicked() {
                            ui.ctx().copy_text(format!("{:08X}", address));
                        }
                        if frozen.contains(&address) {
                            ui.label(RichText::new("frozen").color(YELLOW));
                        }
                    });
                });
            });
        });

    if let Some((hit_index, address)) = pending {
        app.st.selected = Some(hit_index);
        if app.prefs.follow_selection {
            app.goto(address);
        }
        app.hex.cursor = address;
        app.hex.anchor = Some(address);
    }
    if let Some(hit) = bookmark {
        if !app.prefs.watchlist.iter().any(|w| w.address == hit.address) {
            let width = hit_width(hit.value_type, app.st.value_size);
            app.prefs.watchlist.push(super::WatchEntry {
                label: format!("Hit {:08X}", hit.address),
                address: hit.address,
                value_type: hit.value_type,
                value: hit.value,
                edit_text: hit.display_value(width),
            });
            app.st.log(format!("bookmarked {:08X} in Watchlist", hit.address));
        }
    }
    if let Some(address) = watch {
        // kind 0 is EXECUTE: this button promises "trap writes here".  The arm
        // helper pushes "stop on hit" first, like the WATCHPOINT section does.
        let size = app.prefs.watch_size;
        app.arm_breakpoint(address, crate::protocol::break_kind::WRITE, size,
                           "arming watchpoint");
    }
    if let Some((address, width)) = freeze {
        app.send(Cmd::Freeze { address, width }, "freezing");
    }
}

/// Byte width of a wire value type (NxusValueType_*); "All" hits fall back to the
/// width the scan was run with.
fn hit_width(value_type: u16, fallback: u32) -> u32 {
    match value_type {
        0 => 1,   // U8
        1 => 2,   // U16
        2 => 4,   // U32
        3 => 8,   // U64
        4 => 4,   // F32
        5 => 8,   // F64
        _ => fallback.max(1),
    }
}

fn snapshot_tab(app: &mut App, ui: &mut egui::Ui) {
    ui.label(RichText::new("Snapshot diffing").strong());
    ui.label(RichText::new(
        "The console hashes memory in blocks instead of sending it all over: capture A, \
         play the game, capture B, then look at what changed. Only the changed blocks need \
         to be read, which is how you find values you never knew (health, timers, coordinates).")
        .color(DIM));
    ui.separator();
    ui.horizontal(|ui| {
        if ui.button("Capture A").clicked() {
            app.send(Cmd::SnapshotCapture { slot: 0, scope: app.prefs.scope as u32 }, "capturing A");
        }
        if ui.button("Capture B").clicked() {
            app.send(Cmd::SnapshotCapture { slot: 1, scope: app.prefs.scope as u32 }, "capturing B");
        }
        if ui.button("Diff A -> B").clicked() {
            app.send(Cmd::SnapshotDiff { from: 0, to: 1 }, "diffing");
        }
    });
    if let Some(summary) = &app.st.snapshot.summary {
        ui.label(format!("last: slot {} / {} blocks x {} bytes / {} changed",
                         if summary.slot == 0 { "A" } else { "B" }, summary.block_count,
                         summary.block_size, summary.changed_count));
    }
    let changed = app.st.snapshot.changed.clone();
    let mut pending: Option<u64> = None;
    TableBuilder::new(ui)
        .striped(true)
        .column(Column::initial(120.0))
        .column(Column::initial(90.0))
        .column(Column::initial(100.0))
        .column(Column::remainder())
        .header(22.0, |mut header| {
            header.col(|ui| { ui.strong("ADDRESS"); });
            header.col(|ui| { ui.strong("SIZE"); });
            header.col(|ui| { ui.strong("KIND"); });
            header.col(|ui| { ui.strong("NOTE"); });
        })
        .body(|body| {
            body.rows(20.0, changed.len(), |mut row| {
                let index = row.index();
                let block = &changed[index];
                row.col(|ui| {
                    if ui.selectable_label(false, RichText::new(format!("{:08X}", block.address)).monospace()).clicked() {
                        pending = Some(block.address);
                    }
                });
                row.col(|ui| { ui.label(format!("{}", block.size)); });
                row.col(|ui| {
                    let (text, color) = match block.flags {
                        1 => ("vanished", RED),
                        2 => ("appeared", GREEN),
                        _ => ("changed", YELLOW),
                    };
                    ui.label(RichText::new(text).color(color));
                });
                row.col(|ui| {
                    ui.label(RichText::new("open in hex editor to inspect").color(DIM));
                });
            });
        });
    if let Some(address) = pending {
        app.goto(address);
        app.tab = Tab::Hex;
    }
}

fn watch_tab(app: &mut App, ui: &mut egui::Ui) {
    // ---- debug session: what the watchpoint does when it fires ------------------
    let mut do_continue = false;
    let mut do_step = false;
    let mut stop_on_hit_changed = false;
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Debug session").strong());
        stop_on_hit_changed = ui
            .checkbox(&mut app.prefs.watch_stop_on_hit, "stop on hit (GDB style)")
            .on_hover_text("auto_continue=0: the target is held at the hit and the disassembly \
                            opens at the PC; off = only the hit is recorded")
            .changed();
        // `is_stopped()` decides the state (status_flags); `debug_stop` only
        // supplies the details of a breakpoint hit.
        if let Some(stop) = app.st.debug_stop.clone().filter(|_| app.st.is_stopped()) {
            ui.label(RichText::new(format!("■ STOPPED thread {} at main+{:#x}", stop.thread_id,
                                           stop.pc.wrapping_sub(app.st.main_base())))
                .monospace().color(RED));
            if ui.add(egui::Button::new(RichText::new("Continue").strong()))
                .on_hover_text("resume the held threads (F10)").clicked()
            {
                do_continue = true;
            }
            if ui.button("Step").clicked() {
                do_step = true;
            }
        } else if app.st.is_stopped() {
            ui.label(RichText::new("■ STOPPED").color(RED));
            if ui.button("Continue").clicked() {
                do_continue = true;
            }
        } else if app.st.status.as_ref().map(|s| s.debug_attached()).unwrap_or(false) {
            ui.label(RichText::new("running (attached)").color(GREEN));
        } else {
            ui.label(RichText::new("not attached").color(DIM));
        }
    });
    if stop_on_hit_changed {
        app.apply_stop_on_hit();
    }
    if do_continue {
        app.debug_continue();
    }
    if do_step {
        app.debug_step();
    }

    ui.separator();
    ui.label(RichText::new("Watchlist (Address Book)").strong());
    ui.horizontal(|ui| {
        ui.label("label");
        ui.add(egui::TextEdit::singleline(&mut app.st.watch_label_input).desired_width(110.0));
        ui.label("address");
        ui.add(egui::TextEdit::singleline(&mut app.st.watch_addr_input)
            .desired_width(160.0)
            .hint_text("main+0x81000 / 42CA1DC4"));
        let type_idx = app.st.watch_type_index.min(5);
        egui::ComboBox::from_id_salt("watchlist-type")
            .selected_text(VALUE_TYPE_NAMES[type_idx].0)
            .width(90.0)
            .show_ui(ui, |ui| {
                for i in 0..6 {
                    ui.selectable_value(&mut app.st.watch_type_index, i, VALUE_TYPE_NAMES[i].0);
                }
            });
        if ui.button("Add").clicked() {
            if let Some(addr) = crate::protocol::eval_expr(
                &app.st.watch_addr_input, app.st.main_base(), app.st.heap_base(),
            ) {
                let vt = VALUE_TYPE_NAMES[type_idx].1 as u16;
                let width = hit_width(vt, 4);
                app.prefs.watchlist.push(super::WatchEntry {
                    label: if app.st.watch_label_input.trim().is_empty() {
                        format!("{:08X}", addr)
                    } else {
                        app.st.watch_label_input.trim().to_string()
                    },
                    address: addr,
                    value_type: vt,
                    value: 0,
                    edit_text: "0".into(),
                });
                app.send(Cmd::RefreshWatchlist { entries: vec![(addr, width)] }, "reading bookmark");
            } else {
                app.st.log(format!("invalid address expression: {}", app.st.watch_addr_input));
            }
        }
        if ui.button("Add cursor").on_hover_text("Bookmark current hex cursor address").clicked() {
            let addr = app.hex.cursor;
            let vt = VALUE_TYPE_NAMES[type_idx].1 as u16;
            let width = hit_width(vt, 4);
            app.prefs.watchlist.push(super::WatchEntry {
                label: format!("Cursor {:08X}", addr),
                address: addr,
                value_type: vt,
                value: 0,
                edit_text: "0".into(),
            });
            app.send(Cmd::RefreshWatchlist { entries: vec![(addr, width)] }, "reading bookmark");
        }
        if ui.button("Refresh all").clicked() && !app.prefs.watchlist.is_empty() {
            let entries: Vec<(u64, u32)> = app.prefs.watchlist.iter()
                .map(|w| (w.address, hit_width(w.value_type, 4)))
                .collect();
            app.send(Cmd::RefreshWatchlist { entries }, "refreshing watchlist");
        }
    });

    if !app.prefs.watchlist.is_empty() {
        let mut goto_addr: Option<u64> = None;
        let mut write_action: Option<(u64, Vec<u8>)> = None;
        let mut freeze_action: Option<(u64, u32, bool)> = None;
        let mut remove_idx: Option<usize> = None;
        let frozen = app.st.frozen.clone();

        egui::ScrollArea::vertical().id_salt("watchlist-scroll").max_height(180.0).show(ui, |ui| {
            for (idx, entry) in app.prefs.watchlist.iter_mut().enumerate() {
                let width = hit_width(entry.value_type, 4);
                let hit_view = crate::protocol::Hit {
                    address: entry.address,
                    mapping_idx: 0,
                    value_type: entry.value_type,
                    value: entry.value,
                };
                let is_frozen = frozen.contains(&entry.address);
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut entry.label).desired_width(110.0));
                    if ui.selectable_label(false, RichText::new(format!("{:08X}", entry.address)).monospace()).clicked() {
                        goto_addr = Some(entry.address);
                    }
                    ui.label(RichText::new(format!("= {}", hit_view.display_value(width))).monospace().color(GREEN));
                    ui.add(egui::TextEdit::singleline(&mut entry.edit_text).desired_width(80.0));
                    if ui.small_button("poke").clicked() {
                        if let Some(bits) = super::parse_scalar(&entry.edit_text, entry.value_type as usize) {
                            entry.value = bits;
                            write_action = Some((entry.address, bits.to_le_bytes()[..width as usize].to_vec()));
                        }
                    }
                    if ui.small_button(if is_frozen { "unfreeze" } else { "freeze" }).clicked() {
                        freeze_action = Some((entry.address, width, !is_frozen));
                    }
                    if ui.small_button("x").on_hover_text("remove from watchlist").clicked() {
                        remove_idx = Some(idx);
                    }
                });
            }
        });

        if let Some(addr) = goto_addr {
            app.goto(addr);
            app.tab = Tab::Hex;
        }
        if let Some((address, data)) = write_action {
            app.send(Cmd::Write { address, data }, "poking watchlist entry");
        }
        if let Some((address, width, enable)) = freeze_action {
            if enable {
                app.send(Cmd::Freeze { address, width }, "freezing");
            } else {
                app.send(Cmd::Unfreeze { address }, "unfreezing");
            }
        }
        if let Some(idx) = remove_idx {
            app.prefs.watchlist.remove(idx);
        }
    }

    ui.separator();
    ui.label(RichText::new("Watchpoint hits").strong());
    ui.label(RichText::new(
        "Each hit is the instruction that touched the address. The module offset can be pasted \
         straight into Ghidra, and the registers show the value being written (often in r0-r3).")
        .color(DIM));
    ui.separator();
    let hits = app.st.break_hits.clone();
    let mut pending: Option<u64> = None;
    let mut disasm_pc: Option<u64> = None;
    TableBuilder::new(ui)
        .striped(true)
        .column(Column::initial(80.0))
        .column(Column::initial(140.0))
        .column(Column::initial(140.0))
        .column(Column::initial(160.0))
        .column(Column::remainder())
        .header(22.0, |mut header| {
            header.col(|ui| { ui.strong("#"); });
            header.col(|ui| { ui.strong("ADDRESS"); });
            header.col(|ui| { ui.strong("MODULE OFFSET"); });
            header.col(|ui| { ui.strong("REGISTERS"); });
            header.col(|ui| { ui.strong(""); });
        })
        .body(|body| {
            body.rows(20.0, hits.len(), |mut row| {
                let index = row.index();
                let hit = &hits[index];
                let offset = hit.pc.wrapping_sub(app.st.main_base());
                row.col(|ui| { ui.label(RichText::new(format!("{}", hit.index)).monospace()); });
                row.col(|ui| {
                    if ui.selectable_label(false, RichText::new(format!("{:08X}", hit.address)).monospace()).clicked() {
                        pending = Some(hit.address);
                    }
                });
                row.col(|ui| {
                    let text = format!("main+{:#x}", offset);
                    if ui.selectable_label(false, RichText::new(text.clone()).monospace().color(GREEN)).clicked() {
                        ui.ctx().copy_text(text);
                    }
                });
                row.col(|ui| {
                    ui.label(RichText::new(format!("r0={:08X} r1={:08X} r2={:08X} r3={:08X}",
                                                   hit.regs[0], hit.regs[1], hit.regs[2], hit.regs[3]))
                        .monospace().size(12.0));
                });
                row.col(|ui| {
                    ui.horizontal(|ui| {
                        if ui.small_button("Disasm PC")
                            .on_hover_text("disassemble the code at this hit's PC")
                            .clicked()
                        {
                            disasm_pc = Some(hit.pc);
                        }
                        ui.label(RichText::new(format!("{} / slot {:#x}",
                                                       crate::protocol::break_kind::name(hit.kind),
                                                       hit.slot)).color(DIM));
                    });
                });
            });
        });
    if let Some(address) = pending {
        app.goto(address);
        app.tab = Tab::Hex;
    }
    if let Some(pc) = disasm_pc {
        // start a little before the PC so the run-up to the hitting instruction is
        // visible instead of the PC sitting on the first line
        let address = pc.saturating_sub(32);
        app.st.disasm_highlight_pc = Some(pc);
        app.st.disasm_base = address;
        app.st.disasm_addr_input = format!("main+{:#x}", pc.wrapping_sub(app.st.main_base()));
        app.send(Cmd::ReadDisasm { address, size: 96 }, "disassembling code at pc");
        app.tab = Tab::Disasm;
    }
}

// ---------------------------------------------------------------- disassembler

// DISASM_PAGE (one page = 32 AArch64/ARM instructions) lives in `super`: the
// stop handler fetches the same page without going through this tab.
/// Tint used for the "=>" row (the PC being debugged).
const DISASM_HL: Color32 = Color32::from_rgb(0x22, 0x3D, 0x27);

fn disasm_arch_for(app: &App) -> crate::protocol::DisasmArch {
    use crate::protocol::DisasmArch;
    match app.st.disasm_arch {
        1 => DisasmArch::Arm32,
        2 => DisasmArch::Thumb,
        _ => {
            if let Some(ctx) = &app.st.last_regs {
                if ctx.cpsr & 0x20 != 0 {
                    return DisasmArch::Thumb;
                }
                if (ctx.cpsr & 0x10) != 0 {
                    return DisasmArch::Arm32;
                }
            }
            let arm32_hits = app.st.disasm_bytes.chunks_exact(4)
                .filter(|c| (u32::from_le_bytes([c[0], c[1], c[2], c[3]]) >> 28) == 0xE)
                .count();
            if arm32_hits > 0 || (0x0800_0000..0x8000_0000).contains(&app.st.disasm_base) {
                DisasmArch::Arm32
            } else {
                DisasmArch::AArch64
            }
        }
    }
}

/// The arch-correct NOP covering one `size`-byte instruction.
fn nop_bytes(arch: crate::protocol::DisasmArch, size: usize) -> Vec<u8> {
    use crate::protocol::DisasmArch;
    match arch {
        DisasmArch::AArch64 => vec![0x1F, 0x20, 0x03, 0xD5],
        DisasmArch::Arm32 => vec![0x00, 0x00, 0xA0, 0xE1],
        DisasmArch::Thumb if size >= 4 => vec![0xAF, 0xF3, 0x00, 0x80],
        DisasmArch::Thumb => vec![0x00, 0xBF],
    }
}

/// Row-level highlight: each table cell paints its own rect (the table paints the
/// striping first, so this lands underneath the cell contents).
fn paint_hl(ui: &egui::Ui, on: bool) {
    if on {
        ui.painter().rect_filled(ui.max_rect(), 0.0, DISASM_HL);
    }
}

fn disasm_tab(app: &mut App, ui: &mut egui::Ui) {
    let mut do_read: Option<u64> = None;
    let mut fetch_pc = false;
    let mut resume = false;
    let mut step = false;
    let mut clear_exec_bp = false;
    let stopped = app.st.is_stopped();

    ui.horizontal(|ui| {
        ui.label("addr");
        ui.add(egui::TextEdit::singleline(&mut app.st.disasm_addr_input)
            .desired_width(180.0)
            .hint_text("main+0x81000 / 42CA1DC4"));
        ui.label("arch");
        let arch_names = ["Auto / AArch64", "ARM32", "Thumb"];
        egui::ComboBox::from_id_salt("disasm-arch")
            .selected_text(arch_names[app.st.disasm_arch.min(2)])
            .width(120.0)
            .show_ui(ui, |ui| {
                for (index, name) in arch_names.iter().enumerate() {
                    ui.selectable_value(&mut app.st.disasm_arch, index, *name);
                }
            });
        if ui.add(egui::Button::new(RichText::new("Disassemble").strong()))
            .on_hover_text("read one page at the address and decode it")
            .clicked()
        {
            let address = crate::protocol::eval_expr(
                &app.st.disasm_addr_input, app.st.main_base(), app.st.heap_base(),
            ).unwrap_or_else(|| parse_value(&app.st.disasm_addr_input, 8));
            do_read = Some(address);
        }
        if ui.button("At Current PC (Regs)")
            .on_hover_text("thread_list -> first thread -> regs_get, then read around its PC")
            .clicked()
        {
            fetch_pc = true;
        }
        if ui.button("◀ -32B").on_hover_text("previous 32 bytes").clicked() {
            let base = if app.st.disasm_bytes.is_empty() { app.hex.cursor }
                       else { app.st.disasm_base };
            do_read = Some(base.saturating_sub(32));
        }
        if ui.button("+32B ▶").on_hover_text("next 32 bytes").clicked() {
            let base = if app.st.disasm_bytes.is_empty() { app.hex.cursor }
                       else { app.st.disasm_base };
            do_read = Some(base.wrapping_add(32));
        }
        if ui.add(egui::Button::new(RichText::new("Continue").strong()))
            .on_hover_text(if stopped {
                "continue past the breakpoint (DebugContinue)"
            } else {
                "resume the target"
            })
            .clicked()
        {
            resume = true;
        }
        if ui.button("Step")
            .on_hover_text("single step and refresh the listing at the new PC")
            .clicked()
        {
            step = true;
        }
        if ui.button("Clear exec BP")
            .on_hover_text("clear the execute breakpoint slot (0)")
            .clicked()
        {
            clear_exec_bp = true;
        }
    });

    // Compact register bar: enough to read the arguments of the hitting call.
    if let Some(ctx) = app.st.last_regs.clone() {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("REGS").strong().color(ACCENT));
            for (name, value) in [("PC", ctx.pc), ("LR", ctx.lr), ("SP", ctx.sp)] {
                ui.label(RichText::new(format!("{}={:08X}", name, value)).monospace().color(GREEN));
            }
            ui.label(RichText::new(format!("CPSR={:08X}", ctx.cpsr)).monospace().color(YELLOW));
            for (index, value) in ctx.r.iter().enumerate() {
                ui.label(RichText::new(format!("R{}={:08X}", index, value))
                    .monospace().size(11.0).color(DIM));
            }
        });
    }

    if let Some(address) = do_read {
        app.st.disasm_base = address;
        app.st.disasm_addr_input =
            format!("main+{:#x}", address.wrapping_sub(app.st.main_base()));
        app.send(Cmd::ReadDisasm { address, size: DISASM_PAGE }, "disassembling");
    }
    if fetch_pc {
        // At a stop, "the first thread" is usually the wrong one: the console
        // parked a specific thread and that is the one whose PC matters.
        match app.st.debug_stop.clone() {
            Some(stop) => {
                app.send(Cmd::FetchThreadPcAndDisasm {
                    thread_id: stop.thread_id,
                    pc: stop.pc,
                    size: DISASM_PAGE,
                }, "reading the stopped thread");
            }
            None => {
                app.send(Cmd::FetchCurrentPcAndDisasm { size: DISASM_PAGE },
                         "reading registers and code at PC");
            }
        }
    }
    if resume {
        // dmnt's Resume does nothing for a thread the kernel parked on a
        // breakpoint: at a stop the debug continue is the one that works.
        if stopped {
            app.debug_continue();
        } else {
            app.send(Cmd::Resume, "resuming");
        }
    }
    if step {
        app.debug_step();
    }
    if clear_exec_bp {
        // execute breakpoints are armed in slot 0 (watchpoints use 0x10)
        app.send(Cmd::BreakClear { slot: 0 }, "clearing execute breakpoint");
    }

    if app.st.is_stopped() {
        ui.label(RichText::new(
            "■ held: the target will not run until Continue / Step (or Resume in the top bar)")
            .color(RED));
    }
    if app.st.disasm_bytes.is_empty() {
        ui.label(RichText::new(
            "Enter an address (or main+offset) and press Disassemble. \
             'At Current PC (Regs)' reads the running thread's registers and the code around its PC.")
            .color(DIM));
    }
    if let Some(pc) = app.st.disasm_highlight_pc {
        ui.label(RichText::new(format!("=> {:08X} (main+{:#x})", pc,
                                       pc.wrapping_sub(app.st.main_base())))
            .monospace().color(YELLOW));
    }

    let arch = disasm_arch_for(app);
    let main_base = app.st.main_base();
    let highlight = app.st.disasm_highlight_pc;
    let insns = crate::protocol::disasm_stream(app.st.disasm_base, &app.st.disasm_bytes, arch, 0);

    let mut set_bp: Option<(u64, usize)> = None;
    let mut nop: Option<(u64, usize)> = None;
    let mut open_hex: Option<u64> = None;

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(26.0))
        .column(Column::initial(170.0))
        .column(Column::initial(110.0))
        .column(Column::remainder())
        .column(Column::initial(190.0))
        .header(22.0, |mut header| {
            header.col(|ui| { ui.strong(""); });
            header.col(|ui| { ui.strong("ADDRESS"); });
            header.col(|ui| { ui.strong("BYTES"); });
            header.col(|ui| { ui.strong("INSTRUCTION"); });
            header.col(|ui| { ui.strong("ACTIONS"); });
        })
        .body(|body| {
            body.rows(20.0, insns.len(), |mut row| {
                let insn = &insns[row.index()];
                let is_pc = highlight == Some(insn.address);
                row.col(|ui| {
                    paint_hl(ui, is_pc);
                    if is_pc {
                        ui.label(RichText::new("=>").monospace().strong().color(YELLOW));
                    }
                });
                row.col(|ui| {
                    paint_hl(ui, is_pc);
                    let text = format!("{:08X} (main+{:#x})", insn.address,
                                       insn.address.wrapping_sub(main_base));
                    ui.label(RichText::new(text).monospace()
                        .color(if is_pc { GREEN } else { DIM }));
                });
                row.col(|ui| {
                    paint_hl(ui, is_pc);
                    ui.label(RichText::new(&insn.raw_hex).monospace().size(11.0).color(DIM));
                });
                row.col(|ui| {
                    paint_hl(ui, is_pc);
                    let text = RichText::new(&insn.text).monospace();
                    ui.label(if is_pc { text.color(GREEN).strong() } else { text });
                });
                row.col(|ui| {
                    paint_hl(ui, is_pc);
                    ui.horizontal(|ui| {
                        if ui.small_button("BP")
                            .on_hover_text("set an execute breakpoint on this instruction")
                            .clicked()
                        {
                            set_bp = Some((insn.address, insn.size));
                        }
                        if ui.small_button("NOP")
                            .on_hover_text("overwrite this instruction with a NOP and re-read the page")
                            .clicked()
                        {
                            nop = Some((insn.address, insn.size));
                        }
                        if ui.small_button("Hex").on_hover_text("open in the hex editor").clicked() {
                            open_hex = Some(insn.address);
                        }
                    });
                });
            });
        });

    if let Some((address, size)) = set_bp {
        // same path as the WATCHPOINT section: push "stop on hit" first
        app.arm_breakpoint(address, crate::protocol::break_kind::EXECUTE, size as u32,
                           "arming exec breakpoint");
    }
    if let Some((address, size)) = nop {
        let patch = nop_bytes(arch, size);
        app.send(Cmd::Write { address, data: patch }, "writing NOP");
        // the worker is single threaded, so this read runs after the write
        app.send(Cmd::ReadDisasm { address: app.st.disasm_base, size: DISASM_PAGE },
                 "re-reading code");
    }
    if let Some(address) = open_hex {
        app.goto(address);
        app.tab = Tab::Hex;
    }
}

fn info_tab(app: &mut App, ui: &mut egui::Ui) {
    ui.label(RichText::new("Target").strong());
    if let Some(status) = app.st.status.clone() {
        egui::Grid::new("info-grid").num_columns(2).spacing([20.0, 4.0]).show(ui, |ui| {
            ui.label("title id"); ui.monospace(format!("{:016X}", status.program_id)); ui.end_row();
            ui.label("process"); ui.monospace(format!("{}", status.process_id)); ui.end_row();
            ui.label("main"); ui.monospace(format!("{:08X} + {:X}", status.main_base, status.main_size)); ui.end_row();
            ui.label("scan"); ui.monospace(format!("{} / {} hits / {} permille",
                        status.scan_state, status.hit_count, status.progress_permille)); ui.end_row();
            ui.label("uptime"); ui.monospace(format!("{} ms", status.uptime_ms)); ui.end_row();
        });
    }
    // ---- memory regions (pick a scan range from what actually exists) -------------
    ui.separator();
    ui.horizontal(|ui| {
        ui.label(RichText::new("Memory regions").strong());
        if ui.small_button("Reload").on_hover_text(
            "reads the target's memory map (same list as 'nxus mappings')").clicked()
        {
            app.send(Cmd::FetchMappings, "loading memory map");
        }
        if ui.small_button("writable only").on_hover_text("hide read-only regions").clicked() {
            app.st.regions_writable_only = !app.st.regions_writable_only;
        }
    });
    if app.st.mappings.is_empty() {
        ui.label(RichText::new("no regions loaded yet").color(DIM));
    } else {
        egui::ScrollArea::vertical().max_height(220.0).show(ui, |ui| {
            let mut pick: Option<(u64, u64)> = None;
            let maps = app.st.mappings.clone();
            for m in &maps {
                let perms = m.perms();
                if app.st.regions_writable_only && !perms.contains('w') {
                    continue;
                }
                ui.horizontal(|ui| {
                    // clicking the range is the point: it selects a CUSTOM scope covering
                    // exactly this region, which is what "scan only this area" means
                    let label = format!("{:08X} + {:<9X} {} type={}", m.base, m.size, perms, m.memory_type);
                    if ui.small_button("scan this").clicked() {
                        pick = Some((m.base, m.base + m.size));
                    }
                    if ui.small_button("+range")
                        .on_hover_text("add to the multi-range scan list (scope: ranges)")
                        .clicked()
                    {
                        let entry = (m.base, m.base + m.size);
                        if app.st.scan_ranges.contains(&entry) {
                            app.st.log("that region is already in the list".to_string());
                        } else if app.st.scan_ranges.len() >= crate::protocol::MAX_SCAN_RANGES {
                            app.st.log(format!("at most {} ranges - 'clear' first",
                                               crate::protocol::MAX_SCAN_RANGES));
                        } else {
                            app.st.scan_ranges.push(entry);
                            app.prefs.scope = 6;           // ranges
                            app.st.log(format!("{} range(s) selected", app.st.scan_ranges.len()));
                        }
                    }
                    ui.monospace(label);
                });
            }
            if let Some((begin, end)) = pick {
                app.st.scan_range_begin = format!("{:X}", begin);
                app.st.scan_range_end = format!("{:X}", end);
                app.prefs.scope = 3;      // Custom
                app.st.log(format!("scan range set to {:08X}..{:08X} (scope: custom)", begin, end));
            }
        });

        // what "+range" has collected so far
        if !app.st.scan_ranges.is_empty() {
            ui.separator();
            let mut remove: Option<usize> = None;
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("selected ranges ({})",
                                               app.st.scan_ranges.len())).strong());
                if ui.small_button("clear").clicked() {
                    app.st.scan_ranges.clear();
                }
            });
            for (i, (begin, end)) in app.st.scan_ranges.iter().enumerate() {
                ui.horizontal(|ui| {
                    if ui.small_button("x").clicked() {
                        remove = Some(i);
                    }
                    ui.monospace(format!("{:08X}..{:08X}  ({} KB)", begin, end, (end - begin) / 1024));
                });
            }
            if let Some(i) = remove {
                app.st.scan_ranges.remove(i);
            }
            ui.label(RichText::new("scope 'ranges' scans exactly these").color(DIM));
        }
    }

    if let Some(md) = app.st.metadata.clone() {
        ui.separator();
        ui.label(RichText::new("Modules").strong());
        ui.monospace(format!("build id {}", md.build_id_hex()));
        egui::ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
            for module in &app.st.modules {
                ui.monospace(format!("{:08X} + {:<10X} {}", module.base, module.size, module.build_id));
            }
        });
    }
    if app.st.status.is_some() {
        ui.separator();
        if ui.button("Reload modules").clicked() {
            app.send(Cmd::FetchModules, "loading modules");
        }
    }
}

// ---------------------------------------------------------------- settings

pub fn settings_window(app: &mut App, ctx: &egui::Context) {
    if !app.show_settings {
        return;
    }
    let mut open = true;
    egui::Window::new("Settings").open(&mut open).resizable(false).show(ctx, |ui| {
        ui.label(RichText::new("Controller hotkey").strong());
        ui.label(RichText::new("Long-press this combo on the console to freeze the game without \
                                touching the PC. Needs the sysmodule to be able to read the \
                                controller (the probe reports whether it can).").color(DIM));
        ui.horizontal(|ui| {
            ui.checkbox(&mut app.prefs.hotkey_enabled, "enabled");
            ui.label("hold");
            ui.add(egui::DragValue::new(&mut app.prefs.hotkey_hold).range(0..=3000).suffix(" ms"));
        });
        ui.horizontal(|ui| {
            ui.label("combo mask");
            ui.add(egui::DragValue::new(&mut app.prefs.hotkey_mask).range(0..=0xFFFF).speed(1.0)
                .custom_formatter(|v, _| format!("0x{:X}", v as u64)));
            if ui.small_button("PLUS").clicked() { app.prefs.hotkey_mask = 0x400; }
            if ui.small_button("L+PLUS").clicked() { app.prefs.hotkey_mask = 0x440; }
            if ui.small_button("ZL+ZR+PLUS").clicked() { app.prefs.hotkey_mask = 0x700; }
        });
        ui.separator();
        ui.label(RichText::new("Safety").strong());
        ui.horizontal(|ui| {
            ui.label("watchdog");
            ui.add(egui::DragValue::new(&mut app.prefs.watchdog_ms).range(1000..=120000).suffix(" ms"));
        });
        ui.label(RichText::new("If the PC stops talking, the console resumes the game after this long.").color(DIM));
        ui.separator();
        ui.label(RichText::new("Debug").strong());
        ui.horizontal(|ui| {
            ui.label("watchpoint style");
            ui.add(egui::DragValue::new(&mut app.prefs.watch_style).range(0..=2));
            ui.label(RichText::new("(0=plain, 1=linked via slot5, 2=linked via slot4)").color(DIM));
        });
        ui.separator();
        ui.label(RichText::new("Logging").strong());
        ui.horizontal(|ui| {
            ui.label("console log level");
            egui::ComboBox::from_id_salt("log-level")
                .selected_text(match app.prefs.log_level {
                    0 => "0 - errors only",
                    2 => "2 - debug",
                    _ => "1 - info",
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut app.prefs.log_level, 0, "0 - errors only");
                    ui.selectable_value(&mut app.prefs.log_level, 1, "1 - info");
                    ui.selectable_value(&mut app.prefs.log_level, 2, "2 - debug");
                });
        });
        ui.label(RichText::new("Verbosity of the console's own log ring / SD log \
                                (applied with the rest of these settings).").color(DIM));
        ui.separator();
        ui.horizontal(|ui| {
            if ui.add(egui::Button::new(RichText::new("Apply to console").strong())).clicked() {
                let enabled = app.prefs.hotkey_enabled as u32;
                let mask = if enabled == 0 { 0 } else { app.prefs.hotkey_mask };
                app.send(Cmd::Config {
                    mask,
                    hold: app.prefs.hotkey_hold,
                    enabled,
                    watchdog: app.prefs.watchdog_ms,
                    style: app.prefs.watch_style,
                    // The console rewrites its whole config from this request, so
                    // the current policy travels along: sending a constant 1 here
                    // released a target held at a stop (and disarmed the next one).
                    auto_continue: auto_continue_for(app.prefs.watch_stop_on_hit),
                    log_level: app.prefs.log_level,
                }, "applying settings");
            }
            ui.label(RichText::new("settings are remembered between runs").color(DIM));
        });
    });
    app.show_settings = open;
}