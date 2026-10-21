//! nxus - PC client for the Nxus Nintendo Switch sysmodule.
//!
//! Without arguments it opens the GUI; with a command it behaves as the CLI:
//!
//!   nxus                                  GUI
//!   nxus --host 192.168.0.10 status       CLI
//!   nxus --screenshot ui.bmp              render one frame off-screen
//!
//! The GUI is hand-drawn on plain Win32 (no framework, no GPU): instant start,
//! low memory, and a redraw that only touches what is visible.
#![allow(dead_code)]

mod cli;
mod client;
mod dump;
mod edizon;
mod gui;
mod pcscan;
mod png;
mod protocol;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let wants_gui = args.is_empty()
        || args[0] == "--gui"
        || args[0] == "--screenshot"
        || args.iter().any(|a| a == "--screenshot");

    if wants_gui {
        let mut host: Option<String> = std::env::var("NXUS_HOST").ok().filter(|s| !s.trim().is_empty());
        let mut port: Option<u16> = std::env::var("NXUS_PORT").ok().and_then(|s| s.trim().parse().ok());
        let mut screenshot: Option<String> = None;
        let mut start_tab: Option<String> = None;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--host" => {
                    if let Some(v) = args.get(i + 1) {
                        host = Some(v.clone());
                        i += 1;
                    }
                }
                "--port" => {
                    if let Some(v) = args.get(i + 1) {
                        port = v.parse().ok();
                        i += 1;
                    }
                }
                "--screenshot" => {
                    if let Some(v) = args.get(i + 1) {
                        screenshot = Some(v.clone());
                        i += 1;
                    }
                }
                "--tab" => {
                    if let Some(v) = args.get(i + 1) {
                        start_tab = Some(v.clone());
                        i += 1;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        std::process::exit(gui::run(host, port, screenshot, start_tab));
    }

    std::process::exit(cli::run(&args));
}
