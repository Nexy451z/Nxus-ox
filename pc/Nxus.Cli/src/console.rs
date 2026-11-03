//! Console handling for the dual-mode executables (`nxus.exe`, `NCL.exe`).
//!
//! Both binaries are built as **GUI-subsystem** applications in release builds so that
//! double-clicking them does not flash a black console window (the `pythonw`
//! behaviour).  That costs the process its console, so a CLI invocation has to take
//! one back:
//!
//! * inherited `stdout` (a pipe from a test harness, or a shell redirect) is left
//!   exactly as it is - the handle is valid, so nothing is touched;
//! * otherwise the parent console is attached (`cmd`/PowerShell), and only when that
//!   fails (double-click / shortcut) is a new console allocated;
//! * `CONOUT$`/`CONIN$` are then published as the standard handles, which is what
//!   Rust's `println!`/`eprintln!` write to.
//!
//! GUI mode calls [`hide_own_console`] instead.  It is a no-op in a release GUI launch
//! (there is no console), and hides the window in a debug build so the developer sees
//! the same thing the user does.
//!
//! Everything here is best-effort: if libc/Win32 refuses, the program carries on and
//! the CLI output is simply lost instead of the process failing.

#![allow(dead_code)]

use std::ffi::c_void;

const STD_INPUT_HANDLE: u32 = -10i32 as u32;
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
const STD_ERROR_HANDLE: u32 = -12i32 as u32;

/// `AttachConsole(ATTACH_PARENT_PROCESS)`: `(DWORD)-1`.
const ATTACH_PARENT_PROCESS: u32 = 0xFFFF_FFFF;
const SW_HIDE: i32 = 0;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const OPEN_EXISTING: u32 = 3;

#[link(name = "kernel32")]
extern "system" {
    fn GetConsoleWindow() -> *mut c_void;
    fn AttachConsole(process_id: u32) -> i32;
    fn AllocConsole() -> i32;
    fn GetStdHandle(which: u32) -> *mut c_void;
    fn SetStdHandle(which: u32, handle: *mut c_void) -> i32;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        attributes: *mut c_void,
        disposition: u32,
        flags: u32,
        template: *mut c_void,
    ) -> *mut c_void;
    fn ShowWindow(window: *mut c_void, command: i32) -> i32;
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A valid standard handle means the caller inherited one: a pipe (test harness,
/// `| more`) or a shell redirect.  Replacing it with `CONOUT$` would throw that away.
fn inherited(handle: *mut c_void) -> bool {
    !handle.is_null() && handle as isize != -1
}

/// Open `CONOUT$` / `CONIN$` for the console this process is attached to.
fn open_console_device(name: &str) -> *mut c_void {
    let name = wide(name);
    unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    }
}

/// Hide a console window this process owns.
///
/// A release GUI launch has none (`windows_subsystem = "windows"`), so this only does
/// something in a debug build - and it never touches somebody else's terminal, because
/// [`GetConsoleWindow`] returns that process's own console window.
pub fn hide_own_console() {
    unsafe {
        let window = GetConsoleWindow();
        if !window.is_null() {
            ShowWindow(window, SW_HIDE);
        }
    }
}

/// Make sure CLI output has somewhere to go, attaching the parent console if needed.
pub fn ensure_cli_output() {
    unsafe {
        // A pipe or a redirect: keep it.  This is the path every test harness takes.
        if inherited(GetStdHandle(STD_OUTPUT_HANDLE)) {
            return;
        }
        // Payload of the GUI subsystem: no console at all.  Take the parent's when the
        // user typed the command into cmd/PowerShell, otherwise make one.
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            let _ = AllocConsole();
        }
        let out = open_console_device("CONOUT$");
        if !out.is_null() {
            SetStdHandle(STD_OUTPUT_HANDLE, out);
            SetStdHandle(STD_ERROR_HANDLE, out);
        }
        let input = open_console_device("CONIN$");
        if !input.is_null() {
            SetStdHandle(STD_INPUT_HANDLE, input);
        }
    }
}

/// True when the process currently has a console of its own.  Used by the smoke tests
/// that assert a GUI launch is console-free.
pub fn has_console() -> bool {
    unsafe { !GetConsoleWindow().is_null() }
}
