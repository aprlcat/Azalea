pub mod log;

use std::{ffi::OsStr, os::windows::ffi::OsStrExt};

use winapi::{
    shared::minwindef::DWORD,
    um::{
        processthreadsapi::OpenProcess,
        winnt::{HANDLE, PROCESS_ALL_ACCESS},
    },
};

pub fn str_to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub fn open_process(pid: DWORD) -> anyhow::Result<HANDLE> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() {
        anyhow::bail!("failed to open process with pid: {}", pid);
    }
    Ok(handle)
}

pub fn format_address(addr: usize) -> String {
    format!("0x{:x}", addr)
}
