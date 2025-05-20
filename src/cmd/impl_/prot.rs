use winapi::{
    shared::minwindef::DWORD,
    um::{
        handleapi::CloseHandle, memoryapi::VirtualProtectEx, processthreadsapi::OpenProcess,
        winnt::PROCESS_VM_OPERATION,
    },
};

use crate::{cmd::utils, util, util::log};

pub fn set_protection(
    pid: u32,
    address: usize,
    size: usize,
    protection_flags_str: &str,
) -> anyhow::Result<()> {
    log::info(&format!(
        "attempting to set memory protection at {} (size: {}) to '{}' in PID {}",
        util::format_address(address),
        size,
        protection_flags_str,
        pid
    ));

    let protection_flags = utils::parse_protection_flags(protection_flags_str)?;

    let process_handle = unsafe { OpenProcess(PROCESS_VM_OPERATION, 0, pid) };
    if process_handle.is_null() {
        anyhow::bail!(
            "failed to open process with PID {}: error code {}",
            pid,
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
    }

    let mut old_protection: DWORD = 0;
    let success = unsafe {
        VirtualProtectEx(
            process_handle,
            address as *mut _,
            size,
            protection_flags,
            &mut old_protection,
        )
    };

    unsafe { CloseHandle(process_handle) };

    if success == 0 {
        anyhow::bail!(
            "failed to set memory protection at {}: error code {}",
            util::format_address(address),
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
    }

    log::info(&format!(
        "memory protection set successfully at {}. old protection: 0x{:X}",
        util::format_address(address),
        old_protection
    ));

    Ok(())
}
