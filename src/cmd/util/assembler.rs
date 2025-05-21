use winapi::{
    shared::minwindef::DWORD,
    um::{
        memoryapi::{VirtualProtectEx, WriteProcessMemory},
        winnt::{HANDLE, PAGE_EXECUTE_READWRITE},
    },
};

use crate::{util, util::log};

pub fn patch_bytes(
    process_handle: HANDLE,
    address: usize,
    patch_bytes: &[u8],
) -> anyhow::Result<()> {
    log::debug(&format!(
        "Attempting to patch {} bytes at {}",
        patch_bytes.len(),
        util::format_address(address)
    ));

    let mut old_protection: DWORD = 0;
    let protect_success = unsafe {
        VirtualProtectEx(
            process_handle,
            address as *mut _,
            patch_bytes.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protection,
        )
    };

    if protect_success == 0 {
        anyhow::bail!(
            "Failed to change memory protection at {}: error code {}",
            util::format_address(address),
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
    }

    let mut bytes_written: usize = 0;
    let write_success = unsafe {
        WriteProcessMemory(
            process_handle,
            address as *mut _,
            patch_bytes.as_ptr() as *const _,
            patch_bytes.len(),
            &mut bytes_written,
        )
    };

    if write_success == 0 || bytes_written != patch_bytes.len() {
        unsafe {
            VirtualProtectEx(
                process_handle,
                address as *mut _,
                patch_bytes.len(),
                old_protection,
                &mut old_protection,
            )
        };
        anyhow::bail!(
            "Failed to write patch bytes at {}: error code {}",
            util::format_address(address),
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
    }

    log::info(&format!(
        "Successfully patched {} bytes at {}",
        bytes_written,
        util::format_address(address)
    ));
    Ok(())
}

pub fn insert_jmp_hook(
    process_handle: HANDLE,
    hook_address: usize,
    detour_address: usize,
) -> anyhow::Result<Vec<u8>> {
    log::debug(&format!(
        "Attempting to insert JMP hook at {} to {}",
        util::format_address(hook_address),
        util::format_address(detour_address)
    ));

    const JMP_INSTRUCTION_LEN: usize = 5;
    let mut original_bytes = vec![0u8; JMP_INSTRUCTION_LEN];
    let mut bytes_read: usize = 0;

    let read_success = unsafe {
        winapi::um::memoryapi::ReadProcessMemory(
            process_handle,
            hook_address as *const _,
            original_bytes.as_mut_ptr() as *mut _,
            JMP_INSTRUCTION_LEN,
            &mut bytes_read,
        )
    };

    if read_success == 0 || bytes_read != JMP_INSTRUCTION_LEN {
        anyhow::bail!(
            "Failed to read original bytes at {}: error code {}",
            util::format_address(hook_address),
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
    }

    let relative_offset =
        detour_address.wrapping_sub(hook_address.wrapping_add(JMP_INSTRUCTION_LEN)) as i32;

    let mut jmp_instruction = vec![0u8; JMP_INSTRUCTION_LEN];
    jmp_instruction[0] = 0xE9;
    jmp_instruction[1..5].copy_from_slice(&relative_offset.to_le_bytes());

    patch_bytes(process_handle, hook_address, &jmp_instruction)?;

    log::info(&format!(
        "JMP hook inserted at {} to {}. Original bytes backed up.",
        util::format_address(hook_address),
        util::format_address(detour_address)
    ));

    Ok(original_bytes)
}

pub fn nop_region(process_handle: HANDLE, address: usize, size: usize) -> anyhow::Result<()> {
    log::debug(&format!(
        "Attempting to NOP {} bytes at {}",
        size,
        util::format_address(address)
    ));
    if size == 0 {
        log::warn("NOP region size is 0, no operation performed.");
        return Ok(());
    }
    let nop_bytes = vec![0x90u8; size];
    patch_bytes(process_handle, address, &nop_bytes)?;
    log::info(&format!(
        "Successfully NOPed {} bytes at {}",
        size,
        util::format_address(address)
    ));
    Ok(())
}
