use winapi::um::handleapi::CloseHandle;

use crate::{cmd::util as cmd_util_main, util as project_util, util::log};

pub fn apply_detour(pid: u32, target_address: usize, detour_address: usize) -> anyhow::Result<()> {
    log::info(&format!(
        "Attempting to detour function at {} to {} in PID {}",
        project_util::format_address(target_address),
        project_util::format_address(detour_address),
        pid
    ));

    let process_handle = project_util::open_process(pid)?;

    match cmd_util_main::assembler::insert_jmp_hook(process_handle, target_address, detour_address)
    {
        Ok(original_bytes) => {
            log::info(&format!(
                "Detour applied successfully. Original {} bytes at {}: [{}]",
                original_bytes.len(),
                project_util::format_address(target_address),
                original_bytes
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<String>>()
                    .join(" ")
            ));
            unsafe { CloseHandle(process_handle) };
            Ok(())
        }
        Err(e) => {
            unsafe { CloseHandle(process_handle) };
            Err(e)
        }
    }
}
