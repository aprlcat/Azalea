use winapi::um::handleapi::CloseHandle;

use crate::{cmd::util as cmd_util_main, util as project_util, util::log};

pub fn nop_memory_region(pid: u32, address: usize, size: usize) -> anyhow::Result<()> {
    log::info(&format!(
        "Attempting to NOP {} bytes at {} in PID {}",
        size,
        project_util::format_address(address),
        pid
    ));

    if size == 0 {
        log::warn("NOP region size is 0, no operation will be performed.");
        return Ok(());
    }

    let process_handle = project_util::open_process(pid)?;

    match cmd_util_main::assembler::nop_region(process_handle, address, size) {
        Ok(_) => {
            log::info(&format!(
                "Successfully NOPed {} bytes at {}",
                size,
                project_util::format_address(address)
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
