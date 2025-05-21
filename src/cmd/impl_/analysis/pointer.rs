use winapi::um::{
    memoryapi::{ReadProcessMemory, VirtualQueryEx},
    winnt::{
        MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
        PAGE_READONLY, PAGE_READWRITE,
    },
};

use crate::{util, util::log};

pub fn scan_for_pointers(
    pid: u32,
    target_address: usize,
    max_levels: usize,
    max_offset: usize,
) -> anyhow::Result<()> {
    let handle = util::open_process(pid)?;
    log::info(&format!(
        "scanning for pointers to {} (levels: {}, offset: +/-{}) in PID {}",
        util::format_address(target_address),
        max_levels,
        max_offset,
        pid
    ));

    if max_levels == 0 {
        unsafe { winapi::um::handleapi::CloseHandle(handle) };
        anyhow::bail!("max_levels must be at least 1");
    }

    let mut found_pointer_chains = Vec::new();
    find_pointers_recursive(
        handle,
        target_address,
        target_address,
        max_levels,
        max_offset,
        0,
        Vec::new(),
        &mut found_pointer_chains,
    )?;

    if found_pointer_chains.is_empty() {
        log::info("no pointers found matching the criteria.");
    } else {
        log::info(&format!(
            "found {} pointer chains:",
            found_pointer_chains.len()
        ));
        for chain in found_pointer_chains {
            let chain_str = chain
                .iter()
                .map(|addr| util::format_address(*addr))
                .collect::<Vec<String>>()
                .join(" -> ");
            println!("  {}", chain_str);
        }
    }

    unsafe { winapi::um::handleapi::CloseHandle(handle) };
    Ok(())
}

fn find_pointers_recursive(
    process_handle: winapi::um::winnt::HANDLE,
    original_target_address: usize,
    current_scan_target_address: usize,
    max_levels: usize,
    max_offset: usize,
    current_level: usize,
    current_path_addrs: Vec<usize>,
    found_pointer_chains: &mut Vec<Vec<usize>>,
) -> anyhow::Result<()> {
    if current_level >= max_levels {
        return Ok(());
    }

    let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let mut current_base_address: usize = 0;
    let pointer_size = std::mem::size_of::<usize>();

    while unsafe {
        VirtualQueryEx(
            process_handle,
            current_base_address as *const _,
            &mut mem_info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    } == std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
    {
        if mem_info.State == MEM_COMMIT
            && (mem_info.Protect == PAGE_READWRITE
                || mem_info.Protect == PAGE_READONLY
                || mem_info.Protect == PAGE_EXECUTE_READ
                || mem_info.Protect == PAGE_EXECUTE_READWRITE)
            && mem_info.RegionSize > 0
        {
            let mut buffer: Vec<u8> = vec![0; mem_info.RegionSize];
            let mut bytes_read = 0;

            let success = unsafe {
                ReadProcessMemory(
                    process_handle,
                    mem_info.BaseAddress,
                    buffer.as_mut_ptr() as *mut _,
                    mem_info.RegionSize,
                    &mut bytes_read,
                )
            };

            if success != 0 && bytes_read > 0 {
                buffer.truncate(bytes_read as usize);
                for i in (0..bytes_read).step_by(pointer_size) {
                    if i + pointer_size > bytes_read {
                        break;
                    }
                    let mut potential_pointer_bytes = [0u8; std::mem::size_of::<usize>()];
                    potential_pointer_bytes.copy_from_slice(&buffer[i..i + pointer_size]);
                    let potential_pointer_value = usize::from_ne_bytes(potential_pointer_bytes);

                    let min_target = current_scan_target_address.saturating_sub(max_offset);
                    let max_target = current_scan_target_address.saturating_add(max_offset);

                    if potential_pointer_value >= min_target
                        && potential_pointer_value <= max_target
                    {
                        let pointer_location = mem_info.BaseAddress as usize + i;

                        let mut new_path_addrs = current_path_addrs.clone();
                        new_path_addrs.push(pointer_location);

                        if current_level == max_levels - 1 {
                            let mut final_chain_to_display = new_path_addrs.clone();

                            final_chain_to_display.push(potential_pointer_value);
                            found_pointer_chains.push(final_chain_to_display);
                        } else {
                            find_pointers_recursive(
                                process_handle,
                                original_target_address,
                                pointer_location,
                                max_levels,
                                max_offset,
                                current_level + 1,
                                new_path_addrs,
                                found_pointer_chains,
                            )?;
                        }
                    }
                }
            }
        }
        current_base_address = (mem_info.BaseAddress as usize).wrapping_add(mem_info.RegionSize);
        if current_base_address < mem_info.BaseAddress as usize {
            break;
        }
    }
    Ok(())
}
