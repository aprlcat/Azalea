use std::mem;

use winapi::{
    shared::minwindef::DWORD,
    um::{
        handleapi::CloseHandle,
        memoryapi::VirtualQueryEx,
        psapi::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX},
        winnt::{
            MEM_COMMIT, MEM_FREE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE,
            PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
            PAGE_NOACCESS, PAGE_NOCACHE, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOMBINE,
            PAGE_WRITECOPY,
        },
    },
};

use crate::util;

pub fn display_memory_info(pid: u32) -> anyhow::Result<()> {
    let handle = util::open_process(pid)?;

    let mut pmc: PROCESS_MEMORY_COUNTERS_EX = unsafe { mem::zeroed() };
    pmc.cb = mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as DWORD;

    let success = unsafe {
        GetProcessMemoryInfo(
            handle,
            &mut pmc as *mut _ as *mut winapi::um::psapi::PROCESS_MEMORY_COUNTERS,
            mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as DWORD,
        )
    };

    if success == 0 {
        unsafe { CloseHandle(handle) };
        anyhow::bail!(
            "failed to get process memory information: error code {}",
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
    }

    println!("Memory information for PID {}:", pid);
    println!(
        "  Working Set Size:       {:>10} KB",
        pmc.WorkingSetSize / 1024
    );
    println!(
        "  Peak Working Set Size:  {:>10} KB",
        pmc.PeakWorkingSetSize / 1024
    );
    println!(
        "  Pagefile Usage:         {:>10} KB",
        pmc.PagefileUsage / 1024
    );
    println!(
        "  Peak Pagefile Usage:    {:>10} KB",
        pmc.PeakPagefileUsage / 1024
    );
    println!(
        "  Private Usage:          {:>10} KB",
        pmc.PrivateUsage / 1024
    );

    let mut address: usize = 0;
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
    let mbi_size = mem::size_of::<MEMORY_BASIC_INFORMATION>();

    println!("\nMemory Regions (Address, Size, State, Protection, Type):");
    println!("{:-<80}", "");

    let mut regions = 0;
    let mut committed_total_size: usize = 0;
    let mut reserved_total_size: usize = 0;
    let mut free_total_size: usize = 0;
    let mut image_total_size: usize = 0;
    let mut mapped_total_size: usize = 0;
    let mut private_total_size: usize = 0;

    while unsafe { VirtualQueryEx(handle, address as *const _, &mut mbi, mbi_size) } == mbi_size {
        regions += 1;

        let state_str = match mbi.State {
            MEM_COMMIT => {
                committed_total_size += mbi.RegionSize;
                "COMMIT"
            }
            MEM_RESERVE => {
                reserved_total_size += mbi.RegionSize;
                "RESERVE"
            }
            MEM_FREE => {
                free_total_size += mbi.RegionSize;
                "FREE"
            }
            _ => "UNKNOWN",
        };

        let protect_str = if mbi.State == MEM_FREE {
            "---".to_string()
        } else {
            format_protection_flags(mbi.Protect)
        };

        let type_str = match mbi.Type {
            winapi::um::winnt::MEM_IMAGE => {
                image_total_size += mbi.RegionSize;
                "IMAGE"
            }
            winapi::um::winnt::MEM_MAPPED => {
                mapped_total_size += mbi.RegionSize;
                "MAPPED"
            }
            winapi::um::winnt::MEM_PRIVATE => {
                private_total_size += mbi.RegionSize;
                "PRIVATE"
            }
            _ => "---",
        };

        println!(
            "{:<18} {:>10} KB {:<10} {:<25} {:<10}",
            util::format_address(mbi.BaseAddress as usize),
            mbi.RegionSize / 1024,
            state_str,
            protect_str,
            type_str
        );

        address = (mbi.BaseAddress as usize).wrapping_add(mbi.RegionSize);
        if address < (mbi.BaseAddress as usize) {
            break;
        }
    }
    println!("{:-<80}", "");

    println!("\nMemory Summary:");
    println!("  Total Regions Queried: {}", regions);
    println!(
        "  Committed Memory:      {:>10} KB",
        committed_total_size / 1024
    );
    println!(
        "  Reserved Memory:       {:>10} KB",
        reserved_total_size / 1024
    );
    println!(
        "  Free Memory (queried): {:>10} KB (Note: This is complex, refers to address space holes)",
        free_total_size / 1024
    );
    println!(
        "  Image Memory:          {:>10} KB",
        image_total_size / 1024
    );
    println!(
        "  Mapped Memory:         {:>10} KB",
        mapped_total_size / 1024
    );
    println!(
        "  Private Memory:        {:>10} KB",
        private_total_size / 1024
    );

    unsafe { CloseHandle(handle) };
    Ok(())
}

fn format_protection_flags(protection: DWORD) -> String {
    let mut flags = Vec::new();
    if protection == PAGE_NOACCESS {
        return "NO_ACCESS".to_string();
    }
    if protection & PAGE_READONLY != 0 {
        flags.push("R--");
    }
    if protection & PAGE_READWRITE != 0 {
        flags.push("RW-");
    }
    if protection & PAGE_WRITECOPY != 0 {
        flags.push("WC-");
    }
    if protection & PAGE_EXECUTE != 0 {
        flags.push("--X");
    }
    if protection & PAGE_EXECUTE_READ != 0 {
        flags.push("R-X");
    }
    if protection & PAGE_EXECUTE_READWRITE != 0 {
        flags.push("RWX");
    }
    if protection & PAGE_EXECUTE_WRITECOPY != 0 {
        flags.push("WCX");
    }

    let mut result = flags.join("|");

    if protection & PAGE_GUARD != 0 {
        result.push_str("|GUARD");
    }
    if protection & PAGE_NOCACHE != 0 {
        result.push_str("|NOCACHE");
    }
    if protection & PAGE_WRITECOMBINE != 0 {
        result.push_str("|WC");
    }

    if result.is_empty() && protection != 0 {
        format!("0x{:X}", protection)
    } else if result.is_empty() && protection == 0 {
        "---".to_string()
    } else {
        result
    }
}
