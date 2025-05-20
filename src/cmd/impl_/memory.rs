use std::mem;

use winapi::{
    shared::minwindef::{DWORD, FALSE},
    um::{
        memoryapi::VirtualQueryEx,
        psapi::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX},
        tlhelp32::{
            CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next,
            TH32CS_SNAPPROCESS,
        },
        winnt::{MEM_COMMIT, MEM_FREE, MEM_RESERVE, MEMORY_BASIC_INFORMATION},
    },
};

use crate::util;

pub fn list_processes() -> anyhow::Result<()> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        anyhow::bail!("failed to create process snapshot");
    }

    let mut process_entry = PROCESSENTRY32 {
        dwSize: mem::size_of::<PROCESSENTRY32>() as DWORD,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; 260],
    };

    println!("pid\tthreads\tparent pid\tprocess name");
    println!("---\t-------\t----------\t------------");

    let mut success = unsafe { Process32First(snapshot, &mut process_entry) };

    while success != FALSE {
        let exe_file = unsafe {
            let exe_file_ptr = process_entry.szExeFile.as_ptr() as *const i8;
            std::ffi::CStr::from_ptr(exe_file_ptr)
                .to_string_lossy()
                .into_owned()
        };

        println!(
            "{}\t{}\t{}\t\t{}",
            process_entry.th32ProcessID,
            process_entry.cntThreads,
            process_entry.th32ParentProcessID,
            exe_file
        );

        success = unsafe { Process32Next(snapshot, &mut process_entry) };
    }

    unsafe { winapi::um::handleapi::CloseHandle(snapshot) };

    Ok(())
}

pub fn display_memory_info(pid: u32) -> anyhow::Result<()> {
    let handle = util::open_process(pid)?;

    let mut pmc: PROCESS_MEMORY_COUNTERS_EX = unsafe { mem::zeroed() };
    pmc.cb = mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as DWORD;

    let success = unsafe {
        GetProcessMemoryInfo(
            handle,
            &mut pmc as *mut _ as *mut _,
            mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as DWORD,
        )
    };

    if success == 0 {
        anyhow::bail!("failed to get process memory information");
    }

    println!("memory information for pid {}:", pid);
    println!(
        "  working set size:          {} kb",
        pmc.WorkingSetSize / 1024
    );
    println!(
        "  peak working set size:     {} kb",
        pmc.PeakWorkingSetSize / 1024
    );
    println!(
        "  page file usage:           {} kb",
        pmc.PagefileUsage / 1024
    );
    println!(
        "  peak page file usage:      {} kb",
        pmc.PeakPagefileUsage / 1024
    );
    println!(
        "  private usage:             {} kb",
        pmc.PrivateUsage / 1024
    );

    let mut address: usize = 0;
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
    let mbi_size = mem::size_of::<MEMORY_BASIC_INFORMATION>();

    println!("\nmemory regions:");
    println!("address\t\tsize\t\tstate\t\tprotect\t\ttype");

    let mut regions = 0;
    let mut committed = 0;
    let mut reserved = 0;
    let mut free = 0;

    while unsafe { VirtualQueryEx(handle, address as *const _, &mut mbi, mbi_size) } == mbi_size {
        regions += 1;

        let state = match mbi.State {
            MEM_COMMIT => {
                committed += 1;
                "committed"
            }
            MEM_RESERVE => {
                reserved += 1;
                "reserved"
            }
            MEM_FREE => {
                free += 1;
                "free"
            }
            _ => "unknown",
        };

        let protect = match mbi.Protect {
            0 => "-",
            1 => "page_noaccess",
            2 => "page_readonly",
            4 => "page_readwrite",
            8 => "page_writecopy",
            16 => "page_execute",
            32 => "page_execute_read",
            64 => "page_execute_readwrite",
            128 => "page_execute_writecopy",
            256 => "page_guard",
            512 => "page_nocache",
            1024 => "page_writecombine",
            _ => "unknown",
        };

        println!(
            "{:016x}\t{} kb\t{}\t{}\t{:?}",
            mbi.BaseAddress as usize,
            mbi.RegionSize / 1024,
            state,
            protect,
            mbi.Type
        );

        address = (mbi.BaseAddress as usize) + mbi.RegionSize;

        if address < (mbi.BaseAddress as usize) {
            break;
        }
    }

    println!("\nmemory summary:");
    println!("  total regions:     {}", regions);
    println!("  committed regions: {}", committed);
    println!("  reserved regions:  {}", reserved);
    println!("  free regions:      {}", free);

    Ok(())
}
