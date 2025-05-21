use std::mem;

use winapi::{
    shared::minwindef::{DWORD, FALSE},
    um::{
        handleapi::CloseHandle,
        tlhelp32::{
            CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next,
            TH32CS_SNAPPROCESS,
        },
    },
};

pub fn list_processes() -> anyhow::Result<()> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        anyhow::bail!("failed to create process snapshot: error code {}", unsafe {
            winapi::um::errhandlingapi::GetLastError()
        });
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

    println!("PID\tThreads\tParent PID\tProcess Name");
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

    unsafe { CloseHandle(snapshot) };

    Ok(())
}
