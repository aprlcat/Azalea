use std::mem;

use winapi::{
    shared::minwindef::{DWORD, FALSE},
    um::{
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        processthreadsapi::{GetProcessIdOfThread, OpenThread, ResumeThread, SuspendThread},
        tlhelp32::{
            CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
        },
        winnt::{THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME},
    },
};

use crate::util::log;

pub fn list_threads(pid: u32) -> anyhow::Result<()> {
    log::info(&format!("listing threads for PID {}", pid));
    let snapshot_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };

    if snapshot_handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        anyhow::bail!("failed to create thread snapshot: error code {}", unsafe {
            GetLastError()
        });
    }

    let mut thread_entry = THREADENTRY32 {
        dwSize: mem::size_of::<THREADENTRY32>() as DWORD,
        cntUsage: 0,
        th32ThreadID: 0,
        th32OwnerProcessID: 0,
        tpBasePri: 0,
        tpDeltaPri: 0,
        dwFlags: 0,
    };

    println!("TID\tOwner PID\tBase Priority");
    println!("---\t---------\t-------------");

    let mut success = unsafe { Thread32First(snapshot_handle, &mut thread_entry) };
    let mut count = 0;

    while success != FALSE {
        if thread_entry.th32OwnerProcessID == pid {
            count += 1;
            println!(
                "{}\t{}\t\t{}",
                thread_entry.th32ThreadID, thread_entry.th32OwnerProcessID, thread_entry.tpBasePri
            );
        }
        success = unsafe { Thread32Next(snapshot_handle, &mut thread_entry) };
    }

    unsafe { CloseHandle(snapshot_handle) };
    log::info(&format!("found {} threads for PID {}", count, pid));
    Ok(())
}

pub fn suspend_thread_by_pid_tid(pid: u32, tid: u32) -> anyhow::Result<()> {
    log::info(&format!(
        "attempting to suspend thread {} for PID {}",
        tid, pid
    ));

    let thread_handle =
        unsafe { OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, tid) };
    if thread_handle.is_null() {
        anyhow::bail!("failed to open thread {}: error code {}", tid, unsafe {
            GetLastError()
        });
    }

    let owner_pid_of_thread = unsafe { GetProcessIdOfThread(thread_handle) };
    if owner_pid_of_thread == 0 {
        let err_code = unsafe { GetLastError() };
        unsafe { CloseHandle(thread_handle) };
        anyhow::bail!(
            "failed to get owner PID for thread {}: error code {}",
            tid,
            err_code
        );
    }
    if owner_pid_of_thread != pid {
        unsafe { CloseHandle(thread_handle) };
        anyhow::bail!(
            "thread {} does not belong to PID {} (belongs to PID {})",
            tid,
            pid,
            owner_pid_of_thread
        );
    }

    let suspend_count = unsafe { SuspendThread(thread_handle) };
    unsafe { CloseHandle(thread_handle) };

    if suspend_count == -1i32 as u32 {
        anyhow::bail!("failed to suspend thread {}: error code {}", tid, unsafe {
            GetLastError()
        });
    }

    log::info(&format!(
        "thread {} suspended successfully (previous suspend count: {})",
        tid, suspend_count
    ));
    Ok(())
}

pub fn resume_thread_by_pid_tid(pid: u32, tid: u32) -> anyhow::Result<()> {
    log::info(&format!(
        "attempting to resume thread {} for PID {}",
        tid, pid
    ));

    let thread_handle =
        unsafe { OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, tid) };
    if thread_handle.is_null() {
        anyhow::bail!("failed to open thread {}: error code {}", tid, unsafe {
            GetLastError()
        });
    }

    let owner_pid_of_thread = unsafe { GetProcessIdOfThread(thread_handle) };
    if owner_pid_of_thread == 0 {
        let err_code = unsafe { GetLastError() };
        unsafe { CloseHandle(thread_handle) };
        anyhow::bail!(
            "failed to get owner PID for thread {}: error code {}",
            tid,
            err_code
        );
    }
    if owner_pid_of_thread != pid {
        unsafe { CloseHandle(thread_handle) };
        anyhow::bail!(
            "thread {} does not belong to PID {} (belongs to PID {})",
            tid,
            pid,
            owner_pid_of_thread
        );
    }

    let suspend_count = unsafe { ResumeThread(thread_handle) };
    unsafe { CloseHandle(thread_handle) };

    if suspend_count == -1i32 as u32 {
        anyhow::bail!("failed to resume thread {}: error code {}", tid, unsafe {
            GetLastError()
        });
    }

    log::info(&format!(
        "thread {} resumed successfully (new suspend count: {})",
        tid, suspend_count
    ));
    Ok(())
}
