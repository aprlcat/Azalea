use std::{ffi::OsStr, os::windows::ffi::OsStrExt, ptr};

use winapi::{
    shared::minwindef::FARPROC,
    um::{
        handleapi::CloseHandle,
        libloaderapi::{GetModuleHandleW, GetProcAddress},
        memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory},
        processthreadsapi::{CreateRemoteThread, OpenProcess},
        winnt::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, PROCESS_CREATE_THREAD,
            PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
        },
    },
};

use crate::{util, util::log};

pub fn inject_dll(pid: u32, dll_path: &str) -> anyhow::Result<()> {
    log::info(&format!(
        "attempting to inject DLL '{}' into PID {}",
        dll_path, pid
    ));

    let process_handle = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ,
            0,
            pid,
        )
    };

    if process_handle.is_null() {
        anyhow::bail!(
            "failed to open process with PID {}: error code {}",
            pid,
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
    }

    let wide_dll_path: Vec<u16> = OsStr::new(dll_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let dll_path_size = wide_dll_path.len() * std::mem::size_of::<u16>();

    let remote_memory = unsafe {
        VirtualAllocEx(
            process_handle,
            ptr::null_mut(),
            dll_path_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if remote_memory.is_null() {
        unsafe { CloseHandle(process_handle) };
        anyhow::bail!(
            "failed to allocate memory in target process: error code {}",
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
    }

    let mut bytes_written = 0;
    let write_success = unsafe {
        WriteProcessMemory(
            process_handle,
            remote_memory,
            wide_dll_path.as_ptr() as *const _,
            dll_path_size,
            &mut bytes_written,
        )
    };

    if write_success == 0 || bytes_written != dll_path_size {
        unsafe {
            VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
            CloseHandle(process_handle);
        }
        anyhow::bail!(
            "failed to write DLL path to target process: error code {}",
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
    }

    let kernel32_handle = unsafe { GetModuleHandleW(util::str_to_wide("kernel32.dll").as_ptr()) };
    if kernel32_handle.is_null() {
        unsafe {
            VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
            CloseHandle(process_handle);
        }
        anyhow::bail!(
            "failed to get handle for kernel32.dll: error code {}",
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
    }

    let load_library_addr =
        unsafe { GetProcAddress(kernel32_handle, "LoadLibraryW\0".as_ptr() as *const i8) };
    if load_library_addr.is_null() {
        unsafe {
            VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
            CloseHandle(process_handle);
        }
        anyhow::bail!(
            "failed to get address of LoadLibraryW: error code {}",
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
    }

    let remote_thread_handle = unsafe {
        CreateRemoteThread(
            process_handle,
            ptr::null_mut(),
            0,
            Some(std::mem::transmute::<
                FARPROC,
                unsafe extern "system" fn(*mut winapi::ctypes::c_void) -> u32,
            >(load_library_addr)),
            remote_memory,
            0,
            ptr::null_mut(),
        )
    };

    if remote_thread_handle.is_null() {
        unsafe {
            VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
            CloseHandle(process_handle);
        }
        anyhow::bail!(
            "failed to create remote thread in target process: error code {}",
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
    }

    unsafe {
        winapi::um::synchapi::WaitForSingleObject(
            remote_thread_handle,
            winapi::um::winbase::INFINITE,
        );
    }

    let mut exit_code: u32 = 0;
    unsafe {
        winapi::um::processthreadsapi::GetExitCodeThread(remote_thread_handle, &mut exit_code);
    }

    unsafe {
        VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
        CloseHandle(remote_thread_handle);
        CloseHandle(process_handle);
    }

    if exit_code == 0 {
        log::warn(&format!(
            "LoadLibraryW might have failed in remote process (exit code 0), but thread created. \
             DLL: {}",
            dll_path
        ));
    } else {
        log::info(&format!(
            "DLL '{}' successfully injected into PID {}. LoadLibraryW returned module handle: \
             0x{:X}",
            dll_path, pid, exit_code
        ));
    }

    Ok(())
}
