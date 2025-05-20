use std::{ffi::OsStr, os::windows::ffi::OsStrExt};

use winapi::um::{
    memoryapi::{ReadProcessMemory, VirtualQueryEx},
    winnt::{
        MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
        PAGE_READONLY, PAGE_READWRITE,
    },
};

use crate::{util, util::log};

#[derive(Debug, Clone, Copy)]
pub enum StringEncoding {
    Ascii,
    Utf16LE,
}

pub fn scan_for_strings(
    pid: u32,
    search_string: &str,
    encoding: StringEncoding,
) -> anyhow::Result<()> {
    let handle = util::open_process(pid)?;
    log::info(&format!(
        "scanning for {:?} string \"{}\" in PID {}",
        encoding, search_string, pid
    ));

    let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let mut current_base_address: usize = 0;
    let mut found_count = 0;

    let (search_bytes_ascii, search_bytes_utf16): (Option<Vec<u8>>, Option<Vec<u16>>) =
        match encoding {
            StringEncoding::Ascii => (Some(search_string.as_bytes().to_vec()), None),
            StringEncoding::Utf16LE => {
                let utf16_str: Vec<u16> = OsStr::new(search_string).encode_wide().collect();
                (None, Some(utf16_str))
            }
        };

    if search_string.is_empty() {
        anyhow::bail!("search string cannot be empty");
    }

    while unsafe {
        VirtualQueryEx(
            handle,
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
                    handle,
                    mem_info.BaseAddress,
                    buffer.as_mut_ptr() as *mut _,
                    mem_info.RegionSize,
                    &mut bytes_read,
                )
            };

            if success != 0 && bytes_read > 0 {
                let valid_buffer = &buffer[..bytes_read as usize];
                match encoding {
                    StringEncoding::Ascii => {
                        if let Some(ref s_bytes) = search_bytes_ascii {
                            if s_bytes.is_empty() {
                                continue;
                            }
                            for (i, window) in valid_buffer.windows(s_bytes.len()).enumerate() {
                                if window == s_bytes.as_slice() {
                                    let match_address = mem_info.BaseAddress as usize + i;
                                    println!(
                                        "found ASCII string \"{}\" at {}",
                                        search_string,
                                        util::format_address(match_address)
                                    );
                                    found_count += 1;
                                }
                            }
                        }
                    }
                    StringEncoding::Utf16LE => {
                        if let Some(ref s_utf16) = search_bytes_utf16 {
                            if s_utf16.is_empty() {
                                continue;
                            }
                            if valid_buffer.len() < s_utf16.len() * 2 {
                                continue;
                            }

                            for i in 0..=(valid_buffer.len() - s_utf16.len() * 2) {
                                let mut match_found = true;
                                for j in 0..s_utf16.len() {
                                    let buf_idx = i + j * 2;
                                    let char_from_buf = u16::from_le_bytes([
                                        valid_buffer[buf_idx],
                                        valid_buffer[buf_idx + 1],
                                    ]);
                                    if char_from_buf != s_utf16[j] {
                                        match_found = false;
                                        break;
                                    }
                                }
                                if match_found {
                                    let match_address = mem_info.BaseAddress as usize + i;
                                    println!(
                                        "found UTF-16LE string \"{}\" at {}",
                                        search_string,
                                        util::format_address(match_address)
                                    );
                                    found_count += 1;
                                }
                            }
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

    if found_count == 0 {
        log::info(&format!("string \"{}\" not found.", search_string));
    } else {
        log::info(&format!(
            "scan complete. found {} occurrences of \"{}\".",
            found_count, search_string
        ));
    }
    unsafe { winapi::um::handleapi::CloseHandle(handle) };
    Ok(())
}
