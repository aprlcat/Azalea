use std::io::{Write, stdout};

use winapi::um::{
    memoryapi::{ReadProcessMemory, VirtualQueryEx},
    winnt::{
        MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
        PAGE_READONLY, PAGE_READWRITE,
    },
};

use crate::{util, util::log};

pub fn scan_memory(pid: u32, pattern: &[Option<u8>]) -> anyhow::Result<()> {
    let handle = util::open_process(pid)?;

    log::info(&format!(
        "scanning for pattern of {} bytes...",
        pattern.len()
    ));
    let mut matches = 0;

    println!("pattern details:");
    print!("hex: ");
    for byte_option in pattern {
        match byte_option {
            Some(byte) => print!("{:02x} ", byte),
            None => print!("?? "),
        }
    }
    println!();

    print!("ascii: \"");
    for byte_option in pattern {
        match byte_option {
            Some(byte) if *byte >= 32 && *byte <= 126 => print!("{}", *byte as char),
            Some(_) | None => print!("."),
        }
    }
    println!("\"");

    println!("\nscanning memory...");

    let progress_bar_width = 40;
    let mut regions_scanned = 0;
    let line_clear_width = progress_bar_width + 30;

    let mut address: usize = 0;
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

    while unsafe { VirtualQueryEx(handle, address as *const _, &mut mbi, mbi_size) } == mbi_size {
        regions_scanned += 1;

        if mbi.State == MEM_COMMIT
            && (mbi.Protect == PAGE_READWRITE
                || mbi.Protect == PAGE_READONLY
                || mbi.Protect == PAGE_EXECUTE_READ
                || mbi.Protect == PAGE_EXECUTE_READWRITE)
            && mbi.RegionSize > 0
        {
            if regions_scanned % 10 == 0 {
                print!("\rprogress: [");
                let progress = (regions_scanned % (progress_bar_width * 2)) * progress_bar_width
                    / (progress_bar_width * 2);
                for i in 0..progress_bar_width {
                    if i < progress {
                        print!("#");
                    } else {
                        print!("-");
                    }
                }
                print!("] region: {}", regions_scanned);
                let _ = stdout().flush();
            }

            let region_size = mbi.RegionSize;
            let mut buffer = vec![0u8; region_size];
            let mut bytes_read = 0;

            let success = unsafe {
                ReadProcessMemory(
                    handle,
                    mbi.BaseAddress,
                    buffer.as_mut_ptr() as *mut _,
                    region_size,
                    &mut bytes_read,
                )
            };

            if success != 0 && bytes_read > 0 {
                buffer.truncate(bytes_read as usize);
                for i in 0..buffer.len().saturating_sub(pattern.len()).saturating_add(1) {
                    let mut found = true;
                    for j in 0..pattern.len() {
                        if i + j >= buffer.len() {
                            found = false;
                            break;
                        }
                        if let Some(pattern_byte) = pattern[j] {
                            if buffer[i + j] != pattern_byte {
                                found = false;
                                break;
                            }
                        }
                    }

                    if found {
                        let match_addr = (mbi.BaseAddress as usize) + i;

                        print!("\r");
                        for _ in 0..line_clear_width {
                            print!(" ");
                        }
                        print!("\r");
                        let _ = stdout().flush();

                        println!("match found at {}", util::format_address(match_addr));
                        matches += 1;

                        let context_before = 8.min(i);
                        let context_after = 8.min(buffer.len().saturating_sub(i + pattern.len()));
                        let start_context = i - context_before;
                        let end_context = i + pattern.len() + context_after;

                        if end_context > start_context && end_context <= buffer.len() {
                            print!("  context: ");
                            for k in start_context..end_context {
                                if k >= i && k < i + pattern.len() && pattern[k - i].is_some() {
                                    print!("[{:02x}] ", buffer[k]);
                                } else if k >= i
                                    && k < i + pattern.len()
                                    && pattern[k - i].is_none()
                                {
                                    print!("[??={:02x}] ", buffer[k]);
                                } else {
                                    print!("{:02x} ", buffer[k]);
                                }
                            }
                            println!();
                        }
                        if regions_scanned % 10 != 0 && matches > 0 {
                            print!("\rprogress: [");
                            let progress = (regions_scanned % (progress_bar_width * 2))
                                * progress_bar_width
                                / (progress_bar_width * 2);
                            for idx in 0..progress_bar_width {
                                if idx < progress {
                                    print!("#");
                                } else {
                                    print!("-");
                                }
                            }
                            print!("] region: {}", regions_scanned);
                            let _ = stdout().flush();
                        }
                    }
                }
            }
        }

        address = (mbi.BaseAddress as usize).wrapping_add(mbi.RegionSize);
        if address < (mbi.BaseAddress as usize) {
            break;
        }
    }

    print!("\r");
    for _ in 0..line_clear_width {
        print!(" ");
    }
    println!();
    let _ = stdout().flush();

    log::info(&format!("scan complete. found {} matches.", matches));
    unsafe { winapi::um::handleapi::CloseHandle(handle) };
    Ok(())
}
