use std::{
    fs::File,
    io::{Read, Write},
    mem,
    path::Path,
};

use winapi::{
    shared::minwindef::{FALSE, HMODULE, MAX_PATH},
    um::{
        handleapi::CloseHandle,
        memoryapi::ReadProcessMemory,
        psapi::{EnumProcessModules, GetModuleFileNameExA, GetModuleInformation, MODULEINFO},
        winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

use crate::{util, util::log};

const PAGE_SIZE: usize = 4096;

pub fn dump_process_memory(pid: u32, output_path: &str) -> anyhow::Result<()> {
    let handle = unsafe {
        winapi::um::processthreadsapi::OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            FALSE,
            pid,
        )
    };

    if handle.is_null() {
        let error_code = unsafe { winapi::um::errhandlingapi::GetLastError() };
        anyhow::bail!("failed to open process: error code {}", error_code);
    }

    let output_dir = Path::new(output_path);
    if !output_dir.exists() {
        std::fs::create_dir_all(output_dir)?;
    } else if !output_dir.is_dir() {
        unsafe { CloseHandle(handle) };
        anyhow::bail!(
            "output path '{}' exists but is not a directory",
            output_path
        );
    }

    let mut modules = [0 as HMODULE; 1024];
    let mut needed = 0;

    let success = unsafe {
        EnumProcessModules(
            handle,
            modules.as_mut_ptr(),
            (modules.len() * mem::size_of::<HMODULE>()) as u32,
            &mut needed,
        )
    };

    if success == 0 {
        let error_code = unsafe { winapi::um::errhandlingapi::GetLastError() };
        unsafe { CloseHandle(handle) };
        anyhow::bail!(
            "failed to enumerate process modules: error code {}",
            error_code
        );
    }

    let module_count = needed as usize / mem::size_of::<HMODULE>();
    if module_count == 0 {
        log::warn("no modules found in the process");
        unsafe { CloseHandle(handle) };
        return Ok(());
    }

    log::info(&format!(
        "found {} modules in process {}",
        module_count, pid
    ));

    for i in 0..module_count {
        let module = modules[i];

        let mut module_name_buffer = [0u8; MAX_PATH];
        let len = unsafe {
            GetModuleFileNameExA(
                handle,
                module,
                module_name_buffer.as_mut_ptr() as *mut i8,
                module_name_buffer.len() as u32,
            )
        };

        if len == 0 {
            log::warn(&format!(
                "failed to get filename for module at index {}: error code {}",
                i,
                unsafe { winapi::um::errhandlingapi::GetLastError() }
            ));
            continue;
        }

        let module_name_str =
            String::from_utf8_lossy(&module_name_buffer[..len as usize]).to_string();
        let module_file_name = Path::new(&module_name_str)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown_module");

        let mut module_info: MODULEINFO = unsafe { mem::zeroed() };
        let success_info = unsafe {
            GetModuleInformation(
                handle,
                module,
                &mut module_info,
                mem::size_of::<MODULEINFO>() as u32,
            )
        };

        if success_info == 0 {
            log::warn(&format!(
                "failed to get module information for {}: error code {}",
                module_file_name,
                unsafe { winapi::um::errhandlingapi::GetLastError() }
            ));
            continue;
        }

        log::info(&format!(
            "dumping module: {} (base: {:p}, size: {} kb)",
            module_file_name,
            module_info.lpBaseOfDll,
            module_info.SizeOfImage / 1024
        ));

        let output_file_path = output_dir.join(format!("{}.bin", module_file_name));
        let mut file = match File::create(&output_file_path) {
            Ok(f) => f,
            Err(e) => {
                log::warn(&format!(
                    "Failed to create file {}: {}",
                    output_file_path.display(),
                    e
                ));
                continue;
            }
        };

        let mut buffer = vec![0u8; module_info.SizeOfImage as usize];
        let mut total_bytes_read_for_module = 0;

        for offset in (0..module_info.SizeOfImage as usize).step_by(PAGE_SIZE) {
            let current_addr = (module_info.lpBaseOfDll as usize) + offset;
            let bytes_to_read_in_chunk =
                std::cmp::min(PAGE_SIZE, module_info.SizeOfImage as usize - offset);

            if bytes_to_read_in_chunk == 0 {
                continue;
            }

            let mut bytes_read_in_chunk = 0;
            let read_success = unsafe {
                ReadProcessMemory(
                    handle,
                    current_addr as *const _,
                    buffer.as_mut_ptr().add(offset) as *mut winapi::ctypes::c_void,
                    bytes_to_read_in_chunk,
                    &mut bytes_read_in_chunk,
                )
            };

            if read_success == 0 {
                let error_code = unsafe { winapi::um::errhandlingapi::GetLastError() };

                log::warn(&format!(
                    "error reading memory for module {} at {}: error code {}. Read {} of {} bytes \
                     for this chunk.",
                    module_file_name,
                    util::format_address(current_addr),
                    error_code,
                    bytes_read_in_chunk,
                    bytes_to_read_in_chunk
                ));
            }
            total_bytes_read_for_module += bytes_read_in_chunk;
        }

        if let Err(e) = file.write_all(&buffer[..total_bytes_read_for_module]) {
            log::warn(&format!(
                "Failed to write all bytes to {}: {}",
                output_file_path.display(),
                e
            ));
            continue;
        }

        let metadata_path = output_dir.join(format!("{}.meta.json", module_file_name));
        if let Ok(mut metadata_file) = File::create(&metadata_path) {
            let metadata = format!(
                r#"{{
  "module_name": "{}",
  "base_address": "0x{:x}",
  "size": {},
  "dump_size": {},
  "pid": {}
}}"#,
                module_name_str,
                module_info.lpBaseOfDll as usize,
                module_info.SizeOfImage,
                total_bytes_read_for_module,
                pid
            );
            if let Err(e) = metadata_file.write_all(metadata.as_bytes()) {
                log::warn(&format!(
                    "Failed to write metadata to {}: {}",
                    metadata_path.display(),
                    e
                ));
            }
        } else {
            log::warn(&format!(
                "Failed to create metadata file {}",
                metadata_path.display()
            ));
        }

        log::info(&format!(
            "module {} dumped to {} ({} kb read)",
            module_file_name,
            output_file_path.display(),
            total_bytes_read_for_module / 1024
        ));
    }

    unsafe { CloseHandle(handle) };

    log::info(&format!("process memory dumped to {}", output_path));
    Ok(())
}

pub fn dump_memory_region(
    pid: u32,
    address: usize,
    size: usize,
    output_path: &str,
) -> anyhow::Result<()> {
    let handle = unsafe { winapi::um::processthreadsapi::OpenProcess(PROCESS_VM_READ, FALSE, pid) };

    if handle.is_null() {
        let error_code = unsafe { winapi::um::errhandlingapi::GetLastError() };
        anyhow::bail!("failed to open process: error code {}", error_code);
    }

    log::info(&format!(
        "dumping memory region at {} (size: {} kb)",
        util::format_address(address),
        size / 1024
    ));

    let mut file = match File::create(output_path) {
        Ok(f) => f,
        Err(e) => {
            unsafe { CloseHandle(handle) };
            anyhow::bail!("failed to create output file '{}': {}", output_path, e);
        }
    };

    let mut buffer = vec![0u8; size];
    let mut total_bytes_read = 0;
    let mut error_count = 0;

    for offset in (0..size).step_by(PAGE_SIZE) {
        let chunk_size = std::cmp::min(PAGE_SIZE, size - offset);
        if chunk_size == 0 {
            continue;
        }
        let addr = address + offset;
        let mut bytes_read_in_chunk = 0;

        let success = unsafe {
            ReadProcessMemory(
                handle,
                addr as *const _,
                buffer.as_mut_ptr().add(offset) as *mut winapi::ctypes::c_void,
                chunk_size,
                &mut bytes_read_in_chunk,
            )
        };

        if success == 0 || bytes_read_in_chunk == 0 {
            error_count += 1;
            let error_code = unsafe { winapi::um::errhandlingapi::GetLastError() };
            if error_count <= 3 {
                log::warn(&format!(
                    "failed to read memory at {}: error code {}",
                    util::format_address(addr),
                    error_code
                ));
            } else if error_count == 4 {
                log::warn(
                    "too many read errors, suppressing further messages for this region dump",
                );
            }
        }
        total_bytes_read += bytes_read_in_chunk;
    }

    if total_bytes_read == 0 && size > 0 {
        unsafe { CloseHandle(handle) };
        anyhow::bail!("failed to read any data from the specified memory region");
    }

    match file.write_all(&buffer[..total_bytes_read]) {
        Ok(_) => {}
        Err(e) => {
            unsafe { CloseHandle(handle) };
            anyhow::bail!("failed to write data to file '{}': {}", output_path, e);
        }
    }

    let meta_path = format!("{}.meta.json", output_path);
    if let Ok(mut metadata_file) = File::create(&meta_path) {
        let metadata = format!(
            r#"{{
  "base_address": "0x{:x}",
  "requested_size": {},
  "dump_size": {},
  "pid": {}
}}"#,
            address, size, total_bytes_read, pid
        );

        if let Err(e) = metadata_file.write_all(metadata.as_bytes()) {
            log::warn(&format!("Failed to write metadata to {}: {}", meta_path, e));
        }
    } else {
        log::warn(&format!("Failed to create metadata file {}", meta_path));
    }

    unsafe { CloseHandle(handle) };

    log::info(&format!(
        "memory region dumped to {} ({} kb of {} kb requested read)",
        output_path,
        total_bytes_read / 1024,
        size / 1024
    ));

    Ok(())
}

pub fn read_dump(
    input_path: &str,
    offset: usize,
    size: usize,
    analyze: bool,
) -> anyhow::Result<()> {
    let mut file = File::open(input_path)?;

    let file_size = file.metadata()?.len() as usize;

    if offset >= file_size && file_size > 0 {
        anyhow::bail!(
            "offset ({} bytes) exceeds file size ({} bytes)",
            offset,
            file_size
        );
    }
    if offset >= file_size && file_size == 0 && offset > 0 {
        anyhow::bail!(
            "offset ({} bytes) cannot be non-zero for an empty file",
            offset
        );
    }

    let actual_size = std::cmp::min(size, file_size.saturating_sub(offset));

    log::info(&format!(
        "reading dump file {} (offset: {}, size: {} bytes)",
        input_path, offset, actual_size
    ));

    use std::io::Seek;
    file.seek(std::io::SeekFrom::Start(offset as u64))?;

    let mut buffer = vec![0u8; actual_size];
    if actual_size > 0 {
        file.read_exact(&mut buffer)?;
    }

    for (i, chunk) in buffer.chunks(16).enumerate() {
        print!("{:08x}:  ", offset + i * 16);

        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if j == 7 {
                print!(" ");
            }
        }

        let padding_hex_chars = (16 - chunk.len()) * 3
            + if chunk.len() <= 8 && chunk.len() > 0 {
                1
            } else {
                0
            };
        for _ in 0..padding_hex_chars {
            print!(" ");
        }
        if chunk.len() == 0 {
            for _ in 0..(16 * 3 + 1) {
                print!(" ");
            }
        }

        print!(" |");
        for byte_val in chunk {
            if *byte_val >= 32 && *byte_val <= 126 {
                print!("{}", *byte_val as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
    if buffer.is_empty() {
        println!("{:08x}:  (empty)", offset);
    }

    if analyze && !buffer.is_empty() {
        println!("\ndump analysis:");

        let pe_offset = buffer.windows(2).position(|window| window == b"MZ");
        if let Some(pos) = pe_offset {
            println!("  [+] potential PE header found at offset +{:#x}", pos);
        } else {
            println!("  [-] no PE header (MZ) found in this segment.");
        }

        let mut zero_runs = Vec::new();
        let mut zero_run_start: Option<usize> = None;

        for (i, &byte_val) in buffer.iter().enumerate() {
            if byte_val == 0 {
                if zero_run_start.is_none() {
                    zero_run_start = Some(i);
                }
            } else if let Some(start) = zero_run_start.take() {
                let run_length = i - start;
                if run_length >= 16 {
                    zero_runs.push((start, run_length));
                }
            }
        }

        if let Some(start) = zero_run_start {
            let run_length = buffer.len() - start;
            if run_length >= 16 {
                zero_runs.push((start, run_length));
            }
        }

        if !zero_runs.is_empty() {
            println!(
                "  [+] found {} zero runs (min length: 16 bytes)",
                zero_runs.len()
            );
            for (idx, (start, length)) in zero_runs.iter().enumerate().take(5) {
                println!(
                    "      zero run {}: offset +{:#x}, length {} bytes",
                    idx + 1,
                    start,
                    length
                );
            }
            if zero_runs.len() > 5 {
                println!("      ... and {} more", zero_runs.len() - 5);
            }
        } else {
            println!("  [-] no significant zero runs (min length: 16 bytes) found.");
        }

        let mut strings = Vec::new();
        let mut string_start: Option<usize> = None;
        for (i, &byte_val) in buffer.iter().enumerate() {
            if byte_val >= 32 && byte_val <= 126 {
                if string_start.is_none() {
                    string_start = Some(i);
                }
            } else if let Some(start) = string_start.take() {
                let string_length = i - start;
                if string_length >= 4 {
                    let string_data = String::from_utf8_lossy(&buffer[start..i]).into_owned();
                    strings.push((start, string_data));
                }
            }
        }
        if let Some(start) = string_start {
            let string_length = buffer.len() - start;
            if string_length >= 4 {
                let string_data = String::from_utf8_lossy(&buffer[start..]).into_owned();
                strings.push((start, string_data));
            }
        }

        if !strings.is_empty() {
            println!(
                "  [+] found {} strings (min length: 4 chars)",
                strings.len()
            );
            for (idx, (start, string_data)) in strings.iter().enumerate().take(10) {
                let display_string = if string_data.len() > 60 {
                    format!("{}...", &string_data[..60])
                } else {
                    string_data.clone()
                };
                println!(
                    "      string {}: offset +{:#x}, \"{}\"",
                    idx + 1,
                    start,
                    display_string
                );
            }
            if strings.len() > 10 {
                println!("      ... and {} more", strings.len() - 10);
            }
        } else {
            println!("  [-] no significant strings (min length: 4 chars) found.");
        }

        let patterns_to_check = [
            (
                "possible null pointers (x64)",
                &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00][..],
            ),
            (
                "INT3 sequence (debug breaks)",
                &[0xCC, 0xCC, 0xCC, 0xCC][..],
            ),
            ("common x86 RET instruction", &[0xC3][..]),
            ("common x86 CALL rel32 instruction", &[0xE8][..]),
        ];

        println!("  Common patterns search:");
        for (name, pattern) in &patterns_to_check {
            if pattern.is_empty() {
                continue;
            }
            let count = buffer
                .windows(pattern.len())
                .filter(|window| *window == *pattern)
                .count();
            if count > 0 {
                println!("    [+] found {} instances of '{}' pattern", count, name);
            }
        }
    } else if analyze && buffer.is_empty() {
        println!("\ndump analysis: buffer is empty, nothing to analyze.");
    }

    log::info(&format!(
        "successfully read {} bytes from dump file",
        actual_size
    ));
    Ok(())
}
