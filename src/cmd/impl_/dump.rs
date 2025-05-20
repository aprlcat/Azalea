use std::{
    fs::File,
    io::{Read, Write},
    mem,
    path::Path,
};

use winapi::{
    shared::minwindef::{FALSE, HMODULE, MAX_PATH},
    um::{
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
        anyhow::bail!(
            "failed to enumerate process modules: error code {}",
            error_code
        );
    }

    let module_count = needed as usize / mem::size_of::<HMODULE>();
    if module_count == 0 {
        log::warn("no modules found in the process");
        return Ok(());
    }

    log::info(&format!(
        "found {} modules in process {}",
        module_count, pid
    ));

    for i in 0..module_count {
        let module = modules[i];

        let mut module_name = [0u8; MAX_PATH];
        let len = unsafe {
            GetModuleFileNameExA(
                handle,
                module,
                module_name.as_mut_ptr() as *mut _,
                module_name.len() as u32,
            )
        };

        if len == 0 {
            log::warn(&format!("failed to get filename for module at index {}", i));
            continue;
        }

        let module_name = String::from_utf8_lossy(&module_name[..len as usize]).to_string();
        let module_file_name = Path::new(&module_name)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown_module");

        let mut module_info: MODULEINFO = unsafe { mem::zeroed() };
        let success = unsafe {
            GetModuleInformation(
                handle,
                module,
                &mut module_info,
                mem::size_of::<MODULEINFO>() as u32,
            )
        };

        if success == 0 {
            log::warn(&format!(
                "failed to get module information for {}",
                module_file_name
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
        let mut file = File::create(&output_file_path)?;

        let mut buffer = vec![0u8; module_info.SizeOfImage as usize];
        let mut total_bytes_read = 0;

        for offset in (0..module_info.SizeOfImage as usize).step_by(PAGE_SIZE) {
            let chunk_size = std::cmp::min(PAGE_SIZE, module_info.SizeOfImage as usize - offset);
            let addr = (module_info.lpBaseOfDll as usize) + offset;
            let mut bytes_read = 0;

            let success = unsafe {
                ReadProcessMemory(
                    handle,
                    addr as *const _,
                    buffer.as_mut_ptr().add(offset) as *mut _,
                    chunk_size,
                    &mut bytes_read,
                )
            };

            if success == 0 {
                let error_code = unsafe { winapi::um::errhandlingapi::GetLastError() };
                if offset == 0 {
                    log::warn(&format!(
                        "error reading memory at {}: error code {}",
                        util::format_address(addr),
                        error_code
                    ));
                }
                continue;
            }

            total_bytes_read += bytes_read;
        }

        file.write_all(&buffer)?;

        let metadata_path = output_dir.join(format!("{}.meta.json", module_file_name));
        let mut metadata_file = File::create(&metadata_path)?;

        let metadata = format!(
            "{{
  \"module_name\": \"{}\",
  \"base_address\": \"0x{:x}\",
  \"size\": {},
  \"dump_size\": {},
  \"pid\": {}
}}",
            module_name,
            module_info.lpBaseOfDll as usize,
            module_info.SizeOfImage,
            total_bytes_read,
            pid
        );

        metadata_file.write_all(metadata.as_bytes())?;

        log::info(&format!(
            "module dumped to {} ({} kb read)",
            output_file_path.display(),
            total_bytes_read / 1024
        ));
    }

    unsafe { winapi::um::handleapi::CloseHandle(handle) };

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
            unsafe { winapi::um::handleapi::CloseHandle(handle) };
            anyhow::bail!("failed to create output file: {}", e);
        }
    };

    let mut buffer = vec![0u8; size];
    let mut total_bytes_read = 0;
    let mut error_count = 0;

    for offset in (0..size).step_by(PAGE_SIZE) {
        let chunk_size = std::cmp::min(PAGE_SIZE, size - offset);
        let addr = address + offset;
        let mut bytes_read = 0;

        let success = unsafe {
            ReadProcessMemory(
                handle,
                addr as *const _,
                buffer.as_mut_ptr().add(offset) as *mut _,
                chunk_size,
                &mut bytes_read,
            )
        };

        if success == 0 || bytes_read == 0 {
            error_count += 1;

            if error_count <= 3 {
                let error_code = unsafe { winapi::um::errhandlingapi::GetLastError() };
                log::warn(&format!(
                    "failed to read memory at {}: error code {}",
                    util::format_address(addr),
                    error_code
                ));
            } else if error_count == 4 {
                log::warn("too many read errors, suppressing further messages");
            }
            continue;
        }

        total_bytes_read += bytes_read;
    }

    if total_bytes_read == 0 {
        unsafe { winapi::um::handleapi::CloseHandle(handle) };
        anyhow::bail!("failed to read any data from the specified memory region");
    }

    match file.write_all(&buffer) {
        Ok(_) => {}
        Err(e) => {
            unsafe { winapi::um::handleapi::CloseHandle(handle) };
            anyhow::bail!("failed to write data to file: {}", e);
        }
    }

    let meta_path = format!("{}.meta.json", output_path);
    if let Ok(mut metadata_file) = File::create(&meta_path) {
        let metadata = format!(
            "{{
  \"base_address\": \"0x{:x}\",
  \"size\": {},
  \"dump_size\": {},
  \"pid\": {}
}}",
            address, size, total_bytes_read, pid
        );

        let _ = metadata_file.write_all(metadata.as_bytes());
    }

    unsafe { winapi::um::handleapi::CloseHandle(handle) };

    log::info(&format!(
        "memory region dumped to {} ({} kb read)",
        output_path,
        total_bytes_read / 1024
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

    if offset >= file_size {
        anyhow::bail!("offset exceeds file size (file size: {} bytes)", file_size);
    }

    let actual_size = std::cmp::min(size, file_size - offset);

    log::info(&format!(
        "reading dump file {} (offset: {}, size: {} bytes)",
        input_path, offset, actual_size
    ));

    use std::io::Seek;
    file.seek(std::io::SeekFrom::Start(offset as u64))?;

    let mut buffer = vec![0u8; actual_size];
    file.read_exact(&mut buffer)?;

    for (i, chunk) in buffer.chunks(16).enumerate() {
        print!("{:08x}:  ", offset + i * 16);

        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if j == 7 {
                print!(" ");
            }
        }

        let padding = 16 - chunk.len();
        for _ in 0..padding {
            print!("   ");
        }
        if chunk.len() <= 8 {
            print!(" ");
        }

        print!("  |");
        for byte in chunk {
            if *byte >= 32 && *byte <= 126 {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }

    if analyze {
        println!("\ndump analysis:");

        let pe_offset = buffer.windows(2).position(|window| window == [b'M', b'Z']);
        if let Some(pos) = pe_offset {
            println!("  [+] potential PE header found at offset +{:#x}", pos);
        }

        let mut zero_runs = Vec::new();
        let mut zero_run_start = None;

        for (i, &byte) in buffer.iter().enumerate() {
            if byte == 0 {
                if zero_run_start.is_none() {
                    zero_run_start = Some(i);
                }
            } else if let Some(start) = zero_run_start {
                let run_length = i - start;
                if run_length >= 16 {
                    zero_runs.push((start, run_length));
                }
                zero_run_start = None;
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
                    offset + start,
                    length
                );
            }
            if zero_runs.len() > 5 {
                println!("      ... and {} more", zero_runs.len() - 5);
            }
        }

        let mut strings = Vec::new();
        let mut string_start = None;

        for (i, &byte) in buffer.iter().enumerate() {
            if byte >= 32 && byte <= 126 {
                if string_start.is_none() {
                    string_start = Some(i);
                }
            } else if let Some(start) = string_start {
                let string_length = i - start;
                if string_length >= 4 {
                    let string = String::from_utf8_lossy(&buffer[start..i]).into_owned();
                    strings.push((start, string));
                }
                string_start = None;
            }
        }

        if let Some(start) = string_start {
            let string_length = buffer.len() - start;
            if string_length >= 4 {
                let string = String::from_utf8_lossy(&buffer[start..]).into_owned();
                strings.push((start, string));
            }
        }

        if !strings.is_empty() {
            println!(
                "  [+] found {} strings (min length: 4 chars)",
                strings.len()
            );
            for (idx, (start, string)) in strings.iter().enumerate().take(10) {
                if string.len() > 60 {
                    println!(
                        "      string {}: offset +{:#x}, \"{}...\"",
                        idx + 1,
                        offset + start,
                        &string[..60]
                    );
                } else {
                    println!(
                        "      string {}: offset +{:#x}, \"{}\"",
                        idx + 1,
                        offset + start,
                        string
                    );
                }
            }
            if strings.len() > 10 {
                println!("      ... and {} more", strings.len() - 10);
            }
        }

        let patterns = [
            (
                "null pointers",
                &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00][..],
            ),
            ("int3 instructions", &[0xCC, 0xCC, 0xCC, 0xCC][..]),
            ("x86 ret", &[0xC3][..]),
            ("x86 call", &[0xE8][..]),
            (
                "possible vtable",
                &[0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00][..],
            ),
        ];

        for (name, pattern) in &patterns {
            let count = buffer
                .windows(pattern.len())
                .filter(|window| window == pattern)
                .count();
            if count > 0 {
                println!("  [+] found {} instances of {} pattern", count, name);
            }
        }
    }

    log::info(&format!(
        "successfully read {} bytes from dump file",
        actual_size
    ));
    Ok(())
}
