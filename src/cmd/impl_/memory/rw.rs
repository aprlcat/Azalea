use winapi::um::{
    handleapi::CloseHandle,
    memoryapi::{ReadProcessMemory, WriteProcessMemory},
};

use crate::{util, util::log};

pub fn read_memory(pid: u32, address: usize, size: usize) -> anyhow::Result<()> {
    if size == 0 {
        log::warn("read_memory called with size 0. No bytes will be read.");
        println!(
            "memory at {}: (0 bytes requested)",
            util::format_address(address)
        );
        return Ok(());
    }
    let handle = util::open_process(pid)?;

    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0;

    let success = unsafe {
        ReadProcessMemory(
            handle,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            size,
            &mut bytes_read,
        )
    };
    let last_error = unsafe { winapi::um::errhandlingapi::GetLastError() };
    unsafe { CloseHandle(handle) };

    if success == 0 {
        anyhow::bail!(
            "failed to read memory at address {}: error code {}",
            util::format_address(address),
            last_error
        );
    }

    if bytes_read == 0 && size > 0 {
        log::warn(&format!(
            "ReadProcessMemory succeeded but read 0 bytes from {} (size {}). Error: {}",
            util::format_address(address),
            size,
            last_error
        ));
    }

    println!("memory at {}:", util::format_address(address));
    buffer.truncate(bytes_read);

    for (i, chunk) in buffer.chunks(16).enumerate() {
        print!("{:08x}:  ", address + i * 16);

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
    if buffer.is_empty() && size > 0 {
        println!("{:08x}:  (0 bytes read of {} requested)", address, size);
    } else if buffer.is_empty() && size == 0 {
    }

    log::info(&format!("successfully read {} bytes", bytes_read));
    Ok(())
}

pub fn write_memory(pid: u32, address: usize, bytes: &[u8]) -> anyhow::Result<()> {
    if bytes.is_empty() {
        log::warn("write_memory called with empty byte slice. No bytes will be written.");
        return Ok(());
    }
    let handle = util::open_process(pid)?;

    let mut bytes_written = 0;

    let success = unsafe {
        WriteProcessMemory(
            handle,
            address as *mut _,
            bytes.as_ptr() as *const _,
            bytes.len(),
            &mut bytes_written,
        )
    };
    let last_error = unsafe { winapi::um::errhandlingapi::GetLastError() };
    unsafe { CloseHandle(handle) };

    if success == 0 {
        anyhow::bail!(
            "failed to write memory at address {}: error code {}",
            util::format_address(address),
            last_error
        );
    }

    if bytes_written != bytes.len() {
        log::warn(&format!(
            "WriteProcessMemory wrote {} bytes, but {} bytes were requested to be written to {}",
            bytes_written,
            bytes.len(),
            util::format_address(address)
        ));
    }

    log::info(&format!(
        "successfully wrote {} bytes to {}",
        bytes_written,
        util::format_address(address)
    ));
    Ok(())
}
