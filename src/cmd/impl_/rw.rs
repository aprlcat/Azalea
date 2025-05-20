use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};

use crate::{util, util::log};

pub fn read_memory(pid: u32, address: usize, size: usize) -> anyhow::Result<()> {
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

    if success == 0 {
        anyhow::bail!(
            "failed to read memory at address {}",
            util::format_address(address)
        );
    }

    println!("memory at {}:", util::format_address(address));

    for (i, chunk) in buffer.chunks(16).enumerate() {
        print!("{:08x}:  ", address + i * 16);

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

    log::info(&format!("successfully read {} bytes", bytes_read));
    Ok(())
}

pub fn write_memory(pid: u32, address: usize, bytes: &[u8]) -> anyhow::Result<()> {
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

    if success == 0 {
        anyhow::bail!(
            "failed to write memory at address {}",
            util::format_address(address)
        );
    }

    log::info(&format!(
        "successfully wrote {} bytes to {}",
        bytes_written,
        util::format_address(address)
    ));
    Ok(())
}
