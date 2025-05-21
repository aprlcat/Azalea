use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use winapi::um::memoryapi::ReadProcessMemory;

use crate::{util, util::log};

pub fn disassemble_memory(
    pid: u32,
    address: usize,
    instruction_count: usize,
) -> anyhow::Result<()> {
    let handle = util::open_process(pid)?;

    let buffer_size = instruction_count * 15;
    let mut buffer = vec![0u8; buffer_size];
    let mut bytes_read = 0;

    let success = unsafe {
        ReadProcessMemory(
            handle,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            buffer_size,
            &mut bytes_read,
        )
    };

    if success == 0 {
        anyhow::bail!(
            "failed to read memory at address {}: error code {}",
            util::format_address(address),
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
    }

    if bytes_read == 0 {
        log::error("no bytes read from memory");
        unsafe { winapi::um::handleapi::CloseHandle(handle) };
        return Ok(());
    }

    buffer.truncate(bytes_read);

    let mut decoder = Decoder::with_ip(64, &buffer, address as u64, DecoderOptions::NONE);

    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_digit_separator("");
    formatter.options_mut().set_hex_prefix("0x");
    formatter.options_mut().set_hex_suffix("");

    println!("disassembly at {}:", util::format_address(address));

    let mut instructions_decoded = 0;
    let mut output = String::new();
    let mut instruction = iced_x86::Instruction::default();

    while instructions_decoded < instruction_count && decoder.can_decode() {
        decoder.decode_out(&mut instruction);

        output.clear();
        formatter.format(&instruction, &mut output);

        println!("{:016x}  {}", instruction.ip(), output);
        instructions_decoded += 1;
    }

    log::info(&format!(
        "disassembled {} instructions",
        instructions_decoded
    ));
    unsafe { winapi::um::handleapi::CloseHandle(handle) };
    Ok(())
}
