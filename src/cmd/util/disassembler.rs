use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};

use crate::util::log;

pub fn disassemble_bytes_to_strings(
    bytes: &[u8],
    base_ip: u64,
    max_instructions: Option<usize>,
) -> anyhow::Result<Vec<String>> {
    if bytes.is_empty() {
        log::warn("disassemble_bytes_to_strings called with empty byte slice.");
        return Ok(Vec::new());
    }

    let mut decoder = Decoder::with_ip(64, bytes, base_ip, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_digit_separator("");
    formatter.options_mut().set_hex_prefix("0x");
    formatter.options_mut().set_hex_suffix("");
    formatter.options_mut().set_branch_leading_zeros(false);

    let mut output = String::new();
    let mut instruction = Instruction::default();
    let mut disassembled_instructions = Vec::new();
    let mut count = 0;

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        output.clear();
        formatter.format(&instruction, &mut output);

        let instruction_string = format!("{:016x}  {}", instruction.ip(), output);
        disassembled_instructions.push(instruction_string);
        count += 1;

        if let Some(max) = max_instructions {
            if count >= max {
                break;
            }
        }
    }

    if disassembled_instructions.is_empty() && !bytes.is_empty() {
        log::warn("Could not disassemble any instructions from the provided bytes.");
    }

    Ok(disassembled_instructions)
}
