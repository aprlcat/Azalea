use winapi::{
    shared::minwindef::DWORD,
    um::winnt::{
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        PAGE_GUARD, PAGE_NOACCESS, PAGE_NOCACHE, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOMBINE,
        PAGE_WRITECOPY,
    },
};

pub fn parse_address(addr_str: &str) -> anyhow::Result<usize> {
    let trimmed_addr = addr_str.trim();
    if trimmed_addr.starts_with("0x") || trimmed_addr.starts_with("0X") {
        let without_prefix = &trimmed_addr[2..];
        usize::from_str_radix(without_prefix, 16)
            .map_err(|e| anyhow::anyhow!("failed to parse address '{}': {}", addr_str, e))
    } else {
        trimmed_addr
            .parse::<usize>()
            .map_err(|e| anyhow::anyhow!("failed to parse address '{}': {}", addr_str, e))
    }
}

pub fn parse_bytes(bytes_str: &str) -> anyhow::Result<Vec<Option<u8>>> {
    let trimmed_bytes_str = bytes_str.trim();

    if trimmed_bytes_str.starts_with("0x") || trimmed_bytes_str.starts_with("0X") {
        let hex_data = &trimmed_bytes_str[2..];
        let cleaned_hex_data = hex_data.replace(" ", "").replace("..", "??");
        parse_hex_string_with_wildcards(&cleaned_hex_data)
    } else {
        let data_for_analysis = trimmed_bytes_str.replace(" ", "");
        let is_likely_string_literal = data_for_analysis
            .chars()
            .any(|c| !c.is_ascii_hexdigit() && c != '?');

        if is_likely_string_literal {
            Ok(trimmed_bytes_str
                .as_bytes()
                .iter()
                .map(|&b| Some(b))
                .collect())
        } else {
            let cleaned_data = data_for_analysis.replace("..", "??");
            parse_hex_string_with_wildcards(&cleaned_data)
        }
    }
}

fn parse_hex_string_with_wildcards(hex_str: &str) -> anyhow::Result<Vec<Option<u8>>> {
    let mut bytes = Vec::new();
    let mut i = 0;
    let chars: Vec<char> = hex_str.chars().collect();

    while i < chars.len() {
        if chars[i] == '?' && i + 1 < chars.len() && chars[i + 1] == '?' {
            bytes.push(None);
            i += 2;
        } else {
            if i + 1 >= chars.len() {
                anyhow::bail!("incomplete hex byte pair at end of string: '{}'", hex_str);
            }
            let byte_str: String = chars[i..i + 2].iter().collect();
            let byte = u8::from_str_radix(&byte_str, 16).map_err(|e| {
                anyhow::anyhow!(
                    "failed to parse hex byte '{}' in '{}': {}",
                    byte_str,
                    hex_str,
                    e
                )
            })?;
            bytes.push(Some(byte));
            i += 2;
        }
    }
    Ok(bytes)
}

pub fn parse_protection_flags(flags_str: &str) -> anyhow::Result<DWORD> {
    let mut flags: DWORD = 0;
    let upper_flags_str = flags_str.to_uppercase();
    let parts: Vec<&str> = upper_flags_str
        .split('|')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if parts.is_empty() && !flags_str.trim().is_empty() {
        anyhow::bail!("no valid protection flags provided in: '{}'", flags_str);
    }
    if parts.is_empty() && flags_str.trim().is_empty() {
        return Ok(0);
    }

    for part in parts {
        match part {
            "NOACCESS" => flags |= PAGE_NOACCESS,
            "R" => flags |= PAGE_READONLY,
            "RW" => flags |= PAGE_READWRITE,
            "RX" => flags |= PAGE_EXECUTE_READ,
            "RWX" => flags |= PAGE_EXECUTE_READWRITE,
            "X" => flags |= PAGE_EXECUTE,
            "WC" => flags |= PAGE_WRITECOPY,
            "XWC" => flags |= PAGE_EXECUTE_WRITECOPY,
            "GUARD" => flags |= PAGE_GUARD,
            "NOCACHE" => flags |= PAGE_NOCACHE,
            "WRITECOMBINE" => flags |= PAGE_WRITECOMBINE,
            _ => {
                if part.starts_with("0X") {
                    match DWORD::from_str_radix(&part[2..], 16) {
                        Ok(val) => flags |= val,
                        Err(_) => anyhow::bail!("invalid protection flag or hex value: {}", part),
                    }
                } else if let Ok(val) = DWORD::from_str_radix(part, 16) {
                    flags |= val;
                } else {
                    anyhow::bail!("unknown protection flag: {}", part)
                }
            }
        }
    }
    Ok(flags)
}
