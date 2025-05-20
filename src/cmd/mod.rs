pub mod impl_;
pub mod utils;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "azalea")]
#[command(about = "manipulate memory from your cli with ease", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "read memory from a process")]
    Read {
        #[arg(short, long)]
        pid: u32,
        #[arg(short, long)]
        address: String,
        #[arg(short, long, default_value = "16")]
        size: usize,
    },
    #[command(about = "write memory to a process")]
    Write {
        #[arg(short, long)]
        pid: u32,
        #[arg(short, long)]
        address: String,
        #[arg(short, long)]
        bytes: String,
    },
    #[command(about = "scan memory for a pattern (hex, string, or hex with '??' wildcards)")]
    Scan {
        #[arg(short, long)]
        pid: u32,
        #[arg(short = 't', long = "pattern")]
        pattern: String,
    },
    #[command(about = "list all running processes")]
    Ps,
    #[command(about = "disassemble memory region")]
    Disassemble {
        #[arg(short, long)]
        pid: u32,
        #[arg(short, long)]
        address: String,
        #[arg(short, long, default_value = "32")]
        count: usize,
    },
    #[command(about = "display memory information for a process")]
    Memory {
        #[arg(short, long)]
        pid: u32,
    },
    #[command(about = "dump process modules to disk")]
    Dump {
        #[arg(short, long)]
        pid: u32,
        #[arg(short, long)]
        output: String,
    },
    #[command(about = "dump specific memory region to disk")]
    DumpRegion {
        #[arg(short, long)]
        pid: u32,
        #[arg(short, long)]
        address: String,
        #[arg(short, long)]
        size: usize,
        #[arg(short, long)]
        output: String,
    },
    #[command(about = "read memory dump file")]
    ReadDump {
        #[arg(short, long)]
        input: String,
        #[arg(short, long, default_value = "0")]
        offset: usize,
        #[arg(short, long, default_value = "256")]
        size: usize,
        #[arg(short, long, default_value = "false")]
        analyze: bool,
    },
    #[command(about = "inject a DLL into a process")]
    InjectDll {
        #[arg(short, long)]
        pid: u32,
        #[arg(long)]
        path: String,
    },
    #[command(about = "scan for pointers to an address")]
    PointerScan {
        #[arg(short, long)]
        pid: u32,
        #[arg(long)]
        target_address: String,
        #[arg(long, default_value = "1")]
        max_levels: usize,
        #[arg(long, default_value = "0")]
        max_offset: usize,
    },
    #[command(about = "set memory protection for a region")]
    SetProtection {
        #[arg(short, long)]
        pid: u32,
        #[arg(short, long)]
        address: String,
        #[arg(short, long)]
        size: usize,
        #[arg(long)]
        protection: String,
    },
    #[command(about = "scan for a specific string in a process")]
    ScanString {
        #[arg(short, long)]
        pid: u32,
        #[arg(long, value_parser = parse_string_encoding, default_value = "ascii")]
        encoding: impl_::string::StringEncoding,
        #[arg()]
        search_string: String,
    },
    #[command(about = "list threads of a process")]
    ListThreads {
        #[arg(short, long)]
        pid: u32,
    },
    #[command(about = "suspend a thread in a process")]
    SuspendThread {
        #[arg(short, long)]
        pid: u32,
        #[arg(long)]
        tid: u32,
    },
    #[command(about = "resume a thread in a process")]
    ResumeThread {
        #[arg(short, long)]
        pid: u32,
        #[arg(long)]
        tid: u32,
    },
}

fn parse_string_encoding(s: &str) -> Result<impl_::string::StringEncoding, String> {
    match s.to_lowercase().as_str() {
        "ascii" => Ok(impl_::string::StringEncoding::Ascii),
        "utf16" | "utf16le" => Ok(impl_::string::StringEncoding::Utf16LE),
        _ => Err(format!(
            "invalid string encoding: '{}'. valid options are 'ascii', 'utf16le'",
            s
        )),
    }
}

pub struct CommandDispatcher;

impl CommandDispatcher {
    pub fn new() -> Self {
        Self
    }

    pub fn dispatch(&self) -> anyhow::Result<()> {
        let cli = Cli::parse();

        match cli.command {
            Commands::Read { pid, address, size } => {
                let addr = utils::parse_address(&address)?;
                impl_::rw::read_memory(pid, addr, size)
            }
            Commands::Write {
                pid,
                address,
                bytes,
            } => {
                let addr = utils::parse_address(&address)?;
                let bytes_vec_opt = utils::parse_bytes(&bytes)?;
                let bytes_vec: Vec<u8> = bytes_vec_opt
                    .into_iter()
                    .map(|opt_b| {
                        opt_b.ok_or_else(|| {
                            anyhow::anyhow!("pattern for write cannot contain wildcards ('??')")
                        })
                    })
                    .collect::<Result<Vec<u8>, _>>()?;
                impl_::rw::write_memory(pid, addr, &bytes_vec)
            }
            Commands::Scan { pid, pattern } => {
                let bytes_pattern = utils::parse_bytes(&pattern)?;
                impl_::scan::scan_memory(pid, &bytes_pattern)
            }
            Commands::Ps => impl_::memory::list_processes(),
            Commands::Disassemble {
                pid,
                address,
                count,
            } => {
                let addr = utils::parse_address(&address)?;
                impl_::disassemble::disassemble_memory(pid, addr, count)
            }
            Commands::Memory { pid } => impl_::memory::display_memory_info(pid),
            Commands::Dump { pid, output } => impl_::dump::dump_process_memory(pid, &output),
            Commands::DumpRegion {
                pid,
                address,
                size,
                output,
            } => {
                let addr = utils::parse_address(&address)?;
                impl_::dump::dump_memory_region(pid, addr, size, &output)
            }
            Commands::ReadDump {
                input,
                offset,
                size,
                analyze,
            } => impl_::dump::read_dump(&input, offset, size, analyze),
            Commands::InjectDll { pid, path } => impl_::inject::inject_dll(pid, &path),
            Commands::PointerScan {
                pid,
                target_address,
                max_levels,
                max_offset,
            } => {
                let addr = utils::parse_address(&target_address)?;
                impl_::pointer::scan_for_pointers(pid, addr, max_levels, max_offset)
            }
            Commands::SetProtection {
                pid,
                address,
                size,
                protection,
            } => {
                let addr = utils::parse_address(&address)?;
                impl_::prot::set_protection(pid, addr, size, &protection)
            }
            Commands::ScanString {
                pid,
                encoding,
                search_string,
            } => impl_::string::scan_for_strings(pid, &search_string, encoding),
            Commands::ListThreads { pid } => impl_::thread::list_threads(pid),
            Commands::SuspendThread { pid, tid } => {
                impl_::thread::suspend_thread_by_pid_tid(pid, tid)
            }
            Commands::ResumeThread { pid, tid } => {
                impl_::thread::resume_thread_by_pid_tid(pid, tid)
            }
        }
    }
}
