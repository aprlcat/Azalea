pub mod impl_;
pub mod util;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "azalea")]
#[command(version = "0.1.0")]
#[command(about = "Manipulate memory from your CLI with ease", long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    command: CommandGroups,
}

#[derive(Subcommand)]
pub enum CommandGroups {
    #[command(subcommand, about = "Process interaction and control operations")]
    Process(ProcessCommands),
    #[command(
        subcommand,
        about = "Direct memory access, information, and protection operations"
    )]
    Memory(MemoryCommands),
    #[command(subcommand, about = "Memory scanning operations")]
    Scan(ScanCommands),
    #[command(subcommand, about = "Memory dumping and dump file analysis operations")]
    Dump(DumpCommands),
    #[command(subcommand, about = "Code analysis operations")]
    Analysis(AnalysisCommands),
    #[command(subcommand, about = "Advanced memory patching operations")]
    Patching(PatchingCommands),
}

#[derive(Subcommand)]
pub enum ProcessCommands {
    #[command(name = "ps", about = "List all running processes")]
    ListProcesses,
    #[command(name = "inject-dll", about = "Inject a DLL into a process")]
    InjectDll {
        #[arg(short, long)]
        pid: u32,
        #[arg(long)]
        path: String,
    },
    #[command(subcommand, name = "threads", about = "Thread-specific operations")]
    Thread(ThreadCommands),
}

#[derive(Subcommand)]
pub enum ThreadCommands {
    #[command(name = "list", about = "List threads of a specific process")]
    List {
        #[arg(short, long)]
        pid: u32,
    },
    #[command(name = "suspend", about = "Suspend a specific thread in a process")]
    Suspend {
        #[arg(short, long)]
        pid: u32,
        #[arg(long)]
        tid: u32,
    },
    #[command(name = "resume", about = "Resume a specific thread in a process")]
    Resume {
        #[arg(short, long)]
        pid: u32,
        #[arg(long)]
        tid: u32,
    },
}

#[derive(Subcommand)]
pub enum MemoryCommands {
    #[command(about = "Read memory from a process")]
    Read {
        #[arg(short, long)]
        pid: u32,
        #[arg(short, long)]
        address: String,
        #[arg(short, long, default_value = "16")]
        size: usize,
    },
    #[command(about = "Write memory to a process")]
    Write {
        #[arg(short, long)]
        pid: u32,
        #[arg(short, long)]
        address: String,
        #[arg(short, long)]
        bytes: String,
    },
    #[command(
        name = "info",
        about = "Display detailed memory information for a process"
    )]
    Info {
        #[arg(short, long)]
        pid: u32,
    },
    #[command(
        name = "set-protection",
        about = "Set memory protection for a region in a process"
    )]
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
}

#[derive(Subcommand)]
pub enum ScanCommands {
    #[command(
        name = "pattern",
        about = "Scan memory for a byte pattern (hex, string, or hex with '??' wildcards)"
    )]
    Pattern {
        #[arg(short, long)]
        pid: u32,
        #[arg(short = 't', long = "pattern")]
        pattern: String,
    },
    #[command(
        name = "string",
        about = "Scan for a specific string (ASCII or UTF-16LE) in a process"
    )]
    String {
        #[arg(short, long)]
        pid: u32,
        #[arg(long, value_parser = parse_string_encoding, default_value = "ascii")]
        encoding: impl_::analysis::string::StringEncoding,
        #[arg(help = "The string to search for")]
        search_string: String,
    },
    #[command(name = "pointer", about = "Scan for pointers to a target address")]
    Pointer {
        #[arg(short, long)]
        pid: u32,
        #[arg(long)]
        target_address: String,
        #[arg(long, default_value = "1")]
        max_levels: usize,
        #[arg(long, default_value = "0")]
        max_offset: usize,
    },
}

#[derive(Subcommand)]
pub enum DumpCommands {
    #[command(
        name = "process",
        about = "Dump all accessible modules of a process to disk"
    )]
    Process {
        #[arg(short, long)]
        pid: u32,
        #[arg(short, long, help = "Output directory for module dumps")]
        output: String,
    },
    #[command(
        name = "region",
        about = "Dump a specific memory region of a process to disk"
    )]
    Region {
        #[arg(short, long)]
        pid: u32,
        #[arg(short, long)]
        address: String,
        #[arg(short, long)]
        size: usize,
        #[arg(short, long, help = "Output file path for the region dump")]
        output: String,
    },
    #[command(
        name = "read",
        about = "Read and display contents of a memory dump file with analysis options"
    )]
    Read {
        #[arg(short, long, help = "Path to the dump file")]
        input: String,
        #[arg(short, long, default_value = "0")]
        offset: usize,
        #[arg(short, long, default_value = "256")]
        size: usize,
        #[arg(
            short,
            long,
            default_value = "false",
            help = "Enable basic analysis of the dump segment"
        )]
        analyze: bool,
    },
}

#[derive(Subcommand)]
pub enum AnalysisCommands {
    #[command(about = "Disassemble instructions in a memory region of a process")]
    Disassemble {
        #[arg(short, long)]
        pid: u32,
        #[arg(short, long)]
        address: String,
        #[arg(
            short,
            long,
            default_value = "32",
            help = "Number of instructions to disassemble"
        )]
        count: usize,
    },
}

#[derive(Subcommand)]
pub enum PatchingCommands {
    #[command(about = "Detour a function to another address using a JMP instruction (inline hook)")]
    Detour {
        #[arg(short, long)]
        pid: u32,
        #[arg(long, help = "Address of the function to detour")]
        target_address: String,
        #[arg(long, help = "Address where the target function will JMP to")]
        detour_address: String,
    },
    #[command(about = "Overwrite a region of memory with NOP (0x90) instructions")]
    Nop {
        #[arg(short, long)]
        pid: u32,
        #[arg(long, help = "Address to start NOPing")]
        address: String,
        #[arg(long, default_value = "1", help = "Number of bytes to NOP")]
        size: usize,
    },
}

fn parse_string_encoding(s: &str) -> Result<impl_::analysis::string::StringEncoding, String> {
    match s.to_lowercase().as_str() {
        "ascii" => Ok(impl_::analysis::string::StringEncoding::Ascii),
        "utf16" | "utf16le" => Ok(impl_::analysis::string::StringEncoding::Utf16LE),
        _ => Err(format!(
            "invalid string encoding: '{}'. Valid options are 'ascii', 'utf16le'",
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
            CommandGroups::Process(process_cmd) => match process_cmd {
                ProcessCommands::ListProcesses => impl_::process::processes::list_processes(),
                ProcessCommands::InjectDll { pid, path } => {
                    impl_::process::inject::inject_dll(pid, &path)
                }
                ProcessCommands::Thread(thread_cmd) => match thread_cmd {
                    ThreadCommands::List { pid } => impl_::process::thread::list_threads(pid),
                    ThreadCommands::Suspend { pid, tid } => {
                        impl_::process::thread::suspend_thread_by_pid_tid(pid, tid)
                    }
                    ThreadCommands::Resume { pid, tid } => {
                        impl_::process::thread::resume_thread_by_pid_tid(pid, tid)
                    }
                },
            },
            CommandGroups::Memory(memory_cmd) => match memory_cmd {
                MemoryCommands::Read { pid, address, size } => {
                    let addr = util::memory::parse_address(&address)?;
                    impl_::memory::rw::read_memory(pid, addr, size)
                }
                MemoryCommands::Write {
                    pid,
                    address,
                    bytes,
                } => {
                    let addr = util::memory::parse_address(&address)?;
                    let bytes_vec_opt = util::memory::parse_bytes(&bytes)?;
                    let bytes_vec: Vec<u8> = bytes_vec_opt
                        .into_iter()
                        .map(|opt_b| {
                            opt_b.ok_or_else(|| {
                                anyhow::anyhow!("Pattern for write cannot contain wildcards ('??')")
                            })
                        })
                        .collect::<Result<Vec<u8>, _>>()?;
                    impl_::memory::rw::write_memory(pid, addr, &bytes_vec)
                }
                MemoryCommands::Info { pid } => impl_::memory::info::display_memory_info(pid),
                MemoryCommands::SetProtection {
                    pid,
                    address,
                    size,
                    protection,
                } => {
                    let addr = util::memory::parse_address(&address)?;
                    impl_::memory::prot::set_protection(pid, addr, size, &protection)
                }
            },
            CommandGroups::Scan(scan_cmd) => match scan_cmd {
                ScanCommands::Pattern { pid, pattern } => {
                    let bytes_pattern = util::memory::parse_bytes(&pattern)?;
                    impl_::analysis::scan::scan_memory(pid, &bytes_pattern)
                }
                ScanCommands::String {
                    pid,
                    encoding,
                    search_string,
                } => impl_::analysis::string::scan_for_strings(pid, &search_string, encoding),
                ScanCommands::Pointer {
                    pid,
                    target_address,
                    max_levels,
                    max_offset,
                } => {
                    let addr = util::memory::parse_address(&target_address)?;
                    impl_::analysis::pointer::scan_for_pointers(pid, addr, max_levels, max_offset)
                }
            },
            CommandGroups::Dump(dump_cmd) => match dump_cmd {
                DumpCommands::Process { pid, output } => {
                    impl_::memory::dump::dump_process_memory(pid, &output)
                }
                DumpCommands::Region {
                    pid,
                    address,
                    size,
                    output,
                } => {
                    let addr = util::memory::parse_address(&address)?;
                    impl_::memory::dump::dump_memory_region(pid, addr, size, &output)
                }
                DumpCommands::Read {
                    input,
                    offset,
                    size,
                    analyze,
                } => impl_::memory::dump::read_dump(&input, offset, size, analyze),
            },
            CommandGroups::Analysis(analysis_cmd) => match analysis_cmd {
                AnalysisCommands::Disassemble {
                    pid,
                    address,
                    count,
                } => {
                    let addr = util::memory::parse_address(&address)?;
                    impl_::analysis::disassemble::disassemble_memory(pid, addr, count)
                }
            },
            CommandGroups::Patching(patching_cmd) => match patching_cmd {
                PatchingCommands::Detour {
                    pid,
                    target_address,
                    detour_address,
                } => {
                    let target_addr = util::memory::parse_address(&target_address)?;
                    let detour_addr = util::memory::parse_address(&detour_address)?;
                    impl_::patching::detour::apply_detour(pid, target_addr, detour_addr)
                }
                PatchingCommands::Nop { pid, address, size } => {
                    let addr = util::memory::parse_address(&address)?;
                    impl_::patching::patch::nop_memory_region(pid, addr, size)
                }
            },
        }
    }
}
