use std::{
    cell::RefCell,
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
    process::{Child, Command},
    sync::Once,
    thread::sleep,
    time::Duration,
};

use winapi::{
    shared::minwindef::FALSE,
    um::{
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        memoryapi::{ReadProcessMemory, VirtualAllocEx, WriteProcessMemory},
        processthreadsapi::OpenProcess,
        winnt::{
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PROCESS_ALL_ACCESS,
        },
    },
};

use crate::{
    cmd::{impl_, utils},
    util,
};

static INIT: Once = Once::new();
thread_local! {
    static LOG_FILE: RefCell<Option<BufWriter<File>>> = RefCell::new(None);
}

fn setup_test_logger() {
    INIT.call_once(|| {
        let log_path = "testing.log";
        let file = File::create(log_path).expect("Failed to create log file");
        let writer = BufWriter::new(file);

        LOG_FILE.with(|cell| {
            *cell.borrow_mut() = Some(writer);
        });

        println!("Test logging initialized to {}", log_path);
    });
}

pub fn log_test(level: &str, message: &str) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
    let log_message = format!("[{}] [{}] {}\n", timestamp, level, message);

    println!("{}", log_message);

    LOG_FILE.with(|cell| {
        if let Some(writer) = &mut *cell.borrow_mut() {
            let _ = writer.write_all(log_message.as_bytes());
            let _ = writer.flush();
        }
    });
}

struct TestProcess {
    process: Child,
    pub pid: u32,
}

impl TestProcess {
    pub fn new_notepad() -> Self {
        log_test("INFO", "Starting notepad.exe process");
        let process = Command::new("notepad.exe")
            .spawn()
            .expect("Failed to start notepad.exe");

        let pid = process.id();
        log_test("INFO", &format!("Notepad started with PID: {}", pid));

        sleep(Duration::from_millis(1000));

        Self { process, pid }
    }

    pub fn write_pattern(&self, pattern: &[u8], executable: bool) -> anyhow::Result<usize> {
        log_test(
            "INFO",
            &format!(
                "Writing pattern of {} bytes to process {}",
                pattern.len(),
                self.pid
            ),
        );

        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, self.pid) };
        if handle.is_null() {
            let error = unsafe { GetLastError() };
            log_test(
                "ERROR",
                &format!("Failed to open process: error code {}", error),
            );
            anyhow::bail!("Failed to open process: error code {}", error);
        }

        log_test("DEBUG", "Process opened successfully");

        let protection = if executable {
            PAGE_EXECUTE_READWRITE
        } else {
            PAGE_READWRITE
        };
        let address = unsafe {
            VirtualAllocEx(
                handle,
                std::ptr::null_mut(),
                pattern.len(),
                MEM_COMMIT | MEM_RESERVE,
                protection,
            )
        } as usize;

        if address == 0 {
            let error = unsafe { GetLastError() };
            unsafe { CloseHandle(handle) };
            log_test(
                "ERROR",
                &format!("Failed to allocate memory: error code {}", error),
            );
            anyhow::bail!("Failed to allocate memory: error code {}", error);
        }

        log_test(
            "DEBUG",
            &format!("Memory allocated at address 0x{:X}", address),
        );

        let mut bytes_written: usize = 0;
        let success = unsafe {
            WriteProcessMemory(
                handle,
                address as *mut _,
                pattern.as_ptr() as *const _,
                pattern.len(),
                &mut bytes_written,
            )
        };

        if success == FALSE {
            let error = unsafe { GetLastError() };
            unsafe { CloseHandle(handle) };
            log_test(
                "ERROR",
                &format!("Failed to write memory: error code {}", error),
            );
            anyhow::bail!("Failed to write memory: error code {}", error);
        }

        log_test(
            "DEBUG",
            &format!(
                "Successfully wrote {} bytes to address 0x{:X}",
                bytes_written, address
            ),
        );

        unsafe { CloseHandle(handle) };
        log_test("DEBUG", "Handle closed");

        Ok(address)
    }
}

impl Drop for TestProcess {
    fn drop(&mut self) {
        log_test(
            "INFO",
            &format!("Terminating notepad process with PID: {}", self.pid),
        );
        let _ = self.process.kill();
    }
}

fn read_process_memory(pid: u32, address: usize, size: usize) -> anyhow::Result<Vec<u8>> {
    log_test(
        "DEBUG",
        &format!(
            "Reading {} bytes from process {} at address 0x{:X}",
            size, pid, address
        ),
    );

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

    unsafe { CloseHandle(handle) };

    if success == FALSE {
        let error = unsafe { GetLastError() };
        log_test(
            "ERROR",
            &format!("Failed to read memory: error code {}", error),
        );
        anyhow::bail!("Failed to read memory: error code {}", error);
    }

    log_test("DEBUG", &format!("Successfully read {} bytes", bytes_read));
    buffer.truncate(bytes_read);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() {
        setup_test_logger();
    }

    #[test]
    fn process_listing() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting process_listing");

        let _test_process = TestProcess::new_notepad();

        log_test("INFO", "Calling list_processes");
        impl_::memory::list_processes()?;

        log_test("INFO", "process_listing completed successfully");
        Ok(())
    }

    #[test]
    fn read_write_memory() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting read_write_memory");

        let test_process = TestProcess::new_notepad();

        let test_pattern = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78];
        log_test("DEBUG", &format!("Test pattern: {:02X?}", test_pattern));

        let address = test_process.write_pattern(&test_pattern, false)?;

        log_test(
            "INFO",
            &format!("Reading memory at address 0x{:X}", address),
        );
        impl_::rw::read_memory(test_process.pid, address, test_pattern.len())?;

        let read_data = read_process_memory(test_process.pid, address, test_pattern.len())?;
        log_test("DEBUG", &format!("Read data: {:02X?}", read_data));
        assert_eq!(
            read_data, test_pattern,
            "Memory read/write verification failed"
        );

        let new_pattern = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        log_test("DEBUG", &format!("New pattern: {:02X?}", new_pattern));

        log_test(
            "INFO",
            &format!("Writing new pattern to address 0x{:X}", address),
        );
        impl_::rw::write_memory(test_process.pid, address, &new_pattern)?;

        let read_new_data = read_process_memory(test_process.pid, address, new_pattern.len())?;
        log_test("DEBUG", &format!("Read new data: {:02X?}", read_new_data));
        assert_eq!(read_new_data, new_pattern, "Memory write failed");

        log_test("INFO", "read_write_memory completed successfully");
        Ok(())
    }

    #[test]
    fn pattern_scanning() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting pattern_scanning");

        let test_process = TestProcess::new_notepad();

        let test_pattern = vec![0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x12, 0x34];
        log_test("DEBUG", &format!("Test pattern: {:02X?}", test_pattern));

        let address = test_process.write_pattern(&test_pattern, false)?;
        log_test(
            "INFO",
            &format!("Pattern written to address 0x{:X}", address),
        );

        let scan_pattern_str = "A1B2??D4E5F6??34";
        log_test(
            "DEBUG",
            &format!("Scan pattern string: {}", scan_pattern_str),
        );
        let parsed_pattern = utils::parse_bytes(scan_pattern_str)?;

        log_test("INFO", "Starting memory scan");
        impl_::scan::scan_memory(test_process.pid, &parsed_pattern)?;

        log_test("INFO", "pattern_scanning completed successfully");
        Ok(())
    }

    #[test]
    fn disassemble() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting disassemble");

        let test_process = TestProcess::new_notepad();

        let code = vec![
            0xC3, 0x90, 0x90, 0x90, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0x4D,
            0x10, 0xC3,
        ];
        log_test("DEBUG", &format!("Test code sequence: {:02X?}", code));

        log_test("INFO", "Writing code to executable memory");
        let address = test_process.write_pattern(&code, true)?;
        log_test("INFO", &format!("Code written to address 0x{:X}", address));

        log_test("INFO", "Starting disassembly");
        impl_::disassemble::disassemble_memory(test_process.pid, address, 5)?;

        log_test("INFO", "disassemble completed successfully");
        Ok(())
    }

    #[test]
    fn memory_info() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting memory_info");

        let test_process = TestProcess::new_notepad();

        log_test(
            "INFO",
            &format!("Getting memory info for PID {}", test_process.pid),
        );
        impl_::memory::display_memory_info(test_process.pid)?;

        log_test("INFO", "memory_info completed successfully");
        Ok(())
    }

    #[test]
    fn dump_and_read_region() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting dump_and_read_region");

        let test_process = TestProcess::new_notepad();

        let test_data = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA];
        log_test("DEBUG", &format!("Test data: {:02X?}", test_data));

        let address = test_process.write_pattern(&test_data, false)?;
        log_test("INFO", &format!("Data written to address 0x{:X}", address));

        let temp_dir = std::env::temp_dir();
        let dump_path = temp_dir
            .join("azalea_test_dump.bin")
            .to_string_lossy()
            .into_owned();
        log_test("DEBUG", &format!("Dump file path: {}", dump_path));

        log_test("INFO", "Dumping memory region");
        impl_::dump::dump_memory_region(test_process.pid, address, test_data.len(), &dump_path)?;

        log_test(
            "DEBUG",
            &format!("Checking if dump file exists: {}", dump_path),
        );
        assert!(Path::new(&dump_path).exists(), "Dump file was not created");

        log_test("INFO", "Reading dump file");
        impl_::dump::read_dump(&dump_path, 0, test_data.len(), true)?;

        log_test("DEBUG", "Cleaning up dump files");
        let _ = fs::remove_file(&dump_path);
        let _ = fs::remove_file(format!("{}.meta.json", dump_path));

        log_test("INFO", "dump_and_read_region completed successfully");
        Ok(())
    }

    #[test]
    fn string_scanning() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting string_scanning");

        let test_process = TestProcess::new_notepad();

        let test_string = "meowowowo";
        log_test("DEBUG", &format!("Test string: {}", test_string));

        let address = test_process.write_pattern(test_string.as_bytes(), false)?;
        log_test(
            "INFO",
            &format!("String written to address 0x{:X}", address),
        );

        log_test("INFO", "Starting string scan");
        impl_::string::scan_for_strings(
            test_process.pid,
            test_string,
            impl_::string::StringEncoding::Ascii,
        )?;

        log_test("INFO", "string_scanning completed successfully");
        Ok(())
    }

    #[test]
    fn thread_listing() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting thread_listing");

        let test_process = TestProcess::new_notepad();

        log_test(
            "INFO",
            &format!("Listing threads for PID {}", test_process.pid),
        );
        impl_::thread::list_threads(test_process.pid)?;

        log_test("INFO", "thread_listing completed successfully");
        Ok(())
    }

    #[test]
    fn parse_utils() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting parse_utils");

        log_test("DEBUG", "Testing address parsing");
        let addr = utils::parse_address("0x12345678")?;
        assert_eq!(addr, 0x12345678, "Failed to parse hex address");

        let addr2 = utils::parse_address("987654321")?;
        assert_eq!(addr2, 987654321, "Failed to parse decimal address");

        log_test("DEBUG", "Testing byte pattern parsing");
        let bytes = utils::parse_bytes("DEADBEEF")?;
        assert_eq!(
            bytes,
            vec![Some(0xDE), Some(0xAD), Some(0xBE), Some(0xEF)],
            "Failed to parse hex bytes"
        );

        let bytes_with_wildcards = utils::parse_bytes("AA??CC")?;
        assert_eq!(
            bytes_with_wildcards,
            vec![Some(0xAA), None, Some(0xCC)],
            "Failed to parse pattern with wildcards"
        );

        log_test("DEBUG", "Testing protection flag parsing");
        let flags = utils::parse_protection_flags("RWX")?;
        assert_eq!(
            flags,
            winapi::um::winnt::PAGE_EXECUTE_READWRITE,
            "Failed to parse protection flags"
        );

        log_test("INFO", "parse_utils completed successfully");
        Ok(())
    }
}
