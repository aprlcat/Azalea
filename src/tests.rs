use std::{
    cell::RefCell,
    fs::{self, File},
    io::{BufWriter, Write},
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
    cmd::{impl_, util as cmd_util},
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
        log_test("INFO", "Starting notepad.exe process for testing");
        let process = Command::new("notepad.exe")
            .spawn()
            .expect("Failed to start notepad.exe");

        let pid = process.id();
        log_test("INFO", &format!("Notepad started with PID: {}", pid));

        sleep(Duration::from_millis(1500));

        Self { process, pid }
    }

    pub fn write_pattern(&self, pattern: &[u8], executable: bool) -> anyhow::Result<usize> {
        log_test(
            "INFO",
            &format!(
                "Writing pattern of {} bytes to process {} (executable: {})",
                pattern.len(),
                self.pid,
                executable
            ),
        );

        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, self.pid) };
        if handle.is_null() {
            let error = unsafe { GetLastError() };
            log_test(
                "ERROR",
                &format!("Failed to open process {}: error code {}", self.pid, error),
            );
            anyhow::bail!("Failed to open process {}: error code {}", self.pid, error);
        }

        log_test(
            "DEBUG",
            &format!(
                "Process {} opened successfully for writing pattern",
                self.pid
            ),
        );

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
                &format!(
                    "Failed to allocate memory in process {}: error code {}",
                    self.pid, error
                ),
            );
            anyhow::bail!(
                "Failed to allocate memory in process {}: error code {}",
                self.pid,
                error
            );
        }

        log_test(
            "DEBUG",
            &format!(
                "Memory allocated at address 0x{:X} in process {}",
                address, self.pid
            ),
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
        let write_error = unsafe { GetLastError() };

        if success == FALSE || bytes_written != pattern.len() {
            unsafe { CloseHandle(handle) };
            log_test(
                "ERROR",
                &format!(
                    "Failed to write memory to process {}: error code {}. Bytes written: {}/{}",
                    self.pid,
                    write_error,
                    bytes_written,
                    pattern.len()
                ),
            );
            anyhow::bail!(
                "Failed to write memory to process {}: error code {}. Bytes written: {}/{}",
                self.pid,
                write_error,
                bytes_written,
                pattern.len()
            );
        }

        log_test(
            "DEBUG",
            &format!(
                "Successfully wrote {} bytes to address 0x{:X} in process {}",
                bytes_written, address, self.pid
            ),
        );

        unsafe { CloseHandle(handle) };
        log_test("DEBUG", &format!("Handle closed for process {}", self.pid));

        Ok(address)
    }
}

impl Drop for TestProcess {
    fn drop(&mut self) {
        log_test(
            "INFO",
            &format!("Terminating notepad process with PID: {}", self.pid),
        );
        match self.process.kill() {
            Ok(_) => log_test(
                "INFO",
                &format!("Process {} killed successfully.", self.pid),
            ),
            Err(e) => log_test(
                "ERROR",
                &format!("Failed to kill process {}: {}", self.pid, e),
            ),
        }
    }
}

fn read_memory_for_test(pid: u32, address: usize, size: usize) -> anyhow::Result<Vec<u8>> {
    log_test(
        "DEBUG",
        &format!(
            "TEST_READ: Reading {} bytes from process {} at address 0x{:X}",
            size, pid, address
        ),
    );
    if size == 0 {
        return Ok(Vec::new());
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
    let error_code = unsafe { GetLastError() };
    unsafe { CloseHandle(handle) };

    if success == FALSE {
        log_test(
            "ERROR",
            &format!(
                "TEST_READ: Failed to read memory: error code {}",
                error_code
            ),
        );
        anyhow::bail!(
            "TEST_READ: Failed to read memory: error code {}",
            error_code
        );
    }

    buffer.truncate(bytes_read);
    log_test(
        "DEBUG",
        &format!("TEST_READ: Successfully read {} bytes", bytes_read),
    );
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use winapi::um::winnt::PAGE_GUARD;

    use super::*;

    fn setup() {
        setup_test_logger();
    }

    #[test]
    fn process_listing() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting test: process_listing");
        let _test_process = TestProcess::new_notepad();
        impl_::process::processes::list_processes()?;
        log_test("INFO", "Test finished: process_listing");
        Ok(())
    }

    #[test]
    fn read_write_memory() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting test: read_write_memory");
        let test_process = TestProcess::new_notepad();
        let test_pattern = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78];
        let address = test_process.write_pattern(&test_pattern, false)?;

        impl_::memory::rw::read_memory(test_process.pid, address, test_pattern.len())?;

        let read_data = read_memory_for_test(test_process.pid, address, test_pattern.len())?;
        assert_eq!(
            read_data, test_pattern,
            "Memory read/write verification failed (initial write)"
        );

        let new_pattern = vec![0xAA, 0xBB, 0xCC, 0xDD];
        impl_::memory::rw::write_memory(test_process.pid, address, &new_pattern)?;
        let read_new_data = read_memory_for_test(test_process.pid, address, new_pattern.len())?;
        assert_eq!(
            read_new_data, new_pattern,
            "Memory write failed (second write)"
        );
        log_test("INFO", "Test finished: read_write_memory");
        Ok(())
    }

    #[test]
    fn pattern_scanning() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting test: pattern_scanning");
        let test_process = TestProcess::new_notepad();
        let test_pattern_bytes = vec![0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x12, 0x34];
        let address = test_process.write_pattern(&test_pattern_bytes, false)?;
        log_test(
            "INFO",
            &format!("Pattern for scan written to 0x{:X}", address),
        );

        let scan_pattern_str = "A1 B2 ?? D4 E5 F6 ?? 34";
        let parsed_scan_pattern = cmd_util::memory::parse_bytes(scan_pattern_str)?;

        impl_::analysis::scan::scan_memory(test_process.pid, &parsed_scan_pattern)?;

        log_test("INFO", "Test finished: pattern_scanning");
        Ok(())
    }

    #[test]
    fn disassemble_code() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting test: disassemble_code");
        let test_process = TestProcess::new_notepad();

        let code = vec![
            0x48, 0xB8, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0xC3,
        ];
        let address = test_process.write_pattern(&code, true)?;

        impl_::analysis::disassemble::disassemble_memory(test_process.pid, address, 3)?;
        log_test("INFO", "Test finished: disassemble_code");
        Ok(())
    }

    #[test]
    fn memory_information() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting test: memory_information");
        let test_process = TestProcess::new_notepad();
        impl_::memory::info::display_memory_info(test_process.pid)?;
        log_test("INFO", "Test finished: memory_information");
        Ok(())
    }

    #[test]
    fn dump_and_read_region_test() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting test: dump_and_read_region_test");
        let test_process = TestProcess::new_notepad();
        let test_data = (0..=255u8).collect::<Vec<u8>>();
        let address = test_process.write_pattern(&test_data, false)?;

        let temp_dir = std::env::temp_dir().join("azalea_tests");
        fs::create_dir_all(&temp_dir)?;
        let dump_file_path = temp_dir.join("test_region_dump.bin");
        let dump_path_str = dump_file_path.to_string_lossy().into_owned();

        impl_::memory::dump::dump_memory_region(
            test_process.pid,
            address,
            test_data.len(),
            &dump_path_str,
        )?;
        assert!(dump_file_path.exists(), "Dump file was not created");

        impl_::memory::dump::read_dump(&dump_path_str, 0, test_data.len(), true)?;

        let _ = fs::remove_file(&dump_file_path);
        let _ = fs::remove_file(format!("{}.meta.json", dump_path_str));
        let _ = fs::remove_dir(&temp_dir);
        log_test("INFO", "Test finished: dump_and_read_region_test");
        Ok(())
    }

    #[test]
    fn string_scanning_ascii() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting test: string_scanning_ascii");
        let test_process = TestProcess::new_notepad();
        let test_string_ascii = "ThisIsAnAsciiTestStringForAzalea";
        let address_ascii = test_process.write_pattern(test_string_ascii.as_bytes(), false)?;
        log_test(
            "INFO",
            &format!("ASCII string for scan written to 0x{:X}", address_ascii),
        );

        impl_::analysis::string::scan_for_strings(
            test_process.pid,
            test_string_ascii,
            impl_::analysis::string::StringEncoding::Ascii,
        )?;
        log_test("INFO", "Test finished: string_scanning_ascii");
        Ok(())
    }

    #[test]
    fn thread_operations() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting test: thread_operations");
        let test_process = TestProcess::new_notepad();

        impl_::process::thread::list_threads(test_process.pid)?;

        log_test("INFO", "Test finished: thread_operations (list only)");
        Ok(())
    }

    #[test]
    fn parse_cmd_utilities() -> anyhow::Result<()> {
        setup();
        log_test("INFO", "Starting test: parse_cmd_utilities");

        let addr_hex = cmd_util::memory::parse_address("0x1A2B3C")?;
        assert_eq!(addr_hex, 0x1A2B3C);
        let addr_dec = cmd_util::memory::parse_address("123456")?;
        assert_eq!(addr_dec, 123456);

        let bytes_hex = cmd_util::memory::parse_bytes("0xDEADBEEF")?;
        assert_eq!(
            bytes_hex,
            vec![Some(0xDE), Some(0xAD), Some(0xBE), Some(0xEF)]
        );
        let bytes_wild = cmd_util::memory::parse_bytes("AA??CCDD")?;
        assert_eq!(bytes_wild, vec![Some(0xAA), None, Some(0xCC), Some(0xDD)]);
        let bytes_str = cmd_util::memory::parse_bytes("test")?;
        assert_eq!(
            bytes_str,
            vec![Some(b't'), Some(b'e'), Some(b's'), Some(b't')]
        );

        let prot_flags = cmd_util::memory::parse_protection_flags("RWX|GUARD")?;
        assert_eq!(prot_flags, PAGE_EXECUTE_READWRITE | PAGE_GUARD);

        log_test("INFO", "Test finished: parse_cmd_utilities");
        Ok(())
    }
}
