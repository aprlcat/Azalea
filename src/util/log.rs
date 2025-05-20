use log::{Level, LevelFilter, Metadata, Record};

struct Logger;

static LOGGER: Logger = Logger;

pub fn init() {
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(LevelFilter::Info))
        .expect("failed to initialize logger");
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let prefix = match record.level() {
                Level::Error => "[x]",
                Level::Warn => "[-]",
                Level::Info => "[+]",
                Level::Debug => "[~]",
                Level::Trace => "[*]",
            };
            println!("{} {}", prefix, record.args());
        }
    }

    fn flush(&self) {}
}

pub fn error(msg: &str) {
    println!("[x] {}", msg);
}

pub fn warn(msg: &str) {
    println!("[-] {}", msg);
}

pub fn info(msg: &str) {
    println!("[+] {}", msg);
}

pub fn debug(msg: &str) {
    println!("[~] {}", msg);
}

pub fn trace(msg: &str) {
    println!("[*] {}", msg);
}
