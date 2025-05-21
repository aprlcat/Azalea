## azalea - manipulate memory from your cli with ease

azalea is a command-line tool for windows to mess with process memory. you can read, write, scan, and get info about running processes.

### features

  * **list processes**: see what's running.
  * **memory info**: check out a process's memory regions, protections, and usage.
  * **read memory**: dump hex/ascii of a specific memory address.
  * **write memory**: change bytes at a specific address (be careful\!).
  * **scan memory**:
      * find specific byte patterns (e.g., `0xAABB??DD`).
      * find specific ascii or utf-16le strings.
  * **pointer scan**: find memory locations that point to a target address (or near it), up to multiple levels of indirection.
  * **disassemble**: view x86-64 disassembly of code in memory.
  * **dump process**:
      * dump all loaded modules of a process to disk.
      * dump a specific memory region to a file.
  * **read dump**: view and do basic analysis on dumped memory files.
  * **thread management**:
      * list threads of a process.
      * suspend and resume threads.
  * **dll injection**: load a dll into a target process.
  * **memory protection**: change memory protection flags (e.g., make a region read-only).

-----

### commands

all commands start with `azalea.exe <command_name> [options...]`

  * **`ps`**: lists all running processes.

    ```bash
    azalea ps
    ```

  * **`memory`**: shows detailed memory info for a process.

    ```bash
    azalea memory -p <pid>
    ```

  * **`read`**: reads memory from a process.

    ```bash
    azalea read -p <pid> --address <hex_address> [--size <bytes_to_read>]
    ```

    (e.g., `azalea read -p 1234 --address 0x7ff6b0000000 --size 64`)

  * **`write`**: writes bytes to a process's memory.

    ```bash
    azalea write -p <pid> --address <hex_address> --bytes <byte_string>
    ```

    (byte\_string can be "0xdeadbeef", "Hello", etc.)
    (e.g., `azalea write -p 1234 --address 0x12345678 --bytes "0x41424344"`)

  * **`scan`**: scans memory for a byte pattern.

    ```bash
    azalea scan -p <pid> --pattern <pattern_string>
    ```

    (pattern\_string can be "0xABCD??EF", "SomeText", "AA BB CC")
    (e.g., `azalea scan -p 1234 --pattern "0x8BFF55??8B"`)

  * **`scan-string`**: scans for a specific string.

    ```bash
    azalea scan-string -p <pid> --encoding <ascii|utf16le> "<string_to_find>"
    ```

    (e.g., `azalea scan-string -p 1234 --encoding utf16le "MyData"`)

  * **`pointer-scan`**: scans for pointers to a target address.

    ```bash
    azalea pointer-scan -p <pid> --target-address <hex_address> [--max-levels <N>] [--max-offset <M>]
    ```

    (e.g., `azalea pointer-scan -p 1234 --target-address 0x12345678 --max-levels 2`)

  * **`disassemble`**: disassembles instructions at an address.

    ```bash
    azalea disassemble -p <pid> --address <hex_address> [--count <num_instructions>]
    ```

    (e.g., `azalea disassemble -p 1234 --address 0x7ff6b0001000 --count 20`)

  * **`dump`**: dumps all modules of a process.

    ```bash
    azalea dump -p <pid> --output <output_directory_path>
    ```

    (e.g., `azalea dump -p 1234 --output C:\dumps\proc1234`)

  * **`dump-region`**: dumps a specific memory region.

    ```bash
    azalea dump-region -p <pid> --address <hex_address> --size <bytes_to_dump> --output <output_file_path>
    ```

    (e.g., `azalea dump-region -p 1234 --address 0x12340000 --size 4096 --output C:\dumps\region.bin`)

  * **`read-dump`**: reads and analyzes a memory dump file.

    ```bash
    azalea read-dump --input <file_path> [--offset <bytes>] [--size <bytes>] [--analyze]
    ```

    (e.g., `azalea read-dump --input C:\dumps\region.bin --size 256 --analyze`)

  * **`list-threads`**: lists threads for a process.

    ```bash
    azalea list-threads -p <pid>
    ```

  * **`suspend-thread`**: suspends a specific thread.

    ```bash
    azalea suspend-thread -p <pid> --tid <thread_id>
    ```

  * **`resume-thread`**: resumes a suspended thread.

    ```bash
    azalea resume-thread -p <pid> --tid <thread_id>
    ```

  * **`inject-dll`**: injects a dll into a process.

    ```bash
    azalea inject-dll -p <pid> --path <path_to_dll>
    ```

    (e.g., `azalea inject-dll -p 1234 --path C:\mydlls\test.dll`)

  * **`set-protection`**: changes memory protection for a region.

    ```bash
    azalea set-protection -p <pid> --address <hex_address> --size <bytes> --protection <flags>
    ```

    (flags: `R`, `RW`, `RX`, `RWX`, `NOACCESS`, or hex value like `0x40`)
    (e.g., `azalea set-protection -p 1234 --address 0x12340000 --size 4096 --protection R`)

-----

### how to build

1.  make sure you have rust installed.
2.  clone the repo.
3.  `cargo build --release`
4.  find the exe in `target/release/azalea.exe`.

-----

### notes

  * run as admin if you're targeting protected processes or need higher privileges for certain operations.
  * messing with memory can crash processes. save your work\!

### contributors

if you plan to contribute:
 * you will need to install the nightly toolchain, primarily for cargo +nightly fmt
 * make sure your format before you make a pr please
