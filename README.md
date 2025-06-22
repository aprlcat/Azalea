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
  * **advanced patching**: detour functions and NOP memory regions.

-----

### commands

all commands start with `azalea.exe <command_group> <subcommand> [options...]`

#### **process** - process interaction and control operations

  * **`process ps`**: lists all running processes.

    ```bash
    azalea process ps
    ```

  * **`process inject-dll`**: injects a dll into a process.

    ```bash
    azalea process inject-dll -p <pid> --path <path_to_dll>
    ```

    (e.g., `azalea process inject-dll -p 1234 --path C:\mydlls\test.dll`)

  * **`process threads list`**: lists threads for a process.

    ```bash
    azalea process threads list -p <pid>
    ```

  * **`process threads suspend`**: suspends a specific thread.

    ```bash
    azalea process threads suspend -p <pid> --tid <thread_id>
    ```

  * **`process threads resume`**: resumes a suspended thread.

    ```bash
    azalea process threads resume -p <pid> --tid <thread_id>
    ```

#### **memory** - direct memory access, information, and protection operations

  * **`memory read`**: reads memory from a process.

    ```bash
    azalea memory read -p <pid> --address <hex_address> [--size <bytes_to_read>]
    ```

    (e.g., `azalea memory read -p 1234 --address 0x7ff6b0000000 --size 64`)

  * **`memory write`**: writes bytes to a process's memory.

    ```bash
    azalea memory write -p <pid> --address <hex_address> --bytes <byte_string>
    ```

    (byte\_string can be "0xdeadbeef", "Hello", etc.)
    (e.g., `azalea memory write -p 1234 --address 0x12345678 --bytes "0x41424344"`)

  * **`memory info`**: shows detailed memory info for a process.

    ```bash
    azalea memory info -p <pid>
    ```

  * **`memory set-protection`**: changes memory protection for a region.

    ```bash
    azalea memory set-protection -p <pid> --address <hex_address> --size <bytes> --protection <flags>
    ```

    (flags: `R`, `RW`, `RX`, `RWX`, `NOACCESS`, or hex value like `0x40`)
    (e.g., `azalea memory set-protection -p 1234 --address 0x12340000 --size 4096 --protection R`)

#### **scan** - memory scanning operations

  * **`scan pattern`**: scans memory for a byte pattern.

    ```bash
    azalea scan pattern -p <pid> --pattern <pattern_string>
    ```

    (pattern\_string can be "0xABCD??EF", "SomeText", "AA BB CC")
    (e.g., `azalea scan pattern -p 1234 --pattern "0x8BFF55??8B"`)

  * **`scan string`**: scans for a specific string.

    ```bash
    azalea scan string -p <pid> --encoding <ascii|utf16le> "<string_to_find>"
    ```

    (e.g., `azalea scan string -p 1234 --encoding utf16le "MyData"`)

  * **`scan pointer`**: scans for pointers to a target address.

    ```bash
    azalea scan pointer -p <pid> --target-address <hex_address> [--max-levels <N>] [--max-offset <M>]
    ```

    (e.g., `azalea scan pointer -p 1234 --target-address 0x12345678 --max-levels 2`)

#### **dump** - memory dumping and dump file analysis operations

  * **`dump process`**: dumps all modules of a process.

    ```bash
    azalea dump process -p <pid> --output <output_directory_path>
    ```

    (e.g., `azalea dump process -p 1234 --output C:\dumps\proc1234`)

  * **`dump region`**: dumps a specific memory region.

    ```bash
    azalea dump region -p <pid> --address <hex_address> --size <bytes_to_dump> --output <output_file_path>
    ```

    (e.g., `azalea dump region -p 1234 --address 0x12340000 --size 4096 --output C:\dumps\region.bin`)

  * **`dump read`**: reads and analyzes a memory dump file.

    ```bash
    azalea dump read --input <file_path> [--offset <bytes>] [--size <bytes>] [--analyze]
    ```

    (e.g., `azalea dump read --input C:\dumps\region.bin --size 256 --analyze`)

#### **analysis** - code analysis operations

  * **`analysis disassemble`**: disassembles instructions at an address.

    ```bash
    azalea analysis disassemble -p <pid> --address <hex_address> [--count <num_instructions>]
    ```

    (e.g., `azalea analysis disassemble -p 1234 --address 0x7ff6b0001000 --count 20`)

#### **patching** - advanced memory patching operations

  * **`patching detour`**: detours a function to another address using a JMP instruction.

    ```bash
    azalea patching detour -p <pid> --target-address <hex_address> --detour-address <hex_address>
    ```

    (e.g., `azalea patching detour -p 1234 --target-address 0x140001000 --detour-address 0x140002000`)

  * **`patching nop`**: overwrites a region of memory with NOP instructions.

    ```bash
    azalea patching nop -p <pid> --address <hex_address> [--size <bytes>]
    ```

    (e.g., `azalea patching nop -p 1234 --address 0x140001000 --size 10`)

-----

### help and version

  * **`azalea --help`**: shows general help and lists all command groups
  * **`azalea <command_group> --help`**: shows help for a specific command group (e.g., `azalea memory --help`)
  * **`azalea <command_group> <subcommand> --help`**: shows detailed help for a specific subcommand (e.g., `azalea memory read --help`)
  * **`azalea --version`**: shows the version

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