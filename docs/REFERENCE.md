# leakcheck reference

Every finding, option and limit. The short version is the [README](../README.md);
how it works is in [DESIGN.md](DESIGN.md).

A memory and resource leak checker for C and C++ on Linux and Windows, with no AI or
heuristics learned from data: every finding comes from tracking allocations
and handles at run time or from dataflow over the source.

Two engines share one report format:

| | `leakcheck dynamic <program>` | `leakcheck static <source>` |
|---|---|---|
| How | Runs the program with an injected allocator and I/O wrappers (`LD_PRELOAD`) | Parses C/C++ and follows pointers and descriptors through each function |
| Needs | A dynamically linked program, nothing else (no recompiling); Linux, or Windows 64-bit (see "Windows") | Source files, a directory, or `compile_commands.json` |
| Finds: memory | Leaks (definitely/indirectly/possibly lost), double free, use after free, invalid free, heap buffer overflow/underflow, `malloc`/`delete` mismatches, sized-delete mismatches | Leaks on some or all paths (including `asprintf`, `getline`, `posix_memalign`, `realpath(p, NULL)` buffers and the lists from `getaddrinfo`/`getifaddrs`, which only `freeaddrinfo`/`freeifaddrs` release), overwritten pointers, double free, use after free, alloc/free mismatches, frees of non-heap memory, dangling pointers to locals |
| Finds: resources | File descriptors, `FILE` streams, `DIR` streams still open at exit; joinable threads that finished but were never joined; a thread joined or detached twice (`double-join`: its handle may already name another thread); child processes that exited but were never waited for (zombies); descriptors leaked into programs started with `system`/`popen`/`posix_spawn`; double close; `fclose` on a `popen` stream (and the reverse); a `read`/`write`/`send`/`recv`/`connect`/... on a closed descriptor; `fread`/`fwrite`/`fgets`/`fprintf` on a `FILE*` after `fclose`; a read loop that spins on a socket whose peer has hung up; `bind()` to a fixed TCP port without `SO_REUSEADDR`; `select`/`pselect` with `nfds` past `FD_SETSIZE`; running out of descriptors (`descriptor-limit`, naming the call site that holds most of them) | Descriptors, `FILE` and `DIR` streams not closed on some or all paths, double close, use after close, closer mismatches; threads from `pthread_create` (without attributes) never joined or detached, or joined or detached twice (`double-join`) |
| Finds: timing bugs | Lock-order inversions (deadlocks waiting for unlucky timing), a thread locking a mutex it holds, threads ending with a mutex held, a lock whose owner thread is gone (a `fork` child of a threaded parent), `strtok`/`localtime`/`getpwnam`/... called from several threads, a socket `send()` without `MSG_NOSIGNAL` while SIGPIPE can still kill the process, signal handlers calling `malloc`/`printf`/`exit`/... | Mutexes (including `std::lock_guard`/`unique_lock`) still held at a return, locked twice, or locked in opposite orders by two functions; threads started with the address of a loop variable (`pthread_create(.., &i)`, `[&]` lambdas), `std::thread` destroyed unjoined, a condition wait outside a loop |
| Finds: malware behaviour | What a trojan, backdoor or dropper does while it runs: a shell given to a network connection (`reverse-shell`), a file written and then started, or a download piped into a shell (`dropper`), a program run from memory (`fileless-exec`), writes to login scripts, cron, services and SSH keys (`persistence`), reads of SSH keys, password files, browser stores and the keyboard (`credential-access`), `ptrace` and `/proc/<pid>/mem` injection, self-tracing, self-deletion and reads of a process's memory map (`anti-analysis`), the setuid bit (`privilege-escalation`), wiped logs, `rm -rf /` and miners, a process or file that takes a system name (`masquerade`), and writes to the programs in `/usr/bin` and `/usr/lib` (`system-tampering`). See "What a trojan does" | The same command lines, plus source mistakes that let an attacker in: a format that is not a literal, a shell command built from outside text, an unbounded copy, `alloca` of a size from outside text, `gets`/`mktemp`/`scanf("%s")`, a password written into the program, `access()` then `open()`, `chmod 0777`, MD5/DES/RC4, a `memset`/`memcpy` sized with `sizeof` of a pointer, an allocation whose size multiplies outside text, TLS peer verification switched off. See "What the source can be made to do" |
| Exactness | Reports what actually happened in that run | Warnings: may miss bugs or flag impossible paths |

`leakcheck scan <file or directory>` is a third mode. It does not run the
program and does not need source: it reads the files and reports what a
trojan looks like on disk (a double extension, the EICAR test string, a
script named `report.pdf`, a program called `sshd` in `/tmp`). See
"Scanning files".

### Other languages

* **Static mode reads C and C++ only** (`.c .cc .cpp .cxx .h .hpp ...`). A Rust
  or Python file named on the command line is lexed as C and yields nothing;
  in a directory scan such files are skipped.
* **Dynamic mode does not care what the program was written in**, only that it
  is a dynamically linked Linux process that calls the C library. Tried on a
  small Rust program (`rustc`, default allocator) it reported a `Box::leak`ed
  block, a block from `extern "C" malloc`, and a descriptor turned into a raw
  fd. It did not see two `std::sync::Mutex` locked in opposite orders: those
  are futexes, not pthread mutexes (the same goes for `parking_lot`). Tried on
  `python3 script.py` it reported a `ctypes` malloc that was never freed and an
  `os.close` of an already closed descriptor, among about a dozen "definitely
  lost" blocks that are the interpreter's own allocations at exit.
  `-s suppressions/python.supp` hides those (its rules use `near:`, see
  Suppressions) and leaves the `ctypes` leak and the double close. Python-level mistakes (a `threading.Lock` order, a
  forgotten `with`) are invisible to it. A Rust program built with jemalloc or
  mimalloc has its heap in that allocator, not in `malloc`, and is not tracked.
* So for Rust or Python the useful findings are native ones: leaks and
  descriptor bugs in `unsafe`/FFI code and in C extensions. Their own
  languages' mistakes need their own tools (`clippy`, Miri, `ruff`, ...).

## Windows

Everything works on 64-bit Windows (tried on Windows 11): `static` and `scan` as on Linux, and `dynamic` with
a runtime of its own (`leakcheck_preload.dll`, which `leakcheck.exe` makes the program load before
its first instruction). It is tested with programs built by MinGW-w64 (GCC 13, the UCRT runtime);
programs from Visual C++ use the same heap and the same import tables and should behave the same,
but have not been tried.

```powershell
.\build-windows.ps1 -Test          # g++ and Python 3 are all it needs; makes build\leakcheck.exe
build\leakcheck.exe dynamic .\my_program.exe arg1
build\leakcheck.exe static src\
build\leakcheck.exe scan C:\Users\me\Downloads\
```

`leakcheck.exe` and `leakcheck_preload.dll` must stay together. The CMake build has a Windows
branch (`cmake -S . -B build -G Ninja` in a MinGW shell), which was written but not run: the
script is the way that is tested. Build the program under test with `-g` (DWARF) so that
`addr2line` from the same MinGW can name functions and lines; without it, frames show as
`module+offset`.

### What the dynamic mode finds

| Finding | What it watches on Windows |
|---|---|
| `memory-leak`, `double-free`, `invalid-free`, `heap-buffer-overflow/underflow`, `heap-use-after-free`, `alloc-dealloc-mismatch`, `free-size-mismatch` | Every allocation of the process ends in the process heap (`malloc`, `new`, `strdup`, `fopen` buffers, `HeapAlloc`), so `HeapAlloc`, `HeapFree`, `HeapReAlloc`, `HeapSize` are hooked, and `free`/`operator new`/`operator delete` only say which family a block belongs to. Same redzones, quarantine, guard pages (`--guard-every`) and leak classification as on Linux. |
| `resource-leak`, `double-close`, `use-after-close`, `inherited-descriptor` | Handles from `CreateFile`, `CreatePipe`, `CreateEvent`, `CreateMutex`, `CreateSemaphore`, `CreateFileMapping`, `CreateThread`, `_beginthreadex`, `OpenProcess`, `CreateProcess` (process and thread handles), `socket`/`accept`; C streams (`fopen`, `_popen`, `tmpfile`); `FindFirstFile`. Closed by `CloseHandle`, `closesocket`, `fclose`, `FindClose`. A handle that may be inherited and is open when `CreateProcess`, `system` or `_popen` starts a program is reported. |
| `lock-order-inversion`, `double-lock`, `lock-leak`, `unlocked-wait`, `foreign-unlock`, `use-after-destroy`, `destroy-locked`, `orphaned-lock` | `CRITICAL_SECTION`, slim reader/writer locks, mutex handles (`WaitForSingleObject` / `ReleaseMutex`) and the pthread locks of winpthreads, which are what `std::mutex`, `std::shared_mutex` and `std::condition_variable` use under MinGW. |
| `reverse-shell`, `dropper`, `persistence`, `credential-access`, `process-injection`, `anti-analysis`, `privilege-escalation`, `log-tampering`, `destructive-command`, `ransomware-pattern`, `network-scan`, `masquerade`, `system-tampering` | Files opened for writing or reading (`CreateFile`, `fopen`), `CreateProcess`, `ShellExecute`, `WinExec`, `system`, the registry (`RegCreateKeyEx`, `RegOpenKeyEx`, `RegSetValueEx`: `Run` keys, services, Windows Defender policy, the SAM), `WriteProcessMemory`, `ReadProcessMemory`, `VirtualAllocEx`, `CreateRemoteThread`, `QueueUserAPC`, `MiniDumpWriteDump`, `IsDebuggerPresent`, `AdjustTokenPrivileges`, `ClearEventLog`, `MoveFile` (twenty files given one new ending), `connect` (a hundred addresses in ten seconds), `getaddrinfo`, `URLDownloadToFile`. The rules are the Linux ones (`rules.h`) plus Windows paths (the Startup folder, `config\SAM`, the browsers' `Login Data`), commands (`vssadmin delete shadows`, `certutil -urlcache`, `reg add ...\Run`, `schtasks /create`, `wevtutil cl`, PowerShell download-and-run) and process names (`svchost.exe` outside the Windows directory). The program is not stopped. |
| `socket-eof-spin`, `socket-eagain-spin` | `recv`/`recvfrom` returning 0, or `WSAEWOULDBLOCK`, a thousand times in a row on one stream socket. |

### What differs from Linux

* **64-bit programs only.** A 32-bit program is refused with a message (`dynamic`), or runs untraced when
  it is a child (`--trace-children`).
* **The program's own modules and its C/C++ runtime are watched, Windows is not.** Calls made by
  Windows' own DLLs (`kernelbase`, `ntdll`, `combase`, ...) are not hooked, so what they allocate for
  themselves is not tracked; a block that the C runtime allocates *for* such a DLL is treated as that
  DLL's own state (never reported as lost, and what it points to is reachable).
* **`--trace-children`** follows programs started with `CreateProcessA/W` from the program's own
  modules. `system()` and `_popen()` go through the C runtime and start `cmd.exe`
  untraced.
* **Statically linked runtimes.** Memory is still tracked (the heap calls are in the program), but with
  `-static` the `new`/`delete` family check is lost (they are inside the program), and so are the
  pthread lock checks and the exit hook's early leak scan (the scan then runs at `ExitProcess`).
* **Not offered**: signal handlers, `fork` and its orphaned locks, SIGPIPE, `select`/`bind` checks,
  descriptor limit, `thread-unsafe-call` (the Windows C runtime keeps that state per thread),
  `LEAKCHECK_DANGLING`, `--fast-unwind` (Windows unwinds from its tables anyway).
* **Paths.** Reports use `/` in file names. A user name or folder with letters outside ASCII works
  when `leakcheck.exe` has its manifest (Windows 10, version 1903 or later; it is built in).
* **A Windows antivirus** deletes or blocks the EICAR test file. `leakcheck scan` reports
  "cannot read" for it there; that is the antivirus working. The unit tests give the scanner EICAR as
  bytes, never as a file.

## macOS

`static` and `scan` are plain portable C++ and work as on Linux. `dynamic` uses
`DYLD_INSERT_LIBRARIES` to load `libleakcheck_preload.dylib` before the program's own code runs,
the same idea as `LD_PRELOAD`; since macOS's dynamic linker has no symbol-interposition flag, the
library instead carries a `__DATA,__interpose` section (`darwin_interpose.c`) that the linker reads
on load and rewrites in place, which is Apple's documented way to override a libc call for one
image without touching the ones that call it directly.

```sh
cmake -S . -B build && cmake --build build      # the same build as Linux; CMakeLists.txt has an APPLE branch
build/leakcheck dynamic ./my_program arg1
```

What is watched is the same heap, descriptor, stream, directory, socket, `execve`/`posix_spawn`,
`fork`/`wait` and behaviour-rule machinery as Linux, built from the same files
(`dynamic-engine/src/preload/*.cpp`) with the handful of `#if defined(__APPLE__)` sections that a
real difference needs — not a separate runtime the way Windows has one. Specifically absent:
**ptrace injection and `PTRACE_TRACEME`** (no `ptrace(2)` request numbers in the same shape as
Linux's), **`/proc`** (reading another process's memory map, `/proc/<pid>/mem`), **`memfd_create`**
(fileless-exec is not detected on macOS), and the glibc-specific mutex-owner field that
`destroy-locked`/`foreign-unlock` read (macOS's `libpthread` has no public equivalent, so a thread
ending with a lock held, or unlocking one it does not own, is not caught there either). A binary
signed with the hardened runtime and no `com.apple.security.cs.allow-dyld-environment-variables`
entitlement ignores `DYLD_INSERT_LIBRARIES` entirely (Apple's own protection against exactly this
technique); `leakcheck dynamic` on such a program runs it untraced, the same as a statically linked
program on Linux.

**`--malware`'s family rules have macOS-specific tables** (`shared/include/rules.h`,
`dynamic-engine/src/preload/behavior.cpp`): persistence is a launch agent or daemon under
`~/Library/LaunchAgents`, `/Library/LaunchAgents` or `/Library/LaunchDaemons` rather than a registry
key or a cron line; credential access is a keychain file, the TCC privacy-permission database, the
iMessage history or Safari's cookies rather than `config\SAM` or a browser's `Login Data` (which are
still checked too, in case a Windows-style store was copied over); the system directory is
`/System/Library/...` as well as `/usr` and `/bin`; and the command lines include stripping the
quarantine flag that Gatekeeper checks (`xattr -d com.apple.quarantine`), turning Gatekeeper or
System Integrity Protection off (`spctl --master-disable`, `csrutil disable`), loading a launch
agent by hand (`launchctl load`), an AppleScript administrator-rights prompt
(`osascript ... do shell script ... with administrator privileges`), and `dscl` password changes.
A process named `launchd`, `WindowServer`, `coreaudiod` and the other names in `kMacNames` that is
not under `/System` or `/usr` is `masquerade`, matched without regard to case (`windowserver` counts
too).

**None of the `__APPLE__` code in this project has been run on an actual Mac**: it was written from
Apple's documented APIs and verified the same way as everything else here — unit tests of the
platform-independent logic (the rule tables, `name_checks`, `system_dir`/`hiding_place`), and, where
a Linux host can exercise the same code path (the `--malware` family tables, which are plain string
matching with no OS calls), a live `leakcheck dynamic`/`leakcheck scan` run. The dylib build, the
`__interpose` section, and the platform-specific code paths above (ptrace absence aside, which is
simply never compiled in) are unverified past compiling, which this project's own CI cannot do
either without a Mac runner.

## Build

Requirements: Linux with glibc, CMake 3.28+, a C++20 compiler (GCC or Clang),
`addr2line` (binutils) for source locations, Python 3 for the tests.

```sh
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

`build/leakcheck` must stay next to `build/libleakcheck_preload.so`.

The version comes from `VERSION` (one number for CMake, the Windows script and
the tag); `--version` adds the commit and the build type. A build without CMake
and without that header says `0.0.0-dev` rather than pretending.

**Install.** `cmake --install build --prefix /usr/local` writes `bin/leakcheck`
and `bin/libleakcheck_preload.so` (they must stay together), the model under
`share/leakcheck/model/`, the man page under `share/man/man1/` and the docs
under `share/doc/leakcheck/`. The model is looked for next to the project root,
at the configured prefix, and beside the binary (`bin/../share/leakcheck/model`),
so an unpacked archive works wherever it is put. Release archives for Linux
x86_64 and aarch64 and for Windows x86_64 are built from a `v*` tag, with
`SHA256SUMS` and a build-provenance attestation; macOS joins them when the
injected runtime compiles there (see the known issues in
[docs/ROADMAP.md](ROADMAP.md)).

On Windows, see "Windows" below: `.\build-windows.ps1` needs only MinGW-w64.

CTest runs two kinds of tests. The unit tests (`tests/unit`, built as
`build/unit_static`, `build/unit_scan`, `build/unit_reporter`, `build/unit_runtime`) drive the
lexer, parser and analyzer, the report pipeline, and the runtime's allocator,
tables, guard pages and report stream directly. The end-to-end tests
(`tests/run_tests.py`) run the real CLI against the programs in
`tests/dynamic/programs` and the sources in `tests/static/cases`. A unit
binary takes an optional name filter: `build/unit_runtime heap_`.

## Usage

```sh
leakcheck dynamic ./my_program arg1 arg2      # everything after the program is its arguments
leakcheck dynamic -f json -o report.json ./my_program
leakcheck dynamic --guard-every 1 ./my_program  # catch use-after-free reads immediately
leakcheck static src/
leakcheck static build/compile_commands.json -f sarif -o leakcheck.sarif
leakcheck scan ./downloads/                 # files only: nothing is executed
leakcheck scan -f json -o scan.json suspicious.bin
leakcheck scan --ai ./downloads/            # plus the trained classifier on Windows programs
leakcheck ai-features ./downloads/          # the numbers that classifier reads (for training)
```

leakcheck's options go before the program: everything after it, `--`
included, is passed to the program unchanged. `--` before the program also
ends leakcheck's options (`leakcheck dynamic -- ./my_program -f x`).

Build the program with `-g` to get file and line numbers.

Example:

```
[1] ERROR double-free: free() on a 16-byte block that was already freed
    address 0x55d1ae9b52c0, thread 61347
    second release here:
      #0 double_free at heap_errors.c:11
      #1 main at heap_errors.c:83
    first released here:
      #0 double_free at heap_errors.c:10
      #1 main at heap_errors.c:83
    allocated here:
      #0 double_free at heap_errors.c:9
      #1 main at heap_errors.c:83
```

### Options

| Option | Meaning |
|---|---|
| `-o, --output <file>` | Write the report to a file instead of stdout (required for `-f json` and `-f sarif` in dynamic mode, so the program's own output is not mixed into the report) |
| `-f, --format <fmt>` | `console` (default), `json`, or `sarif` (SARIF 2.1.0, for code-scanning services) |
| `-s, --suppressions <file>` | Ignore findings matching rules (see below) |
| `--error-exitcode <n>` | Exit status when problems are found, 1-255 (default 2) |
| `--malware` | Also look for the malware families of `shared/include/malware.h` (virus, worm, trojan, ransomware, spyware, rootkit, RAT, botnet, ... see "Malware families" below). Works in `scan`, `static` and `dynamic` mode; much slower than the default checks, so it is opt-in |
| `--ai` | `scan` only: also ask the trained classifier about every Windows program read (see "The classifier" below). Needs `model/pe-malware.ai`; about twice as slow on a folder of PE files, no cost on other files |
| `--ai-model <file>` | The model to use instead of `model/pe-malware.ai` |
| `--ai-threshold <0..1>` | Score above which `--ai` calls a file malware; default: the threshold the model was exported with |
| `-j, --jobs <n>` | `scan` and `ai-features`: how many files are read (and scanned) at the same time, 1-256 (default: one per CPU). The output is the same, in file order, for any number; on 16 CPUs a 650-file, 85 MB tree took 1.4 s with one thread and 0.26 s with all (3.2 s and 0.76 s with `--malware`), and the 6,149 programs in `System32` take a minute instead of six |
| `-V, --version` | The release, the commit it was built from, the build type, the platform, and the classifier it would load: its file, tree count and threshold. The first line is what a bug report needs |
| `--show-reachable` | Also list blocks still reachable at exit |
| `--no-leak-check` | Skip the leak checks at exit (memory and resources) |
| `--guard-every <n>` | Give every n-th allocation its own pages with inaccessible guard pages, so use-after-free reads and overflows fault at the faulting instruction (0 = off). At most 2048 guarded blocks are live at once |
| `--quarantine-mb <n>` | How much freed memory is held back (poisoned) before reuse; larger catches more stale accesses (default 64) |
| `--stack-depth <n>` | Frames recorded per stack, 1-64 (default 24) |
| `--fast-unwind` | Walk frame pointers instead of DWARF unwind tables: about 4x faster on allocation-heavy programs; frames compiled without `-fno-omit-frame-pointer` are left out of the stacks |
| `--abort-on-error` | Stop the program at the first memory error |
| `--trace-children` | Also check processes the program forks or executes |

### Exit status

* `--error-exitcode` (2) if any error or warning was reported;
* otherwise the program's own status (`128 + signal` if it was killed, or its exit code, including a clean 2);
* `0` when clean and the program exited 0, `1` for usage errors, a json/sarif dynamic report with no `-o`, or when nothing could be analysed
  (for example a statically linked program), `127` if the program cannot start.

### Suppressions

One rule per line, `<type>:<pattern>`; `#` starts a comment. The type is a
finding type (`memory-leak`, `double-free`, ...), `leak`, or `*`. The pattern is
a shell glob matched against every frame's function name, source file and
module path.

```
leak:*libfontconfig*
double-free:legacy_cleanup
*:third_party/*
leak:near:*/python3*
leak:top:PyMem_*
```

A pattern is matched against every frame of the stack, so `leak:*python3*`
also hides what a C extension allocated and the interpreter then called. With
a `near:` prefix only the innermost three frames of each stack are looked at:
the allocation belongs to that library, not to something further out that
passed through it. A `top:` prefix matches only the innermost frame, so
`leak:top:PyMem_*` hides the interpreter's own leak and still shows a ctypes
leak whose top frame is the extension. `suppressions/python.supp` is a ready file for CPython.

Leaks allocated by the dynamic loader itself are suppressed by default.

## Leak categories

Same meaning as valgrind's memcheck. At exit the heap is scanned
conservatively from global data, thread stacks, thread-local storage,
registers and anonymous mappings:

* **definitely lost**: no pointer to the block anywhere;
* **indirectly lost**: only referenced from other lost blocks (the contents of a lost list);
* **possibly lost**: only referenced by pointers into its middle;
* **still reachable**: a pointer to its start still exists (not reported unless `--show-reachable`).

## Resource leaks

Dynamic mode records where every descriptor, stream, directory, thread and
child process was created, and judges them at the very end of the run, after static
destructors and `atexit` handlers have had their chance to close things.
Each `resource-leak` finding has a category:

| Category | Created by | Released by |
|---|---|---|
| `fd` | `open`, `openat`, `creat`, `socket`, `socketpair`, `accept`, `pipe`, `dup`, `eventfd`, `epoll_create`, `timerfd_create`, `signalfd`, `inotify_init`, `memfd_create`, `mkstemp` family, `fcntl(F_DUPFD)` | `close`, `close_range` |
| `stream` | `fopen`, `fdopen`, `tmpfile`, `fmemopen`, `open_memstream`; `popen` | `fclose`; `pclose` |
| `dir` | `opendir`, `fdopendir` | `closedir` |
| `thread` | `pthread_create` (joinable) | `pthread_join`, `pthread_detach` |
| `process` | `fork`, `posix_spawn` | `wait`, `waitpid`, `wait4`, `waitid` |

Descriptors 0-2 are never reported, nor are threads and child processes
still running at the end. A resource still open at exit is a
warning rather than an error: it was certainly never released, but programs
sometimes keep one open on purpose. The memory a library allocated for a
leaked handle (such as a `DIR`'s buffer) is reported with the handle, not as
a second leak.

A socket that is leaked after a failed `connect`, `bind` or `listen` says so:
"file descriptor 5 from socket() is still open when the program ends (its
connect() failed: Connection refused)" (retryable results such as
`EINPROGRESS` do not count; the last failure is the one told). A descriptor received by `recvmsg` (`SCM_RIGHTS`) is opened by that call and leaks if never closed.

A second `close` is reported when the kernel answers `EBADF` for a descriptor
the program had already closed (closing an unknown number is not). A second
`fclose`/`closedir` is reported and not passed on to libc, which would
corrupt its heap. A call that uses a closed descriptor (`read`, `write`, `send`,
`recv`, `connect`, ...) fails with `EBADF` and is reported as `use-after-close`
(see the rules below); it costs nothing until a call fails.

The static engine knows the same creators and closers. A descriptor is an
`int`, so `fd < 0`, `fd == -1` (failed) and `fd >= 0`, `fd != -1` (open) are
its null checks, and `-1` is its null value.

### Locks (static)

`pthread_mutex_lock`, `pthread_spin_lock`, `pthread_rwlock_*lock`, C11
`mtx_lock`, Windows critical sections and SRW locks, and `m.lock()` on a
mutex object are followed through each function:

* `lock-leak`: the function returns, or ends, with the mutex held on every
  path into that point, although it unlocks it elsewhere.
* `double-lock`: a mutex is locked again while certainly held.
* `foreign-unlock`: a mutex is unlocked again after this function unlocked
  it, on every path into that point or on some ("may be unlocked twice",
  as an error path that unlocks and then jumps to the cleanup that unlocks
  again); `unlocked-wait`: a condition wait on such a mutex. A lock whose
  result is tested, or a call that may reach the mutex (a global or member
  one, or one under an argument, as `ctx_lock(c)` for `c->mu`), makes it
  count as maybe held again. The "some paths" case is not judged inside an
  `if`, whose condition may be the flag that tells the paths apart
  (`if (locked) pthread_mutex_unlock(&m);`); such an unlock also stops
  `lock-leak` from judging that mutex.
* `lock-order-inversion`: one function locks global mutex B while holding
  A, another locks A while holding B (or the same function does both). It
  needs no thread to run: two threads calling both functions deadlock.
  Only mutexes declared at file scope are compared, since `p->mu` in two
  functions may be two different objects; cycles through three or more
  mutexes are left to dynamic mode. When a directory or compile database is
  analysed, global mutexes (not `static`) are also compared across files:
  one file's function locks A then B, another file's B then A. A call
  made while holding A to a function of the same file that locks B counts
  as A then B ("'B' is locked (in journal_add()) while holding 'A'"); one
  call level deep.

A function that never unlocks the mutex is a lock wrapper and is not judged,
nor is a lock whose result is tested (it may have failed). A mutex passed to
some other function may be unlocked there; `pthread_cond_wait` hands it back
locked. `std::lock_guard<...> g(m)`, `std::unique_lock<...> lk(m)` and a
single-mutex `std::scoped_lock` hold `m` to the end of their block (or a
`break` out of it, or `lk.unlock()`) without being a lock leak, and count for
`double-lock` (a second guard or `m.lock()` on the same non-recursive mutex)
and `lock-order-inversion`; `std::defer_lock`, `std::adopt_lock` and
`lk.lock()` are followed, `std::try_to_lock` and a `std::scoped_lock` of
several mutexes are not. In a `lock-order-inversion`, a field of a file-scope
object (`account.mu`) counts as one mutex; `p->mu` and `accounts[i].mu` do
not. `cv.wait(lk)` with no predicate outside a loop is a `spurious-wakeup`.

### Streams used before checking them (static)

`fopen`, `popen` and `opendir` return NULL when they fail. A stream handed
to a stream call (`fgets`, `fprintf`, `fread`, `readdir`, `fclose`, ...)
before any test of it is an `unchecked-stream`: it crashes when the file is
missing. Any condition that names the stream counts as its test, so does a
test earlier in the same statement (`ok = f != NULL && fputs(s, f) >= 0`)
and passing it to anything else first (`assert(f)`, a `CHECK(f)` macro).
Descriptors are not judged: `read(-1, ...)` only fails.

### Variadic argument lists (static)

`va_start(ap, last)` and `va_copy(copy, ap)` must be paired with
`va_end` on every path out of the function; undefined behaviour otherwise
(and a leak on ABIs where the list is heap-allocated). A path that
returns without it, a list restarted before it was ended, and a second
`va_end` are reported like any other handle leak, `resource-leak` or
`double-close`. Only plain local lists are followed.

### Threads started with a changing argument, and condition waits (static)

* `thread-stack-argument`: `pthread_create(&t[i], NULL, f, &i)` where the
  loop assigns, steps or re-declares that local (the counter, `int job = i`
  in the body, `task.id = i`) and the loop never joins or waits. A thread
  starts later and reads whatever the variable holds by then: usually the
  last value for every thread, or a stack slot already reused. A shared
  context that the loop leaves alone, `&args[i]`, a heap copy, the value
  itself and start-then-join in one iteration are fine. The C++ form is a
  lambda given to `std::thread`, `std::jthread`, `std::async` or a vector of
  threads that captures such a local by reference (`[&]`, `[&i]`), or a
  detached thread whose lambda captures any local by reference (the
  function may return first). `[i]`, `[=]`, `[&, i]` and what the lambda
  itself declares or writes are fine.
* `std::thread` locals (`std::thread t(f, x);`) are followed like other
  handles: destroyed while still joinable (no `join`, `detach`, move or
  `joinable()` test on some path out) is a `resource-leak`, because the
  destructor calls `std::terminate`; a second `join` is a `double-join`.
* `spurious-wakeup`: `pthread_cond_wait()` (or `cnd_wait`) that is not
  inside any loop. A wakeup without a signal, or another thread taking what
  the signal announced, lets the waiter go on with the condition false.
  Waits in a `while`, `do`, `for` or a function with a `goto` retry are
  left alone.

### Signal handlers (static)

A function installed in the same file as a signal handler
(`signal(SIGINT, h)`, `sa.sa_handler = h`, `.sa_sigaction = h`) that
directly calls `malloc`/`free`, the `printf` family, `puts`, `fwrite`,
`fflush`, `fopen`/`fclose`, `opendir`/`closedir` or `exit` is a
`signal-unsafe-call`, reported at the call with the line that installs it:
the same list dynamic mode checks while handlers run, found without running
the program. A call to a function of the same file that calls one directly
counts too ("calls it through log_line()"); deeper chains are left to
dynamic mode.

## Bugs that depend on timing

Some bugs strike once in thousands of runs, when two threads or a signal
line up badly, and take weeks to reproduce. Dynamic mode reports them from
any run that merely executes the code involved, even when nothing went
wrong in that run:

| Finding | What it means |
|---|---|
| `lock-order-inversion` | One path takes lock A and then B, another B and then A (or a longer cycle). Two threads doing both at once deadlock. Reported with the stacks of both orders. |
| `double-lock` | A thread takes a lock it already holds and waits for itself: a non-recursive mutex, a spin lock, or a write lock on a read-write lock it holds for reading. That run would hang forever, so the program is stopped with the report instead. |
| `lock-leak` | A thread ends while holding a lock: whoever takes it next waits forever. |
| `unlocked-wait` | A condition wait (`pthread_cond_wait`, `_timedwait`, `_clockwait`) with a mutex the thread does not hold. A signal sent just before the wait starts is lost, and the waiter sleeps through it. |
| `foreign-unlock` | A thread unlocks a normal mutex that another thread holds, or that is not locked at all, as when a mutex is used as a signal between threads. The next owner's critical section is no longer protected. (In a `fork` child, the parent's forking thread counts as the child's, as `pthread_atfork` handlers expect.) |
| `use-after-destroy` | A mutex is locked, unlocked or waited with after `pthread_mutex_destroy` (and before it is initialised again). glibc answers `EINVAL`, so a caller that ignores the result runs its critical section unprotected: typical of shutdown code destroying a mutex another thread still reaches. |
| `orphaned-lock` | A normal mutex is locked whose owner thread no longer exists: the thread ended holding it, or it was another thread of the parent when the process forked (the child has only the thread that called `fork`). Nothing will ever unlock it, so the call would wait forever; the program is stopped after the report. Reported from `fork` children even without `--trace-children`. Robust and process-shared mutexes are left alone. |
| `thread-unsafe-call` | `strtok`, `localtime`, `gmtime`, `ctime`, `asctime`, `getpwnam`, `getpwuid`, `getgrnam`, `getgrgid`, `gethostbyname`, `gethostbyaddr`, `inet_ntoa`, `getlogin`, `ttyname`, `tmpnam` or `getservby*`/`getprotobyname` is called from a second thread while the first one that called it is still alive, and the two calls have no lock in common. They keep a result (or a scan position) in static storage all threads share, so two calls overlapping give a wrong timestamp or a half-split string. Use the `_r` variant, or one lock around the call and the use of its result. It judges who calls, not whether the calls overlapped in this run. |
| `sigpipe-exposure` | `send`, `sendto` or `sendmsg` without `MSG_NOSIGNAL`, or `write`, `writev`, `dprintf` or `vdprintf` on a descriptor that `socket`, `socketpair`, `accept` or `accept4` made (a `dup` of one, or a pipe, is not looked at), on a stream socket (`SOCK_STREAM`, `SOCK_SEQPACKET`) while the calling thread can still receive SIGPIPE: its action is the default and the thread has not blocked it. A peer that closes the connection then kills the whole process, usually in production and never in a test. Each thread looks on its first such send, and again after SIGPIPE's action or that thread's mask changes; reported once per run. Datagram sockets, `MSG_NOSIGNAL`, an ignored, handled or blocked SIGPIPE are silent. `sendmmsg` and `sendfile` on a socket get the same look. Fix: pass `MSG_NOSIGNAL`, or `signal(SIGPIPE, SIG_IGN)` once at startup and check for `EPIPE`. |
| `use-after-close` | (dynamic) `read`, `readv`, `pread`, `preadv`, `write`, `writev`, `pwrite`, `pwritev`, `send`, `sendto`, `sendmsg`, `sendfile`, `copy_file_range`, `splice`, `recv`, `recvfrom`, `recvmsg`, `connect`, `bind`, `listen`, `accept`, `shutdown`, `flock` or `fdopendir` fails with `EBADF` on a descriptor number the program closed earlier (the report shows where it was opened, closed and used). The same for `fread`, `fwrite`, `fgets`, `fgetc`, `fscanf`, `fputc`, `fprintf`, `fputs`, `fflush`, `getline`, `getdelim`, `fseek`, `fseeko`, `ftell`, `ftello`, `rewind`, `ungetc` or `fileno` on a `FILE*` that `fclose` already released: the call is not passed on, because the stream's memory is freed and the next use would crash. `readdir`, `rewinddir`, `seekdir` and `telldir` on a directory `closedir` already released are refused the same way. A second `fclose` is a `double-close` and is refused the same way. The data is lost, the error is usually not checked, and in a threaded program the number may already name another thread's file. A closed number or stream address that was opened again is a different file while it stays open. A descriptor closed, opened again and closed again is a `double-close` of the first lifetime (the second close shuts the new file), reported at that close, not a `use-after-close` of the new owner. A close the runtime did not see goes unnoticed. `fcloseall` marks every tracked `FILE*` closed, so a later use is the same finding. |
| `socket-eof-spin` | `read` or `recv` returned 0 a thousand times in a row on a stream socket: the peer hung up and the loop does not treat end of file as the end, so the thread spins at full CPU. Empty datagrams, files read to their end and reads of length 0 do not count. |
| `socket-eagain-spin` | `read` or `recv` returned `EAGAIN` a thousand times in a row on a non-blocking stream socket: the loop does not wait. A shorter run, a pipe or a file is silent. |
| `bind-without-reuseaddr` (warning) | `bind()` to a fixed port (not 0) on a TCP socket (IPv4 or IPv6) that has neither `SO_REUSEADDR` nor `SO_REUSEPORT` *at that moment* (setting it after the bind does not help, and is reported). After the server exits with clients connected the port stays in TIME_WAIT and the next start fails with "Address already in use". One report per call site. |
| `descriptor-limit` | A call that makes a descriptor (`open`, `socket`, `accept`, `pipe`, `dup`, `fopen`, `opendir`, ...) fails with `EMFILE` or `ENFILE`. The report says what the limit is, how many descriptors the runtime saw open, and names the call site that opened most of them ("opened here"): in practice the leak, e.g. an accepted socket not closed on one error path. Once per run. The runtime keeps one spare descriptor (a `/dev/null` duplicate at the highest number the limit allows, at most 1023, closed on `exec`) and gives it up to write the report and read `/proc/self/maps`, so this works when the program has used everything; a limit the program lowers itself after start-up places the spare outside it, and then the report may be lost. |
| `select-overflow` | `select` or `pselect` is called with `nfds` greater than `FD_SETSIZE` (1024). An `fd_set` holds that many bits; the kernel copies `nfds` of them and so reads and writes past the set, which is the classic stack smash. Nothing is checked until the call, and `nfds` up to `FD_SETSIZE` (including exactly that) is silent. Use `poll` or `epoll_wait`. |
| `destroy-locked` | A mutex, read-write lock or spin lock is destroyed while this thread or another holds it. glibc answers `EBUSY` for a mutex, which programs rarely check, and the memory is then freed or reused while someone may still unlock it. (Freeing an object with its lock held, as the last reference often does, is not reported.) |
| `signal-unsafe-call` | A signal handler calls `malloc`, `free`, `new`/`delete`, the `printf` family, `puts`, `fwrite`, `fflush`, `fopen`/`fclose`, `opendir`/`closedir` or `exit`. If the signal arrives while the program is inside one of them, the handler deadlocks on its lock or corrupts the heap. Reported with the stack where the handler was installed. |
| `inherited-descriptor` | A descriptor opened without close-on-exec was open when `system`, `popen`, `posix_spawn` or an `exec` (in a `fork` child, typically) started another program, which then keeps it open: the port stays taken, the pipe never reaches end of file. Children that are not traced report it too, once for all of them ("seen 3 times"). |

On request, the end-of-program scan also looks for **latent use-after-free**:
data the program still uses (reachable heap blocks, its own globals) that
holds the address of a block it already freed. Nothing failed yet, but the
next path that follows that pointer reads or writes freed memory:

```bash
LEAKCHECK_DANGLING=1 leakcheck dynamic ./server
```

It is off by default because many programs tear down at exit and leave such
pointers behind on purpose (V8 inside node reports dozens), and a container
keeps old pointers in its unused capacity.

Locks are `pthread_mutex_*`, `pthread_rwlock_*` and `pthread_spin_*` ones,
so `std::mutex`, `std::shared_mutex` and the lock guards are covered.
Try-locks never create an order (they cannot wait), and neither do read
locks: a reader waits only for writers, so only orders that end in an
exclusive lock (a mutex, a spin lock, a write lock) can deadlock. Recursive
mutexes may be relocked, readers may read-lock again, and a lock that is
destroyed, initialised again or freed with its heap block starts over with
no recorded order.

## What a trojan does

A trojan, backdoor or dropper is known by what it does to the machine. Dynamic
mode watches the calls that do it and reports each one with the stack that made
it, even when the attempt fails (a non-root program that opens `/etc/shadow` is
refused, and is reported). **Dynamic mode runs the program.** Run a program you
do not trust inside a virtual machine or a container with nothing in it worth
stealing; leakcheck reports what the program did, it does not stop it.

None of these is wrong in itself: an installer writes `~/.bashrc`, `ssh` reads
`~/.ssh/id_rsa`, a debugger attaches to a process. So `persistence`,
`credential-access`, `dropper` and `anti-analysis` are *warnings* and the
others errors; the person reading the report knows whether the program was
meant to.

| Finding | What it means |
|---|---|
| `reverse-shell` | A shell (`sh`, `bash`, `dash`, ...) is started with standard input, output or error on a socket, or a command line connects one to the network: `/dev/tcp/`, `nc -e`, `ncat -e`, `socat EXEC:`, `bash -i >&`, a named pipe into `nc`, a script that opens a socket and `dup2`s or `pty.spawn`s a shell. Whoever is at the other end has a command line on this machine. |
| `dropper` | The program starts a file it wrote itself (an exec, or the first word of a `system()` command line, or the script given to `sh`), pipes a `curl`/`wget`/`base64 -d` into a shell, or makes a file in `/tmp` executable. The harmful code is not in the file you were given. |
| `fileless-exec` | A program is started from a `memfd_create` file or from a file deleted after it was opened (`fexecve`, or `/proc/self/fd/N`): nothing on disk for a scanner to read. |
| `persistence` | A file the system reads at login or boot is opened for writing, renamed or linked onto: `~/.bashrc` and the other shell start-up files, `authorized_keys`, `/etc/cron*`, `/var/spool/cron`, autostart entries, systemd units, `/etc/init.d`, `/etc/rc.local`, `/etc/ld.so.preload`, `/etc/passwd`, `/etc/shadow`, sudoers, PAM. Also `crontab`, `systemctl enable` and `>> ~/.bashrc` in a command line. |
| `credential-access` | A file with secrets is opened (even only to look): `/etc/shadow`, SSH private keys (not `.pub`), `~/.aws/credentials`, `.git-credentials`, `.kube/config`, `.gnupg`, a browser's saved logins and cookies, wallets, `/dev/input/event*` (what a key logger reads), `/dev/mem`, `/proc/kcore`, and `/proc/<pid>/mem` or `environ` of another process. |
| `process-injection` | `ptrace` attaches to another process (`ATTACH`, `SEIZE`) or writes into it (`POKE*`, `SETREGS`), `process_vm_writev` does, or `/proc/<pid>/mem` is opened for writing. |
| `anti-analysis` | `ptrace(PTRACE_TRACEME)` in the program's own first process, or an attach to its own parent (no debugger can then attach), `unlink` of its own executable, or a read of a process's memory map (`/proc/<pid>/maps`), which injection helpers and anti-debugging code walk to see what is loaded where. A debugger's forked child doing `TRACEME` is not reported. |
| `privilege-escalation` | `chmod`/`fchmod`/`fchmodat` with the setuid or setgid bit, `chmod u+s` / `4755` / `setcap cap_setuid` / `NOPASSWD` in a command line, or `setuid(0)`, `seteuid(0)`, `setreuid`, `setresuid` with 0 by a process that is not root. |
| `log-tampering` | A system log (`/var/log/*`, `utmp`, `wtmp`) or the shell history is removed, emptied (`O_TRUNC`, `truncate`, `fopen "w"`) or, in a command line, `history -c`, `rm /var/log/...`, `HISTFILE=/dev/null`. Appending to a log and rotating it with `rename` are not reported. |
| `destructive-command` | A command line that erases the file system (`rm -rf /`, `--no-preserve-root`), overwrites a disk (`dd of=/dev/sda`), formats one, or is a fork bomb. |
| `cryptominer` | A command line that starts `xmrig`, `minerd`, `cpuminer`, or names a `stratum+tcp://` pool. |
| `ransomware-pattern` | Twenty `rename()` calls that add the same new ending to a name (`report.docx.locked`): how ransomware marks the files it has encrypted. Endings that backups and rotation add (`.bak`, `.old`, `.orig`, `.tmp`, `.gz`, `.lock`, `.1`, ...) are not counted. |
| `network-scan` (warning) | `connect()` to a hundred different addresses and ports within ten seconds, once per run: a worm or a bot looking for victims, or a port scanner such as nmap doing what it is for. |
| `masquerade` | The process is not what its name says. It renames itself (`prctl`) to `kworker/0:1` or `sshd`, it is started with another program's name (`exec -a '[kworker/0:1]'`), it creates a file of such a name in `/tmp`, `/dev/shm` or a hidden directory, or a command or a `getaddrinfo` looks up a host built to look like one you trust (`github.com.update.example`, `paypa1.com`, `micros0ft.com`, `gooogle.com`). The system's own programs, in `/usr/bin` and the other system directories, may name themselves whatever they like. A name one letter, one look-alike digit (`0`/`o`, `1`/`l`, `rn`/`m`) or one swapped pair away counts; the real host, and a name under it (`api.github.com`), does not. |
| `system-tampering` | A file under `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/lib` or `/boot` is opened for writing, replaced, removed or given new permissions. A package manager does this; so does a trojan that swaps `ls` or a library for its own. `/usr/share`, `/usr/include`, `/usr/local`, `/opt` and a language's `__pycache__` are not the system. Writing `/etc/hosts` or `/etc/resolv.conf` redirects the machine's connections and is reported the same way. This one is a warning. |

Command lines are the text of `system()`, `popen()` and the argument of an
`sh -c`; they are read, not run by leakcheck. Limits: only calls through libc
are seen (a static binary or a raw system call is not), `execveat` is watched like `execve` (`AT_EMPTY_PATH` uses the directory descriptor), a program that is not traced (children without
`--trace-children`) is not watched, and a program that builds its command line
or its paths at run time out of pieces is seen as it finally calls the
function: that is the point of watching at run time.

The names, the host names and the command lines are one list (`rules.h`),
shared with scan mode, so a script on disk and the same command at run time
are judged the same way.

## What the source can be made to do

Static mode also reads each function for mistakes that are about the text of
the program, not about which pointer owns which block. They are warnings, like
the other static findings. A name is followed through assignments in the
function; `argv`, `getenv`, `fgets`, `recv` and a parameter that a caller
passes text from outside into count as text from outside. When the text crosses
a file boundary, the finding is reported at the call that passed it on, with
the route it took (see [the route](#the-route-text-from-outside-took)).

| Finding | What it means |
|---|---|
| `format-string` | `printf`, `fprintf`, `syslog`, `snprintf` (and the `v` forms, when the format comes from outside) are given a format that is not a string literal. With nothing after it, any format is reported; with further arguments, only one that comes from outside, because the caller chose those arguments to match a format of its own. `printf("%s", buf)` is the fix. A format the function itself sets to one literal, and a macro such as `_("hello")`, are not. |
| `command-injection` | `system()`, `popen()` or `execl(sh, "-c", ...)` is given a string built from that outside text. `x; rm -rf ~` then runs with the program's rights. Pass the arguments to `execv` without a shell. |
| `unbounded-copy` | `strcpy`, `strcat`, `stpcpy` or `sprintf` writes into a local array: a literal that does not fit, or outside text with no length check. A copy from a shorter array, and `snprintf` with the array's size, are not. |
| `unbounded-alloca` | `alloca` (or `__builtin_alloca`) takes a size from outside text: an argument, `getenv`, a read, or a variable assigned from one of those (`n = strtoul(argv[1])`). A long value smashes the stack. `alloca(64)`, `alloca(sizeof buf)` and a size the function sets back to a constant are not. Use `malloc` and check the size. |
| `unsafe-function` | `gets` and `getwd` have no limit; `mktemp`, `tmpnam` and `tempnam` only choose a name; `scanf`/`fscanf` with `%s` or `%[` and no width, and `sscanf` of a longer string into a shorter array, write a word of any length. `cin >> word` into a `char` array with no `setw` is the same. |
| `hardcoded-secret` | A variable named like a password, secret, token or key is set to a literal, a password is compared with a literal, or a string has the shape of a private key (`-----BEGIN ... PRIVATE KEY-----`) or an AWS access key (`AKIA...`). A prompt, a file name, a parser token and a short word are not. |
| `toctou-race` | `access`, `stat` or `lstat` checks a path and, later in the function, `open`/`fopen`/`chmod`/`unlink`/... uses that same path. Between the two calls the path can be replaced. `open` with `O_EXCL` or `O_NOFOLLOW` is the check itself. |
| `insecure-permissions` | `chmod`, `fchmod` or `fchmodat` with a mode anyone can write (`0777`, `0666`, `S_IWOTH`). `0644` is not. |
| `weak-crypto` | MD5, SHA-1, DES, RC4, ECB or `crypt()`. One report per algorithm per function. A function that implements the algorithm (its name begins with the algorithm's) is not reporting itself. |
| `sizeof-pointer` | `memset`, `memcpy` or `memmove` is given `sizeof(p)` where `p` is a pointer (a `malloc`'ed name, an alias of one, or a parameter): only the pointer's own bytes are touched, not the buffer. `sizeof` of a real array, and `sizeof *p`, are correct. |
| `alloc-size-overflow` | `malloc` or `realloc` is given a size that multiplies text from outside (`n * 4`): the product can wrap around and the buffer come out smaller than asked. `calloc` checks the product itself; constant sizes are exact. |
| `tls-no-verify` | `SSL_CTX_set_verify` or `SSL_set_verify` with `SSL_VERIFY_NONE`: the peer's certificate is not checked, so anyone who intercepts the connection impersonates the server. `SSL_VERIFY_PEER` is not reported. |
| `path-traversal` | `open` or `fopen` is given a path constructed by joining directory path with outside text without validating or rejecting `..`. |
| `sql-injection` | `sqlite3_exec`, `mysql_query`, `PQexec`, or SQL formatting calls are given query strings constructed from outside text. Use parameterized prepared statements instead. |
| `null-dereference` | A pointer variable is dereferenced after being explicitly assigned `NULL`/`nullptr`/`0` or inside an `if (!p)` or `if (p == NULL)` branch without reassigning or returning. |
| `insecure-prng` | `rand()`, `random()`, or `drand48()` is used to generate security-sensitive tokens, passwords, keys, salts, or nonces. Use `getrandom()` or OpenSSL `RAND_bytes()` instead. |
| `ssrf` | `curl_easy_setopt()` is configured with `CURLOPT_URL` pointing to an unvalidated URL from outside input. |
| `xss` | Output formatting functions (`printf`, `fprintf`, `dprintf`) emit unescaped outside text into an HTML response. |
| `off-by-one` | A local array of capacity `N` is indexed at `N` or at `sizeof(arr)` without subtracting 1, corrupting adjacent stack memory. |
| `integer-overflow` | Arithmetic (multiplication or addition) on untrusted inputs can wrap around or overflow, bypassing length/bounds checks. |

### The route text from outside took

Every finding that is about outside text (`command-injection`,
`path-traversal`, `sql-injection`, `format-string`, `unbounded-copy`,
`unbounded-alloca`, `process-injection`) carries the way the text got there.
The console prints it under the finding:

```
[2] WARNING command-injection: text from outside is passed to run(), which reaches system() in run() (util.c:7): what that call does with this text is chosen by whoever controls it
    vulnerability: CWE-78 (Command Injection) [critical]
    here:
      #0 main at main.c:10
    how the text got here:
      #0 argv in main at main.c:9
      #1 run() in main at main.c:10
      #2 system() in run at util.c:7
```

The JSON report has the same thing as `flow`: an array of steps, each with
`what`, `function`, `file` and `line`, in the order the text moved. SARIF gets
it as a `codeFlows` entry with one `threadFlowLocation` per step, so a
code-scanning service draws the route in the editor.

### Text that crosses files

`static` reads the functions of a file together, but a program is not one
file. A pass after the files have been read connects them:

* each file records, for every function, which of its parameters reaches which
dangerous call, and which parameter is passed on to another function's
parameter;
* each file records the calls that hand text from outside to a function it does
not define, and where that text entered the program;
* the calls are then followed through those records, through as many files as
the text travels (`main` → `handle` → `execute` → `system`), and the finding is
written at the call that passed it on, with the whole route.

One finding per dangerous call: the same `system()` reached from two callers is
one vulnerability, reported from the call with the furthest known origin, which
is the entry point an attacker uses.

The limits: only parameters carry text between files, not struct fields, globals
or return values, so a text that comes back from a function is not followed. A
function has to be defined in the files being analysed — a declaration with the
body in a library says nothing. And the same-file rules still apply: a parameter
is only reported as reaching a sink when the sink is one of the calls listed
above.

On the Juliet C/C++ suite (NIST SAMATE), where the flawed functions are named
`*bad*` and the repaired ones `*good*`, the same rules find the flawed case
and stay quiet on the repaired one as follows. A case is a group of files
that belong together; the second figure is the cases that live in one file,
which is all this analysis looks at.

| CWE | What | Cases | Flawed code found | Repaired code flagged |
|---|---|---:|---:|---:|
| 134 | format string | 1200 (700 in one file) | 970 (670) | 405 (105) |
| 78 | command injection | 1200 (700 in one file) | 240 (240) | 0 |
| 121 | stack copy | 3100 (1905 in one file) | 776 (776) | 0 |
| 367 | access then use | 36 | 36 | 0 |
| 242, 676 | `gets` and the other banned calls | 18 + 18 | 18 + 18 | 0 |
| 377 | `mktemp` / temporary files | 72 | 54 | 0 |

The parenthesised counts are the cases that live in one file. The table was
measured one file at a time; the cross-file pass described above now follows a
parameter through several files, which is where the rest of those cases pass
the buffer. CWE259, CWE327 and CWE328 in this tree are Windows-only (`_w32_`,
`wchar`) and were not scored. Format strings are the noisy one: 105 of the
700 repaired one-file cases are still flagged, because a repaired Juliet
function often keeps a non-literal format that is safe for a reason the
tokens do not show.

The same rules over busybox, OpenSSH, Redis, lighttpd, tinyproxy and miniupnpd
report the calls that are what they look like (`system(cmd)` built from a
watch expression, `gets` in a small demo, `chmod` of a world-writable socket,
MD5 used as a password hash). tinyproxy's own code produced none.

## Scanning files

```
leakcheck scan downloads/
leakcheck scan -f json -o scan.json invoice.pdf
```

Nothing is executed and nothing is written except the report. A directory is
walked (symlinks are not followed; `/proc`, `/sys` and `/dev` are not
entered). Files larger than 256 MB are skipped; the first 16 MB of the others
are read. Findings use the same types as dynamic mode where the fact is the
same one (`reverse-shell` in a script, `masquerade` for a name), plus five
that only a file can show:

| Finding | What it means |
|---|---|
| `malware-signature` | The EICAR test string, a mining-pool address, the name of a known web shell, the text of a ransom note, or PHP that passes `$_POST`/`$_GET`/`$_REQUEST`/`$_COOKIE` to `eval`, `system`, `assert` or `base64_decode`, or PHP that runs code from an encoded string (`eval(base64_decode(...))`). EICAR is harmless: it exists so a scanner can be shown to find it. |
| `disguised-executable` | The bytes are a Linux, Windows or macOS program, or a script (`#!`), and the name ends in `.pdf`, `.jpg`, `.doc`, `.txt` or another extension of something that is only read. |
| `obfuscated-code` (warning) | A script decodes text and runs the result: `exec(base64.b64decode(...))`, `eval(atob(...))`, `eval(gzinflate(base64_decode(...)))`, `powershell -EncodedCommand`, or a line of thousands of characters that is nearly all base64. The decoder and the thing that runs must be within about a hundred characters of each other; a script that decodes data and never runs it is not reported. |
| `suspicious-binary` | Packed (UPX and the other packer section names), bytes that look encrypted, an executable section whose own bytes look random, a segment that is writable and executable (in an ELF, a PE section or a Mach-O segment), an executable stack, an entry point outside the code, a section table that was cut off, a Windows import table that names almost nothing, or a shared library other than libc that defines `readdir` or `getdents`. Some honest programs are packed; the finding says so. |
| `ai-classifier` (warning) | `--ai` only: a Windows program whose headers, sections, imports and strings the trained model scores above the threshold as malware. The message gives the score, the threshold, what the model was trained on, and says that it is a guess from the shape of the file and not a matched rule. See "The classifier" below. |

A Windows program's import table is read as a table — which API names each DLL
is asked for — and not as strings that happen to be in the file. Two pairs are
a capability on their own: `URLDownloadToFile` together with `WinExec` or
`ShellExecute` is `dropper` (fetch a file and start it), and
`CryptUnprotectData` together with `CredEnumerate` is `credential-access`
(decrypt and walk every password saved on the machine). `CredRead` alone is not
reported: Remote Desktop and the sync clients read one named credential the
same way. A table that names no more than eight functions and includes
`LoadLibrary` and `GetProcAddress` is `suspicious-binary`: everything else the
program calls is chosen at run time, so the table does not say what it does.
The calls a debugger makes (`GetThreadContext`, `SetThreadContext`,
`WriteProcessMemory`) are imported by debuggers, profilers and the .NET runtime
too, so on their own they are not evidence of anything; the injection rule for
those stays the string trio (`WriteProcessMemory`, `CreateRemoteThread`,
`VirtualAllocEx`), which a program that is not an injection helper does not
carry.

An executable section of at least 2 KB whose bytes are close to random
(entropy 7.2 of 8 or more) is `suspicious-binary` even when the file as a whole
is not; the message names the section. A TLS callback — code the loader runs
before the entry point, where an unpacker works — is added to that message and
is not reported on its own: several compilers register one in every program.

On the 7,758 normal programs of the training collection these checks added
nine findings: eight are Microsoft code whose sections are obfuscated or
compressed (two codecs, the software-protection service and its helpers, a
media decoder, a driver), and the ninth is Quick Assist, which downloads and
starts what it is told to. No import pair and no 64-bit program was reported.
On the 3,327 malicious files they added 110 (`suspicious-binary`, mostly
packed sections and tables that name only `LoadLibrary` and `GetProcAddress`).

A name is judged too. `invoice.pdf.exe` and a name that contains a
right-to-left override are `masquerade` even when the file is not a program.
So is a program called `sshd` or `kworker` in `/tmp` or a hidden directory,
a name one letter away from those (`systemdd`, `svch0st.exe`), and a file
that is not the system's own `/bin/ls` but is named `ls` somewhere else: a
directory earlier in `PATH` would run it instead. The real `ls`, copied
byte for byte, is still `ls`.

A Mach-O program (macOS) is read for three things beside its strings: a library
it loads by bare name (`libcrypto.dylib`), through a path that climbs out of its
own folder (`@loader_path/../../tmp/x.dylib`) or from a directory any user can
write (`dll-sideloading`); a code signature that is only ad-hoc while its
entitlements claim an Apple-private one, which no team was granted
(`certificate-abuse`); and the same writable-and-executable segment check as ELF
and PE. A read-execute segment, the ordinary signature of a Mac application, and
libraries from `/usr/lib` or `@rpath` say nothing.

Scripts (a `#!` line, or a text file whose extension is `.sh`, `.py`, `.php`,
...) are read line by line for the command lines in "What a trojan does". A
`.txt` or a `.md` that quotes such a line is documentation, and is not
reported. The same host-name rules apply to any `://` in those lines. A host
is read up to the first character that cannot be in one, the trusted name has
to sit on a boundary (`github.com.evil.example`, not `pyopenssl.org`), and the
registrable label has to share its first letter (`gooogle.com` counts,
`ipython.org` does not).

Files that already live in a system directory (`/usr`, `/bin`, `/lib`, ...)
are not read for those command lines, and not judged by the shape of a packer.
The system's own `bash` contains `/dev/tcp`, `passwd` contains `/etc/shadow`,
`sudo` contains `ptrace`, the files in `/usr/lib/debug` are compressed, and
the Windows drivers under `/usr/lib/wsl` have a writable, executable section.
A program named one letter away from another is not reported there either:
`gpasswd`, `login` and `cron` are real programs. The same bytes outside those
directories are.

## The classifier (`--ai`)

Everything else in leakcheck reports a fact it observed. This one reports a
probability, so it is off unless asked for, it never changes the exit status of
the rule-based findings, and its message carries the number it came from.

It applies to Windows programs only — a PE image with code in it (at least one
executable section and an entry point) — and only in `scan` mode. Resource-only
satellite files (`.mui`, `-RES.dll`, `.rll`, `.tlb`) are untouched and no non-PE
file is looked at: on a real Windows installation those were three quarters of
its false alarms, and a file with no code cannot run by itself. They are still
scanned by the rule-based checks. `leakcheck ai-features` applies the same rule,
so the trainer never learns from a file the scanner would not score; the cost is
73 payload images in the training collection (files with no code) that the
classifier does not flag. Kernel
drivers (`System32\drivers\*.sys`) are judged: the training data now holds every
driver of the machine that trained the model.

### What the model reads

49 numbers, computed by `static-engine/src/ai_features.cpp` and printed by
`leakcheck ai-features`. The same function produces them for training and for
scanning, so a model cannot end up fed something it was not trained on; if the
count does not match the model's header, the model is not used at all. The
command reads several files at once (`-j`, by default one per CPU) and prints
the rows in file order whatever the number of threads: a Windows installation's
6,000 programs take a minute instead of six.

The shipped model uses 42 of them. `tools/train_ai.py` leaves out seven that
record how a file was built or collected rather than what it contains (debug
directory, PDB path, Rich header, checksum, zero timestamp, DLL characteristics,
and 64-bit-ness, which is 64% of the old normal programs and 0.03% of the
malicious ones). On the old corpus, trained on all 49, it measured 100% by
learning a shortcut that would not survive a real download. `--exclude ''` keeps every
feature.

| Group | Features |
|---|---|
| Whole file | size (log), entropy, printable ratio, zero ratio, overlay (log), URL count, `.dll` string count, `cmd.exe`/`powershell` strings, `LoadLibrary` + `GetProcAddress` strings, `.pdb` string, the standard DOS stub |
| Optional header | PE32 vs PE32+, entry point (log) and whether it is zero, image size, headers size, code size, section and file alignment, subsystem, DLL characteristics, timestamp zero, checksum present, number of data directories |
| Data directories | export, import, resource, exception, relocation and debug sizes (log); TLS, signature and bound-import present |
| Imports and exports | how many DLLs and functions, how many of them are on a list of calls used to hide what a program does (`LoadLibrary`, `GetProcAddress`, `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, `URLDownloadToFile`, ...), export count (log) |
| Sections | count, names starting with `.`, max and mean entropy, count above 7.2, executable, writable, writable-and-executable, max and mean raw size (log), max virtual/raw ratio |
| Rich header | the marker a Microsoft linker leaves between the DOS stub and the PE header |

No file name, path, timestamp value or hash is used: only what is inside the
file.

### The model file

`model/pe-malware.ai` is text:

```
leakcheck-ai 1
features 49
feature_names size_log entropy ...
trained_on 10413 Windows programs (3211 malicious, 7202 normal) from crovax/CNN_Project (an old Windows system), a Windows 11 installation
evaluation grouped by imphash: no cluster on two sides of the split
threshold 0.500000
accuracy 0.996919
precision 0.998148
recall 0.992634
trees 231
tree 35
31 6.6170050000000007 1 16 0 0
4 4.5000000000000009 2 5 0 0
42 1.0000000180025095e-35 3 4 0 0
-1 0 0 0 1 0.091010008857441246
...
end
```

Each node is `feature threshold left right leaf value`: a split goes left when
`value <= threshold`, a leaf adds `value`, and the sum over all trees goes
through a sigmoid. The header always declares every feature the build computes,
and a model trained on a subset writes each split at its column in that full
vector, so a model that leaves features out is still fed the numbers it expects.
`leakcheck` reads it with `static-engine/src/ai_model.cpp`;
there is no library to link and the file can be reviewed in a diff. A model
whose version, feature count or tree indices do not make sense is refused with
the reason, never half-loaded.

### Training it

```sh
python3 -m venv .venv-train && .venv-train/bin/pip install numpy lightgbm
python3 tools/fetch_dataset.py --per-class 3000     # data/samples/{benign,malware}
python3 tools/fetch_benign.py --windows /mnt/c/Windows  # data/samples/benign-modern
.venv-train/bin/python tools/train_ai.py            # model/pe-malware.ai + metrics
```

`tools/fetch_dataset.py` reads the central directory of the
[crovax/CNN_Project](https://huggingface.co/datasets/crovax/CNN_Project) archive
over HTTP range requests and fetches only the entries it needs, checking each
against the archive's size and CRC. Nothing is ever executed. The samples are
live malicious code: `data/` is in `.gitignore`, and it can be deleted once the
model is trained.

`tools/fetch_benign.py` reads (never runs) a Windows installation and copies a
deterministic, capped sample of its programs into `data/samples/benign-modern`:
all the `.exe` files, a sample of the DLLs, the .NET assemblies and executables,
PowerShell's host programs and every `.sys` driver, with a SHA-256 manifest. It
is what teaches the classifier what a current installer, a managed assembly, a
protected-media library or a driver looks like; without it the model flagged
hundreds of them on a clean Windows folder.

`tools/train_ai.py` runs `leakcheck ai-features` over every `benign*` and
`malware*` folder, drops rows with identical numbers, and splits 70/15/15 **by
sample family**: files that share an imphash (the imported `dll.function` pairs,
lowercased and hashed) stay on one side, so a family cannot be memorised on one
side and tested on the other. The merged collection becomes 7,438 clusters; the
test split holds 1,147 and shares none with training. `--split random`
reproduces the older, flattering split. No rows are discarded: the classes are
balanced by weight (the modern normal files weigh as much as the old corpus;
`--modern-weight`), because cutting rows to fit used to leave the old corpus
nearly unrepresented.

It then trains LightGBM (400 rounds, early stopping on the validation split,
`boost_from_average=false` so the exported trees add up to exactly what LightGBM
predicts), picks the threshold on the validation split (best F1, never below
0.5), writes the text model and `model/pe-malware.metrics.json`, and finally
proves the export: it re-reads its own text model and refuses to ship it if any
score differs from LightGBM's by more than 1e-9. The metrics file carries the
confusion matrix, a table by kind of program (normal/malicious, 32/64-bit,
exe/dll) and the cluster counts.

`tools/evaluate.py` scores any folder with the shipped model, with the same
feature extractor and text-model reader, and with `--sweep` shows the false
alarms and detections at rising thresholds:

```sh
.venv-train/bin/python tools/evaluate.py --sweep samples/clean samples/bad:malware
```

### What it measured

1,623 held-out files (15% of the merged set), from clusters none of which was
in training, never used for training or for choosing the threshold:

| | |
|---|---|
| accuracy | 0.997 (balanced 0.996) |
| precision | 0.998 (1 of 1,080 normal programs called malware) |
| recall | 0.993 (4 of 543 malicious programs missed) |
| ROC AUC | 1.000 |
| trees | 231 |

By kind of program: 539 of 543 malicious 32-bit executables flagged; 0 of 269
normal 32-bit DLLs, 0 of 597 normal 64-bit DLLs, 0 of 146 normal 64-bit
executables and 1 of 68 normal 32-bit executables flagged. Through the command
line over all 10,664 judged files (mostly training files, so this checks the
wiring, not the quality): 3,246 of 3,254 malicious files flagged (the 73 payload
images with no code are not judged, and the 8 that are not flagged are scored
normal), 0 of 3,409 old normal programs and 2 of 4,001 modern ones. On a real
Windows 11 installation (System32 and SysWOW64, 8,819 judged of 30,898 files):
**2 false alarms, 0.02%** — see
[MODEL.md](MODEL.md#a-real-windows-installation-as-a-false-alarm-test).

Those numbers are still an upper bound: one old malicious collection, and a
normal side that is two Windows systems, makes a cleaner boundary than the real
world does. The two false alarms on a current install name the shape of the
gap — 32-bit signed Microsoft executables of a family the corpus holds once —
and more data of that kind is the fix, not another rule.

Every feature that matters is the shape of the file, and the shape of the next
packer is not in the training set. Expect it to be wrong more often on new
malware than the table says. [MODEL.md](MODEL.md) has the full protocol and
these numbers in one place.

### Using and tuning it

```sh
leakcheck scan --ai downloads/
leakcheck scan --ai --ai-model retrained.ai --ai-threshold 0.85 downloads/
leakcheck scan --ai -s suppressions/ai.txt downloads/   # "ai-classifier:..." rules apply
```

A retrained model drops into `model/pe-malware.ai` and is picked up next to the
project root or next to the binary (`build/leakcheck` finds `../model`).
`--ai` is `scan` only: the same features could be taken from the sources in
`static` mode, but nothing has trained a model on that yet.

## Malware families (`--malware`)

`shared/include/malware.h` lists named malware families (virus, worm, trojan
horse, ransomware, spyware, rootkit, keylogger, backdoor, RAT, botnet,
cryptojacker, wiper, and on) with one finding type each, so a report or a
suppression rule can name a family directly. `--malware` turns on the rules
for all of them, in whichever mode is running:

* **`scan`** reads the signs each family leaves in a file's bytes (tool and
  pool names, API call combinations, shell-code patterns, OLE/ZIP contents of
  Office documents, APKs and archives), and some that are decided by what is
  found together in one file (a disguise plus harmful behaviour is a trojan
  horse; a remote shell plus the tools of spying is a RAT).
* **`static`** reads the same signs in C/C++ source text.
* **`dynamic`** adds the command lines and behaviour each family is known for
  (living-off-the-land tools, DNS and proxy hijacking, wiping disks, ...) to
  the trojan/backdoor checks that are already on by default.

None of this runs code or compares against a signature database fetched from
anywhere; everything is a fixed, local, read-only check of bytes, text or
behaviour, the same kind of heuristic a `grep` of known strings or a hand-written
antivirus or YARA rule would do, and some of it is a weak signal that honest
software can also trip (an installer that downloads and runs something,
software built with a packer): the report says so (`severity: warning`), not
that the file is malicious.

Inside those families the signs also name particular strains: the ransomware and
wiper families above (WannaCry, LockBit, Conti, Ryuk, REvil, BlackCat, Akira,
RansomHub, Hunters International, ...), the loaders (SmokeLoader, DarkGate,
Latrodectus, SocGholish), the stealers (Agent Tesla, RedLine, Lumma, ACR
Stealer), the bankers (Grandoreiro, Mekotio, Casbaneiro), the bots (Mirai,
Hajime, BrickerBot, EnemyBot, XorDdos, Symbiote) and the C2 frameworks (Cobalt
Strike, Sliver, Havoc, Brute Ratel, Nighthawk, Alchimist). macOS samples are read
for what the same families do on that platform: AMOS reading the keychain and the
wallets, Shlayer and Bundlore taking the quarantine flag off a download, a
LaunchAgent that restarts a program kept in `/tmp`, and KeRanger and EvilQuest
holding the files for money. Before those rows a Mac sample was read as ordinary
Unix code, and nothing was said about it.

**On Windows, building with `--malware` wired in puts literal indicators of
known malicious code into `leakcheck.exe`'s own bytes** (exploit names,
shell-code sequences, miner and RAT tool names, the EICAR test string). That
is what lets the scanner find them in a target file, but it is also exactly
what makes an antivirus product's own heuristics flag `leakcheck.exe` itself,
the same false positive a YARA rule file, a ClamAV signature database, or a
strings-based IDS ruleset gets from carrying the very text it is written to
recognise. The bytes are not hidden or transformed to get past that check;
if it happens, add a local antivirus exclusion for the build output (or
report it to the vendor as a false positive on a known, open-source tool)
rather than treating it as a bug to silence here.

## Limitations

* Dynamic mode intercepts the C and C++ allocation functions of dynamically
  linked programs. Statically linked programs, setuid programs, and memory
  from custom allocators that do not use `malloc` are not seen.
* Without guard pages, use-after-free is caught for writes (when the freed
  block leaves quarantine, or at exit) and for frees/reallocs of freed blocks;
  reads need `--guard-every`.
* Overflows are found when the block is freed or at exit (redzones), or
  immediately with guard pages. Out-of-bounds accesses on the stack or in
  globals are not detected.
* Descriptors opened or closed inside libc itself are not seen; a descriptor
  closed that way is never reported, since the kernel is asked at exit.
* Lock tracking covers pthread mutexes, read-write locks and spin locks
  (and what is built on them), not hand-written locks or futexes. A lock on
  the stack that is never destroyed keeps its recorded order after its
  function returns. At most 16 locks held at once per thread are followed.
  Read-write locks are assumed to prefer readers (glibc's default): a cycle
  of read locks that a waiting writer would block is not reported.
* Signal handlers are followed when installed with `sigaction` or `signal`;
  only the calls listed above are checked, not every function that is
  unsafe in a handler.
* Inherited descriptors are checked at `system`, `popen`, `posix_spawn`
  without file actions, and the `exec` family, but not in a `vfork` child
  (it runs on its parent's memory, where only `exec` is safe). A descriptor
  passed on on purpose (a shell's `exec 3<file`, socket activation) is
  reported too: suppress it.
* The static analyzer works per function, does not expand macros and takes
  the first branch of each `#if`. It cannot see ownership moving through
  calls it does not know, so it assumes such calls take ownership. Helpers
  defined earlier in the same file that return fresh memory (`xmalloc`,
  `xstrdup`, factories) are known: their results are tracked like
  `malloc`'s. So are helpers that always release their argument
  (`obj_destroy`, `conn_free`): calling one twice is a double free.
* `--ai` judges Windows programs by the shape of their PE headers and contents.
  It sees the first 16 MB of a file, it says nothing about what the program
  does, and it knows only what its training set taught it: packed, obfuscated
  or freshly built malware can score like an honest program, and an unusual but
  honest program can score like malware (on a current Windows install, 2 of the
  8,819 files the classifier judges: the 32-bit PowerShell ISE and `msiexec`).
  It is a warning carrying a score for that reason. Resource-only files are not
  judged at all. It does not name a family.

See [DESIGN.md](DESIGN.md) for how it works.
