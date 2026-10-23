# ADR-0001: The Windows dynamic engine hooks the heap through import tables

**Status:** Accepted
**Date:** 2026-10-20
**Deciders:** the maintainer of leakcheck

## Context

`leakcheck dynamic` on Linux works because `LD_PRELOAD` puts a library first in the symbol search
order: its `malloc`, `free`, `open`, `pthread_mutex_lock` replace libc's for the whole process, without
recompiling the program. Windows has nothing like it. A program's calls go to addresses that the
loader bound into import tables (or that sit inside its own statically linked runtime), and a library
cannot come first in a search that does not happen.

The requirement: every property of the dynamic engine (memory, handles, locks, trojan behaviour,
sockets) has to be usable on Windows, on programs that are not rebuilt, with the findings, protocol and
rules of the Linux side unchanged. The machine available for the work has MinGW-w64 and no Visual
Studio, so the programs it can build use the UCRT dynamically (`api-ms-win-crt-*`) or statically.

## Decision

Start the program suspended, make it load `leakcheck_preload.dll` before its first instruction (the
first thread's entry point is replaced by a stub that calls `LoadLibraryW` and then jumps to the real
one), and let the DLL **patch the import-table slots** of every module that is not Windows' own, and
of the C runtime for the heap calls. Watch memory at the bottom: `HeapAlloc`, `HeapFree`,
`HeapReAlloc`, `HeapSize` of the process heap, with `free` and `operator new/delete` hooked only to say
which family a block belongs to. Everything above that (block table, redzones, quarantine, leak scan,
resource table, lock graph, behaviour rules, report stream) is the Linux code, compiled for Windows.

## Options Considered

### Option A: import-table patching, heap level (chosen)

| Dimension | Assessment |
|---|---|
| Complexity | Medium: a PE import walker and a stub of 44 bytes |
| Cost | A few hundred lines of Windows-specific hooks per area |
| Coverage | Dynamic CRT, static CRT (the heap calls are in the program), C++ allocations, `strdup`, `fopen` buffers |
| Risk | Calls that bypass imports (direct syscalls, `GetProcAddress` before the DLL loads) are not seen |

**Pros:** no instruction of any code is rewritten, so nothing needs disassembling and nothing can be
half patched; one hook point sees every allocation of the process; the Linux runtime's code is reused.
**Cons:** Windows' own DLLs are not watched; a statically linked C++ runtime loses the `new`/`delete`
family check.

### Option B: inline hooks on `malloc`/`free` (Detours style)

| Dimension | Assessment |
|---|---|
| Complexity | High: relocating the overwritten instructions needs a length disassembler per prologue |
| Cost | A hooking library (third-party code) or one written here |
| Coverage | Also sees calls inside the C runtime DLL |
| Risk | A wrong prologue crashes the program; CET/CFG-protected processes object |

**Pros:** catches internal calls and static runtimes at `malloc` itself.
**Cons:** rewriting code in other programs is the riskiest thing a checker can do, for coverage the
heap-level hook already has.

### Option C: a debugger (breakpoints on the allocator, ReadProcessMemory for the scan)

| Dimension | Assessment |
|---|---|
| Complexity | Medium |
| Cost | Two exceptions per call: allocation-heavy programs run a hundred times slower |
| Coverage | Good, and symbols could come from DbgHelp |
| Risk | The program sees a debugger (`IsDebuggerPresent`), which is a trojan tell this tool reports |

**Pros:** no code in the target. **Cons:** no redzones (the block cannot be moved), slow, changes
the behaviour that is being observed.

## Trade-off Analysis

The choice is between rewriting code (B), slowing and disturbing the program (C), and rewriting data
that the loader wrote for exactly this purpose (A). A also happens to be the layer where Windows is
simple: the C runtime, the C++ runtime and the program all allocate from one heap, so one set of four
functions covers memory, and `free`/`new`/`delete` need only a one-word hint. Where A does not see
(Windows' own DLLs), the cost is bounded: a block they make for themselves is tagged as theirs, a root
of the leak scan and never a leak.

## Consequences

* **Easier:** the runtime shares most of its code with Linux (`blocks.cpp`, `heap.cpp`, `leakscan.cpp`, `resources.cpp`, `behavior.cpp`, `report.cpp`), so a fix to the block table or the leak
  classification applies to both; the tests (`tests/run_tests.py --suite windows`) mirror the Linux ones.
* **Harder:** per-thread state cannot use `__thread` (MinGW emulates it with `malloc`, which is hooked)
  nor `TlsGetValue` (it clears the program's last error); owners of pthread and SRW locks have to be
  tracked by the runtime because Windows does not say.
* **To revisit:** 32-bit programs (not supported); Visual C++ programs (the same heap and import tables,
  but not tried here); a statically linked pthread/C++ runtime (memory yes, `new`/`delete` family and
  pthread locks no); following `system()` and `_popen()` children, which start from inside the C runtime.

## Action Items

1. [x] Injection stub shared by the launcher and `--trace-children` (`shared/include/win_inject.h`)
2. [x] Import-table patcher, module notifications, `GetProcAddress` and `LoadLibrary` hooks
3. [x] Heap, handles, locks, behaviour, sockets; the Windows test suite
4. [ ] Try Visual C++ builds (needs a machine with Visual Studio)
5. [ ] Run the CMake Windows branch (needs CMake on Windows)
