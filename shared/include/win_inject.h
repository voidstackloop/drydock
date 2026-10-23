#pragma once
// Making a program that is just being started load a DLL before its own code runs
// (Windows, 64-bit). Used by the leakcheck command to start the program under the
// runtime, and by the runtime itself to follow the programs it starts (--trace-children).
//
// A new process's first thread starts in ntdll with the program's entry point in rcx,
// and calls it once the loader has bound every import. Pointing rcx at a stub that
// loads the DLL and then jumps to the real entry point runs our code at the one moment
// when kernel32 is ready and no program code has run. No code of the program is
// changed.
#include <windows.h>

#include <stdint.h>
#include <string.h>

namespace lcinject {

struct ProcessBasic {
    PVOID exit_status, peb, affinity, priority, pid, parent_pid;
};

// `process` and `thread` come from CreateProcess(CREATE_SUSPENDED). False with a
// reason in `error` if it could not be done; the thread is then untouched.
inline bool load_dll_first(HANDLE process, HANDLE thread, const wchar_t *dll, char *error, size_t cap) {
    auto fail = [&](const char *why) {
        if (cap)
            strncpy(error, why, cap - 1), error[cap - 1] = 0;
        return false;
    };
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(thread, &ctx))
        return fail("cannot read the program's first thread");
    // rcx must be the entry point; refuse to jump anywhere else.
    using Query = LONG(WINAPI *)(HANDLE, int, PVOID, ULONG, PULONG);
    auto query = reinterpret_cast<Query>(
        reinterpret_cast<void *>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess")));
    ProcessBasic pbi = {};
    uint64_t image = 0;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    SIZE_T got = 0;
    if (!query || query(process, 0, &pbi, sizeof pbi, nullptr) < 0 ||
        !ReadProcessMemory(process, reinterpret_cast<char *>(pbi.peb) + 0x10, &image, 8, &got) ||
        !ReadProcessMemory(process, reinterpret_cast<void *>(image), &dos, sizeof dos, &got) ||
        !ReadProcessMemory(process, reinterpret_cast<void *>(image + dos.e_lfanew), &nt, sizeof nt, &got) ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        image + nt.OptionalHeader.AddressOfEntryPoint != ctx.Rcx)
        return fail("cannot find the program's entry point (is it a 64-bit program?)");
    void *remote = VirtualAllocEx(process, nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote)
        return fail("cannot allocate memory in the program");
    unsigned char buf[4096] = {};
    const size_t bytes = (wcslen(dll) + 1) * sizeof(wchar_t);
    if (64 + bytes > sizeof buf)
        return fail("the path of the runtime is too long");
    const uint64_t path_at = uint64_t(reinterpret_cast<uintptr_t>(remote)) + 64;
    const uint64_t load = uint64_t(
        reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW")));
    const uint64_t entry = ctx.Rcx;
    unsigned char *p = buf;
    auto put = [&](const unsigned char *b, size_t n) {
        memcpy(p, b, n);
        p += n;
    };
    auto put64 = [&](uint64_t v) {
        memcpy(p, &v, 8);
        p += 8;
    };
    static const unsigned char push_rcx[] = {0x51};
    static const unsigned char sub_rsp[] = {0x48, 0x83, 0xEC, 0x20};
    static const unsigned char mov_rcx[] = {0x48, 0xB9};
    static const unsigned char mov_rax[] = {0x48, 0xB8};
    static const unsigned char call_rax[] = {0xFF, 0xD0};
    static const unsigned char add_rsp[] = {0x48, 0x83, 0xC4, 0x20};
    static const unsigned char pop_rcx[] = {0x59};
    static const unsigned char jmp_rax[] = {0xFF, 0xE0};
    put(push_rcx, 1);   // push rcx
    put(sub_rsp, 4);    // sub rsp, 0x20
    put(mov_rcx, 2);    // mov rcx, <path>
    put64(path_at);
    put(mov_rax, 2);    // mov rax, <LoadLibraryW>
    put64(load);
    put(call_rax, 2);   // call rax
    put(add_rsp, 4);    // add rsp, 0x20
    put(pop_rcx, 1);    // pop rcx
    put(mov_rax, 2);    // mov rax, <entry point>
    put64(entry);
    put(jmp_rax, 2);    // jmp rax
    memcpy(buf + 64, dll, bytes);
    if (!WriteProcessMemory(process, remote, buf, sizeof buf, &got))
        return fail("cannot write into the program");
    FlushInstructionCache(process, remote, sizeof buf);
    ctx.Rcx = uint64_t(reinterpret_cast<uintptr_t>(remote));
    if (!SetThreadContext(thread, &ctx))
        return fail("cannot redirect the program's first thread");
    return true;
}

} // namespace lcinject
