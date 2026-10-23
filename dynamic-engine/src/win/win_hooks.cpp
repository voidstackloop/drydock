#include "win_hooks.h"

#include <algorithm>
#include <cstring>
#include <winternl.h>

static_assert(sizeof(void *) == 8, "the Windows runtime is 64-bit only");

namespace lc::win {
namespace {

constexpr size_t kMaxModules = 1024;

SpinLock g_lock; // the lists below
uintptr_t g_patched[kMaxModules];
size_t g_npatched;
struct Mod {
    uintptr_t lo, hi;
    bool system; // in the Windows directory
    bool crt;    // the C runtime: ucrtbase, msvcrt
};
Mod g_mods[kMaxModules]; // every loaded module, sorted
size_t g_nmods;
uint64_t g_refreshed;    // when the list was last made
volatile LONG g_dirty;   // the loader loaded or unloaded a module since

// ntdll tells us when a module comes or goes (the loader's own notification), so the list
// is made again before the next stack is looked at, not at the next hooked LoadLibrary.
struct DllNotification;
void CALLBACK dll_changed(ULONG, const DllNotification *, PVOID) { InterlockedExchange(&g_dirty, 1); }

const Hook *g_hooks;
size_t g_nhooks;

wchar_t g_windir[MAX_PATH + 1];
size_t g_windir_len;

LPVOID WINAPI (*real_GetProcAddress)(HMODULE, LPCSTR) = nullptr;
HMODULE WINAPI (*real_LoadLibraryA)(LPCSTR) = nullptr;
HMODULE WINAPI (*real_LoadLibraryW)(LPCWSTR) = nullptr;
HMODULE WINAPI (*real_LoadLibraryExA)(LPCSTR, HANDLE, DWORD) = nullptr;
HMODULE WINAPI (*real_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD) = nullptr;

char lower(char c) { return c >= 'A' && c <= 'Z' ? char(c | 0x20) : c; }
wchar_t lower(wchar_t c) { return c >= L'A' && c <= L'Z' ? wchar_t(c | 0x20) : c; }

bool ieq(const char *a, const char *b) {
    for (; *a && *b; ++a, ++b)
        if (lower(*a) != lower(*b))
            return false;
    return !*a && !*b;
}

void utf8(const UNICODE_STRING &u, char *out, size_t cap) {
    int n = WideCharToMultiByte(CP_UTF8, 0, u.Buffer, int(u.Length / 2), out, int(cap) - 1,
                                nullptr, nullptr);
    out[n > 0 ? n : 0] = 0;
}

bool in_windows_dir(const UNICODE_STRING &u) {
    if (!g_windir_len)
        return false;
    if (u.Length / 2 <= g_windir_len)
        return false;
    for (size_t i = 0; i < g_windir_len; ++i)
        if (lower(u.Buffer[i]) != lower(g_windir[i]))
            return false;
    return u.Buffer[g_windir_len] == L'\\';
}

const char *base_of(const char *path) {
    const char *s = strrchr(path, '\\');
    return s ? s + 1 : path;
}

// The C runtime allocates for the program, so its heap calls are watched even
// though it lives in the Windows directory.
bool crt_module(const char *path) {
    const char *n = base_of(path);
    return ieq(n, "ucrtbase.dll") || ieq(n, "msvcrt.dll");
}

size_t image_size(uintptr_t base) {
    const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
    return nt->Signature == IMAGE_NT_SIGNATURE ? nt->OptionalHeader.SizeOfImage : 0;
}

struct Entry {
    uintptr_t base;
    size_t size;
    char path[520];
    bool system;
};

template <class F> void walk(F f) {
    PEB *peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    LIST_ENTRY *head = &peb->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY *e = head->Flink; e && e != head; e = e->Flink) {
        auto *m = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (!m->DllBase)
            continue;
        Entry en;
        en.base = uintptr_t(m->DllBase);
        en.size = image_size(en.base);
        if (!en.size)
            continue;
        utf8(m->FullDllName, en.path, sizeof en.path);
        en.system = in_windows_dir(m->FullDllName);
        f(en);
    }
}

void rebuild_system_ranges() {
    Mod tmp[kMaxModules];
    size_t n = 0;
    walk([&](const Entry &e) {
        if (n < kMaxModules)
            tmp[n++] = Mod{e.base, e.base + e.size, e.system, e.system && crt_module(e.path)};
    });
    std::sort(tmp, tmp + n, [](const Mod &a, const Mod &b) { return a.lo < b.lo; });
    LockGuard g(g_lock);
    memcpy(g_mods, tmp, n * sizeof(Mod));
    g_nmods = n;
    g_refreshed = GetTickCount64();
}

// ---- the import tables --------------------------------------------------------------

void patch_slot(uintptr_t *slot, const Hook &h) {
    if (*slot == uintptr_t(h.replacement))
        return;
    if (h.original && !*h.original)
        *h.original = reinterpret_cast<void *>(*slot);
    DWORD old;
    if (!VirtualProtect(slot, sizeof *slot, PAGE_READWRITE, &old))
        return;
    *slot = uintptr_t(h.replacement);
    VirtualProtect(slot, sizeof *slot, old, &old);
}

void patch_module(const Entry &e) {
    const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(e.base);
    const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(e.base + dos->e_lfanew);
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return;
    const IMAGE_DATA_DIRECTORY &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress)
        return;
    const bool crt_only = e.system; // only CRT modules get here when system
    for (auto *d = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(e.base + dir.VirtualAddress);
         d->Name; ++d) {
        const DWORD names = d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk;
        auto *nm = reinterpret_cast<const IMAGE_THUNK_DATA64 *>(e.base + names);
        auto *iat = reinterpret_cast<uintptr_t *>(e.base + d->FirstThunk);
        for (; nm->u1.AddressOfData; ++nm, ++iat) {
            if (IMAGE_SNAP_BY_ORDINAL64(nm->u1.Ordinal))
                continue;
            const char *fn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME *>(e.base +
                                                                        nm->u1.AddressOfData)->Name;
            for (size_t i = 0; i < g_nhooks; ++i) {
                const Hook &h = g_hooks[i];
                if ((!crt_only || h.crt) && !strcmp(fn, h.name)) {
                    patch_slot(iat, h);
                    break;
                }
            }
        }
    }
}

bool already(uintptr_t base) {
    LockGuard g(g_lock);
    for (size_t i = 0; i < g_npatched; ++i)
        if (g_patched[i] == base)
            return true;
    if (g_npatched < kMaxModules)
        g_patched[g_npatched++] = base;
    return false;
}

void patch_all() {
    const uintptr_t self = uintptr_t(self_module());
    walk([&](const Entry &e) {
        if (e.base == self)
            return;
        if (e.system && !crt_module(e.path))
            return;
        if (!already(e.base))
            patch_module(e);
    });
}

// ---- modules loaded later ---------------------------------------------------------------

HMODULE after_load(HMODULE m) {
    if (m && g_nhooks) {
        patch_all();
        rebuild_system_ranges();
    }
    return m;
}

HMODULE WINAPI hk_LoadLibraryA(LPCSTR n) { return after_load(real_LoadLibraryA(n)); }
HMODULE WINAPI hk_LoadLibraryW(LPCWSTR n) { return after_load(real_LoadLibraryW(n)); }
HMODULE WINAPI hk_LoadLibraryExA(LPCSTR n, HANDLE f, DWORD fl) {
    return after_load(real_LoadLibraryExA(n, f, fl));
}
HMODULE WINAPI hk_LoadLibraryExW(LPCWSTR n, HANDLE f, DWORD fl) {
    return after_load(real_LoadLibraryExW(n, f, fl));
}

// A program that looks a function up by name (GetProcAddress) gets ours too, when
// the module is one the import tables would have patched.
LPVOID WINAPI hk_GetProcAddress(HMODULE m, LPCSTR name) {
    LPVOID real = real_GetProcAddress(m, name);
    if (!real || IS_INTRESOURCE(name))
        return real;
    char path[520];
    if (!module_of(uintptr_t(m), path, sizeof path))
        return real;
    const char *base = base_of(path);
    const bool system = ieq(base, "kernel32.dll") || ieq(base, "kernelbase.dll") ||
                        ieq(base, "ntdll.dll") || ieq(base, "ucrtbase.dll") ||
                        ieq(base, "msvcrt.dll") || !strncmp(base, "api-ms-win-", 11);
    for (size_t i = 0; i < g_nhooks; ++i) {
        const Hook &h = g_hooks[i];
        if (!strcmp(name, h.name) && (system || !strncmp(base, "libstdc++", 9) ||
                                      !strncmp(base, "vcruntime", 9))) {
            if (h.original && !*h.original)
                *h.original = real;
            return h.replacement;
        }
    }
    return real;
}

Hook g_loader_hooks[] = {
    {"LoadLibraryA", reinterpret_cast<void *>(hk_LoadLibraryA), nullptr, false},
    {"LoadLibraryW", reinterpret_cast<void *>(hk_LoadLibraryW), nullptr, false},
    {"LoadLibraryExA", reinterpret_cast<void *>(hk_LoadLibraryExA), nullptr, false},
    {"LoadLibraryExW", reinterpret_cast<void *>(hk_LoadLibraryExW), nullptr, false},
    {"GetProcAddress", reinterpret_cast<void *>(hk_GetProcAddress), nullptr, false},
};

} // namespace

// ---- views of the process ---------------------------------------------------------------

void for_each_module(ModuleFn fn, void *ctx) {
    walk([&](const Entry &e) { fn(e.base, e.size, e.path, ctx); });
}

bool module_of(uintptr_t addr, char *path, size_t cap) {
    bool found = false;
    walk([&](const Entry &e) {
        if (!found && addr >= e.base && addr < e.base + e.size) {
            found = true;
            strncpy(path, e.path, cap - 1);
            path[cap - 1] = 0;
        }
    });
    return found;
}

void exe_path(char *out, size_t cap) {
    wchar_t w[MAX_PATH + 1];
    DWORD n = GetModuleFileNameW(nullptr, w, MAX_PATH);
    int k = n ? WideCharToMultiByte(CP_UTF8, 0, w, int(n), out, int(cap) - 1, nullptr, nullptr) : 0;
    out[k > 0 ? k : 0] = 0;
}

HMODULE self_module() {
    static HMODULE h;
    if (!h)
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&self_module), &h);
    return h;
}

void self_range(uintptr_t *lo, uintptr_t *hi) {
    *lo = uintptr_t(self_module());
    *hi = *lo + image_size(*lo);
}

uint32_t capture_frames(uintptr_t *out, uint32_t max) {
    return RtlCaptureStackBackTrace(0, max, reinterpret_cast<PVOID *>(out), nullptr);
}

// The module list moves when Windows loads a library for the program (without going
// through LoadLibrary, which is hooked): an address that belongs to no known module
// is looked for again, at most once in 20 ms.
const Mod *module_at(uintptr_t pc) {
    if (InterlockedExchange(&g_dirty, 0))
        rebuild_system_ranges();
    for (int attempt = 0; attempt < 2; ++attempt) {
        {
            LockGuard g(g_lock);
            size_t lo = 0, hi = g_nmods;
            while (lo < hi) {
                const size_t mid = lo + (hi - lo) / 2;
                if (g_mods[mid].hi <= pc)
                    lo = mid + 1;
                else
                    hi = mid;
            }
            if (lo < g_nmods && g_mods[lo].lo <= pc)
                return &g_mods[lo];
        }
        if (attempt || GetTickCount64() - g_refreshed < 20)
            break;
        rebuild_system_ranges();
    }
    return nullptr;
}

bool is_system_pc(uintptr_t pc) {
    const Mod *m = module_at(pc);
    return m && m->system;
}

bool is_crt_pc(uintptr_t pc) {
    const Mod *m = module_at(pc);
    return m && m->crt;
}

bool captured_from_system() { return ts().sys_owned != 0; }

uint32_t trim_system(uintptr_t *frames, uint32_t n) {
    // Who made the allocation: the first caller that is not the C runtime itself.
    bool owned = false;
    for (uint32_t i = 0; i < n; ++i) {
        if (is_crt_pc(frames[i]))
            continue;
        owned = is_system_pc(frames[i]);
        break;
    }
    ts().sys_owned = owned;
    uint32_t first = 0, last = n;
    while (first < n && is_system_pc(frames[first]))
        ++first;
    if (first == n) // nothing of the program's own: keep what there is
        return n;
    while (last > first + 1 && is_system_pc(frames[last - 1]))
        --last;
    if (first)
        memmove(frames, frames + first, (last - first) * sizeof(uintptr_t));
    return last - first;
}

void install_hooks(const Hook *hooks, size_t n) {
    GetWindowsDirectoryW(g_windir, MAX_PATH);
    g_windir_len = wcslen(g_windir);
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    real_GetProcAddress = proc_address<decltype(real_GetProcAddress)>(k32, "GetProcAddress");
    real_LoadLibraryA = proc_address<decltype(real_LoadLibraryA)>(k32, "LoadLibraryA");
    real_LoadLibraryW = proc_address<decltype(real_LoadLibraryW)>(k32, "LoadLibraryW");
    real_LoadLibraryExA = proc_address<decltype(real_LoadLibraryExA)>(k32, "LoadLibraryExA");
    real_LoadLibraryExW = proc_address<decltype(real_LoadLibraryExW)>(k32, "LoadLibraryExW");
    // The table lives for the whole run: the caller's hooks, then the loader's.
    static Hook all[512];
    size_t k = 0;
    for (size_t i = 0; i < n && k + 8 < 512; ++i)
        all[k++] = hooks[i];
    for (const Hook &h : g_loader_hooks)
        all[k++] = h;
    g_hooks = all;
    g_nhooks = k;
    rebuild_system_ranges();
    using Register = LONG(NTAPI *)(ULONG, void (CALLBACK *)(ULONG, const DllNotification *, PVOID), PVOID, PVOID *);
    static PVOID cookie;
    if (auto reg = proc_address<Register>(GetModuleHandleW(L"ntdll.dll"), "LdrRegisterDllNotification"))
        reg(0, dll_changed, nullptr, &cookie);
    patch_all();
}

void patch_new_modules() {
    if (!g_nhooks)
        return;
    patch_all();
    rebuild_system_ranges();
}

} // namespace lc::win
