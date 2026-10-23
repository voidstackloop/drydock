// The runtime primitives of rt.h on Windows (rt.cpp is the Linux side).
#include "rt.h"
#include "heap.h"
#include "protocol.h"
#include "win_heap.h"
#include "win_hooks.h"

#include <algorithm>
#include <cerrno>
#include <intrin.h>
#include <cstdlib>
#include <cstring>

namespace lc {

Config g_cfg;
uint32_t g_self_pid;
uint32_t g_fork_tid;

namespace {
DWORD g_slot = TLS_OUT_OF_INDEXES;
SpinLock g_ts_lock;
ThreadState *g_ts_free;
char *g_ts_chunk;
size_t g_ts_left;

ThreadState *ts_create() {
    ThreadState *s;
    {
        LockGuard g(g_ts_lock);
        if (g_ts_free) {
            s = g_ts_free;
            g_ts_free = *reinterpret_cast<ThreadState **>(s);
            memset(s, 0, sizeof *s);
        } else {
            if (g_ts_left < sizeof(ThreadState)) {
                g_ts_chunk = static_cast<char *>(VirtualAlloc(nullptr, 1 << 16, MEM_RESERVE | MEM_COMMIT,
                                                              PAGE_READWRITE));
                if (!g_ts_chunk)
                    TerminateProcess(GetCurrentProcess(), 70);
                g_ts_left = 1 << 16;
            }
            s = reinterpret_cast<ThreadState *>(g_ts_chunk);
            g_ts_chunk += sizeof(ThreadState);
            g_ts_left -= sizeof(ThreadState);
        }
    }
    TlsSetValue(g_slot, s);
    return s;
}
} // namespace

void ts_init() {
    if (g_slot == TLS_OUT_OF_INDEXES)
        g_slot = TlsAlloc();
}

// TlsGetValue sets the last error to 0 when it succeeds, and every hook asks for
// the thread's state: read the slot straight from the thread block (TEB.TlsSlots
// is at 0x1480 on x64) so the program's last error survives.
ThreadState &ts() {
    void *p;
    if (LC_LIKELY(g_slot < 64)) {
        p = reinterpret_cast<void *>(__readgsqword(0x1480 + g_slot * 8));
    } else {
        const DWORD e = GetLastError();
        p = TlsGetValue(g_slot);
        SetLastError(e);
    }
    return LC_LIKELY(p != nullptr) ? *static_cast<ThreadState *>(p) : *ts_create();
}

void ts_exit() {
    if (g_slot == TLS_OUT_OF_INDEXES)
        return;
    auto *s = static_cast<ThreadState *>(g_slot < 64 ? reinterpret_cast<void *>(__readgsqword(0x1480 + g_slot * 8))
                                                      : TlsGetValue(g_slot));
    if (!s)
        return;
    TlsSetValue(g_slot, nullptr);
    LockGuard g(g_ts_lock);
    *reinterpret_cast<ThreadState **>(s) = g_ts_free;
    g_ts_free = s;
}

size_t page_size() {
    static size_t cached = 0;
    if (LC_UNLIKELY(!cached)) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        cached = si.dwPageSize ? si.dwPageSize : 4096;
    }
    return cached;
}

namespace {
constexpr size_t kMaxRanges = 1 << 16;
SpinLock g_ranges_lock;
Range g_ranges[kMaxRanges];
size_t g_nranges;
} // namespace

// Pages from VirtualAlloc, not from the heap being watched.
void *map_pages(size_t bytes) {
    if (!bytes)
        bytes = 1;
    bytes = round_up(bytes, page_size());
    void *p = VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!p)
        return nullptr;
    LockGuard g(g_ranges_lock);
    if (g_nranges < kMaxRanges)
        g_ranges[g_nranges++] = Range{uintptr_t(p), uintptr_t(p) + bytes};
    return p;
}

void unmap_pages(void *p, size_t bytes) {
    if (!p)
        return;
    (void)bytes;
    VirtualFree(p, 0, MEM_RELEASE);
    LockGuard g(g_ranges_lock);
    for (size_t i = 0; i < g_nranges; ++i) {
        if (g_ranges[i].lo == uintptr_t(p)) {
            g_ranges[i] = g_ranges[--g_nranges];
            break;
        }
    }
}

size_t runtime_ranges(Range *out, size_t max) {
    size_t n;
    {
        LockGuard g(g_ranges_lock);
        n = g_nranges < max ? g_nranges : max;
        for (size_t i = 0; i < n; ++i)
            out[i] = g_ranges[i];
    }
    std::sort(out, out + n, [](const Range &a, const Range &b) { return a.lo < b.lo; });
    return n;
}

void ranges_lock() { g_ranges_lock.lock(); }
void ranges_unlock() { g_ranges_lock.unlock(); }
void ranges_reset_lock() { g_ranges_lock.reset(); }

void yield_thread() { SwitchToThread(); }

uint32_t current_tid() { return GetCurrentThreadId(); }

uint32_t process_id() { return GetCurrentProcessId(); }

// The Windows "errno" a hook must not disturb is the last error.
ErrnoSaver::ErrnoSaver() : saved_(int(GetLastError())) {}
ErrnoSaver::~ErrnoSaver() { SetLastError(DWORD(saved_)); }
void set_errno(int e) { SetLastError(e == ENOMEM ? ERROR_NOT_ENOUGH_MEMORY : DWORD(e)); }

void die(const char *msg) {
    char b[512];
    Buf out(b, sizeof b);
    out.s("leakcheck: fatal: ").s(msg).c('\n');
    write_all(2, out.data(), out.size());
    TerminateProcess(GetCurrentProcess(), 70);
    for (;;) {
    }
}

bool write_all(int fd, const char *p, size_t n) {
    HANDLE h = GetStdHandle(fd == 1 ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
    while (n) {
        DWORD w = 0;
        if (!WriteFile(h, p, DWORD(n > 1u << 20 ? 1u << 20 : n), &w, nullptr) || !w)
            return false;
        p += w;
        n -= w;
    }
    return true;
}

const char *env_str(const char *name) {
    static char buf[1024]; // one value at a time; callers copy it at once
    DWORD n = GetEnvironmentVariableA(name, buf, sizeof buf);
    return n && n < sizeof buf ? buf : nullptr;
}

uint64_t env_u64(const char *name, uint64_t def) {
    char v[64];
    DWORD n = GetEnvironmentVariableA(name, v, sizeof v);
    if (!n || n >= sizeof v)
        return def;
    uint64_t r = 0;
    for (const char *s = v; *s; ++s) {
        if (*s < '0' || *s > '9')
            return def;
        r = r * 10 + uint64_t(*s - '0');
    }
    return r;
}

void load_config() {
    using namespace lcproto;
    Config &c = g_cfg;
    g_self_pid = GetCurrentProcessId();
    c.quarantine_bytes = env_u64(kEnvQuarantineMb, 64) << 20;
    uint64_t depth = env_u64(kEnvStackDepth, 24);
    c.stack_depth = uint32_t(depth < 1 ? 1 : depth > 64 ? 64 : depth);
    c.guard_every = uint32_t(env_u64(kEnvGuardEvery, 0));
    c.abort_on_error = env_u64(kEnvAbort, 0) != 0;
    c.fast_unwind = env_u64(kEnvFastUnwind, 0) != 0;
    c.leak_check = env_u64(kEnvLeaks, 1) != 0;
    c.show_reachable = env_u64(kEnvReachable, 0) != 0;
    c.trace_children = env_u64(kEnvTraceChildren, 0) != 0;
    c.malware = env_u64(kEnvMalware, 0) != 0;
    c.dangling = false; // not offered on Windows
    c.root_pid = uint32_t(env_u64(kEnvRootPid, 0));
    c.active = c.root_pid == 0 || c.root_pid == g_self_pid || c.trace_children;
    c.report_enabled = c.active;
    if (!c.active)
        return;
    c.report_fd = 2;
    char path[sizeof c.report_path];
    DWORD n = GetEnvironmentVariableA(kEnvReport, path, sizeof path);
    if (n && n < sizeof path)
        strcpy(c.report_path, path);
}

// The report file is reopened for each write, so a program that closes its
// handles cannot silence it.
bool append_report(const char *p, size_t n) {
    if (!g_cfg.report_path[0])
        return write_all(g_cfg.report_fd, p, n);
    HANDLE h = CreateFileA(g_cfg.report_path, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    bool ok = true;
    while (n && ok) {
        DWORD w = 0;
        ok = WriteFile(h, p, DWORD(n > 1u << 20 ? 1u << 20 : n), &w, nullptr) && w;
        p += w;
        n -= w;
    }
    CloseHandle(h);
    return ok;
}

// The runtime's own small allocations go to the real heap, untracked: the hooks
// do not run for them (tl_in_hook), so nothing needs a private arena.
namespace ih {
bool owns(const void *) { return false; }
void *alloc(size_t size, size_t) { return win::real_HeapAlloc(win::process_heap(), 0, size); }
void free(void *p) { win::real_HeapFree(win::process_heap(), 0, p); }
size_t usable(const void *p) { return win::real_HeapSize(win::process_heap(), 0, p); }
bool used_range(uintptr_t *, uintptr_t *) { return false; }
bool full_range(uintptr_t *, uintptr_t *) { return false; } // no private arena to exclude
void lock() {}
void unlock() {}
void reset_lock() {}
} // namespace ih

} // namespace lc

// The allocator under heap.cpp: the real process heap.
extern "C" {
void *__libc_malloc(size_t n) { return lc::win::real_HeapAlloc(lc::win::process_heap(), 0, n); }
void *__libc_calloc(size_t a, size_t b) {
    size_t n;
    if (__builtin_mul_overflow(a, b, &n))
        return nullptr;
    return lc::win::real_HeapAlloc(lc::win::process_heap(), HEAP_ZERO_MEMORY, n);
}
void *__libc_realloc(void *p, size_t n) {
    return p ? lc::win::real_HeapReAlloc(lc::win::process_heap(), 0, p, n) : __libc_malloc(n);
}
void *__libc_memalign(size_t align, size_t n) {
    return align <= 16 ? __libc_malloc(n) : nullptr; // Windows' own heap aligns to 16 only
}
void __libc_free(void *p) { lc::win::real_HeapFree(lc::win::process_heap(), 0, p); }
}
