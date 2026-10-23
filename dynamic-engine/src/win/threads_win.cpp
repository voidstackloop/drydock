// The stacks of the program's threads (threads.h) on Windows: the thread
// environment blocks (TEB) say where each one starts and ends, and they are
// found at load time (Toolhelp) and by the loader's thread attach calls.
#include "threads.h"
#include "win_hooks.h"

#include <tlhelp32.h>

namespace lc::threads {
namespace {

struct Entry {
    uint32_t tid;
    uintptr_t teb;
};

constexpr size_t kMax = 4096;
SpinLock g_lock;
Entry g_ent[kMax];
size_t g_n;

// TEB.DeallocationStack: the lowest address ever reserved for the stack.
constexpr size_t kDeallocationStackOffset = 0x1478;

struct ThreadBasic {
    LONG status;
    PVOID teb;
    PVOID pid, tid;
    ULONG_PTR affinity;
    LONG priority, base_priority;
};

uintptr_t teb_of_thread(uint32_t tid) {
    using Query = LONG(WINAPI *)(HANDLE, int, PVOID, ULONG, PULONG);
    static Query query = win::proc_address<Query>(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");
    HANDLE h = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!h)
        return 0;
    ThreadBasic tb = {};
    const bool ok = query && query(h, 0, &tb, sizeof tb, nullptr) >= 0;
    CloseHandle(h);
    return ok ? uintptr_t(tb.teb) : 0;
}

void add(uint32_t tid, uintptr_t teb) {
    if (!teb)
        return;
    LockGuard g(g_lock);
    for (size_t i = 0; i < g_n; ++i)
        if (g_ent[i].tid == tid) {
            g_ent[i].teb = teb;
            return;
        }
    if (g_n < kMax)
        g_ent[g_n++] = Entry{tid, teb};
}

bool bounds_of(uintptr_t teb, uintptr_t *lo, uintptr_t *hi) {
    const NT_TIB *tib = reinterpret_cast<const NT_TIB *>(teb);
    *lo = uintptr_t(tib->StackLimit);
    *hi = uintptr_t(tib->StackBase);
    return *hi > *lo;
}

} // namespace

// The threads that exist when the runtime loads; later ones announce themselves.
void init() {
    const DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;
    THREADENTRY32 te;
    te.dwSize = sizeof te;
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te))
        if (te.th32OwnerProcessID == pid)
            add(te.th32ThreadID, teb_of_thread(te.th32ThreadID));
    CloseHandle(snap);
}

void register_current(uint32_t, bool) {
    add(current_tid(), uintptr_t(NtCurrentTeb()));
}

void unregister_current() {
    const uint32_t me = current_tid();
    LockGuard g(g_lock);
    for (size_t i = 0; i < g_n; ++i)
        if (g_ent[i].tid == me) {
            g_ent[i] = g_ent[--g_n];
            return;
        }
}

bool current_bounds(uintptr_t *lo, uintptr_t *hi) {
    return bounds_of(uintptr_t(NtCurrentTeb()), lo, hi);
}

bool find_stack(uintptr_t addr, uint32_t *tid) {
    LockGuard g(g_lock);
    for (size_t i = 0; i < g_n; ++i) {
        uintptr_t lo, hi;
        if (!bounds_of(g_ent[i].teb, &lo, &hi))
            continue;
        lo = *reinterpret_cast<const uintptr_t *>(g_ent[i].teb + kDeallocationStackOffset);
        if (addr >= lo && addr < hi) {
            *tid = g_ent[i].tid;
            return true;
        }
    }
    return false;
}

size_t snapshot(Range *out, size_t max) {
    LockGuard g(g_lock);
    size_t n = 0;
    for (size_t i = 0; i < g_n && n < max; ++i) {
        uintptr_t lo, hi;
        if (bounds_of(g_ent[i].teb, &lo, &hi))
            out[n++] = Range{lo, hi, g_ent[i].tid};
    }
    return n;
}

void after_fork_child() {}
void lock() { g_lock.lock(); }
void unlock() { g_lock.unlock(); }
void reset_lock() { g_lock.reset(); }

} // namespace lc::threads
