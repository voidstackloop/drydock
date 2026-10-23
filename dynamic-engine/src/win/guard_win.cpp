// Guard pages on Windows (guard.cpp is the Linux side): a sampled block gets
// its own reservation with inaccessible pages around it, and a vectored
// exception handler turns the access violation into a report.
#include "guard.h"
#include "protocol.h"
#include "report.h"
#include "stacks.h"
#include "win_hooks.h"

#include <cstring>

namespace lc::guard {
namespace {

uint64_t g_counter;
uint64_t g_live;
bool g_installed;

enum class Where { LeftGuard, Data, RightGuard };

bool classify(uintptr_t addr, Block *out, Where *where) {
    const size_t pg = page_size();
    bool found = false;
    blocks::lock_all();
    for (size_t s = 0; s < blocks::kShards && !found; ++s) {
        size_t cap;
        Block *slots = blocks::shard_slots(s, &cap);
        for (size_t i = 0; i < cap; ++i) {
            const Block &b = slots[i];
            if (!b.user || !(b.flags & kFlagGuarded))
                continue;
            if (addr < b.base || addr >= b.base + b.total)
                continue;
            *out = b;
            if (addr < b.base + pg)
                *where = Where::LeftGuard;
            else if (addr >= b.base + b.total - pg)
                *where = Where::RightGuard;
            else
                *where = Where::Data;
            found = true;
            break;
        }
    }
    blocks::unlock_all();
    return found;
}

LONG CALLBACK on_fault(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION ||
        ep->ExceptionRecord->NumberParameters < 2 || tl_in_hook)
        return EXCEPTION_CONTINUE_SEARCH;
    const uintptr_t addr = uintptr_t(ep->ExceptionRecord->ExceptionInformation[1]);
    const bool is_write = ep->ExceptionRecord->ExceptionInformation[0] == 1;
    HookGuard hg;
    ErrnoSaver es;
    Block b;
    Where where;
    if (!classify(addr, &b, &where) || (b.state == State::Live && where == Where::Data))
        return EXCEPTION_CONTINUE_SEARCH;

    const uintptr_t pc = uintptr_t(ep->ContextRecord->Rip);
    uintptr_t frames[stacks::kMaxDepth + 1];
    uintptr_t raw[stacks::kMaxDepth + 16];
    uint32_t n = win::capture_frames(raw, stacks::kMaxDepth + 16);
    n = stacks::trim_self(raw, n);
    uint32_t m = 0;
    if (pc)
        frames[m++] = pc + 1; // stored as a return address; the reader subtracts 1
    for (uint32_t i = (n && raw[0] == pc) ? 1 : 0; i < n && m <= g_cfg.stack_depth; ++i)
        frames[m++] = raw[i];
    m = win::trim_system(frames + 1, m - 1) + 1;

    char text[320];
    Buf msg(text, sizeof text);
    const char *rw = is_write ? "write" : "read";
    report::Finding f;
    if (b.state == State::Freed) {
        f.type = lcproto::kUseAfterFree;
        msg.s(rw).s(" of freed memory at offset ");
        if (addr >= b.user)
            msg.u(addr - b.user);
        else
            msg.c('-').u(b.user - addr);
        msg.s(" of a freed ").u(b.size).s("-byte block (guard page)");
        f.free_stack = b.free_stack;
    } else if (where == Where::RightGuard) {
        f.type = lcproto::kOverflow;
        msg.s(rw).s(" at ").u(addr - (b.user + b.size)).s(" byte(s) after the end of a ");
        msg.u(b.size).s("-byte block (guard page)");
    } else {
        f.type = lcproto::kUnderflow;
        msg.s(rw).s(" at ").u(b.user - addr).s(" byte(s) before the start of a ");
        msg.u(b.size).s("-byte block (guard page)");
    }
    f.addr = addr;
    f.size = b.size;
    f.tid = current_tid();
    f.msg = msg.cstr();
    f.access_frames = frames;
    f.access_n = m;
    f.alloc_stack = b.alloc_stack;
    f.fatal = true;
    report::emit(f);

    // Report once, then let the program run on as it would have without us.
    const size_t pg = page_size();
    VirtualAlloc(reinterpret_cast<void *>(addr & ~(pg - 1)), pg, MEM_COMMIT, PAGE_READWRITE);
    return EXCEPTION_CONTINUE_EXECUTION;
}

} // namespace

void init() {
    if (!g_cfg.guard_every || g_installed)
        return;
    g_installed = AddVectoredExceptionHandler(1, on_fault) != nullptr;
}

bool want(size_t size, size_t align) {
    const uint32_t every = g_cfg.guard_every;
    if (!every || !g_installed || align > page_size() || size > (size_t(1) << 32))
        return false;
    if (__atomic_add_fetch(&g_counter, 1, __ATOMIC_RELAXED) % every)
        return false;
    return __atomic_load_n(&g_live, __ATOMIC_RELAXED) < g_cfg.guard_max_live;
}

bool alloc(size_t size, size_t align, uintptr_t *base, uint64_t *total, uintptr_t *user) {
    const size_t pg = page_size();
    const size_t rsize = round_up(size ? size : 1, align);
    const size_t data = round_up(rsize, pg);
    const size_t len = data + 2 * pg;
    byte *mb = static_cast<byte *>(VirtualAlloc(nullptr, len, MEM_RESERVE, PAGE_NOACCESS));
    if (!mb)
        return false;
    if (!VirtualAlloc(mb + pg, data, MEM_COMMIT, PAGE_READWRITE)) {
        VirtualFree(mb, 0, MEM_RELEASE);
        return false;
    }
    *base = reinterpret_cast<uintptr_t>(mb);
    *total = len;
    *user = reinterpret_cast<uintptr_t>(mb + pg + data - rsize);
    __atomic_add_fetch(&g_live, 1, __ATOMIC_RELAXED);
    return true;
}

// The data pages go back to the system: touching them is an access violation.
void on_free(const Block &b) {
    const size_t pg = page_size();
    VirtualFree(reinterpret_cast<void *>(b.base + pg), size_t(b.total - 2 * pg), MEM_DECOMMIT);
    __atomic_sub_fetch(&g_live, 1, __ATOMIC_RELAXED);
}

void release(const Block &b) { VirtualFree(reinterpret_cast<void *>(b.base), 0, MEM_RELEASE); }

} // namespace lc::guard
