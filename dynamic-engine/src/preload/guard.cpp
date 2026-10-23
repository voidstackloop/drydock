// The macOS SDK hides the deprecated ucontext routines (used for the saved
// signal context) behind _XOPEN_SOURCE, and that in turn hides the BSD mmap
// flags and madvise() this file needs, so ask for both. It has to come before
// any include.
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#define _XOPEN_SOURCE 700
#endif

#include "guard.h"
#include "protocol.h"
#include "report.h"
#include "stacks.h"

#include <csignal>
#include <cstring>
#include <execinfo.h>
#include <sys/mman.h>
#include <ucontext.h>

namespace lc::guard {
namespace {

uint64_t g_counter;
uint64_t g_live;
struct sigaction g_prev;
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

uintptr_t fault_pc(void *uctx, bool *is_write) {
    auto *uc = static_cast<ucontext_t *>(uctx);
    *is_write = false;
#if defined(__APPLE__) && defined(__x86_64__)
    *is_write = (uc->uc_mcontext->__es.__err & 2) != 0;
    return uintptr_t(uc->uc_mcontext->__ss.__rip);
#elif defined(__APPLE__) && defined(__aarch64__)
    *is_write = (uc->uc_mcontext->__es.__esr & (1u << 6)) != 0;
    return uintptr_t(uc->uc_mcontext->__ss.__pc);
#elif defined(__x86_64__)
    *is_write = (uc->uc_mcontext.gregs[REG_ERR] & 2) != 0;
    return uintptr_t(uc->uc_mcontext.gregs[REG_RIP]);
#elif defined(__aarch64__)
    return uintptr_t(uc->uc_mcontext.pc);
#else
    (void)uc;
    return 0;
#endif
}

void chain(int sig, siginfo_t *si, void *uctx) {
    if (g_prev.sa_flags & SA_SIGINFO) {
        if (g_prev.sa_sigaction) {
            g_prev.sa_sigaction(sig, si, uctx);
            return;
        }
    } else if (g_prev.sa_handler != SIG_DFL && g_prev.sa_handler != SIG_IGN) {
        g_prev.sa_handler(sig);
        return;
    }
    // Default action: returning re-executes the faulting access and kills us.
    signal(sig, SIG_DFL);
}

void on_segv(int sig, siginfo_t *si, void *uctx) {
    ErrnoSaver es;
    HookGuard hg;
    const uintptr_t addr = reinterpret_cast<uintptr_t>(si->si_addr);
    Block b;
    Where where;
    if (!classify(addr, &b, &where) ||
        (b.state == State::Live && where == Where::Data)) {
        chain(sig, si, uctx);
        return;
    }

    bool is_write;
    const uintptr_t pc = fault_pc(uctx, &is_write);
    uintptr_t frames[stacks::kMaxDepth + 1];
    void *raw[stacks::kMaxDepth + 16];
    int n = backtrace(raw, int(stacks::kMaxDepth + 16));
    uint32_t m = 0;
    if (pc)
        frames[m++] =
            pc + 1; // stored as a return address; the reader subtracts 1
    int start = 0;
    for (int i = 0; i < n; ++i)
        if (reinterpret_cast<uintptr_t>(raw[i]) == pc) {
            start = i + 1;
            break;
        }
    for (int i = start; i < n && m <= g_cfg.stack_depth; ++i) {
        uintptr_t f = reinterpret_cast<uintptr_t>(raw[i]);
        if (start == 0 && stacks::in_self(f))
            continue;
        frames[m++] = f;
    }

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
        msg.s(rw)
            .s(" at ")
            .u(addr - (b.user + b.size))
            .s(" byte(s) after the end of a ");
        msg.u(b.size).s("-byte block (guard page)");
    } else {
        f.type = lcproto::kUnderflow;
        msg.s(rw)
            .s(" at ")
            .u(b.user - addr)
            .s(" byte(s) before the start of a ");
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
    mprotect(reinterpret_cast<void *>(addr & ~(pg - 1)), pg,
             PROT_READ | PROT_WRITE);
}

} // namespace

void init() {
    if (!g_cfg.guard_every || g_installed)
        return;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, &g_prev) == 0)
        g_installed = true;
}

bool want(size_t size, size_t align) {
    const uint32_t every = g_cfg.guard_every;
    if (!every || !g_installed || align > page_size() ||
        size > (size_t(1) << 32))
        return false;
    if (__atomic_add_fetch(&g_counter, 1, __ATOMIC_RELAXED) % every)
        return false;
    return __atomic_load_n(&g_live, __ATOMIC_RELAXED) < g_cfg.guard_max_live;
}

bool alloc(size_t size, size_t align, uintptr_t *base, uint64_t *total,
           uintptr_t *user) {
    const size_t pg = page_size();
    const size_t rsize = round_up(size ? size : 1, align);
    const size_t data = round_up(rsize, pg);
    const size_t len = data + 2 * pg;
    void *m = mmap(nullptr, len, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (m == MAP_FAILED)
        return false;
    byte *mb = static_cast<byte *>(m);
    if (mprotect(mb + pg, data, PROT_READ | PROT_WRITE) != 0) {
        munmap(m, len);
        return false;
    }
    *base = reinterpret_cast<uintptr_t>(mb);
    *total = len;
    *user = reinterpret_cast<uintptr_t>(mb + pg + data - rsize);
    __atomic_add_fetch(&g_live, 1, __ATOMIC_RELAXED);
    return true;
}

void on_free(const Block &b) {
    const size_t pg = page_size();
    void *data = reinterpret_cast<void *>(b.base + pg);
    const size_t len = b.total - 2 * pg;
    madvise(data, len, MADV_DONTNEED);
    mprotect(data, len, PROT_NONE);
    __atomic_sub_fetch(&g_live, 1, __ATOMIC_RELAXED);
}

void release(const Block &b) {
    munmap(reinterpret_cast<void *>(b.base), b.total);
}

} // namespace lc::guard
