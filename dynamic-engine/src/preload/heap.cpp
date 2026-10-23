#include "heap.h"
#include "guard.h"
#include "locks.h"
#include "protocol.h"
#include "stacks.h"
#include "threads.h"

#include <cstring>
#ifdef _WIN32
#include "win_heap.h"
#include "win_hooks.h"
#else
#if !defined(__APPLE__)
#include <link.h>
#endif
#endif

namespace lc {
namespace {

using namespace lcproto;

struct Counters {
    uint64_t allocs, frees, bytes, live_blocks, live_bytes, peak_bytes;
};
Counters g_ctr;
uint64_t g_seq;

struct QEntry {
    uintptr_t user;
    uint64_t seq;
    uint64_t retained;
};
SpinLock g_qlock;
QEntry *g_q;
size_t g_qcap, g_qhead, g_qcount;
uint64_t g_qbytes;

void stats_on_free(uint64_t size) {
    __atomic_add_fetch(&g_ctr.frees, 1, __ATOMIC_RELAXED);
    __atomic_sub_fetch(&g_ctr.live_blocks, 1, __ATOMIC_RELAXED);
    __atomic_sub_fetch(&g_ctr.live_bytes, size, __ATOMIC_RELAXED);
}

void q_push(const QEntry &e) {
    LockGuard g(g_qlock);
    if (g_qcount == g_qcap) {
        size_t ncap = g_qcap ? g_qcap * 2 : 4096;
        auto *nq = static_cast<QEntry *>(map_pages(ncap * sizeof(QEntry)));
        if (!nq)
            die("out of memory for quarantine");
        for (size_t i = 0; i < g_qcount; ++i)
            nq[i] = g_q[(g_qhead + i) % g_qcap];
        unmap_pages(g_q, g_qcap * sizeof(QEntry));
        g_q = nq;
        g_qcap = ncap;
        g_qhead = 0;
    }
    g_q[(g_qhead + g_qcount) % g_qcap] = e;
    ++g_qcount;
    g_qbytes += e.retained;
}

bool q_pop_if_over(QEntry *out) {
    LockGuard g(g_qlock);
    if (!g_qcount || (g_qbytes <= g_cfg.quarantine_bytes &&
                      g_qcount <= g_cfg.quarantine_entries))
        return false;
    *out = g_q[g_qhead];
    g_qhead = (g_qhead + 1) % g_qcap;
    --g_qcount;
    g_qbytes -= out->retained;
    return true;
}

struct Zones {
    byte *l;
    size_t ln;
    byte *r;
    size_t rn;
};

Zones zones_of(const Block &b) {
    byte *user = reinterpret_cast<byte *>(b.user);
    if (!(b.flags & kFlagGuarded))
        return Zones{user - kRedzone, kRedzone, user + b.size, kRedzone};
    const size_t pg = page_size();
    byte *data_lo = reinterpret_cast<byte *>(b.base) + pg;
    byte *data_hi = reinterpret_cast<byte *>(b.base) + b.total - pg;
    byte *l = user - kRedzone < data_lo ? data_lo : user - kRedzone;
    byte *r = user + b.size;
    size_t rn = size_t(data_hi - r);
    return Zones{l, size_t(user - l), r, rn < kRedzone ? rn : kRedzone};
}

// rz_byte() repeats every 16 bytes, so the redzone can be written and checked
// a whole run at a time: these run once per allocation and once per release,
// where a byte loop with a call per byte was a large part of the overhead.
constexpr size_t kRzPeriod = 16;

void pattern_run(byte *out, uint8_t base) {
    for (size_t i = 0; i < kRzPeriod; ++i)
        out[i] = rz_byte(i, base);
}

// Returns the number of corrupted bytes; *lo/*hi = first/last bad index.
size_t check_pattern(const byte *p, size_t n, uint8_t base, size_t *lo,
                     size_t *hi) {
    byte want[kRzPeriod];
    pattern_run(want, base);
    size_t bad = 0;
    size_t i = 0;
    for (; i + kRzPeriod <= n; i += kRzPeriod) {
        if (memcmp(p + i, want, kRzPeriod) == 0)
            continue;
        for (size_t j = i; j < i + kRzPeriod; ++j) {
            if (p[j] != want[j - i]) {
                if (!bad)
                    *lo = j;
                *hi = j;
                ++bad;
            }
        }
    }
    for (; i < n; ++i) {
        if (p[i] != want[i % kRzPeriod]) {
            if (!bad)
                *lo = i;
            *hi = i;
            ++bad;
        }
    }
    return bad;
}

void fill_zones(const Block &b) {
    Zones z = zones_of(b);
    fill_rz(z.l, z.ln, kLeftBase);
    fill_rz(z.r, z.rn, kRightBase);
}

void report_overflow(const Block &b, uint32_t access_stack, const char *when) {
    Zones z = zones_of(b);
    size_t lo = 0, hi = 0;
    char m[256];
    if (size_t bad = check_pattern(z.r, z.rn, kRightBase, &lo, &hi)) {
        Buf msg(m, sizeof m);
        msg.u(hi + 1).s(" byte(s) written past the end of a ").u(b.size);
        msg.s("-byte block (")
            .u(bad)
            .s(" corrupted redzone byte(s), detected ")
            .s(when)
            .c(')');
        report::Finding f;
        f.type = kOverflow;
        f.addr = b.user;
        f.size = b.size;
        f.tid = current_tid();
        f.msg = msg.cstr();
        f.access_stack = access_stack;
        f.alloc_stack = b.alloc_stack;
        f.fatal = true;
        report::emit(f);
    }
    if (size_t bad = check_pattern(z.l, z.ln, kLeftBase, &lo, &hi)) {
        Buf msg(m, sizeof m);
        msg.u(z.ln - lo).s(" byte(s) written before the start of a ").u(b.size);
        msg.s("-byte block (")
            .u(bad)
            .s(" corrupted redzone byte(s), detected ")
            .s(when)
            .c(')');
        report::Finding f;
        f.type = kUnderflow;
        f.addr = b.user;
        f.size = b.size;
        f.tid = current_tid();
        f.msg = msg.cstr();
        f.access_stack = access_stack;
        f.alloc_stack = b.alloc_stack;
        f.fatal = true;
        report::emit(f);
    }
}

bool poison_check(const Block &b, const char *when) {
    const byte *p = reinterpret_cast<const byte *>(b.user);
    const size_t n = b.size < kPoisonMax ? b.size : kPoisonMax;
    size_t first = 0, last = 0, bad = 0;
    // A freed block is normally untouched, so test it a machine word at a
    // time and only look at the bytes of the words that differ. This runs for
    // every block that leaves quarantine, over up to a megabyte.
    constexpr size_t kWord = sizeof(uintptr_t);
    const uintptr_t want = uintptr_t(kPoison) * 0x0101010101010101ULL;
    size_t i = 0;
    for (; i + kWord <= n; i += kWord) {
        uintptr_t w;
        memcpy(&w, p + i, kWord);
        if (w == want)
            continue;
        for (size_t j = i; j < i + kWord; ++j) {
            if (p[j] != kPoison) {
                if (!bad)
                    first = j;
                last = j;
                ++bad;
            }
        }
    }
    for (; i < n; ++i) {
        if (p[i] != kPoison) {
            if (!bad)
                first = i;
            last = i;
            ++bad;
        }
    }
    if (!bad)
        return true;
    char m[256];
    Buf msg(m, sizeof m);
    msg.s("write to freed memory: ").u(bad).s(" byte(s) of a freed ").u(b.size);
    msg.s("-byte block changed after free (offsets ").u(first).s("..").u(last);
    msg.s("), detected ").s(when);
    report::Finding f;
    f.type = kUseAfterFree;
    f.addr = b.user + first;
    f.size = b.size;
    f.tid = current_tid();
    f.msg = msg.cstr();
    f.alloc_stack = b.alloc_stack;
    f.free_stack = b.free_stack;
    f.fatal = true;
    report::emit(f);
    return false;
}

void release_memory(const Block &b) {
    if (b.flags & kFlagGuarded)
        guard::release(b);
    else if (!(b.flags & kFlagReleased))
        __libc_free(reinterpret_cast<void *>(b.base));
}

void finalize(const Block &b) {
    if (!(b.flags & (kFlagGuarded | kFlagReleased)))
        poison_check(b, "when the block left quarantine");
    release_memory(b);
}

void evict() {
    QEntry e;
    while (q_pop_if_over(&e)) {
        Block old;
        if (blocks::remove(e.user, &old, e.seq))
            finalize(old);
    }
}

void retire(const Block &b) {
    if (g_cfg.quarantine_bytes == 0) {
        Block old;
        if (blocks::remove(b.user, &old, b.seq)) {
            if (old.flags & kFlagGuarded)
                guard::on_free(old);
            release_memory(old);
        }
        return;
    }
    uint64_t retained = b.total;
    if (b.flags & kFlagGuarded) {
        guard::on_free(b);
    } else if (retained <= g_cfg.quarantine_bytes / 4) {
        memset(reinterpret_cast<void *>(b.user), kPoison,
               b.size < kPoisonMax ? b.size : kPoisonMax);
    } else {
        // Too big to hold on to: keep only the record for double-free checks.
        {
            blocks::Handle h = blocks::lookup(b.user);
            if (h.get())
                h.get()->flags |= kFlagReleased;
        }
        __libc_free(reinterpret_cast<void *>(b.base));
        retained = 0;
    }
    q_push(QEntry{b.user, b.seq, retained});
    evict();
}

const char *dekind_name(DeKind d) {
    switch (d) {
    case DeKind::Free:
        return "free()";
    case DeKind::Delete:
        return "operator delete";
    case DeKind::DeleteArray:
        return "operator delete[]";
    case DeKind::Any:
        return "HeapFree()";
    }
    return "free()";
}

bool compatible(Kind k, DeKind d) {
    if (d == DeKind::Any) // released by the Windows heap API itself: no family to compare
        return true;
    switch (k) {
    case Kind::Malloc:
    case Kind::Memalign:
        return d == DeKind::Free;
    case Kind::New:
        return d == DeKind::Delete;
    case Kind::NewArray:
        return d == DeKind::DeleteArray;
    default:
        return true;
    }
}

struct ModHit {
    uintptr_t addr;
    const char *name;
    bool found;
};

#ifdef _WIN32
void find_module(ModHit *hit) {
    static char path[512];
    hit->found = win::module_of(hit->addr, path, sizeof path);
    hit->name = path;
}
#elif defined(__APPLE__)
int mod_one(const stacks::ImageView &im, void *data) {
    auto *hit = static_cast<ModHit *>(data);
    if (hit->addr < im.lo || hit->addr >= im.hi)
        return 0;
    hit->name = im.name[0] ? im.name : "the main executable";
    hit->found = true;
    return 1;
}
void find_module(ModHit *hit) { stacks::for_each_image(mod_one, hit); }
#else
int mod_cb(struct dl_phdr_info *info, size_t, void *data) {
    auto *hit = static_cast<ModHit *>(data);
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const auto &ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD)
            continue;
        uintptr_t a = info->dlpi_addr + ph.p_vaddr;
        if (hit->addr >= a && hit->addr < a + ph.p_memsz) {
            hit->name = (info->dlpi_name && *info->dlpi_name)
                            ? info->dlpi_name
                            : "the main executable";
            hit->found = true;
            return 1;
        }
    }
    return 0;
}
#endif

// Finds a tracked block containing addr (not at its start).
bool find_enclosing(uintptr_t addr, Block *out) {
    // Linear over every block: only runs on the error path.
    blocks::lock_all();
    bool found = false;
    for (size_t s = 0; s < blocks::kShards && !found; ++s) {
        size_t cap;
        Block *slots = blocks::shard_slots(s, &cap);
        for (size_t i = 0; i < cap; ++i) {
            const Block &b = slots[i];
            if (b.user && addr > b.user &&
                addr < b.user + (b.size ? b.size : 1)) {
                *out = b;
                found = true;
                break;
            }
        }
    }
    blocks::unlock_all();
    return found;
}

void report_unknown(void *ptr, const char *op, uint32_t stack) {
    const uintptr_t a = reinterpret_cast<uintptr_t>(ptr);
    char m[512];
    Buf msg(m, sizeof m);
    msg.s(op).s(" called on ").p(a);
    report::Finding f;
    f.type = kInvalidFree;
    f.addr = a;
    f.tid = current_tid();
    f.access_stack = stack;
    f.fatal = true;
    uint32_t tid = 0;
    Block enc;
    ModHit hit{a, nullptr, false};
    if (threads::find_stack(a, &tid)) {
        msg.s(", which is on the stack of thread ").u(tid);
    } else if (find_enclosing(a, &enc)) {
        msg.s(", which points ")
            .u(a - enc.user)
            .s(" byte(s) inside a ")
            .u(enc.size);
        msg.s(enc.state == State::Freed ? "-byte freed block" : "-byte block");
        f.size = enc.size;
        f.alloc_stack = enc.alloc_stack;
        f.free_stack = enc.state == State::Freed ? enc.free_stack : 0;
    } else if (
#ifdef _WIN32
        find_module(&hit),
#else
#if defined(__APPLE__)
        find_module(&hit),
#else
        dl_iterate_phdr(mod_cb, &hit),
#endif
#endif
        hit.found) {
        msg.s(", which is static memory of ").s(hit.name);
    } else if (a == 0xddddddddddddddddULL) {
        msg.s(", leakcheck's fill pattern for freed memory: the pointer itself "
              "was read ");
        msg.s("from a block that had already been freed (use after free)");
    } else {
        msg.s(", which was not returned by the allocator (or was freed and "
              "already ");
        msg.s("recycled)");
    }
    f.msg = msg.cstr();
    report::emit(f);
}

void free_impl(DeKind dk, void *ptr, size_t hint, bool sized, bool nested,
               bool check_kind) {
    const uintptr_t user = reinterpret_cast<uintptr_t>(ptr);
    const uint32_t fstack = nested ? 0 : stacks::capture();
    const uint32_t tid = current_tid();
    Block snap;
    {
        blocks::Handle h = blocks::lookup(user);
        Block *b = h.get();
        if (!b) {
            h.release();
#ifdef _WIN32
            // Windows and the loader allocate from the same heap; a block the
            // heap knows is theirs (or was made before we started), not a mistake.
            if (nested || win::untracked_heap_block(ptr))
#else
            if (nested)
#endif
                __libc_free(ptr);
            else
                report_unknown(ptr, dekind_name(dk), fstack);
            return;
        }
        snap = *b;
        if (b->state == State::Freed) {
            h.release();
            char m[256];
            Buf msg(m, sizeof m);
            msg.s(dekind_name(dk)).s(" on a ").u(snap.size);
            msg.s("-byte block that was already freed");
            report::Finding f;
            f.type = kDoubleFree;
            f.addr = user;
            f.size = snap.size;
            f.tid = tid;
            f.msg = msg.cstr();
            f.access_stack = fstack;
            f.alloc_stack = snap.alloc_stack;
            f.free_stack = snap.free_stack;
            f.fatal = true;
            report::emit(f);
            return;
        }
        b->state = State::Freed;
        b->free_stack = fstack;
        b->free_tid = tid;
        snap = *b;
    }
    stats_on_free(snap.size);
    locks::block_freed(user, snap.size);

    if (check_kind && !compatible(snap.kind, dk)) {
        char m[256];
        Buf msg(m, sizeof m);
        msg.s("memory allocated with ")
            .s(kind_name(snap.kind))
            .s(" was released with ");
        msg.s(dekind_name(dk));
        report::Finding f;
        f.type = kMismatch;
        f.addr = user;
        f.size = snap.size;
        f.tid = tid;
        f.msg = msg.cstr();
        f.access_stack = fstack;
        f.alloc_stack = snap.alloc_stack;
        f.fatal = true;
        report::emit(f);
    }
    if (sized && dk == DeKind::Delete && snap.kind == Kind::New &&
        hint != snap.size) {
        char m[256];
        Buf msg(m, sizeof m);
        msg.s("sized operator delete was told ")
            .u(hint)
            .s(" byte(s) but the block holds ");
        msg.u(snap.size).s(
            " (deleting through a base class without a virtual destructor?)");
        report::Finding f;
        f.type = kSizeMismatch;
        f.addr = user;
        f.size = snap.size;
        f.tid = tid;
        f.msg = msg.cstr();
        f.access_stack = fstack;
        f.alloc_stack = snap.alloc_stack;
        f.fatal = true;
        report::emit(f);
    }
    report_overflow(snap, fstack, "when the block was freed");
    retire(snap);
}

} // namespace

void fill_rz(byte *p, size_t n, uint8_t base) {
    byte want[kRzPeriod];
    pattern_run(want, base);
    size_t i = 0;
    for (; i + kRzPeriod <= n; i += kRzPeriod)
        memcpy(p + i, want, kRzPeriod);
    for (; i < n; ++i)
        p[i] = want[i % kRzPeriod];
}

const char *kind_name(Kind k) {
    switch (k) {
    case Kind::Malloc:
        return "malloc()";
    case Kind::Memalign:
        return "an aligned allocator (memalign/posix_memalign/aligned_alloc)";
    case Kind::New:
        return "operator new";
    case Kind::NewArray:
        return "operator new[]";
    default:
        return "an unknown allocator";
    }
}

void stats_on_alloc(uint64_t size) {
    __atomic_add_fetch(&g_ctr.allocs, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&g_ctr.bytes, size, __ATOMIC_RELAXED);
    __atomic_add_fetch(&g_ctr.live_blocks, 1, __ATOMIC_RELAXED);
    uint64_t live =
        __atomic_add_fetch(&g_ctr.live_bytes, size, __ATOMIC_RELAXED);
    uint64_t peak = __atomic_load_n(&g_ctr.peak_bytes, __ATOMIC_RELAXED);
    while (live > peak &&
           !__atomic_compare_exchange_n(&g_ctr.peak_bytes, &peak, live, true,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
    }
}

void *heap_alloc(Kind kind, size_t size, size_t align, bool zero) {
    if (align < 16)
        align = 16;
    if (size > kMaxAlloc || align > kMaxAlign || (align & (align - 1)))
        return nullptr;

    Block b{};
    b.size = size;
    b.kind = kind;
    b.state = State::Live;
    b.align_log2 = uint8_t(__builtin_ctzll(align));

    bool placed = false;
    if (guard::want(size, align)) {
        uintptr_t base, user;
        uint64_t total;
        if (guard::alloc(size, align, &base, &total, &user)) {
            b.base = base;
            b.total = total;
            b.user = user;
            b.flags = kFlagGuarded;
            placed = true;
        }
    }
    if (!placed) {
        const size_t left = align > kRedzone ? align : kRedzone;
        const size_t total = left + size + kRedzone;
        byte *base;
        if (align <= 16)
            base = static_cast<byte *>(zero ? __libc_calloc(1, total)
                                            : __libc_malloc(total));
        else
            base = static_cast<byte *>(__libc_memalign(align, total));
        if (!base)
            return nullptr;
        if (zero && align > 16)
            memset(base + left, 0, size);
        b.base = reinterpret_cast<uintptr_t>(base);
        b.total = total;
        b.user = reinterpret_cast<uintptr_t>(base + left);
    }
    fill_zones(b);
    b.seq = __atomic_add_fetch(&g_seq, 1, __ATOMIC_RELAXED);
    b.alloc_stack = stacks::capture();
#ifdef _WIN32
    if (win::captured_from_system())
        b.flags |= kFlagSystem;
#endif
    b.alloc_tid = current_tid();
    blocks::insert(b);
    stats_on_alloc(size);
    return reinterpret_cast<void *>(b.user);
}

void heap_free(DeKind dk, void *p, size_t hint, bool sized, bool nested) {
    free_impl(dk, p, hint, sized, nested, true);
}

void *heap_realloc(void *p, size_t n, bool nested) {
    Block snap;
    {
        blocks::Handle h = blocks::lookup(reinterpret_cast<uintptr_t>(p));
        if (!h.get()) {
            h.release();
#ifdef _WIN32
            if (nested || win::untracked_heap_block(p))
#else
            if (nested)
#endif
                return __libc_realloc(p, n);
            report_unknown(p, "realloc()", stacks::capture());
            return nullptr;
        }
        snap = *h.get();
    }
    if (snap.state == State::Freed) {
        char m[256];
        Buf msg(m, sizeof m);
        msg.s("realloc() on a ")
            .u(snap.size)
            .s("-byte block that was already freed");
        report::Finding f;
        f.type = kUseAfterFree;
        f.addr = snap.user;
        f.size = snap.size;
        f.tid = current_tid();
        f.msg = msg.cstr();
        f.access_stack = nested ? 0 : stacks::capture();
        f.alloc_stack = snap.alloc_stack;
        f.free_stack = snap.free_stack;
        f.fatal = true;
        report::emit(f);
        return nullptr;
    }
    const bool c_block =
        snap.kind == Kind::Malloc || snap.kind == Kind::Memalign;
    if (!c_block) {
        char m[256];
        Buf msg(m, sizeof m);
        msg.s("memory allocated with ")
            .s(kind_name(snap.kind))
            .s(" was resized with realloc()");
        report::Finding f;
        f.type = kMismatch;
        f.addr = snap.user;
        f.size = snap.size;
        f.tid = current_tid();
        f.msg = msg.cstr();
        f.access_stack = nested ? 0 : stacks::capture();
        f.alloc_stack = snap.alloc_stack;
        f.fatal = true;
        report::emit(f);
    }
    void *np = heap_alloc(Kind::Malloc, n, 16, false);
    if (!np)
        return nullptr;
    memcpy(np, p, snap.size < n ? snap.size : n);
    free_impl(DeKind::Free, p, 0, false, nested, false);
    return np;
}

size_t heap_usable(const void *p) {
    blocks::Handle h = blocks::lookup(reinterpret_cast<uintptr_t>(p));
    return (h.get() && h.get()->state == State::Live) ? h.get()->size : 0;
}

void heap_verify_all_locked() {
    for (size_t s = 0; s < blocks::kShards; ++s) {
        size_t cap;
        Block *slots = blocks::shard_slots(s, &cap);
        for (size_t i = 0; i < cap; ++i) {
            const Block &b = slots[i];
            if (!b.user)
                continue;
            if (b.state == State::Live)
                report_overflow(b, 0, "at exit");
            else if (!(b.flags & (kFlagGuarded | kFlagReleased)))
                poison_check(b, "at exit");
        }
    }
}

report::Stats heap_stats() {
    report::Stats st{};
    st.allocs = __atomic_load_n(&g_ctr.allocs, __ATOMIC_RELAXED);
    st.frees = __atomic_load_n(&g_ctr.frees, __ATOMIC_RELAXED);
    st.bytes = __atomic_load_n(&g_ctr.bytes, __ATOMIC_RELAXED);
    st.live_blocks = __atomic_load_n(&g_ctr.live_blocks, __ATOMIC_RELAXED);
    st.live_bytes = __atomic_load_n(&g_ctr.live_bytes, __ATOMIC_RELAXED);
    st.peak_bytes = __atomic_load_n(&g_ctr.peak_bytes, __ATOMIC_RELAXED);
    return st;
}

void quarantine_lock() { g_qlock.lock(); }
void quarantine_unlock() { g_qlock.unlock(); }
void quarantine_reset_lock() { g_qlock.reset(); }

} // namespace lc
