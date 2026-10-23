#include "stacks.h"
#include "threads.h"

#include <cstring>
#ifdef _WIN32
#include "win_hooks.h"
#else
#include <execinfo.h>
#if !defined(__APPLE__)
#include <link.h>
#else
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#endif
#endif

namespace lc::stacks {
namespace {

constexpr unsigned kShardBits = 5;
constexpr size_t kShards = size_t(1) << kShardBits;
constexpr size_t kArenaChunk = size_t(1) << 20;
constexpr uint32_t kLocalBits = 24;

struct Rec {
    uint32_t n;
    uint32_t hash;
    uintptr_t frames[1];
};

struct alignas(64) Shard {
    SpinLock lock;
    uint32_t *table; // local index + 1, 0 = empty
    uint32_t cap;
    uint32_t count;
    Rec **recs;
    uint32_t recs_cap;
    char *arena;
    size_t arena_left;
};

Shard g_shards[kShards];
uintptr_t g_self_lo, g_self_hi;
bool g_ready;

uint64_t hash_frames(const uintptr_t *f, uint32_t n) {
    uint64_t h = 0xcbf29ce484222325ULL ^ n;
    for (uint32_t i = 0; i < n; ++i) {
        h ^= f[i];
        h *= 0x100000001b3ULL;
        h ^= h >> 29;
    }
    return h;
}

#if !defined(_WIN32) && !defined(__APPLE__)
int self_cb(struct dl_phdr_info *info, size_t, void *data) {
    const uintptr_t probe = reinterpret_cast<uintptr_t>(data);
    uintptr_t lo = UINTPTR_MAX, hi = 0;
    bool mine = false;
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const auto &ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD)
            continue;
        uintptr_t a = info->dlpi_addr + ph.p_vaddr;
        uintptr_t b = a + ph.p_memsz;
        if (a < lo)
            lo = a;
        if (b > hi)
            hi = b;
        if (probe >= a && probe < b)
            mine = true;
    }
    if (!mine)
        return 0;
    g_self_lo = lo;
    g_self_hi = hi;
    return 1;
}
#endif

void *arena_take(Shard &s, size_t n) {
    n = round_up(n, 16);
    if (s.arena_left < n) {
        size_t chunk = n > kArenaChunk ? n : kArenaChunk;
        s.arena = static_cast<char *>(map_pages(chunk));
        if (!s.arena)
            die("out of memory for stack traces");
        s.arena_left = round_up(chunk, page_size());
    }
    void *p = s.arena;
    s.arena += n;
    s.arena_left -= n;
    return p;
}

void grow_table(Shard &s) {
    uint32_t ncap = s.cap ? s.cap * 2 : 1024;
    auto *nt = static_cast<uint32_t *>(map_pages(size_t(ncap) * 4));
    if (!nt)
        die("out of memory for stack traces");
    for (uint32_t i = 0; i < s.cap; ++i) {
        if (!s.table[i])
            continue;
        uint32_t j = s.recs[s.table[i] - 1]->hash & (ncap - 1);
        while (nt[j])
            j = (j + 1) & (ncap - 1);
        nt[j] = s.table[i];
    }
    unmap_pages(s.table, size_t(s.cap) * 4);
    s.table = nt;
    s.cap = ncap;
}

void grow_recs(Shard &s) {
    uint32_t ncap = s.recs_cap ? s.recs_cap * 2 : 1024;
    auto *nr = static_cast<Rec **>(map_pages(size_t(ncap) * sizeof(Rec *)));
    if (!nr)
        die("out of memory for stack traces");
    if (s.recs)
        memcpy(nr, s.recs, size_t(s.count) * sizeof(Rec *));
    unmap_pages(s.recs, size_t(s.recs_cap) * sizeof(Rec *));
    s.recs = nr;
    s.recs_cap = ncap;
}

} // namespace

#if defined(__APPLE__)
int for_each_image(int (*cb)(const ImageView &, void *), void *data) {
    const uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; ++i) {
        const mach_header *mh = _dyld_get_image_header(i);
        if (!mh)
            continue;
        const char *name = _dyld_get_image_name(i);
        const uintptr_t slide = uintptr_t(_dyld_get_image_vmaddr_slide(i));
        ImageView im{};
        im.name = name && *name ? name : "";
        im.slide = slide;
        im.lo = UINTPTR_MAX;
        im.hi = 0;
        im.nw = 0;
        const uint8_t *p = reinterpret_cast<const uint8_t *>(mh);
        p += mh->magic == MH_MAGIC_64 ? sizeof(mach_header_64) : sizeof(mach_header);
        for (uint32_t c = 0; c < mh->ncmds; ++c) {
            auto *cmd = reinterpret_cast<const load_command *>(p);
            if (cmd->cmd == LC_SEGMENT_64) {
                auto *sg = reinterpret_cast<const segment_command_64 *>(p);
                if (std::strcmp(sg->segname, "__PAGEZERO") != 0 && sg->vmsize) {
                    const uintptr_t a = uintptr_t(sg->vmaddr) + slide;
                    if (a < im.lo)
                        im.lo = a;
                    if (a + sg->vmsize > im.hi)
                        im.hi = a + sg->vmsize;
                    if ((sg->initprot & VM_PROT_WRITE) && im.nw < ImageView::kW) {
                        im.wlo[im.nw] = a;
                        im.whi[im.nw] = a + sg->vmsize;
                        ++im.nw;
                    }
                }
            }
            if (cmd->cmdsize == 0)
                break;
            p += cmd->cmdsize;
        }
        if (im.lo < im.hi && cb(im, data))
            return 1;
    }
    return 0;
}
#endif

#ifdef _WIN32
void init() { win::self_range(&g_self_lo, &g_self_hi); }
#elif defined(__APPLE__)
int self_one(const ImageView &im, void *data) {
    const uintptr_t probe = reinterpret_cast<uintptr_t>(data);
    if (probe < im.lo || probe >= im.hi)
        return 0;
    g_self_lo = im.lo;
    g_self_hi = im.hi;
    return 1;
}
void init() { for_each_image(self_one, reinterpret_cast<void *>(&init)); }
#else
void init() { dl_iterate_phdr(self_cb, reinterpret_cast<void *>(&init)); }
#endif

void set_ready() { __atomic_store_n(&g_ready, true, __ATOMIC_RELEASE); }

bool in_self(uintptr_t pc) { return pc >= g_self_lo && pc < g_self_hi; }

uint32_t trim_self(uintptr_t *frames, uint32_t n) {
    uint32_t i = 0;
    while (i < n && in_self(frames[i]))
        ++i;
    if (i)
        memmove(frames, frames + i, (n - i) * sizeof(uintptr_t));
    return n - i;
}

#ifndef _WIN32
namespace {

LC_TLS uintptr_t tl_stack_lo;
LC_TLS uintptr_t tl_stack_hi;

// Walks the frame-pointer chain. Every step is checked against this
// thread's stack, so code built without frame pointers ends the walk early
// (a shorter stack) rather than reading wild memory.
LC_NOINLINE uint32_t fp_unwind(uintptr_t *out, uint32_t max) {
    if (!tl_stack_hi) {
        uintptr_t lo, hi;
        if (!threads::current_bounds(&lo, &hi))
            return 0;
        tl_stack_lo = lo;
        tl_stack_hi = hi;
    }
    uintptr_t fp = reinterpret_cast<uintptr_t>(__builtin_frame_address(0));
    // Live frames are above us; below is unmapped or dead.
    const uintptr_t lo = fp > tl_stack_lo ? fp : tl_stack_lo;
    uint32_t n = 0;
    while (n < max) {
        if (fp < lo || fp + 2 * sizeof(uintptr_t) > tl_stack_hi || (fp & 7))
            break;
        const uintptr_t next = reinterpret_cast<const uintptr_t *>(fp)[0];
        const uintptr_t ret = reinterpret_cast<const uintptr_t *>(fp)[1];
        if (ret < 4096)
            break;
        out[n++] = ret;
        if (next <= fp)
            break;
        fp = next;
    }
    return n;
}

} // namespace
#endif

#if !defined(_WIN32)
uint32_t bt_capture(uintptr_t *frames, uint32_t want) {
    int got = backtrace(reinterpret_cast<void **>(frames), int(want));
    return got > 0 ? uint32_t(got) : 0;
}
#endif

uint32_t capture() {
    if (!__atomic_load_n(&g_ready, __ATOMIC_ACQUIRE))
        return 0;
    uintptr_t frames[kMaxDepth + 16];
    const uint32_t want = g_cfg.stack_depth + 16;
    uint32_t n;
#ifdef _WIN32
    n = win::capture_frames(frames, want); // the unwind tables of x64 Windows; no frame pointers needed
#else
    // The tables give the whole stack for any code; walking frame pointers is
    // several times cheaper but steps over every frame compiled without
    // -fno-omit-frame-pointer, so it stays opt-in (--fast-unwind).
    if (g_cfg.fast_unwind)
        n = fp_unwind(frames, want);
    else
        n = bt_capture(frames, want);
#endif
    uint32_t m = trim_self(frames, n);
#ifdef _WIN32
    m = win::trim_system(frames, m); // the C runtime and Windows around the program's own code
#endif
    if (m > g_cfg.stack_depth)
        m = g_cfg.stack_depth;
    return intern(frames, m);
}

uint32_t intern(const uintptr_t *frames, uint32_t n) {
    if (!n)
        return 0;
    const uint64_t h64 = hash_frames(frames, n);
    const uint32_t h = uint32_t(h64);
    const size_t si = h64 >> (64 - kShardBits);
    Shard &s = g_shards[si];
    LockGuard g(s.lock);
    if (s.cap) {
        for (uint32_t j = h & (s.cap - 1); s.table[j];
             j = (j + 1) & (s.cap - 1)) {
            const Rec *r = s.recs[s.table[j] - 1];
            if (r->hash == h && r->n == n &&
                memcmp(r->frames, frames, n * sizeof(uintptr_t)) == 0)
                return uint32_t(si << kLocalBits) | s.table[j];
        }
    }
    if (s.count + 1 >= (uint32_t(1) << kLocalBits))
        return 0;
    if ((s.count + 1) * 2 > s.cap)
        grow_table(s);
    if (s.count + 1 > s.recs_cap)
        grow_recs(s);
    auto *r = static_cast<Rec *>(arena_take(s, 8 + n * sizeof(uintptr_t)));
    r->n = n;
    r->hash = h;
    memcpy(r->frames, frames, n * sizeof(uintptr_t));
    s.recs[s.count] = r;
    const uint32_t local = ++s.count;
    uint32_t j = h & (s.cap - 1);
    while (s.table[j])
        j = (j + 1) & (s.cap - 1);
    s.table[j] = local;
    return uint32_t(si << kLocalBits) | local;
}

bool get(uint32_t id, const uintptr_t **frames, uint32_t *n) {
    if (!id)
        return false;
    Shard &s = g_shards[id >> kLocalBits];
    const uint32_t local = id & ((uint32_t(1) << kLocalBits) - 1);
    LockGuard g(s.lock);
    if (!local || local > s.count)
        return false;
    const Rec *r = s.recs[local - 1];
    *frames = r->frames;
    *n = r->n;
    return true;
}

void lock_all() {
    for (auto &s : g_shards)
        s.lock.lock();
}

void unlock_all() {
    for (auto &s : g_shards)
        s.lock.unlock();
}

void reset_locks() {
    for (auto &s : g_shards)
        s.lock.reset();
}

} // namespace lc::stacks
