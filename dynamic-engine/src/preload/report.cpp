#include "report.h"
#include "protocol.h"
#include "stacks.h"

#include <cstdlib>
#include <cstring>
#ifdef _WIN32
#include "win_hooks.h"
#else
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#else
#include <link.h>
#endif
#include <unistd.h>
#endif

namespace lc::report {
namespace {

constexpr size_t kBufSize = size_t(1) << 16;
constexpr uint64_t kMaxFindings = 20000;
constexpr size_t kMaxModules = 1024;
constexpr size_t kPathMax = 512;
constexpr size_t kDedupe = 8192;

struct Known {
    char path[kPathMax];
    bool emitted;
};

struct Snap {
    uintptr_t lo, hi, bias;
    uint32_t id;
};

struct Dup {
    uint64_t key;
    uint64_t extra;
};

SpinLock g_lock;
char g_buf[kBufSize];
char g_exe[kPathMax];
bool g_opened;
bool g_finished;
Known *g_known;
size_t g_known_n;
Snap g_snap[kMaxModules];
size_t g_snap_n;
Dup g_dups[kDedupe];
size_t g_dups_n;
uint64_t g_emitted;
uint64_t g_dropped;

uint32_t known_id(const char *path) {
    for (size_t i = 0; i < g_known_n; ++i)
        if (strcmp(g_known[i].path, path) == 0)
            return uint32_t(i + 1);
    if (!g_known) {
        g_known = static_cast<Known *>(map_pages(kMaxModules * sizeof(Known)));
        if (!g_known)
            return 0;
    }
    if (g_known_n >= kMaxModules)
        return 0;
    Known &k = g_known[g_known_n++];
    strncpy(k.path, path, kPathMax - 1);
    k.path[kPathMax - 1] = 0;
    k.emitted = false;
    return uint32_t(g_known_n);
}

#ifdef _WIN32
void refresh_modules() {
    g_snap_n = 0;
    win::for_each_module([](uintptr_t base, size_t size, const char *path, void *) {
        if (g_snap_n < kMaxModules)
            g_snap[g_snap_n++] = Snap{base, base + size, base, known_id(path)};
    }, nullptr);
}
#elif defined(__APPLE__)
int snap_one(const stacks::ImageView &im, void *) {
    if (g_snap_n >= kMaxModules)
        return 1;
    const char *name = im.name[0] ? im.name : g_exe;
    g_snap[g_snap_n++] = Snap{im.lo, im.hi, im.slide, known_id(name)};
    return 0;
}

void refresh_modules() {
    g_snap_n = 0;
    stacks::for_each_image(snap_one, nullptr);
}
#else
int snap_cb(struct dl_phdr_info *info, size_t, void *) {
    if (g_snap_n >= kMaxModules)
        return 1;
    const char *name = info->dlpi_name;
    if (!name || !*name)
        name = g_exe;
    if (strncmp(name, "linux-vdso", 10) == 0 ||
        strncmp(name, "linux-gate", 10) == 0)
        return 0;
    uintptr_t lo = UINTPTR_MAX, hi = 0;
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const auto &ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD)
            continue;
        uintptr_t a = info->dlpi_addr + ph.p_vaddr;
        if (a < lo)
            lo = a;
        if (a + ph.p_memsz > hi)
            hi = a + ph.p_memsz;
    }
    if (lo >= hi)
        return 0;
    g_snap[g_snap_n++] = Snap{lo, hi, info->dlpi_addr, known_id(name)};
    return 0;
}

void refresh_modules() {
    g_snap_n = 0;
    dl_iterate_phdr(snap_cb, nullptr);
}
#endif

const Snap *module_of(uintptr_t pc) {
    for (size_t i = 0; i < g_snap_n; ++i)
        if (pc >= g_snap[i].lo && pc < g_snap[i].hi)
            return &g_snap[i];
    return nullptr;
}

struct Resolved {
    uint32_t id;
    uint64_t off;
};

// Our own frames (e.g. the main() wrapper) are noise in the target's stacks.
uint32_t resolve(const uintptr_t *frames, uint32_t n, Resolved *out) {
    uint32_t k = 0;
    for (uint32_t i = 0; i < n; ++i) {
        uintptr_t q = frames[i] ? frames[i] - 1 : 0;
        if (stacks::in_self(q))
            continue;
        const Snap *m = module_of(q);
        out[k++] = m ? Resolved{m->id, q - m->bias} : Resolved{0, q};
    }
    return k;
}

uint64_t mix(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

uint64_t key_of(const Finding &f) {
    uint64_t h = 0x9e3779b97f4a7c15ULL;
    for (const char *t = f.type; t && *t; ++t)
        h = mix(h ^ uint8_t(*t));
    if (f.category)
        for (const char *t = f.category; *t; ++t)
            h = mix(h ^ uint8_t(*t));
    // Stack ids are numbered per process, and children forked at different
    // moments number the same stack differently; their return addresses
    // are the same until they exec. The reporter merges such records by key.
    if (f.untraced_too) {
        const uint32_t ids[] = {f.alloc_stack, f.free_stack, f.access_stack};
        for (uint32_t id : ids) {
            const uintptr_t *fr = nullptr;
            uint32_t n = 0;
            if (stacks::get(id, &fr, &n))
                for (uint32_t i = 0; i < n; ++i)
                    h = mix(h ^ fr[i]);
            h = mix(h ^ 0x51);
        }
        return h ? h : 1;
    }
    h = mix(h ^ f.alloc_stack);
    h = mix(h ^ (uint64_t(f.free_stack) << 32));
    if (f.access_frames) {
        for (uint32_t i = 0; i < f.access_n; ++i)
            h = mix(h ^ f.access_frames[i]);
    } else {
        h = mix(h ^ (uint64_t(f.access_stack) << 16));
    }
    return h ? h : 1;
}

// True if this key was already reported (and counts the repeat).
bool seen(uint64_t key) {
    size_t mask = kDedupe - 1;
    for (size_t i = key & mask;; i = (i + 1) & mask) {
        if (g_dups[i].key == key) {
            ++g_dups[i].extra;
            return true;
        }
        if (!g_dups[i].key) {
            if (g_dups_n * 4 < kDedupe * 3) {
                g_dups[i].key = key;
                ++g_dups_n;
            }
            return false;
        }
    }
}

void flush(Buf &b) {
    append_report(b.data(), b.size());
    b.reset();
}

void open_locked() {
    if (g_opened)
        return;
    g_opened = true;
#ifdef _WIN32
    win::exe_path(g_exe, kPathMax);
#elif defined(__APPLE__)
    uint32_t sz = kPathMax;
    if (_NSGetExecutablePath(g_exe, &sz) != 0)
        g_exe[0] = 0;
#else
    ssize_t n = readlink("/proc/self/exe", g_exe, kPathMax - 1);
    g_exe[n > 0 ? n : 0] = 0;
#endif
    Buf b(g_buf, kBufSize);
    b.s("H v=").u(lcproto::kVersion).s(" pid=").u(uint64_t(process_id()));
    b.s(" exe=").line(g_exe).c('\n');
    flush(b);
}

void put_stack(Buf &b, char role, const Resolved *r, uint32_t n) {
    if (!n)
        return;
    b.c('S').c(' ').c(role);
    for (uint32_t i = 0; i < n; ++i)
        b.c(' ').u(r[i].id).c(':').x(r[i].off);
    b.c('\n');
}

} // namespace

void open_stream() {
    if (!g_cfg.report_enabled || g_cfg.report_fd < 0)
        return;
    LockGuard g(g_lock);
    open_locked();
}

void emit(const Finding &f) {
    if ((!g_cfg.report_enabled && !f.untraced_too) || g_cfg.report_fd < 0)
        return;
    const uint64_t key = key_of(f);
    {
        LockGuard g(g_lock);
        if (g_finished)
            return;
        open_locked();
        if (!seen(key)) {
            if (g_emitted >= kMaxFindings) {
                ++g_dropped;
            } else {
                ++g_emitted;
                const uintptr_t *fr[3] = {nullptr, nullptr, nullptr};
                uint32_t fn[3] = {0, 0, 0};
                if (f.access_frames) {
                    fr[0] = f.access_frames;
                    fn[0] = f.access_n;
                } else {
                    stacks::get(f.access_stack, &fr[0], &fn[0]);
                }
                stacks::get(f.alloc_stack, &fr[1], &fn[1]);
                stacks::get(f.free_stack, &fr[2], &fn[2]);

                refresh_modules();
                Resolved res[3][stacks::kMaxDepth + 1];
                for (int k = 0; k < 3; ++k) {
                    if (fn[k] > stacks::kMaxDepth + 1)
                        fn[k] = stacks::kMaxDepth + 1;
                    fn[k] = resolve(fr[k], fn[k], res[k]);
                }

                Buf b(g_buf, kBufSize);
                const uint64_t pid = uint64_t(process_id());
                for (int k = 0; k < 3; ++k) {
                    for (uint32_t i = 0; i < fn[k]; ++i) {
                        uint32_t id = res[k][i].id;
                        if (!id || g_known[id - 1].emitted)
                            continue;
                        g_known[id - 1].emitted = true;
                        b.s("M ")
                            .u(pid)
                            .c(' ')
                            .u(id)
                            .c(' ')
                            .line(g_known[id - 1].path)
                            .c('\n');
                    }
                }
                b.s("B type=").s(f.type).s(" pid=").u(pid).s(" addr=").x(
                    f.addr);
                b.s(" size=").u(f.size).s(" tid=").u(f.tid).s(" key=").x(key);
                if (f.category)
                    b.s(" cat=")
                        .s(f.category)
                        .s(" blocks=")
                        .u(f.blocks)
                        .s(" bytes=")
                        .u(f.bytes);
                b.s(" msg=").line(f.msg).c('\n');
                put_stack(b, 'a', res[0], fn[0]);
                put_stack(b, 'l', res[1], fn[1]);
                put_stack(b, 'f', res[2], fn[2]);
                b.s("X\n");
                flush(b);
            }
        }
    }
    if (f.fatal && g_cfg.abort_on_error) {
        static const char msg[] =
            "leakcheck: stopping at first error (--abort-on-error)\n";
        write_all(2, msg, sizeof msg - 1);
        abort();
    }
}

void finish(const Stats &st) {
    if (!g_cfg.report_enabled || g_cfg.report_fd < 0)
        return;
    LockGuard g(g_lock);
    if (g_finished)
        return;
    open_locked();
    g_finished = true;
    Buf b(g_buf, kBufSize);
    for (const Dup &d : g_dups) {
        if (!d.key || !d.extra)
            continue;
        b.s("D key=").x(d.key).s(" count=").u(d.extra).c('\n');
        if (b.size() > kBufSize - 256)
            flush(b);
    }
    const uint64_t pid = uint64_t(process_id());
    b.s("T pid=").u(pid).s(" allocs=").u(st.allocs).s(" frees=").u(st.frees);
    b.s(" bytes=").u(st.bytes).s(" live_blocks=").u(st.live_blocks);
    b.s(" live_bytes=").u(st.live_bytes).s(" peak_bytes=").u(st.peak_bytes);
    b.s(" dropped=").u(g_dropped).s(" scanned=").u(st.scanned ? 1 : 0).c('\n');
    b.s("Z pid=").u(pid).c('\n');
    flush(b);
}

void after_fork_child() {
    g_opened = false;
    for (size_t i = 0; i < g_known_n; ++i)
        g_known[i].emitted = false;
}

void lock() { g_lock.lock(); }
void unlock() { g_lock.unlock(); }
void reset_lock() { g_lock.reset(); }

} // namespace lc::report
