#include "rt.h"
#include "protocol.h"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <pthread.h>
#include <mach-o/dyld.h>
#include <malloc/malloc.h>
#endif

namespace lc {

LC_TLS uint8_t tl_in_hook = 0;
LC_TLS uint32_t tl_tid = 0;
Config g_cfg;
uint32_t g_self_pid;
uint32_t g_fork_tid;

size_t page_size() {
    static size_t cached = 0;
    if (LC_UNLIKELY(!cached)) {
        long v = sysconf(_SC_PAGESIZE);
        cached = v > 0 ? size_t(v) : 4096;
    }
    return cached;
}

namespace {
constexpr size_t kMaxRanges = 1 << 16;
SpinLock g_ranges_lock;
Range g_ranges[kMaxRanges];
size_t g_nranges;
} // namespace

void *map_pages(size_t bytes) {
    if (!bytes)
        bytes = 1;
    bytes = round_up(bytes, page_size());
    void *p = mmap(nullptr, bytes, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED)
        return nullptr;
    LockGuard g(g_ranges_lock);
    if (g_nranges < kMaxRanges)
        g_ranges[g_nranges++] = Range{uintptr_t(p), uintptr_t(p) + bytes};
    return p;
}

void unmap_pages(void *p, size_t bytes) {
    if (!p)
        return;
    munmap(p, round_up(bytes ? bytes : 1, page_size()));
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
    std::sort(out, out + n,
              [](const Range &a, const Range &b) { return a.lo < b.lo; });
    return n;
}

void ranges_lock() { g_ranges_lock.lock(); }
void ranges_unlock() { g_ranges_lock.unlock(); }
void ranges_reset_lock() { g_ranges_lock.reset(); }

void yield_thread() { sched_yield(); }

uint32_t current_tid() {
    if (LC_UNLIKELY(!tl_tid)) {
#if defined(__APPLE__)
        uint64_t tid = 0;
        pthread_threadid_np(nullptr, &tid);
        tl_tid = uint32_t(tid);
#else
        tl_tid = uint32_t(syscall(SYS_gettid));
#endif
    }
    return tl_tid;
}

uint32_t process_id() { return uint32_t(getpid()); }

ErrnoSaver::ErrnoSaver() : saved_(errno) {}
ErrnoSaver::~ErrnoSaver() { errno = saved_; }
void set_errno(int e) { errno = e; }

void die(const char *msg) {
    char b[512];
    Buf out(b, sizeof b);
    out.s("leakcheck: fatal: ").s(msg).c('\n');
    write_all(2, out.data(), out.size());
    _exit(70);
}

bool write_all(int fd, const char *p, size_t n) {
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        p += w;
        n -= size_t(w);
    }
    return true;
}

const char *env_str(const char *name) {
    const char *v = getenv(name);
    return (v && *v) ? v : nullptr;
}

uint64_t env_u64(const char *name, uint64_t def) {
    const char *v = env_str(name);
    if (!v)
        return def;
    uint64_t r = 0;
    for (; *v; ++v) {
        if (*v < '0' || *v > '9')
            return def;
        r = r * 10 + uint64_t(*v - '0');
    }
    return r;
}

void load_config() {
    using namespace lcproto;
    Config &c = g_cfg;
    g_self_pid = uint32_t(getpid());
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
    c.dangling = env_u64(kEnvDangling, 0) != 0;
    c.root_pid = uint32_t(env_u64(kEnvRootPid, 0));
    c.active =
        c.root_pid == 0 || c.root_pid == uint32_t(getpid()) || c.trace_children;
    c.report_enabled = c.active;
    if (!c.active)
        return;
    c.report_fd = 2;
    const char *path = env_str(kEnvReport);
    if (path) {
        const size_t n = strlen(path);
        if (n < sizeof c.report_path)
            memcpy(c.report_path, path, n + 1);
    }
}

namespace {
// The spare descriptor: a /dev/null duplicate at the highest number the limit
// allows (at most 1023), so it never changes which numbers the program gets.
// Only the very same file is ever closed again: the program may have closed
// it and used the number for something else.
int g_reserve = -1;
long g_reserve_want; // the number asked for
dev_t g_reserve_dev, g_reserve_rdev;
ino_t g_reserve_ino;

bool is_reserve(int fd) {
    struct stat st;
#if defined(__APPLE__)
    // This dylib does not define fstat; the call is libSystem's.
    const bool ok = fstat(fd, &st) == 0;
#else
    const bool ok = syscall(SYS_fstat, fd, &st) == 0;
#endif
    return ok && S_ISCHR(st.st_mode) && st.st_dev == g_reserve_dev &&
           st.st_rdev == g_reserve_rdev && st.st_ino == g_reserve_ino;
}

void reserve_take() {
    if (!g_reserve_want)
        return;
#if defined(__APPLE__)
    const int tmp = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (tmp < 0)
        return;
    if (tmp >= g_reserve_want) {
        __atomic_store_n(&g_reserve, tmp, __ATOMIC_RELEASE);
        return;
    }
    const int fd = fcntl(tmp, F_DUPFD_CLOEXEC, g_reserve_want);
    close(tmp);
    if (fd >= 0)
        __atomic_store_n(&g_reserve, fd, __ATOMIC_RELEASE);
#else
    const long tmp = syscall(SYS_openat, AT_FDCWD, "/dev/null", O_RDONLY | O_CLOEXEC);
    if (tmp < 0)
        return;
    if (tmp >= g_reserve_want) { // the only free number is the one we want
        __atomic_store_n(&g_reserve, int(tmp), __ATOMIC_RELEASE);
        return;
    }
    const long fd = syscall(SYS_fcntl, tmp, F_DUPFD_CLOEXEC, g_reserve_want);
    syscall(SYS_close, tmp);
    if (fd >= 0)
        __atomic_store_n(&g_reserve, int(fd), __ATOMIC_RELEASE);
#endif
}
} // namespace

void fd_reserve_make() {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0 || rl.rlim_cur < 16)
        return;
    g_reserve_want = rl.rlim_cur > 1024 ? 1023 : long(rl.rlim_cur) - 1;
    struct stat st;
    if (stat("/dev/null", &st) != 0)
        return;
    g_reserve_dev = st.st_dev;
    g_reserve_rdev = st.st_rdev;
    g_reserve_ino = st.st_ino;
    reserve_take();
}

int open_for_runtime(const char *path, int flags) {
    int fd = open(path, flags | O_CLOEXEC, 0600);
    if (fd >= 0 || (errno != EMFILE && errno != ENFILE))
        return fd;
    // Out of descriptors: give up the spare, use its number, take another.
    const int spare = __atomic_exchange_n(&g_reserve, -1, __ATOMIC_ACQ_REL);
    if (spare < 0)
        return -1;
    if (is_reserve(spare))
#if defined(__APPLE__)
        close(spare);
#else
        syscall(SYS_close, spare);
#endif
    fd = open(path, flags | O_CLOEXEC, 0600);
    const int err = errno;
    if (fd >= 0)
        return fd; // the caller closes it with close_for_runtime()
    reserve_take();
    errno = err;
    return -1;
}

void close_for_runtime(int fd) {
    close(fd);
    if (__atomic_load_n(&g_reserve, __ATOMIC_ACQUIRE) < 0)
        reserve_take();
}

bool append_report(const char *p, size_t n) {
    if (!g_cfg.report_path[0])
        return write_all(g_cfg.report_fd, p, n);
    int fd = open_for_runtime(g_cfg.report_path, O_WRONLY | O_APPEND | O_CREAT);
    if (fd < 0)
        return false;
    bool ok = write_all(fd, p, n);
    close_for_runtime(fd);
    return ok;
}

namespace ih {
namespace {
constexpr size_t kRegion = size_t(256) << 20;
constexpr size_t kHdr = 16;
constexpr unsigned kMinCls = 5;
constexpr unsigned kMaxCls = 26;
constexpr uint32_t kMagic = 0x1ea4c0deu;

struct Hdr {
    uint32_t magic;
    uint32_t cls;
    uint32_t back;
    uint32_t pad;
};

SpinLock g_lock;
char *g_base;
size_t g_off;
void *g_free[kMaxCls + 1];
} // namespace

bool owns(const void *p) {
    char *base = __atomic_load_n(&g_base, __ATOMIC_ACQUIRE);
    return base && static_cast<const char *>(p) >= base &&
           static_cast<const char *>(p) < base + kRegion;
}

void *alloc(size_t size, size_t align) {
    if (align < 16)
        align = 16;
    if (size > (size_t(1) << kMaxCls))
        return nullptr;
    size_t need = size + kHdr + (align > 16 ? align : 0);
    unsigned cls = kMinCls;
    while ((size_t(1) << cls) < need)
        ++cls;
    if (cls > kMaxCls)
        return nullptr;
    char *blk;
    {
        LockGuard g(g_lock);
        if (!g_base) {
            // Not map_pages: this memory holds libc/ld.so state allocated on
            // the program's behalf, so the leak scan must treat it as roots.
            void *r = mmap(nullptr, kRegion, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
            if (r == MAP_FAILED)
                return nullptr;
            __atomic_store_n(&g_base, static_cast<char *>(r), __ATOMIC_RELEASE);
        }
        if (g_free[cls]) {
            blk = static_cast<char *>(g_free[cls]);
            g_free[cls] = *reinterpret_cast<void **>(blk);
        } else {
            size_t sz = size_t(1) << cls;
            if (g_off + sz > kRegion)
                return nullptr;
            blk = g_base + g_off;
            g_off += sz;
        }
    }
    uintptr_t user = round_up(uintptr_t(blk) + kHdr, align);
    Hdr *h = reinterpret_cast<Hdr *>(user - kHdr);
    h->magic = kMagic;
    h->cls = cls;
    h->back = uint32_t(user - uintptr_t(blk));
    return reinterpret_cast<void *>(user);
}

void free(void *p) {
    Hdr *h = reinterpret_cast<Hdr *>(static_cast<char *>(p) - kHdr);
    if (h->magic != kMagic)
        return;
    // The leak scan treats this region as roots: a freed block's stale
    // pointers would keep, or half-keep, program blocks alive.
    memset(p, 0, usable(p));
    h->magic = 0;
    const uint32_t cls = h->cls;
    char *blk = static_cast<char *>(p) - h->back;
    LockGuard g(g_lock);
    *reinterpret_cast<void **>(blk) = g_free[cls];
    g_free[cls] = blk;
}

size_t usable(const void *p) {
    const Hdr *h =
        reinterpret_cast<const Hdr *>(static_cast<const char *>(p) - kHdr);
    return (size_t(1) << h->cls) - h->back;
}

bool used_range(uintptr_t *lo, uintptr_t *hi) {
    LockGuard g(g_lock);
    if (!g_base)
        return false;
    *lo = uintptr_t(g_base);
    *hi = uintptr_t(g_base) + g_off;
    return true;
}

bool full_range(uintptr_t *lo, uintptr_t *hi) {
    char *base = __atomic_load_n(&g_base, __ATOMIC_ACQUIRE);
    if (!base)
        return false;
    *lo = uintptr_t(base);
    *hi = uintptr_t(base) + kRegion;
    return true;
}

void lock() { g_lock.lock(); }
void unlock() { g_lock.unlock(); }
void reset_lock() { g_lock.reset(); }
} // namespace ih

} // namespace lc

#if defined(__APPLE__)
namespace {
// glibc spellings for the allocator the wrappers use when tracking is off: the
// backing store of a tracked block, and a pointer the program never asked us to
// track. On Linux those are libc's own entry points. On Darwin they are not:
// dyld's interpose table rewrites every reference to `malloc` and `free` in the
// process, and that includes the references inside this dylib, so `dlsym(RTLD_NEXT,
// "malloc")` hands back lc_malloc and the fallback becomes a loop that only ends
// when the stack does - which is what killed every target, tracked or not.
// The zone API is not in the table and does not go through those symbols.
malloc_zone_t *system_zone() {
    static malloc_zone_t *zone;
    if (!zone)
        zone = malloc_default_zone();
    return zone;
}
} // namespace

extern "C" {
void *__libc_malloc(size_t n) { return malloc_zone_malloc(system_zone(), n); }
void *__libc_calloc(size_t a, size_t b) {
    return malloc_zone_calloc(system_zone(), a, b);
}
void *__libc_realloc(void *p, size_t n) {
    return malloc_zone_realloc(system_zone(), p, n);
}
void *__libc_memalign(size_t align, size_t n) {
    if (align < sizeof(void *))
        align = sizeof(void *);
    return malloc_zone_memalign(system_zone(), align, n);
}
void __libc_free(void *p) {
    if (p)
        malloc_zone_free(system_zone(), p);
}
} // extern "C"
#endif
