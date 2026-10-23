#pragma once
// Runtime primitives for the injected library. Nothing in here may call
// malloc: the library is the process's malloc.
#include <cstddef>
#include <cstdint>

#define LC_NOINLINE __attribute__((noinline))
#define LC_LIKELY(x) __builtin_expect(!!(x), 1)
#define LC_UNLIKELY(x) __builtin_expect(!!(x), 0)
#ifdef _WIN32
#define LC_TLS __thread
#else
#define LC_TLS __attribute__((tls_model("initial-exec"))) __thread
#endif

namespace lc {

using byte = unsigned char;

inline constexpr size_t kMaxAlloc = size_t(1) << 46;
inline constexpr size_t kMaxAlign = size_t(1) << 30;

inline size_t round_up(size_t v, size_t a) { return (v + a - 1) & ~(a - 1); }

size_t page_size();
void *map_pages(size_t bytes); // zeroed; nullptr on failure
void unmap_pages(void *p, size_t bytes);

// Every mapping made by map_pages is recorded so the leak scan can skip the
// runtime's own memory (its tables are full of block addresses).
struct Range {
    uintptr_t lo, hi;
};
size_t runtime_ranges(Range *out, size_t max); // sorted by address
void ranges_lock();
void ranges_unlock();
void ranges_reset_lock();

void yield_thread();
inline void cpu_relax() {
#if defined(__x86_64__) || defined(__i386__)
    __builtin_ia32_pause();
#elif defined(__aarch64__)
    __asm__ __volatile__("yield");
#endif
}

struct SpinLock {
    uint32_t state = 0;
    void lock() {
        unsigned spins = 0;
        while (__atomic_exchange_n(&state, 1u, __ATOMIC_ACQUIRE)) {
            while (__atomic_load_n(&state, __ATOMIC_RELAXED)) {
                if (++spins < 128)
                    cpu_relax();
                else
                    yield_thread();
            }
        }
    }
    bool try_lock() {
        return !__atomic_exchange_n(&state, 1u, __ATOMIC_ACQUIRE);
    }
    void unlock() { __atomic_store_n(&state, 0u, __ATOMIC_RELEASE); }
    void reset() { __atomic_store_n(&state, 0u, __ATOMIC_RELAXED); }
};

class LockGuard {
  public:
    explicit LockGuard(SpinLock &l) : l_(l) { l_.lock(); }
    ~LockGuard() { l_.unlock(); }
    LockGuard(const LockGuard &) = delete;
    LockGuard &operator=(const LockGuard &) = delete;

  private:
    SpinLock &l_;
};

// Set while this thread runs inside the runtime; allocations made then are
// served from the internal heap and are never tracked or reported.
#ifdef _WIN32
// MinGW's __thread is emulated with malloc, which is the very thing hooked
// here: the per-thread state sits in a Win32 TLS slot instead (rt_win.cpp).
struct ThreadState {
    uint8_t in_hook;
    uint8_t alloc_kind;  // the family the next heap allocation belongs to (mem_win.cpp)
    uint8_t free_kind;   // and the next release
    uint8_t free_sized;  // the release came from a sized operator delete...
    uint32_t tid;
    uint64_t free_size;  // ...which said this many bytes
    uint8_t busy;
    uint8_t sys_owned; // the last stack captured was made by Windows' own code
    uint8_t pad[6];
    void *locks; // locks_win.cpp's record of this thread
    uint64_t spare[4];
};
ThreadState &ts();
void ts_init();   // before anything else
void ts_exit();   // the thread is ending: give its state back
#define tl_in_hook (::lc::ts().in_hook)
#define tl_tid (::lc::ts().tid)
#else
extern LC_TLS uint8_t tl_in_hook;
extern LC_TLS uint32_t tl_tid;
#endif
uint32_t current_tid();
uint32_t process_id();

class HookGuard {
  public:
    HookGuard() : prev_(tl_in_hook) { tl_in_hook = 1; }
    ~HookGuard() { tl_in_hook = prev_; }
    HookGuard(const HookGuard &) = delete;
    HookGuard &operator=(const HookGuard &) = delete;

  private:
    uint8_t prev_;
};

class ErrnoSaver {
  public:
    ErrnoSaver();
    ~ErrnoSaver();
    ErrnoSaver(const ErrnoSaver &) = delete;
    ErrnoSaver &operator=(const ErrnoSaver &) = delete;

  private:
    int saved_;
};
void set_errno(int e);

[[noreturn]] void die(const char *msg);

class Buf {
  public:
    Buf(char *p, size_t cap) : p_(p), cap_(cap) {}
    Buf &c(char ch) {
        if (n_ + 1 < cap_)
            p_[n_++] = ch;
        else
            over_ = true;
        return *this;
    }
    Buf &s(const char *str) {
        if (!str)
            str = "(null)";
        while (*str)
            c(*str++);
        return *this;
    }
    // Strings that end up inside a single protocol line.
    Buf &line(const char *str) {
        if (!str)
            return *this;
        for (; *str; ++str)
            c((*str == '\n' || *str == '\r') ? ' ' : *str);
        return *this;
    }
    Buf &u(uint64_t v) {
        char t[24];
        int k = 0;
        do {
            t[k++] = char('0' + v % 10);
            v /= 10;
        } while (v);
        while (k)
            c(t[--k]);
        return *this;
    }
    Buf &x(uint64_t v) {
        constexpr char d[] = "0123456789abcdef";
        char t[17];
        int k = 0;
        do {
            t[k++] = d[v & 15];
            v >>= 4;
        } while (v);
        while (k)
            c(t[--k]);
        return *this;
    }
    Buf &p(uint64_t v) { return s("0x").x(v); }
    const char *data() const { return p_; }
    size_t size() const { return n_; }
    const char *cstr() {
        p_[n_ < cap_ ? n_ : cap_ - 1] = 0;
        return p_;
    }
    void reset() {
        n_ = 0;
        over_ = false;
    }

  private:
    char *p_;
    size_t cap_;
    size_t n_ = 0;
    bool over_ = false;
};

bool write_all(int fd, const char *p, size_t n);

const char *env_str(const char *name);
uint64_t env_u64(const char *name, uint64_t def);

struct Config {
    uint64_t quarantine_bytes = 64ull << 20;
    uint64_t quarantine_entries = 1u << 20;
    uint32_t stack_depth = 24;
    uint32_t guard_every = 0;
    uint32_t guard_max_live = 2048;
    uint32_t root_pid = 0;
    int report_fd = -1;          // used when no report path is set (stderr)
    char report_path[1024] = {}; // reopened per write: targets may close fds
    bool abort_on_error = false;
    bool fast_unwind = false;
    bool leak_check = true;
    bool show_reachable = false;
    bool trace_children = false;
    bool malware = false;        // LEAKCHECK_MALWARE: the rules of the 49 malware families
    bool dangling = false;       // LEAKCHECK_DANGLING: stale pointers at exit
    bool active = false;         // track allocations in this process image
    bool report_enabled = false; // write findings (false in untraced forks)
};
extern Config g_cfg;
// This process's pid, set at start and in each fork() child. A vfork()
// child shares the parent's memory, so getpid() differs from it there.
extern uint32_t g_self_pid;
// In a fork() child: the parent's thread that forked (glibc still names it
// as the owner of the mutexes it held, e.g. from a pthread_atfork prepare
// handler). 0 in the parent once fork() returns.
extern uint32_t g_fork_tid;
void load_config();
bool append_report(const char *p, size_t n);

// A descriptor number the runtime keeps free for itself (the report file and
// /proc/self/maps are opened while reporting), so it can still report when the
// program has used every descriptor it may have. open_for_runtime() is open(2)
// that gives the spare up when the program is out of descriptors, and
// close_for_runtime() closes what it opened and takes the spare again.
void fd_reserve_make();
int open_for_runtime(const char *path, int flags);
void close_for_runtime(int fd);

// Small allocator for allocations made while tl_in_hook is set.
namespace ih {
bool owns(const void *p);
void *alloc(size_t size, size_t align);
void free(void *p);
size_t usable(const void *p);
bool used_range(uintptr_t *lo, uintptr_t *hi);
// The whole reserved region [lo, hi), including not-yet-used pages: the leak
// scan's anonymous pass must skip it (the used part is scanned as roots).
bool full_range(uintptr_t *lo, uintptr_t *hi);
void lock();
void unlock();
void reset_lock();
} // namespace ih

} // namespace lc
