// Unit tests for the injected runtime, linked into an ordinary program so
// its pieces can be driven directly: the allocation table, stack interning,
// the internal heap, error detection in the tracked heap, guard pages and
// the report stream it writes.
#include "check.h"

#include "blocks.h"
#include "guard.h"
#include "heap.h"
#include "protocol.h"
#include "resources.h"
#include "stacks.h"
#include "threads.h"

#include "../../reporter/include/report.h"

#include <csignal>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <pthread.h>
#include <random>
#include <set>
#include <string>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <vector>

using namespace lc;
using namespace lcproto;

namespace {

constexpr size_t npos = std::string::npos;

std::string g_report;
size_t g_read;

// The runtime as init() would leave it, minus the interposed entry points.
struct Setup {
    Setup() {
        char path[] = "/tmp/lc_runtime_XXXXXX";
        int fd = mkstemp(path);
        if (fd >= 0)
            close(fd);
        g_report = path;
        strcpy(g_cfg.report_path, path);
        g_cfg.report_fd = 2;
        g_cfg.active = g_cfg.report_enabled = true;
        threads::init();
        stacks::set_ready(); // not stacks::init(): that would hide this
                             // program's frames
    }
    ~Setup() { unlink(g_report.c_str()); }
} g_setup;

// Report stream written since the previous call.
std::string drain() {
    std::ifstream in(g_report, std::ios::binary);
    const std::string all((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());
    const std::string fresh = all.size() > g_read ? all.substr(g_read) : "";
    g_read = all.size();
    return fresh;
}

// A loop bound the compiler cannot see through, so the loop is not unrolled
// and every iteration calls from the same site.
LC_NOINLINE int reps(int n) {
    volatile int v = n;
    return v;
}

int occurrences(const std::string &s, const std::string &what) {
    int n = 0;
    for (size_t i = s.find(what); i != npos; i = s.find(what, i + 1))
        ++n;
    return n;
}

int findings(const std::string &s, const char *type) {
    return occurrences(s, std::string("B type=") + type + " ");
}

int total_findings(const std::string &s) {
    return occurrences("\n" + s, "\nB ");
}

char *alloc(size_t n, Kind k = Kind::Malloc, size_t align = 16,
            bool zero = false) {
    return static_cast<char *>(heap_alloc(k, n, align, zero));
}

void release(void *p, DeKind dk = DeKind::Free) {
    heap_free(dk, p, 0, false, false);
}

// Verifies and releases everything in quarantine.
void flush_quarantine() {
    const uint64_t saved = g_cfg.quarantine_entries;
    g_cfg.quarantine_entries = 0;
    release(alloc(1));
    g_cfg.quarantine_entries = saved;
}

constexpr uintptr_t kFakeBase =
    0xF000'0000'0000; // non-canonical: never a real pointer

Block fake(uintptr_t user, uint64_t seq) {
    Block b{};
    b.user = user;
    b.size = user & 0xffff;
    b.seq = seq;
    b.state = State::Live;
    return b;
}

} // namespace

// ------------------------------------------------------------ primitives

TEST(buf_formats_and_truncates) {
    char m[64];
    Buf b(m, sizeof m);
    b.u(0).c(' ').u(18446744073709551615ull).c(' ').x(0).c(' ').p(0xbeef);
    b.c(' ').s(nullptr).c(' ').line("a\nb\rc");
    CHECK_EQ(std::string(b.cstr()),
             std::string("0 18446744073709551615 0 0xbeef (null) a b c"));
    char t[8];
    Buf small(t, sizeof t);
    small.s("abcdefghij");
    CHECK_EQ(small.size(), size_t(7));
    CHECK_EQ(std::string(small.cstr()), std::string("abcdefg"));
}

TEST(env_and_config) {
    setenv("LC_UNIT_N", "42", 1);
    CHECK_EQ(env_u64("LC_UNIT_N", 7), uint64_t(42));
    setenv("LC_UNIT_N", "4x", 1);
    CHECK_EQ(env_u64("LC_UNIT_N", 7), uint64_t(7));
    setenv("LC_UNIT_N", "", 1);
    CHECK_EQ(env_u64("LC_UNIT_N", 7), uint64_t(7));
    unsetenv("LC_UNIT_N");

    const Config saved = g_cfg;
    setenv(kEnvStackDepth, "500", 1);
    setenv(kEnvQuarantineMb, "8", 1);
    setenv(kEnvReport, "/tmp/x", 1);
    g_cfg = Config{};
    load_config();
    CHECK(g_cfg.active && g_cfg.report_enabled);
    CHECK_EQ(g_cfg.stack_depth, 64u);
    CHECK_EQ(g_cfg.quarantine_bytes, uint64_t(8) << 20);
    CHECK_EQ(std::string(g_cfg.report_path), std::string("/tmp/x"));

    setenv(kEnvStackDepth, "0", 1);
    setenv(kEnvRootPid, "1", 1); // another process's run: stay passive
    g_cfg = Config{};
    load_config();
    CHECK_EQ(g_cfg.stack_depth, 1u);
    CHECK(!g_cfg.active && !g_cfg.report_enabled);

    setenv(kEnvTraceChildren, "1", 1);
    g_cfg = Config{};
    load_config();
    CHECK(g_cfg.active && g_cfg.report_enabled);

    for (const char *e : {kEnvStackDepth, kEnvQuarantineMb, kEnvReport,
                          kEnvRootPid, kEnvTraceChildren})
        unsetenv(e);
    g_cfg = saved;
}

TEST(map_pages_registers_ranges) {
    static Range r[1 << 16];
    const size_t pg = page_size();
    auto *p = static_cast<byte *>(map_pages(pg + 1));
    CHECK(p && uintptr_t(p) % pg == 0);
    if (!p)
        return;
    CHECK(p[0] == 0 && p[2 * pg - 1] == 0);
    auto registered = [&] {
        const size_t n = runtime_ranges(r, 1 << 16);
        for (size_t i = 0; i < n; ++i)
            if (r[i].lo == uintptr_t(p))
                return r[i].hi == uintptr_t(p) + 2 * pg;
        return false;
    };
    CHECK(registered());
    const size_t n = runtime_ranges(r, 1 << 16);
    for (size_t i = 1; i < n; ++i)
        CHECK(r[i - 1].lo < r[i].lo);
    unmap_pages(p, pg + 1);
    CHECK(!registered());
}

// ------------------------------------------------------------ blocks

TEST(blocks_match_a_reference_map) {
    const size_t base = blocks::count();
    std::unordered_map<uintptr_t, uint64_t> ref;
    std::mt19937_64 rng(1);
    uint64_t seq = 0;
    bool ok = true;
    for (int op = 0; op < 200000; ++op) {
        const uintptr_t key = kFakeBase + (rng() % 20000) * 16;
        const auto it = ref.find(key);
        switch (rng() % 4) {
        case 0:
        case 1:
            blocks::insert(fake(key, ++seq));
            ref[key] = seq;
            break;
        case 2: {
            Block old{};
            if (blocks::remove(key, &old) != (it != ref.end()) ||
                (it != ref.end() && old.seq != it->second))
                ok = false;
            ref.erase(key);
            break;
        }
        default: {
            blocks::Handle h = blocks::lookup(key);
            if ((h.get() != nullptr) != (it != ref.end()) ||
                (h.get() && h.get()->seq != it->second))
                ok = false;
        }
        }
    }
    CHECK(ok);
    CHECK_EQ(blocks::count(), base + ref.size());
    if (!ref.empty()) {
        // A stale sequence number never removes the current record.
        const auto [key, cur] = *ref.begin();
        CHECK(!blocks::remove(key, nullptr, cur + 1));
        CHECK(blocks::remove(key, nullptr, cur));
        ref.erase(key);
    }
    for (const auto &[key, s] : ref)
        CHECK(blocks::remove(key, nullptr, s));
    CHECK_EQ(blocks::count(), base);
}

TEST(blocks_concurrent_threads) {
    const size_t base = blocks::count();
    constexpr int kThreads = 8;
    bool ok[kThreads] = {};
    std::vector<std::thread> ts;
    for (int t = 0; t < kThreads; ++t)
        ts.emplace_back([t, &ok] {
            std::unordered_map<uintptr_t, uint64_t> mine;
            std::mt19937_64 rng(t);
            bool good = true;
            for (uint64_t op = 1; op <= 50000; ++op) {
                const uintptr_t key =
                    kFakeBase + (uintptr_t(t + 1) << 32) + (rng() % 2000) * 16;
                const auto it = mine.find(key);
                if (rng() % 2) {
                    blocks::insert(fake(key, op));
                    mine[key] = op;
                } else if (it != mine.end()) {
                    if (!blocks::remove(key, nullptr, it->second))
                        good = false;
                    mine.erase(it);
                } else {
                    blocks::Handle h = blocks::lookup(key);
                    if (h.get())
                        good = false;
                }
            }
            for (const auto &[key, s] : mine)
                if (!blocks::remove(key, nullptr, s))
                    good = false;
            ok[t] = good;
        });
    for (auto &th : ts)
        th.join();
    for (bool b : ok)
        CHECK(b);
    CHECK_EQ(blocks::count(), base);
}

// ------------------------------------------------------------ stacks

TEST(stacks_intern_and_get) {
    const uintptr_t *fr = nullptr;
    uint32_t n = 0;
    CHECK_EQ(stacks::intern(nullptr, 0), 0u);
    CHECK(!stacks::get(0, &fr, &n));
    std::set<uint32_t> ids;
    bool ok = true;
    for (uintptr_t i = 0; i < 20000; ++i) {
        const uintptr_t f[3] = {0x400000 + i, 0x500000, 0x600000 + i / 3};
        const uint32_t len = uint32_t(1 + i % 3);
        const uint32_t id = stacks::intern(f, len);
        if (!id || !ids.insert(id).second || stacks::intern(f, len) != id)
            ok = false;
        if (!stacks::get(id, &fr, &n) || n != len ||
            memcmp(fr, f, len * sizeof *f) != 0)
            ok = false;
    }
    CHECK(ok);
}

TEST(stacks_capture_is_interned) {
    uint32_t ids[2] = {};
    for (int i = 0; i < reps(2); ++i) // one call site: one stack
        ids[i] = stacks::capture();
    CHECK(ids[0] != 0 && ids[0] == ids[1]);
    const uint32_t other = stacks::capture();
    CHECK(other != 0 && other != ids[0]);

    const Config saved = g_cfg;
    g_cfg.fast_unwind = true;
    g_cfg.stack_depth = 2;
    const uint32_t fast = stacks::capture();
    g_cfg = saved;
    const uintptr_t *fr = nullptr;
    uint32_t n = 0;
    CHECK(stacks::get(fast, &fr, &n));
    CHECK(n >= 1 && n <= 2);
}

// ------------------------------------------------------------ internal heap

TEST(internal_heap) {
    void *a = ih::alloc(10, 16);
    void *b = ih::alloc(100, 256);
    CHECK(a && b && ih::owns(a) && ih::owns(b));
    CHECK(uintptr_t(a) % 16 == 0 && uintptr_t(b) % 256 == 0);
    CHECK(ih::usable(a) >= 10 && ih::usable(b) >= 100);
    int local = 0;
    CHECK(!ih::owns(&local));
    uintptr_t lo = 0, hi = 0;
    CHECK(ih::used_range(&lo, &hi) && lo <= uintptr_t(b) &&
          uintptr_t(b) + 100 <= hi);
    memset(b, 0x5a, 100);

    ih::free(a);
    void *c = ih::alloc(12, 16);
    CHECK(c == a); // same size class: reused
    ih::free(c);
    ih::free(c); // ignored: the header is no longer valid
    void *d = ih::alloc(10, 16);
    void *e = ih::alloc(10, 16);
    CHECK(d && e && d != e);
    // Over-aligned: the header is not where the free-list link goes.
    ih::free(b);
    // The leak scan reads this region as roots: a freed block keeps nothing.
    bool zeroed = true;
    for (int i = 0; i < 100; ++i)
        zeroed = zeroed && static_cast<unsigned char *>(b)[i] == 0;
    CHECK(zeroed);
    ih::free(b);
    void *f = ih::alloc(100, 256);
    void *g = ih::alloc(100, 256);
    CHECK(f && g && f != g);
    CHECK(ih::alloc(size_t(1) << 27, 16) == nullptr);
    ih::free(d);
    ih::free(e);
    ih::free(f);
    ih::free(g);
}

// ------------------------------------------------------------ tracked heap

TEST(heap_clean_use_reports_nothing) {
    drain();
    char *p = alloc(100, Kind::Malloc, 16, true);
    CHECK(p && uintptr_t(p) % 16 == 0);
    if (!p)
        return;
    bool zero = true;
    for (int i = 0; i < 100; ++i)
        zero = zero && p[i] == 0;
    CHECK(zero);
    memset(p, 1, 100);
    CHECK_EQ(heap_usable(p), size_t(100));
    char *empty = alloc(0);
    CHECK(empty && empty != p);
    char *a64 = alloc(100, Kind::Memalign, 64, true);
    char *a4k = alloc(10, Kind::Memalign, 4096);
    CHECK(a64 && uintptr_t(a64) % 64 == 0 && a64[99] == 0);
    CHECK(a4k && uintptr_t(a4k) % 4096 == 0);
    char *n = alloc(8, Kind::New);
    char *na = alloc(8, Kind::NewArray);
    release(p);
    release(empty);
    release(a64);
    release(a4k);
    release(n, DeKind::Delete);
    release(na, DeKind::DeleteArray);
    CHECK_EQ(heap_usable(p), size_t(0));
    CHECK_EQ(total_findings(drain()), 0);
}

TEST(heap_rejects_impossible_requests) {
    CHECK(alloc(10, Kind::Memalign, 48) == nullptr);
    CHECK(alloc(kMaxAlloc + 1) == nullptr);
    CHECK(alloc(10, Kind::Memalign, kMaxAlign * 2) == nullptr);
}

TEST(heap_stats_track_live_memory) {
    const report::Stats a = heap_stats();
    char *x = alloc(10);
    char *y = alloc(20);
    char *z = alloc(30);
    release(x);
    release(y);
    const report::Stats b = heap_stats();
    CHECK_EQ(b.allocs - a.allocs, uint64_t(3));
    CHECK_EQ(b.frees - a.frees, uint64_t(2));
    CHECK_EQ(b.bytes - a.bytes, uint64_t(60));
    CHECK_EQ(b.live_blocks - a.live_blocks, uint64_t(1));
    CHECK_EQ(b.live_bytes - a.live_bytes, uint64_t(30));
    CHECK(b.peak_bytes >= b.live_bytes);
    release(z);
}

TEST(heap_double_free) {
    drain();
    char *p = alloc(24);
    release(p);
    release(p);
    const std::string s = drain();
    CHECK_EQ(findings(s, kDoubleFree), 1);
    CHECK(s.find("msg=free() on a 24-byte block that was already freed\n") !=
          npos);
    CHECK(s.find("\nS a ") != npos && s.find("\nS l ") != npos &&
          s.find("\nS f ") != npos);
    CHECK_EQ(total_findings(s), 1);
}

TEST(heap_redzone_overflow_and_underflow) {
    drain();
    char *p = alloc(10);
    p[12] = 'x';
    release(p);
    std::string s = drain();
    CHECK_EQ(findings(s, kOverflow), 1);
    CHECK(s.find("msg=3 byte(s) written past the end of a 10-byte block (1 "
                 "corrupted "
                 "redzone byte(s), detected when the block was freed)") !=
          npos);

    char *q = alloc(10);
    q[-1] = 'x';
    release(q);
    s = drain();
    CHECK_EQ(findings(s, kUnderflow), 1);
    CHECK(s.find("msg=1 byte(s) written before the start of a 10-byte block") !=
          npos);
    CHECK_EQ(total_findings(s), 1);
}

TEST(heap_exit_verification) {
    drain();
    char *live = alloc(16);
    live[16] = 'x';
    char *dead = alloc(16);
    release(dead);
    dead[3] = 'y';
    blocks::lock_all();
    heap_verify_all_locked();
    blocks::unlock_all();
    const std::string s = drain();
    CHECK_EQ(findings(s, kOverflow), 1);
    CHECK_EQ(findings(s, kUseAfterFree), 1);
    CHECK(s.find("1 byte(s) written past the end of a 16-byte block (1 "
                 "corrupted redzone "
                 "byte(s), detected at exit)") != npos);
    CHECK(s.find("changed after free (offsets 3..3), detected at exit") !=
          npos);
    CHECK_EQ(total_findings(s), 2);
    // Repair both so later checks stay quiet.
    live[16] = char(rz_byte(0, kRightBase));
    dead[3] = char(kPoison);
    release(live);
    CHECK_EQ(total_findings(drain()), 0);
}

TEST(heap_write_after_free_found_on_eviction) {
    flush_quarantine();
    drain();
    char *p = alloc(40);
    release(p);
    p[39] = 1;
    flush_quarantine();
    const std::string s = drain();
    CHECK_EQ(findings(s, kUseAfterFree), 1);
    CHECK(s.find("(offsets 39..39), detected when the block left quarantine") !=
          npos);
    CHECK_EQ(total_findings(s), 1);
    CHECK_EQ(heap_usable(p), size_t(0));
}

TEST(heap_quarantine_is_bounded) {
    flush_quarantine();
    const size_t base = blocks::count();
    const uint64_t saved = g_cfg.quarantine_bytes;
    g_cfg.quarantine_bytes = 64 << 10;
    for (int i = 0; i < reps(1000); ++i)
        release(alloc(1000));
    // A thousand ~1 KiB blocks through a 64 KiB quarantine: most were let go.
    CHECK(blocks::count() - base <= 64);
    g_cfg.quarantine_bytes = saved;
    flush_quarantine();
    CHECK_EQ(blocks::count(), base);
}

TEST(heap_large_block_skips_quarantine) {
    flush_quarantine();
    drain();
    const uint64_t saved = g_cfg.quarantine_bytes;
    g_cfg.quarantine_bytes = 1 << 20; // blocks over 256 KiB go back at once
    const size_t big = 300 << 10;
    char *p = alloc(big);
    release(p);
    {
        blocks::Handle h = blocks::lookup(uintptr_t(p));
        CHECK(h.get() && h.get()->state == State::Freed &&
              (h.get()->flags & kFlagReleased));
    }
    release(p); // the record outlives the memory: still a double free
    CHECK_EQ(findings(drain(), kDoubleFree), 1);

    // The allocator may hand the same address straight back; the stale
    // quarantine entry must not take the new block's record with it.
    char *q = alloc(big);
    flush_quarantine();
    CHECK_EQ(heap_usable(q), big);
    release(q);
    g_cfg.quarantine_bytes = saved;
    flush_quarantine();
    CHECK_EQ(total_findings(drain()), 0);
}

TEST(heap_alloc_dealloc_mismatch) {
    drain();
    release(alloc(8, Kind::New));
    release(alloc(8, Kind::NewArray), DeKind::Delete);
    release(alloc(8), DeKind::DeleteArray);
    release(alloc(8, Kind::Memalign, 64), DeKind::Delete);
    const std::string s = drain();
    CHECK_EQ(findings(s, kMismatch), 4);
    CHECK(s.find("msg=memory allocated with operator new was released with "
                 "free()\n") != npos);
    CHECK(s.find("msg=memory allocated with operator new[] was released with "
                 "operator delete\n") != npos);
    CHECK(s.find("msg=memory allocated with malloc() was released with "
                 "operator delete[]\n") != npos);
    CHECK_EQ(total_findings(s), 4);
}

TEST(heap_sized_delete) {
    drain();
    char *p = alloc(24, Kind::New);
    heap_free(DeKind::Delete, p, 24, true, false);
    CHECK_EQ(total_findings(drain()), 0);
    p = alloc(24, Kind::New);
    heap_free(DeKind::Delete, p, 16, true, false);
    const std::string s = drain();
    CHECK_EQ(findings(s, kSizeMismatch), 1);
    CHECK(s.find("msg=sized operator delete was told 16 byte(s) but the block "
                 "holds 24") != npos);
    CHECK_EQ(total_findings(s), 1);
}

TEST(heap_invalid_frees_are_explained) {
    drain();
    char local[16];
    release(local);
    char *p = alloc(64);
    release(p + 8);
    static char s_static[16];
    release(s_static);
    release(reinterpret_cast<void *>(uintptr_t(0xdddddddddddddddd)));
    void *foreign = __libc_malloc(32);
    release(foreign);
    const std::string s = drain();
    CHECK_EQ(findings(s, kInvalidFree), 5);
    CHECK(s.find(", which is on the stack of thread ") != npos);
    CHECK(s.find(", which points 8 byte(s) inside a 64-byte block") != npos);
    CHECK(s.find(", which is static memory of the main executable") != npos);
    CHECK(s.find("fill pattern for freed memory") != npos);
    CHECK(s.find(", which was not returned by the allocator") != npos);
    CHECK_EQ(total_findings(s), 5);
    // The runtime's own frees of foreign memory go straight to libc.
    heap_free(DeKind::Free, foreign, 0, false, true);
    release(p);
    CHECK_EQ(total_findings(drain()), 0);
}

TEST(heap_realloc) {
    drain();
    char *p = alloc(8);
    memcpy(p, "abcdefg", 8);
    char *q = static_cast<char *>(heap_realloc(p, 1000, false));
    CHECK(q && q != p && memcmp(q, "abcdefg", 8) == 0);
    CHECK_EQ(heap_usable(p), size_t(0));
    CHECK_EQ(heap_usable(q), size_t(1000));
    char *r = static_cast<char *>(heap_realloc(q, 4, false));
    CHECK(r && memcmp(r, "abcd", 4) == 0);
    CHECK_EQ(total_findings(drain()), 0);

    CHECK(heap_realloc(p, 16, false) == nullptr); // p is gone
    std::string s = drain();
    CHECK_EQ(findings(s, kUseAfterFree), 1);
    CHECK(s.find("msg=realloc() on a 8-byte block that was already freed") !=
          npos);

    char *n = alloc(8, Kind::New);
    char *m = static_cast<char *>(heap_realloc(n, 16, false));
    s = drain();
    CHECK(m != nullptr);
    CHECK_EQ(findings(s, kMismatch), 1);
    CHECK(s.find("msg=memory allocated with operator new was resized with "
                 "realloc()") != npos);
    CHECK_EQ(total_findings(s), 1);

    int local = 0;
    CHECK(heap_realloc(&local, 8, false) == nullptr);
    CHECK_EQ(findings(drain(), kInvalidFree), 1);
    release(r);
    release(m);
}

TEST(heap_concurrent_use_is_clean) {
    drain();
    const uint64_t saved = g_cfg.quarantine_bytes;
    g_cfg.quarantine_bytes = 256 << 10; // keep eviction busy
    const report::Stats before = heap_stats();
    constexpr int kThreads = 8;
    bool ok[kThreads] = {};
    std::vector<std::thread> ts;
    for (int t = 0; t < kThreads; ++t)
        ts.emplace_back([t, &ok] {
            std::mt19937 rng(t);
            std::vector<std::pair<char *, size_t>> live;
            bool good = true;
            for (int op = 0; op < 20000; ++op) {
                if (live.empty() || (live.size() < 64 && rng() % 2)) {
                    const size_t n = rng() % 300;
                    char *p = alloc(n);
                    if (!p) {
                        good = false;
                        continue;
                    }
                    memset(p, int(n & 0xff), n);
                    live.emplace_back(p, n);
                } else {
                    const size_t i = rng() % live.size();
                    const auto [p, n] = live[i];
                    for (size_t k = 0; k < n; ++k)
                        if (p[k] != char(n & 0xff))
                            good = false;
                    release(p);
                    live[i] = live.back();
                    live.pop_back();
                }
            }
            for (const auto &[p, n] : live)
                release(p);
            ok[t] = good;
        });
    for (auto &th : ts)
        th.join();
    for (bool b : ok)
        CHECK(b);
    g_cfg.quarantine_bytes = saved;
    const report::Stats after = heap_stats();
    CHECK_EQ(after.allocs - before.allocs, after.frees - before.frees);
    CHECK_EQ(after.live_bytes, before.live_bytes);
    CHECK_EQ(total_findings(drain()), 0);
}

// ------------------------------------------------------------ guard pages

namespace {
// One block in its own guard-page mapping, or nullptr.
volatile char *guarded(size_t n) {
    g_cfg.guard_every = 1;
    guard::init();
    char *p = alloc(n);
    g_cfg.guard_every = 0;
    blocks::Handle h = blocks::lookup(uintptr_t(p));
    return h.get() && (h.get()->flags & kFlagGuarded) ? p : nullptr;
}
} // namespace

TEST(guard_pages_fault_on_bad_access) {
    drain();
    volatile char *p = guarded(16);
    CHECK(p != nullptr);
    if (!p)
        return;
    // The handler reports each fault, then opens the page so the access
    // completes.
    p[16] = 1; // first byte of the right guard page
    std::string s = drain();
    CHECK_EQ(findings(s, kOverflow), 1);
    CHECK(s.find("msg=write at 0 byte(s) after the end of a 16-byte block "
                 "(guard page)") != npos);

    const size_t below =
        page_size() - 16 + 1; // last byte of the left guard page
    char c = p[-ptrdiff_t(below)];
    (void)c;
    s = drain();
    CHECK_EQ(findings(s, kUnderflow), 1);
    CHECK(s.find("msg=read at " + std::to_string(below) +
                 " byte(s) before the start of a 16-byte") != npos);

    release(const_cast<char *>(p));
    c = p[5];
    (void)c;
    s = drain();
    CHECK_EQ(findings(s, kUseAfterFree), 1);
    CHECK(s.find("msg=read of freed memory at offset 5 of a freed 16-byte "
                 "block (guard page)") != npos);
    CHECK_EQ(total_findings(s), 1);
}

// ------------------------------------------------------------ threads

TEST(threads_registry_tracks_stacks) {
    int here = 0;
    uint32_t tid = 0;
    CHECK(threads::find_stack(uintptr_t(&here), &tid) && tid == current_tid());
    uintptr_t addr = 0;
    uint32_t seen = 0, want = 0;
    bool found = false;
    std::thread t([&] {
        volatile int local = 0;
        addr = uintptr_t(&local);
        want = current_tid();
        found = threads::find_stack(addr, &seen);
    });
    t.join();
    CHECK(found && seen == want && want != current_tid());
    CHECK(!threads::find_stack(addr, nullptr)); // its slot went with the thread
}

// ------------------------------------------------------------ report stream

// ------------------------------------------------------------ resources

TEST(resources_report_what_stays_open) {
    using res::Kind;
    drain();
    // This program has no interposed open/close: drive the table directly.
    const int kept = ::open("/dev/null", O_RDONLY);
    const int shut = ::open("/dev/null", O_RDONLY);
    res::opened(Kind::Fd, uint64_t(kept), "open()");
    res::opened(Kind::Fd, uint64_t(shut), "open()");
    ::close(shut);
    res::closed(Kind::Fd, uint64_t(shut));
    // Closed where the table could not see it: the kernel has the last word.
    const int unseen = ::open("/dev/null", O_RDONLY);
    res::opened(Kind::Fd, uint64_t(unseen), "socket()");
    ::close(unseen);
    int streams[2];
    res::opened(Kind::File, uint64_t(&streams[0]), "fopen()");
    res::opened(Kind::Pipe, uint64_t(&streams[1]), "popen()");
    res::opened(Kind::Dir, 0x1000, "opendir()");
    res::forget(Kind::Dir, 0x1000);
    res::opened(Kind::Fd, 1, "dup2()"); // standard streams are the program's
    res::report_at_exit();
    const std::string s = drain();
    CHECK_EQ(findings(s, kResourceLeak), 3);
    CHECK(s.find("msg=file descriptor " + std::to_string(kept) +
                 " from open() is still open when the program ends\n") != npos);
    CHECK(s.find("socket()") == npos && s.find("opendir()") == npos &&
          s.find("dup2()") == npos);
    CHECK(s.find("msg=FILE stream from fopen() is never closed\n") != npos);
    CHECK(s.find("from popen() is never closed (the command is never waited "
                 "for)") != npos);
    CHECK(s.find("cat=fd") != npos && s.find("cat=stream") != npos);
    CHECK(s.find("\nS l ") != npos); // where it was opened
    ::close(kept);
    res::closed(Kind::Fd, uint64_t(kept));
    res::closed(Kind::File, uint64_t(&streams[0]));
    res::closed(Kind::Pipe, uint64_t(&streams[1]));
    res::forget(Kind::Fd, 1);
    res::forget(Kind::Fd, uint64_t(unseen)); // its number will be reused
}

TEST(children_that_exit_unwaited_are_reported) {
    using res::Kind;
    drain();
    int gate[2];
    CHECK(::pipe(gate) == 0);
    pid_t exited[2];
    for (pid_t &p : exited)
        if ((p = ::fork()) == 0)
            _exit(0);
    const pid_t running = ::fork();
    if (running == 0) { // until the parent closes the pipe
        ::close(gate[1]);
        char c;
        _exit(int(::read(gate[0], &c, 1)));
    }
    siginfo_t si{};
    for (pid_t p : exited) // exited, status not collected
        CHECK(::waitid(P_PID, id_t(p), &si, WEXITED | WNOWAIT) == 0);
    // Separate calls: findings with the same stack are folded into one.
    res::opened(Kind::Process, uint64_t(exited[0]), "fork()");
    res::opened(Kind::Process, uint64_t(exited[1]), "fork()");
    res::opened(Kind::Process, uint64_t(running), "fork()");
    si.si_pid = exited[1]; // as if waitid() had collected it
    res::waited_id(&si, WEXITED);
    si.si_pid = exited[0]; // only peeked at
    res::waited_id(&si, WEXITED | WNOWAIT);
    res::report_at_exit();
    const std::string s = drain();
    CHECK_EQ(findings(s, kResourceLeak), 1);
    CHECK(s.find("msg=child process " + std::to_string(exited[0]) +
                 " from fork() exited but was never waited for") != npos);
    CHECK(s.find("cat=process") != npos);
    ::close(gate[1]);
    for (pid_t p : {exited[0], exited[1], running})
        ::waitpid(p, nullptr, 0);
    ::close(gate[0]);
    res::forget(Kind::Process, uint64_t(exited[0]));
    res::forget(Kind::Process, uint64_t(running));
}

TEST(resources_double_close_and_mismatch) {
    using res::Kind;
    drain();
    int x[2];
    const uint64_t f = uint64_t(&x[0]);
    res::opened(Kind::File, f, "fopen()");
    CHECK(res::closing(Kind::File, f, "fclose()"));
    res::closed(Kind::File, f);
    CHECK(!res::closing(Kind::File, f, "fclose()")); // refused: already closed
    std::string s = drain();
    CHECK_EQ(findings(s, kDoubleClose), 1);
    CHECK(s.find("msg=fclose() on a FILE stream that was already closed\n") !=
          npos);
    CHECK(s.find("\nS f ") != npos); // the first close

    const uint64_t g = uint64_t(&x[1]);
    res::opened(Kind::File, g, "fopen()");
    CHECK(res::closing(Kind::Pipe, g, "pclose()"));
    res::closed(Kind::Pipe, g);
    s = drain();
    CHECK_EQ(findings(s, kMismatch), 1);
    CHECK(s.find("msg=FILE stream opened with fopen() was closed with "
                 "pclose(); use fclose()\n") != npos);

    // EBADF on a descriptor seen closed is a double close; on one never
    // seen, or reopened since, it is not.
    res::closed(Kind::Fd, 900);
    res::close_failed(900, "close()");
    res::close_failed(901, "close()");
    s = drain();
    CHECK_EQ(findings(s, kDoubleClose), 1);
    CHECK(s.find("msg=close() on file descriptor 900, which was already "
                 "closed\n") != npos);
    res::opened(Kind::Fd, 900, "open()");
    res::close_failed(900, "close()");
    CHECK_EQ(total_findings(drain()), 0);
    res::forget(Kind::Fd, 900);

    res::opened(Kind::Fd, 910, "open()");
    res::opened(Kind::Fd, 911, "open()");
    res::closed_range(905, 910);
    res::close_failed(910, "close()");
    res::close_failed(911, "close()");
    s = drain();
    CHECK_EQ(findings(s, kDoubleClose), 1);
    CHECK(s.find("file descriptor 910,") != npos);
    res::forget(Kind::Fd, 910);
    res::forget(Kind::Fd, 911);
}

TEST(resources_reused_fd_second_close_is_double_close) {
    using res::Kind;
    drain();
    // Closed and not reused: the failing use is a use after close.
    res::opened(Kind::Fd, 920, "open()");
    res::closed(Kind::Fd, 920);
    res::used_closed(920, "write()");
    std::string s = drain();
    CHECK_EQ(findings(s, kUseAfterClose), 1);
    CHECK_EQ(findings(s, kDoubleClose), 0);

    // Closed, opened again, closed again, then used: double close of the
    // first lifetime, at the second close, not a use after close.
    res::opened(Kind::Fd, 921, "open()");
    res::closed(Kind::Fd, 921);
    res::opened(Kind::Fd, 921, "open()");
    res::closed(Kind::Fd, 921);
    res::used_closed(921, "write()");
    s = drain();
    CHECK_EQ(findings(s, kDoubleClose), 1);
    CHECK_EQ(findings(s, kUseAfterClose), 0);
    CHECK(s.find("msg=close() on file descriptor 921, which was already "
                 "closed\n") != npos);
    res::forget(Kind::Fd, 920);
    res::forget(Kind::Fd, 921);
}

TEST(resources_closed_records_are_bounded) {
    using res::Kind;
    drain();
    // Open across the purges that drop closed records: must survive them.
    res::opened(Kind::Dir, 0x5000, "opendir()");
    for (uint64_t i = 0; i < 70000; ++i)
        res::closed(Kind::File, 0x100000 + i * 16);
    res::report_at_exit();
    CHECK_EQ(findings(drain(), kResourceLeak), 1);
    res::forget(Kind::Dir, 0x5000);
}

namespace {
volatile int g_thread_done;

void *note_tid(void *) {
    g_thread_done = 1;
    return nullptr;
}

// Waits until the thread started last has exited (SYS_gettid/SYS_tgkill are
// Linux-only; a flag works everywhere: the test only needs the exit done).
void wait_gone() {
    while (!__atomic_load_n(&g_thread_done, __ATOMIC_ACQUIRE))
        usleep(1000);
    usleep(10000);
    __atomic_store_n(&g_thread_done, 0, __ATOMIC_RELEASE);
}
} // namespace

TEST(threads_that_finish_unjoined_are_reported) {
    drain();
    pthread_t joined, leaked, detached;
    CHECK(pthread_create(&joined, nullptr, note_tid, nullptr) == 0);
    wait_gone();
    pthread_join(joined, nullptr);
    CHECK(pthread_create(&leaked, nullptr, note_tid, nullptr) == 0);
    wait_gone();
    CHECK(pthread_create(&detached, nullptr, note_tid, nullptr) == 0);
    pthread_detach(detached);
    wait_gone();
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    CHECK(pthread_create(&detached, &attr, note_tid, nullptr) == 0);
    pthread_attr_destroy(&attr);
    wait_gone();
    res::report_at_exit();
    const std::string s = drain();
    CHECK_EQ(findings(s, kResourceLeak), 1);
    CHECK(s.find("cat=thread") != npos);
    CHECK(s.find("msg=thread from pthread_create() finished but was never "
                 "joined or detached") != npos);
    pthread_join(leaked, nullptr);
}

TEST(abort_on_error_stops_at_first_error) {
    const pid_t pid = fork();
    if (pid == 0) {
        const rlimit no_core{0, 0};
        setrlimit(RLIMIT_CORE, &no_core);
        const int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, 2);
        strcpy(g_cfg.report_path, "/dev/null");
        g_cfg.abort_on_error = true;
        char *p = alloc(8);
        release(p);
        release(p);
        _exit(0);
    }
    int status = 0;
    CHECK(pid > 0 && waitpid(pid, &status, 0) == pid);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
}

// Must stay last: finishing the stream ends reporting for this process.
TEST(zz_stream_round_trip) {
    drain();
    for (int i = 0; i < reps(3); ++i) { // one site, three times: one finding
        char *p = alloc(777);
        release(p);
        release(p);
    }
    report::finish(heap_stats());
    std::ifstream in(g_report);
    const std::string raw((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());
    CHECK(occurrences(raw, "\nD key=") >= 1);
    CHECK(raw.find("\nZ pid=" + std::to_string(getpid()) + "\n") != npos);

    lcreport::Report r;
    CHECK(lcreport::parse_runtime_stream(g_report, r));
    CHECK_EQ(r.processes.size(), size_t(1));
    if (r.processes.size() != 1)
        return;
    CHECK_EQ(r.processes[0].pid, uint32_t(getpid()));
    CHECK(r.processes[0].complete);
    CHECK(r.processes[0].stats.allocs > 0);
    CHECK_EQ(r.findings.size(), size_t(total_findings(raw)));

    const lcreport::Finding *df = nullptr;
    for (const auto &f : r.findings)
        if (f.type == kDoubleFree && f.size == 777)
            df = &f;
    CHECK(df != nullptr);
    if (!df)
        return;
    CHECK_EQ(df->occurrences, uint64_t(3));
    CHECK(!df->access.empty() && !df->alloc.empty() && !df->freed.empty());
    char exe[4096];
    const ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    exe[n > 0 ? n : 0] = 0;
    CHECK(!df->access.empty() && df->access[0].module == exe);

    // Module-relative offsets must lead addr2line back to this function.
    const size_t at = size_t(df - r.findings.data());
    lcreport::symbolize(r);
    bool named = false;
    for (const auto &fr : r.findings[at].access)
        named = named || fr.function.find("zz_stream_round_trip") != npos;
    CHECK(named);
}

TEST_MAIN()
