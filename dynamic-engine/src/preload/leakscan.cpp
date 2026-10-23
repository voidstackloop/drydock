#include "leakscan.h"
#include "blocks.h"
#include "protocol.h"
#include "report.h"
#include "stacks.h"
#include "threads.h"

#include <algorithm>
#include <cstring>
#ifdef _WIN32
#include "win_hooks.h"
#else
#include <csetjmp>
#include <csignal>
#include <dlfcn.h>
#include <fcntl.h>
#if defined(__APPLE__)
#include <mach/mach.h>
#else
#include <link.h>
#endif
#include <unistd.h>
#endif

namespace lc::leakscan {
namespace {

enum Cat : uint8_t { kUnset = 0, kReachable, kPossible, kIndirect, kDefinite };

struct Node {
    uintptr_t start;
    uint64_t size;
    uint64_t seq;
    uint32_t stack;
    uint32_t tid;
    bool system; // made by Windows' own code
};

struct MapEnt {
    uintptr_t lo, hi;
    bool readable;
    bool writable;
    bool priv;
    bool anonymous; // no backing file and not a kernel-named region
};

struct Group {
    uint8_t cat;
    uint32_t stack;
    uint64_t blocks;
    uint64_t bytes;
    size_t first;
};

const uintptr_t *g_extra; // set_extra_roots
size_t g_extra_n;
char *g_maps_text; // kept mapped until the scan ends: it is in the snapshot
size_t g_maps_text_cap;
Node *g_nodes;
uint8_t *g_cat;
uint8_t *g_flag; // pending-interior in phase A, has-incoming in phase C
uint32_t *g_work;
uint32_t *g_pending;
size_t g_n, g_wn, g_pn;
uintptr_t g_min, g_max;
MapEnt *g_maps;
size_t g_nmaps, g_maps_cap;

template <class T> T *alloc_array(size_t n) {
    void *p = map_pages(n * sizeof(T) + 1);
    if (!p)
        die("out of memory during leak scan");
    return static_cast<T *>(p);
}

#ifdef _WIN32
// Every committed region of the address space, in order (VirtualQuery in place
// of /proc/self/maps). "Anonymous" is private memory: not an image, not a file.
void load_maps() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    const uintptr_t end = uintptr_t(si.lpMaximumApplicationAddress);
    for (int pass = 0; pass < 2; ++pass) {
        size_t n = 0;
        for (uintptr_t addr = uintptr_t(si.lpMinimumApplicationAddress); addr < end;) {
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQuery(reinterpret_cast<void *>(addr), &mbi, sizeof mbi))
                break;
            const uintptr_t lo = uintptr_t(mbi.BaseAddress), hi = lo + mbi.RegionSize;
            addr = hi > addr ? hi : addr + si.dwPageSize;
            if (mbi.State != MEM_COMMIT)
                continue;
            const DWORD p = mbi.Protect;
            const DWORD rw = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE |
                             PAGE_EXECUTE_WRITECOPY;
            const DWORD ro = rw | PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE;
            MapEnt e;
            e.lo = lo;
            e.hi = hi;
            e.readable = (p & ro) && !(p & (PAGE_NOACCESS | PAGE_GUARD)) && !(p == PAGE_EXECUTE);
            e.writable = (p & rw) != 0;
            e.priv = mbi.Type == MEM_PRIVATE;
            e.anonymous = mbi.Type == MEM_PRIVATE;
            if (pass == 1 && g_nmaps < g_maps_cap)
                g_maps[g_nmaps++] = e;
            ++n;
        }
        if (pass == 0) {
            g_maps_cap = n + 64; // our own array splits a region or two
            g_maps = alloc_array<MapEnt>(g_maps_cap);
        }
    }
}
#elif defined(__APPLE__)
void load_maps() {
    auto collect = [](bool store) {
        vm_address_t addr = 0;
        size_t n = 0;
        while (true) {
            vm_size_t size = 0;
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t object = MACH_PORT_NULL;
            if (vm_region_64(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64,
                             reinterpret_cast<vm_region_info_t>(&info), &count,
                             &object) != KERN_SUCCESS)
                break;
            if (store) {
                if (n >= g_maps_cap)
                    return n;
                MapEnt e;
                e.lo = addr;
                e.hi = addr + size;
                e.readable = (info.protection & VM_PROT_READ) != 0;
                e.writable = (info.protection & VM_PROT_WRITE) != 0;
                e.priv = !info.shared;
                e.anonymous = !info.shared;
                g_maps[n] = e;
            }
            ++n;
            addr += size;
            if (!size)
                break;
        }
        return n;
    };
    g_maps_cap = collect(false) + 64;
    g_maps = alloc_array<MapEnt>(g_maps_cap);
    g_nmaps = collect(true);
}
#else
uintptr_t parse_hex(const char *&s) {
    uintptr_t v = 0;
    for (;; ++s) {
        char c = *s;
        if (c >= '0' && c <= '9')
            v = v * 16 + uintptr_t(c - '0');
        else if (c >= 'a' && c <= 'f')
            v = v * 16 + uintptr_t(c - 'a' + 10);
        else
            return v;
    }
}

void load_maps() {
    int fd = open_for_runtime("/proc/self/maps", O_RDONLY);
    if (fd < 0)
        return;
    size_t cap = size_t(1) << 20, len = 0;
    char *buf = static_cast<char *>(map_pages(cap));
    while (buf) {
        if (len + 4096 > cap) {
            char *nb = static_cast<char *>(map_pages(cap * 2));
            if (nb)
                memcpy(nb, buf, len);
            unmap_pages(buf, cap);
            buf = nb;
            cap *= 2;
            if (!buf)
                break;
        }
        ssize_t r = read(fd, buf + len, cap - len - 1);
        if (r <= 0)
            break;
        len += size_t(r);
    }
    close_for_runtime(fd);
    if (!buf)
        return;
    buf[len] = 0;
    size_t lines = 0;
    for (size_t i = 0; i < len; ++i)
        lines += buf[i] == '\n';
    g_maps_cap = lines + 1;
    g_maps = alloc_array<MapEnt>(g_maps_cap);
    const char *s = buf;
    while (*s && g_nmaps < g_maps_cap) {
        MapEnt e;
        e.lo = parse_hex(s);
        if (*s == '-')
            ++s;
        e.hi = parse_hex(s);
        if (*s == ' ')
            ++s;
        e.readable = s[0] == 'r';
        e.writable = s[0] && s[1] == 'w';
        e.priv = s[0] && s[1] && s[2] && s[3] == 'p';
        // skip perms, offset, dev and inode to the optional path
        for (int field = 0; field < 4 && *s && *s != '\n'; ++field) {
            while (*s && *s != ' ' && *s != '\n')
                ++s;
            while (*s == ' ')
                ++s;
        }
        e.anonymous = *s == '\n' || *s == 0 ||
                      (s[0] == '[' && s[1] == 'a' && s[2] == 'n');
        if (e.hi > e.lo)
            g_maps[g_nmaps++] = e;
        while (*s && *s != '\n')
            ++s;
        if (*s)
            ++s;
    }
    g_maps_text = buf;
    g_maps_text_cap = cap;
}
#endif

const MapEnt *map_containing(uintptr_t a) {
    size_t lo = 0, hi = g_nmaps;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (g_maps[mid].hi <= a)
            lo = mid + 1;
        else
            hi = mid;
    }
    return (lo < g_nmaps && g_maps[lo].lo <= a) ? &g_maps[lo] : nullptr;
}

// Index of the block the word points into, or -1.
inline long find(uintptr_t w, bool *is_start) {
    if (w < g_min || w > g_max)
        return -1;
    size_t lo = 0, hi = g_n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (g_nodes[mid].start <= w)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (!lo)
        return -1;
    const Node &nd = g_nodes[lo - 1];
    const uint64_t off = w - nd.start;
    *is_start = off == 0;
    return (off == 0 || off < nd.size) ? long(lo - 1) : -1;
}

void push(uint32_t i) { g_work[g_wn++] = i; }

void note_pending(uint32_t i) {
    if (!g_flag[i]) {
        g_flag[i] = 1;
        g_pending[g_pn++] = i;
    }
}

// Phase A: start pointers make blocks reachable; interior ones are remembered.
void root_word(uintptr_t w) {
    bool st;
    long i = find(w, &st);
    if (i < 0 || g_cat[i] != kUnset)
        return;
    if (st) {
        g_cat[i] = kReachable;
        push(uint32_t(i));
    } else {
        note_pending(uint32_t(i));
    }
}

void scan_raw(uintptr_t lo, uintptr_t hi) {
    lo = round_up(lo, sizeof(uintptr_t));
    for (uintptr_t a = lo; a + sizeof(uintptr_t) <= hi; a += sizeof(uintptr_t))
        root_word(*reinterpret_cast<const uintptr_t *>(a));
}

#ifdef _WIN32
// The regions come from VirtualQuery a moment ago and only readable ones are
// asked for; a thread releasing memory in between is not guarded against.
void scan_tolerant(uintptr_t lo, uintptr_t hi) { scan_raw(lo, hi); }
#else
// Other threads may unmap memory between our /proc/self/maps snapshot and
// the scan. Faults while scanning such regions skip to the next page.
sigjmp_buf g_probe_jmp;
volatile uintptr_t g_probe_fault;
LC_TLS uint8_t tl_probing; // only the scanning thread may jump back
struct sigaction g_old_segv, g_old_bus;

void probe_handler(int sig, siginfo_t *si, void *uctx) {
    if (tl_probing) {
        g_probe_fault = reinterpret_cast<uintptr_t>(si->si_addr);
        siglongjmp(g_probe_jmp, 1);
    }
    // A fault in some other thread while we scan: not ours to handle.
    const struct sigaction &prev = sig == SIGBUS ? g_old_bus : g_old_segv;
    if ((prev.sa_flags & SA_SIGINFO) && prev.sa_sigaction) {
        prev.sa_sigaction(sig, si, uctx);
    } else if (!(prev.sa_flags & SA_SIGINFO) && prev.sa_handler != SIG_DFL &&
               prev.sa_handler != SIG_IGN) {
        prev.sa_handler(sig);
    } else {
        signal(sig, SIG_DFL); // returning re-executes the access and dies
    }
}

void scan_tolerant(uintptr_t lo, uintptr_t hi) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = probe_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &g_old_segv);
    sigaction(SIGBUS, &sa, &g_old_bus);
    volatile uintptr_t cur = lo;
    const size_t pg = page_size();
    tl_probing = 1;
    while (cur < hi) {
        if (sigsetjmp(g_probe_jmp, 1) == 0) {
            scan_raw(cur, hi);
            break;
        }
        uintptr_t next = (g_probe_fault & ~(pg - 1)) + pg;
        cur = next > cur ? next : cur + pg;
    }
    tl_probing = 0;
    sigaction(SIGSEGV, &g_old_segv, nullptr);
    sigaction(SIGBUS, &g_old_bus, nullptr);
}
#endif

void scan_clamped(uintptr_t lo, uintptr_t hi) {
    if (hi <= lo)
        return;
    for (size_t k = 0; k < g_nmaps; ++k) {
        const MapEnt &m = g_maps[k];
        if (m.hi <= lo)
            continue;
        if (m.lo >= hi)
            break;
        if (!m.readable)
            continue;
        scan_raw(m.lo > lo ? m.lo : lo, m.hi < hi ? m.hi : hi);
    }
}

uintptr_t vma_end(uintptr_t a, uintptr_t fallback) {
    const MapEnt *m = map_containing(a);
    return m ? m->hi : fallback;
}

template <class F> void for_words_in(uint32_t i, F f) {
    const Node &nd = g_nodes[i];
    uintptr_t a = nd.start;
    const uintptr_t end = nd.start + nd.size;
    for (; a + sizeof(uintptr_t) <= end; a += sizeof(uintptr_t))
        f(*reinterpret_cast<const uintptr_t *>(a));
}

#ifdef _WIN32
// The writable sections of every module but ours (.data, .bss, and the
// thread-local template). Thread-local copies are found with the thread's
// own block (see untracked_roots).
void module_roots() {
    win::for_each_module([](uintptr_t base, size_t, const char *, void *) {
        if (stacks::in_self(base))
            return;
        const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
        const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
        const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (!(sec[i].Characteristics & IMAGE_SCN_MEM_WRITE))
                continue;
            const uintptr_t lo = base + sec[i].VirtualAddress;
            const size_t len = sec[i].Misc.VirtualSize > sec[i].SizeOfRawData
                                   ? sec[i].Misc.VirtualSize
                                   : sec[i].SizeOfRawData;
            scan_clamped(lo, round_up(lo + len, page_size()));
        }
    }, nullptr);
}
#elif defined(__APPLE__)
int module_root_one(const stacks::ImageView &im, void *) {
    if (stacks::in_self(im.lo))
        return 0;
    for (int i = 0; i < im.nw; ++i)
        scan_clamped(im.wlo[i], round_up(im.whi[i], page_size()));
    return 0;
}
void module_roots() { stacks::for_each_image(module_root_one, nullptr); }
#else
int module_roots_cb(struct dl_phdr_info *info, size_t, void *) {
    bool self = false;
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const auto &ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_LOAD &&
            stacks::in_self(info->dlpi_addr + ph.p_vaddr))
            self = true;
    }
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const auto &ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_LOAD && (ph.p_flags & PF_W) && !self) {
            // Through the end of the last page: ld.so's startup allocator
            // keeps link maps in the slack after its .bss.
            uintptr_t a = info->dlpi_addr + ph.p_vaddr;
            scan_clamped(a, round_up(a + ph.p_memsz, page_size()));
        }
        if (ph.p_type == PT_TLS && info->dlpi_tls_data) {
            uintptr_t a = reinterpret_cast<uintptr_t>(info->dlpi_tls_data);
            scan_clamped(a, a + ph.p_memsz);
        }
    }
    return 0;
}
#endif

void scan_threads(uintptr_t stack_lo) {
    const uint32_t me = current_tid();
    threads::Range ranges[512];
    const size_t n = threads::snapshot(ranges, 512);
    uintptr_t my_hi = 0;
    for (size_t i = 0; i < n; ++i) {
        if (ranges[i].tid == me) {
            my_hi = ranges[i].hi;
            continue;
        }
        // Above a thread's stack sit its descriptor and static TLS.
        scan_clamped(ranges[i].lo, vma_end(ranges[i].hi - 1, ranges[i].hi));
    }
    if (!my_hi) {
        uintptr_t lo;
        if (!threads::current_bounds(&lo, &my_hi))
            return;
    }
    scan_clamped(stack_lo, my_hi);
    scan_clamped(my_hi, vma_end(my_hi - 1, my_hi));
}

struct ExclList {
    Range *r;
    size_t n, cap;
};

#ifdef _WIN32
// Memory the program's heap allocations never reach: the busy blocks of the
// process heap that this runtime does not track (the loader's and Windows'
// own, thread-local copies of the program's variables among them) and the
// thread environment blocks. A pointer kept only there still counts.
void untracked_roots() {
    HANDLE heap = GetProcessHeap();
    size_t nb = 0;
    for (size_t s = 0; s < blocks::kShards; ++s) {
        size_t cap;
        Block *slots = blocks::shard_slots(s, &cap);
        for (size_t i = 0; i < cap; ++i)
            if (slots[i].user && !(slots[i].flags & (kFlagGuarded | kFlagReleased)))
                ++nb;
    }
    uintptr_t *bases = alloc_array<uintptr_t>(nb + 1);
    nb = 0;
    for (size_t s = 0; s < blocks::kShards; ++s) {
        size_t cap;
        Block *slots = blocks::shard_slots(s, &cap);
        for (size_t i = 0; i < cap; ++i)
            if (slots[i].user && !(slots[i].flags & (kFlagGuarded | kFlagReleased)))
                bases[nb++] = slots[i].base;
    }
    std::sort(bases, bases + nb);
    HeapLock(heap);
    PROCESS_HEAP_ENTRY e;
    e.lpData = nullptr;
    while (HeapWalk(heap, &e)) {
        if (!(e.wFlags & PROCESS_HEAP_ENTRY_BUSY) || !e.cbData)
            continue;
        const uintptr_t p = uintptr_t(e.lpData);
        if (std::binary_search(bases, bases + nb, p))
            continue;
        scan_raw(p, p + e.cbData);
    }
    HeapUnlock(heap);
    unmap_pages(bases, (nb + 1) * sizeof(uintptr_t));
}
#elif !defined(__APPLE__)
// Module segments (the .bss tail of a module looks anonymous in
// /proc/self/maps) are covered by the module pass, or skipped for ourselves.
int module_excl_cb(struct dl_phdr_info *info, size_t, void *data) {
    auto *ex = static_cast<ExclList *>(data);
    const size_t pg = page_size();
    for (int i = 0; i < info->dlpi_phnum && ex->n < ex->cap; ++i) {
        const auto &ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD)
            continue;
        uintptr_t a = info->dlpi_addr + ph.p_vaddr;
        ex->r[ex->n++] = Range{a & ~(pg - 1), round_up(a + ph.p_memsz, pg)};
    }
    return 0;
}
#endif

// Anonymous private memory not owned by the allocator: custom allocators,
// interpreter arenas, mmap'd buffers. Like valgrind, treat it as roots.
// Mappings that hold tracked blocks are heaps and are skipped: their free
// chunks still contain stale pointers.
void scan_anonymous() {
    constexpr size_t kMaxExcl = (size_t(1) << 16) + 8192;
    Range *excl = alloc_array<Range>(kMaxExcl);
    size_t ne = runtime_ranges(excl, kMaxExcl - 8192);
#ifndef _WIN32
    ExclList mods{excl + ne, 0, 4096};
#if defined(__APPLE__)
    stacks::for_each_image(
        [](const stacks::ImageView &im, void *data) -> int {
            auto *ex = static_cast<ExclList *>(data);
            if (ex->n < ex->cap)
                ex->r[ex->n++] = Range{im.lo, im.hi};
            return 0;
        },
        &mods);
#else
    dl_iterate_phdr(module_excl_cb, &mods);
#endif
    ne += mods.n;
#endif
    threads::Range thr[512];
    const size_t nt = threads::snapshot(thr, 512);
    for (size_t i = 0; i < nt; ++i) // thread stacks are scanned separately
        excl[ne++] = Range{thr[i].lo, vma_end(thr[i].hi - 1, thr[i].hi)};
    // The internal heap's reserved region (up to 256 MB, mostly untouched
    // MAP_NORESERVE pages) is scanned as roots via ih::used_range, not here.
    uintptr_t ih_lo, ih_hi;
    if (ih::full_range(&ih_lo, &ih_hi))
        excl[ne++] = Range{ih_lo, ih_hi};
    std::sort(excl, excl + ne,
              [](const Range &a, const Range &b) { return a.lo < b.lo; });

    for (size_t k = 0; k < g_nmaps; ++k) {
        const MapEnt &m = g_maps[k];
        if (!m.readable || !m.writable || !m.priv || !m.anonymous)
            continue;
        // any live block inside? (nodes are sorted by start)
        size_t lo = 0, hi = g_n;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (g_nodes[mid].start < m.lo)
                lo = mid + 1;
            else
                hi = mid;
        }
        if (lo < g_n && g_nodes[lo].start < m.hi)
            continue;
        uintptr_t cur = m.lo;
        for (size_t x = 0; x < ne && cur < m.hi; ++x) {
            if (excl[x].hi <= cur || excl[x].lo >= m.hi)
                continue;
            if (excl[x].lo > cur)
                scan_tolerant(cur, excl[x].lo);
            if (excl[x].hi > cur)
                cur = excl[x].hi;
        }
        if (cur < m.hi)
            scan_tolerant(cur, m.hi);
    }
}

void propagate(uint8_t mark_as, bool follow_interior) {
    while (g_wn) {
        const uint32_t i = g_work[--g_wn];
        for_words_in(i, [&](uintptr_t w) {
            bool st;
            long j = find(w, &st);
            if (j < 0 || g_cat[j] != kUnset)
                return;
            if (st || follow_interior) {
                g_cat[j] = mark_as;
                push(uint32_t(j));
            } else {
                note_pending(uint32_t(j));
            }
        });
    }
}

void classify_lost() {
    memset(g_flag, 0, g_n);
    for (size_t i = 0; i < g_n; ++i) {
        if (g_cat[i] != kUnset)
            continue;
        for_words_in(uint32_t(i), [&](uintptr_t w) {
            bool st;
            long j = find(w, &st);
            if (j >= 0 && size_t(j) != i && g_cat[j] == kUnset)
                g_flag[j] = 1;
        });
    }
    for (size_t i = 0; i < g_n; ++i) {
        if (g_cat[i] == kUnset && !g_flag[i]) {
            g_cat[i] = kDefinite;
            push(uint32_t(i));
        }
    }
    propagate(kIndirect, true);
    // Cycles of lost blocks have no head: pick one per cycle.
    for (size_t i = 0; i < g_n; ++i) {
        if (g_cat[i] == kUnset) {
            g_cat[i] = kDefinite;
            push(uint32_t(i));
            propagate(kIndirect, true);
        }
    }
}

const char *cat_name(uint8_t c) {
    switch (c) {
    case kDefinite:
        return lcproto::kCatDefinite;
    case kIndirect:
        return lcproto::kCatIndirect;
    case kPossible:
        return lcproto::kCatPossible;
    default:
        return lcproto::kCatReachable;
    }
}

const char *cat_words(uint8_t c) {
    switch (c) {
    case kDefinite:
        return "definitely lost";
    case kIndirect:
        return "indirectly lost";
    case kPossible:
        return "possibly lost";
    default:
        return "still reachable";
    }
}

int cat_rank(uint8_t c) {
    switch (c) {
    case kDefinite:
        return 0;
    case kIndirect:
        return 1;
    case kPossible:
        return 2;
    default:
        return 3;
    }
}

void emit_groups() {
    uint32_t *idx = alloc_array<uint32_t>(g_n);
    size_t k = 0;
    for (size_t i = 0; i < g_n; ++i) {
        if (g_cat[i] == kReachable && !g_cfg.show_reachable)
            continue;
        idx[k++] = uint32_t(i);
    }
    std::sort(idx, idx + k, [](uint32_t a, uint32_t b) {
        if (g_cat[a] != g_cat[b])
            return g_cat[a] < g_cat[b];
        if (g_nodes[a].stack != g_nodes[b].stack)
            return g_nodes[a].stack < g_nodes[b].stack;
        return g_nodes[a].seq < g_nodes[b].seq;
    });
    Group *groups = alloc_array<Group>(k + 1);
    size_t ng = 0;
    for (size_t i = 0; i < k; ++i) {
        const Node &nd = g_nodes[idx[i]];
        const uint8_t c = g_cat[idx[i]];
        // Blocks without a captured stack are grouped by address.
        bool same = ng && groups[ng - 1].cat == c &&
                    groups[ng - 1].stack == nd.stack && nd.stack != 0;
        if (!same)
            groups[ng++] = Group{c, nd.stack, 0, 0, idx[i]};
        groups[ng - 1].blocks += 1;
        groups[ng - 1].bytes += nd.size;
    }
    std::sort(groups, groups + ng, [](const Group &a, const Group &b) {
        if (cat_rank(a.cat) != cat_rank(b.cat))
            return cat_rank(a.cat) < cat_rank(b.cat);
        return a.bytes > b.bytes;
    });
    for (size_t i = 0; i < ng; ++i) {
        const Group &g = groups[i];
        const Node &first = g_nodes[g.first];
        char text[200];
        Buf msg(text, sizeof text);
        msg.u(g.bytes)
            .s(" byte(s) in ")
            .u(g.blocks)
            .s(" block(s) are ")
            .s(cat_words(g.cat));
        report::Finding f;
        f.type = lcproto::kLeak;
        f.addr = first.start;
        f.size = first.size;
        f.tid = first.tid;
        f.msg = msg.cstr();
        f.alloc_stack = g.stack;
        f.category = cat_name(g.cat);
        f.blocks = g.blocks;
        f.bytes = g.bytes;
        report::emit(f);
    }
    unmap_pages(groups, (k + 1) * sizeof(Group) + 1);
    unmap_pages(idx, g_n * sizeof(uint32_t) + 1);
}

// ---- dangling pointers ------------------------------------------------------
// A block the program still uses (reachable, or a global of its own) that
// holds the start address of a freed block: whoever follows it later reads
// or writes freed memory. Only freed blocks still in quarantine count; once
// released, their memory may hold something new.

struct Freed {
    uintptr_t start;
    uint64_t size;
    uint32_t alloc_stack, free_stack;
};
Freed *g_freed;
size_t g_nfreed;

const Freed *freed_at(uintptr_t w) {
    size_t lo = 0, hi = g_nfreed;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        if (g_freed[mid].start < w)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo < g_nfreed && g_freed[lo].start == w ? &g_freed[lo] : nullptr;
}

// holder: where the pointer is, as words ("global 'cache'").
void report_dangling(const Freed &f, const char *holder, uintptr_t where,
                     uint32_t holder_stack) {
    char text[320];
    Buf msg(text, sizeof text);
    msg.s(holder)
        .s(" still holds a pointer to a ")
        .u(f.size)
        .s("-byte block that was freed: following it reads or writes freed "
           "memory");
    report::Finding r;
    r.type = lcproto::kDangling;
    r.category = lcproto::kCatHeap;
    r.addr = where;
    r.size = f.size;
    r.msg = msg.cstr();
    r.access_stack = holder_stack;
    r.alloc_stack = f.alloc_stack;
    r.free_stack = f.free_stack;
    report::emit(r);
}

void dangling_in_blocks() {
    for (size_t i = 0; i < g_n; ++i) {
        if (g_cat[i] != kReachable)
            continue;
        const Node &nd = g_nodes[i];
        for (uintptr_t a = nd.start; a + sizeof(uintptr_t) <= nd.start + nd.size;
             a += sizeof(uintptr_t)) {
            const Freed *f = freed_at(*reinterpret_cast<const uintptr_t *>(a));
            if (!f)
                continue;
            char holder[96];
            Buf h(holder, sizeof holder);
            h.s("a ").u(nd.size).s("-byte block still in use (at offset ");
            h.u(a - nd.start).c(')');
            report_dangling(*f, h.cstr(), a, nd.stack);
        }
    }
}

#ifdef _WIN32
void dangling_globals() {} // LEAKCHECK_DANGLING is not offered on Windows
#elif defined(__APPLE__)
bool system_module(const char *name) {
    return strncmp(name, "/usr/lib", 8) == 0 || strncmp(name, "/System/", 8) == 0;
}
int dangling_one(const stacks::ImageView &im, void *) {
    if (system_module(im.name) || stacks::in_self(im.lo))
        return 0;
    for (int i = 0; i < im.nw; ++i) {
        const uintptr_t lo = round_up(im.wlo[i], sizeof(uintptr_t));
        for (uintptr_t a = lo; a + sizeof(uintptr_t) <= im.whi[i];
             a += sizeof(uintptr_t)) {
            const Freed *f = freed_at(*reinterpret_cast<const uintptr_t *>(a));
            if (!f)
                continue;
            char holder[160];
            Buf h(holder, sizeof holder);
            Dl_info di;
            if (dladdr(reinterpret_cast<void *>(a), &di) && di.dli_sname)
                h.s("global '").s(di.dli_sname).c('\'');
            else
                h.s("a global variable at ").s(im.name[0] ? im.name : "the program")
                    .c('+').p(a - im.slide);
            report_dangling(*f, h.cstr(), a, 0);
        }
    }
    return 0;
}
void dangling_globals() { stacks::for_each_image(dangling_one, nullptr); }
#else
bool system_module(const char *name) {
    return strncmp(name, "/lib", 4) == 0 || strncmp(name, "/usr/", 5) == 0;
}

// The program's own globals (system libraries keep their own caches).
int dangling_globals_cb(struct dl_phdr_info *info, size_t, void *) {
    const char *name = info->dlpi_name && *info->dlpi_name ? info->dlpi_name
                                                           : "the program";
    if (system_module(name) || strncmp(name, "linux-vdso", 10) == 0)
        return 0;
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const auto &ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD || !(ph.p_flags & PF_W) ||
            stacks::in_self(info->dlpi_addr + ph.p_vaddr))
            continue;
        const uintptr_t lo = round_up(info->dlpi_addr + ph.p_vaddr,
                                      sizeof(uintptr_t));
        const uintptr_t hi = info->dlpi_addr + ph.p_vaddr + ph.p_memsz;
        for (uintptr_t a = lo; a + sizeof(uintptr_t) <= hi;
             a += sizeof(uintptr_t)) {
            const Freed *f = freed_at(*reinterpret_cast<const uintptr_t *>(a));
            if (!f)
                continue;
            char holder[160];
            Buf h(holder, sizeof holder);
            Dl_info di;
            void *entry = nullptr;
            const bool found = dladdr1(reinterpret_cast<void *>(a), &di, &entry,
                                       RTLD_DL_SYMENT);
            const auto *sym = static_cast<const ElfW(Sym) *>(entry);
            if (found &&
                sym && di.dli_sname &&
                a < uintptr_t(di.dli_saddr) + sym->st_size) {
                h.s("global '").s(di.dli_sname).c('\'');
                if (a != uintptr_t(di.dli_saddr))
                    h.s(" (at offset ").u(a - uintptr_t(di.dli_saddr)).c(')');
            } else {
                h.s("a global variable at ").s(name).c('+').p(
                    a - info->dlpi_addr);
            }
            report_dangling(*f, h.cstr(), a, 0);
        }
    }
    return 0;
}
void dangling_globals() { dl_iterate_phdr(dangling_globals_cb, nullptr); }
#endif

} // namespace

void set_extra_roots(const uintptr_t *words, size_t n) {
    g_extra = words;
    g_extra_n = n;
}

void run_locked(uintptr_t stack_lo) {
    size_t n = 0, nf = 0;
    for (size_t s = 0; s < blocks::kShards; ++s) {
        size_t cap;
        Block *slots = blocks::shard_slots(s, &cap);
        for (size_t i = 0; i < cap; ++i) {
            n += slots[i].user && slots[i].state == State::Live;
            nf += g_cfg.dangling && slots[i].user &&
                  slots[i].state == State::Freed &&
                  !(slots[i].flags & kFlagReleased);
        }
    }
    if (!n && !nf)
        return;
    g_freed = alloc_array<Freed>(nf);
    for (size_t s = 0; s < blocks::kShards; ++s) {
        size_t cap;
        Block *slots = blocks::shard_slots(s, &cap);
        for (size_t i = 0; i < cap; ++i) {
            const Block &b = slots[i];
            if (g_nfreed < nf && b.user && b.state == State::Freed &&
                !(b.flags & kFlagReleased))
                g_freed[g_nfreed++] =
                    Freed{b.user, b.size, b.alloc_stack, b.free_stack};
        }
    }
    std::sort(g_freed, g_freed + g_nfreed,
              [](const Freed &a, const Freed &b) { return a.start < b.start; });
    if (!n) { // nothing to classify, but globals may still point at the dead
        if (g_nfreed)
            dangling_globals();
        return;
    }
    g_nodes = alloc_array<Node>(n);
    for (size_t s = 0; s < blocks::kShards; ++s) {
        size_t cap;
        Block *slots = blocks::shard_slots(s, &cap);
        for (size_t i = 0; i < cap; ++i) {
            const Block &b = slots[i];
            if (b.user && b.state == State::Live)
                g_nodes[g_n++] = Node{b.user,        b.size,    b.seq,
                                      b.alloc_stack, b.alloc_tid, (b.flags & kFlagSystem) != 0};
        }
    }
    std::sort(g_nodes, g_nodes + g_n,
              [](const Node &a, const Node &b) { return a.start < b.start; });
    g_min = g_nodes[0].start;
    for (size_t i = 0; i < g_n; ++i)
        if (g_nodes[i].start + g_nodes[i].size > g_max)
            g_max = g_nodes[i].start + g_nodes[i].size;
    g_cat = alloc_array<uint8_t>(g_n);
    g_flag = alloc_array<uint8_t>(g_n);
    g_work = alloc_array<uint32_t>(g_n);
    g_pending = alloc_array<uint32_t>(g_n);

    load_maps();
#if defined(_WIN32) || defined(__APPLE__)
    module_roots();
#endif
#ifdef _WIN32
    untracked_roots();
#elif !defined(__APPLE__)
    dl_iterate_phdr(module_roots_cb, nullptr);
#endif
    scan_threads(stack_lo);
    for (size_t i = 0; i < g_extra_n; ++i)
        root_word(g_extra[i]);
    scan_anonymous();
    uintptr_t ih_lo, ih_hi;
    if (ih::used_range(&ih_lo, &ih_hi))
        scan_raw(ih_lo, ih_hi);

    // Windows' own state is never lost, and what it points to is not either
    for (size_t i = 0; i < g_n; ++i)
        if (g_nodes[i].system && g_cat[i] == kUnset) {
            g_cat[i] = kReachable;
            push(uint32_t(i));
        }
    propagate(kReachable, false);
    for (size_t p = 0; p < g_pn; ++p) {
        const uint32_t i = g_pending[p];
        if (g_cat[i] == kUnset) {
            g_cat[i] = kPossible;
            push(i);
        }
    }
    propagate(kPossible, true);
    classify_lost();
    emit_groups();
    if (g_nfreed) {
        dangling_in_blocks();
        dangling_globals();
    }
    unmap_pages(g_maps_text, g_maps_text_cap);
    g_maps_text = nullptr;
}

} // namespace lc::leakscan
