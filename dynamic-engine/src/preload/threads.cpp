#include "threads.h"
#include "locks.h"
#include "protocol.h"
#include "report.h"
#include "resources.h"
#include "stacks.h"

#include <dlfcn.h>
#include <pthread.h>
#include "lc_api.h"

namespace lc::threads {
namespace {

constexpr size_t kMax = 4096;

struct Slot {
    uintptr_t lo, hi;
    uint32_t tid;
    uint32_t used;
    uint32_t create_stack;
    bool ours; // started through our pthread_create
};

SpinLock g_lock;
Slot g_slots[kMax];
pthread_key_t g_key;
bool g_key_ok;

// The generation of the thread each handle names, for threads started
// through our pthread_create: glibc hands a finished thread's pthread_t to
// the next thread it starts. 0 is unknown and never matches. Direct-mapped
// (under g_lock): a collision forgets the older handle.
struct Gen {
    uint64_t t;
    uint32_t gen;
};
constexpr size_t kGens = 16384;
Gen g_gens[kGens];
uint32_t g_next_gen;

Gen &gen_slot(uint64_t t) {
    return g_gens[size_t((t * 0x9E3779B97F4A7C15ull) >> 50)];
}

void set_gen(uint64_t t, uint32_t gen) {
    LockGuard g(g_lock);
    gen_slot(t) = Gen{t, gen};
}

// Threads joined or detached lately (a ring, under g_lock), with the
// generation their handle had then: a second join or detach of the same
// thread is undefined, while a record of an earlier thread with that
// handle no longer matches.
struct Gone {
    uint64_t t;
    uint32_t stack; // where it was joined or detached
    uint32_t gen;
    bool detached;
};
constexpr size_t kGone = 256;
Gone g_gone[kGone];
size_t g_gone_next;

using CreateFn = int (*)(pthread_t *, const pthread_attr_t *, void *(*)(void *),
                         void *);
CreateFn g_real_create;

struct Start {
    void *(*fn)(void *);
    void *arg;
    uint32_t create_stack;
    uint32_t gen;
};

// A thread that ends while still joinable keeps its stack and descriptor
// until someone joins it; remember it in case nobody does.
void on_thread_exit(void *p) {
    auto *slot = static_cast<Slot *>(p);
    if (slot->ours && g_cfg.active) {
        HookGuard hg;
        ErrnoSaver es;
        int state = PTHREAD_CREATE_DETACHED;
#if !defined(__APPLE__)
        pthread_attr_t a;
        if (pthread_getattr_np(pthread_self(), &a) == 0) {
            pthread_attr_getdetachstate(&a, &state);
            pthread_attr_destroy(&a);
        }
#endif
        if (state == PTHREAD_CREATE_JOINABLE)
            res::thread_exited(uint64_t(pthread_self()), slot->create_stack);
    }
    if (g_cfg.active) {
        HookGuard hg;
        ErrnoSaver es;
        locks::thread_exiting(slot->create_stack);
    }
    LockGuard g(g_lock);
    slot->used = 0;
}

Slot *add(uintptr_t lo, uintptr_t hi, uint32_t tid) {
    LockGuard g(g_lock);
    for (auto &s : g_slots) {
        if (!s.used) {
            s.lo = lo;
            s.hi = hi;
            s.tid = tid;
            s.used = 1;
            s.create_stack = 0;
            s.ours = false;
            return &s;
        }
    }
    return nullptr;
}

void *trampoline(void *p) {
    Start st = *static_cast<Start *>(p);
    ih::free(p);
    // Before its function runs: it may detach itself before the creator
    // records the handle's generation.
    set_gen(uint64_t(pthread_self()), st.gen);
    register_current(st.create_stack, true);
    return st.fn(st.arg);
}

} // namespace

bool current_bounds(uintptr_t *lo, uintptr_t *hi) {
#if defined(__APPLE__)
    // The address is the high end; the stack grows down.
    void *top = pthread_get_stackaddr_np(pthread_self());
    size_t size = pthread_get_stacksize_np(pthread_self());
    if (!top || !size)
        return false;
    *hi = reinterpret_cast<uintptr_t>(top);
    *lo = *hi - size;
    return true;
#else
    HookGuard hg;
    pthread_attr_t a;
    if (pthread_getattr_np(pthread_self(), &a) != 0)
        return false;
    void *addr = nullptr;
    size_t size = 0;
    int rc = pthread_attr_getstack(&a, &addr, &size);
    pthread_attr_destroy(&a);
    if (rc != 0)
        return false;
    *lo = reinterpret_cast<uintptr_t>(addr);
    *hi = *lo + size;
    return true;
#endif
}

void register_current(uint32_t create_stack, bool ours) {
    uintptr_t lo, hi;
    if (!current_bounds(&lo, &hi))
        return;
    Slot *s = add(lo, hi, current_tid());
    if (s) {
        s->create_stack = create_stack;
        s->ours = ours;
    }
    if (s && g_key_ok) {
        HookGuard hg;
        pthread_setspecific(g_key, s);
    }
}

void init() {
    HookGuard hg;
    g_real_create =
        reinterpret_cast<CreateFn>(dlsym(RTLD_NEXT, "pthread_create"));
    g_key_ok = pthread_key_create(&g_key, on_thread_exit) == 0;
    register_current();
}

bool find_stack(uintptr_t addr, uint32_t *tid) {
    LockGuard g(g_lock);
    for (const auto &s : g_slots) {
        if (s.used && addr >= s.lo && addr < s.hi) {
            if (tid)
                *tid = s.tid;
            return true;
        }
    }
    return false;
}

size_t snapshot(Range *out, size_t max) {
    LockGuard g(g_lock);
    size_t n = 0;
    for (const auto &s : g_slots)
        if (s.used && n < max)
            out[n++] = Range{s.lo, s.hi, s.tid};
    return n;
}

void after_fork_child() {
    const uint32_t me = current_tid();
    for (auto &s : g_slots)
        if (s.used && s.tid != me)
            s.used = 0;
}

void lock() { g_lock.lock(); }
void unlock() { g_lock.unlock(); }
void reset_lock() { g_lock.reset(); }

} // namespace lc::threads

extern "C" __attribute__((visibility("default"))) int
LC_FN(pthread_create)(pthread_t *thread, const pthread_attr_t *attr,
               void *(*fn)(void *), void *arg) {
    using namespace lc::threads;
    if (!g_real_create) {
        lc::HookGuard hg;
        g_real_create =
            reinterpret_cast<CreateFn>(dlsym(RTLD_NEXT, "pthread_create"));
        if (!g_real_create)
            return 11; // EAGAIN
    }
    auto *st = static_cast<Start *>(lc::ih::alloc(sizeof(Start), 16));
    if (!st)
        return g_real_create(thread, attr, fn, arg);
    st->fn = fn;
    st->arg = arg;
    st->create_stack = 0;
    if (lc::g_cfg.active && !lc::tl_in_hook) {
        lc::HookGuard hg;
        st->create_stack = lc::stacks::capture();
    }
    uint32_t gen;
    {
        lc::LockGuard g(g_lock);
        gen = ++g_next_gen ? g_next_gen : ++g_next_gen;
    }
    st->gen = gen;
    int rc = g_real_create(thread, attr, trampoline, st); // st is the thread's
    if (rc != 0)
        lc::ih::free(st);
    else
        set_gen(uint64_t(*thread), gen); // the thread may not have run yet
    return rc;
}

// Joining or detaching releases a thread: it is no longer a leak.
namespace {

template <class F> F real_fn(F &slot, const char *name) {
    if (!slot) {
        lc::HookGuard hg;
        slot = reinterpret_cast<F>(dlsym(RTLD_NEXT, name));
        if (!slot)
            lc::die("cannot find a pthread function to forward to");
    }
    return slot;
}

bool tracking() { return lc::g_cfg.active && !lc::tl_in_hook; }

// Before a join or detach: report it if this very thread was joined or
// detached already. Returns the handle's generation now, before the call
// lets glibc give the handle to another thread.
uint32_t check_twice(pthread_t t, bool detach) {
    using namespace lc::threads;
    if (!tracking() || !t)
        return 0;
    Gone first{};
    uint32_t gen;
    {
        lc::LockGuard g(g_lock);
        const Gen &e = gen_slot(uint64_t(t));
        gen = e.t == uint64_t(t) ? e.gen : 0;
        for (const auto &x : g_gone)
            if (x.t == uint64_t(t) && gen && x.gen == gen)
                first = x;
    }
    if (!first.t)
        return gen;
    static const char *const kMsg[2][2] = {
        {"joins a thread that was already joined",
         "joins a thread that was detached"},
        {"detaches a thread that was already joined",
         "detaches a thread that was already detached"}};
    lc::HookGuard hg;
    lc::ErrnoSaver es;
    lc::report::Finding f;
    f.type = lcproto::kDoubleJoin;
    f.category = lcproto::kCatThread;
    f.addr = uintptr_t(t);
    f.tid = lc::current_tid();
    f.msg = kMsg[detach][first.detached];
    f.access_stack = lc::stacks::capture();
    f.free_stack = first.stack;
    f.fatal = true;
    lc::report::emit(f);
    return gen;
}

// gen: the handle's generation before the call (check_twice).
int released(int rc, pthread_t t, uint32_t gen, bool detach = false) {
    using namespace lc::threads;
    if (rc != 0)
        return rc;
    lc::res::forget(lc::res::Kind::Thread, uint64_t(t));
    if (tracking() && gen) {
        lc::HookGuard hg;
        lc::ErrnoSaver es;
        const uint32_t stack = lc::stacks::capture();
        lc::LockGuard g(g_lock);
        g_gone[g_gone_next++ % kGone] = {uint64_t(t), stack, gen, detach};
    }
    return rc;
}

using JoinFn = int (*)(pthread_t, void **);
using TimedJoinFn = int (*)(pthread_t, void **, const struct timespec *);
using ClockJoinFn = int (*)(pthread_t, void **, clockid_t,
                            const struct timespec *);
using DetachFn = int (*)(pthread_t);
JoinFn g_join, g_tryjoin;
TimedJoinFn g_timedjoin;
ClockJoinFn g_clockjoin;
DetachFn g_detach;

} // namespace

extern "C" __attribute__((visibility("default"))) int LC_FN(pthread_join)(pthread_t t,
                                                                   void **ret) {
    const uint32_t gen = check_twice(t, false);
    return released(real_fn(g_join, "pthread_join")(t, ret), t, gen);
}

#if !defined(__APPLE__)
extern "C" __attribute__((visibility("default"))) int
LC_FN(pthread_tryjoin_np)(pthread_t t, void **ret) noexcept {
    const uint32_t gen = check_twice(t, false);
    return released(real_fn(g_tryjoin, "pthread_tryjoin_np")(t, ret), t, gen);
}

extern "C" __attribute__((visibility("default"))) int
pthread_timedjoin_np(pthread_t t, void **ret, const struct timespec *until) {
    const uint32_t gen = check_twice(t, false);
    return released(real_fn(g_timedjoin, "pthread_timedjoin_np")(t, ret, until),
                    t, gen);
}

extern "C" __attribute__((visibility("default"))) int
pthread_clockjoin_np(pthread_t t, void **ret, clockid_t clock,
                     const struct timespec *until) {
    const uint32_t gen = check_twice(t, false);
    return released(
        real_fn(g_clockjoin, "pthread_clockjoin_np")(t, ret, clock, until), t,
        gen);
}

#endif

extern "C" __attribute__((visibility("default"))) int
LC_FN(pthread_detach)(pthread_t t) noexcept {
    const uint32_t gen = check_twice(t, true);
    return released(real_fn(g_detach, "pthread_detach")(t), t, gen, true);
}
