#pragma once
// Stack extents of the target's threads, used as roots by the leak scan and
// to recognise frees of stack addresses.
#include "rt.h"

namespace lc::threads {

struct Range {
    uintptr_t lo, hi;
    uint32_t tid;
};

void init(); // main thread + pthread_create interception
// Called on each new thread; ours = started through our pthread_create.
void register_current(uint32_t create_stack = 0, bool ours = false);
#ifdef _WIN32
void unregister_current(); // the thread is ending
#endif
bool current_bounds(uintptr_t *lo, uintptr_t *hi);
bool find_stack(uintptr_t addr, uint32_t *tid);
size_t snapshot(Range *out, size_t max);
void after_fork_child();

void lock();
void unlock();
void reset_lock();

} // namespace lc::threads
