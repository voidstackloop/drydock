#pragma once
// Mutex tracking: lock-order inversions (deadlocks waiting for the wrong
// timing), a thread locking a mutex it already holds, and threads that end
// while holding one. The pthread_mutex_* wrappers live in locks.cpp.
#include "rt.h"

namespace lc::locks {

void init(); // resolve the real pthread functions early
// A heap block is released: mutexes inside it no longer exist.
void block_freed(uintptr_t lo, size_t size);
// The calling thread is ending (created at create_stack).
void thread_exiting(uint32_t create_stack);
// The mutexes the calling thread holds (up to `max`, oldest first): returns
// how many were stored in out.
size_t held_snapshot(uintptr_t *out, size_t max);

#ifdef _WIN32
void set_on();        // start judging what the hooks report
void thread_gone();   // give back the thread's record
#endif

void lock();
void unlock();
void reset_lock();

} // namespace lc::locks
