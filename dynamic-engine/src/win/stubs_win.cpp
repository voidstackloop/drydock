// Parts of the runtime that Windows does not have yet, or does not need,
// behind the interfaces the shared code calls. Each is replaced by a real
// file as the feature arrives (guard pages, locks, handles).
#include "locks.h"

namespace lc {

namespace locks {
void init() {}
void block_freed(uintptr_t, size_t) {}
void thread_exiting(uint32_t) {}
size_t held_snapshot(uintptr_t *, size_t) { return 0; }
void lock() {}
void unlock() {}
void reset_lock() {}
} // namespace locks

} // namespace lc
