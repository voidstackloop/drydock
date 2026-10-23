// unit_runtime leaves out locks.cpp: linked in, its pthread_mutex_* wrappers
// would track every mutex of the test program itself. The lock tracker is
// tested end to end (tests/dynamic/programs/locks.c). The same goes for
// sockets.cpp, whose read/write wrappers would watch the test's own I/O
// (tests/dynamic/programs/sockets.c).
#include "locks.h"
#include "sockets.h"

namespace lc::locks {
void block_freed(uintptr_t, size_t) {}
void thread_exiting(uint32_t) {}
} // namespace lc::locks

namespace lc::sockets {
void fd_changed(int) {}
void fd_opened(int, const char *) {}
} // namespace lc::sockets
