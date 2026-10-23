#pragma once
// Non-memory resources: file descriptors, FILE and DIR streams, threads,
// child processes. Records who opened each handle, reports handles still
// open when the program ends, and closes of handles that were already closed.
#include "rt.h"

namespace lc::res {

enum class Kind : uint8_t { Fd = 1, File, Pipe, Dir, Thread, Process };

// A handle came into existence; how = the call that made it ("open()").
void opened(Kind k, uint64_t handle, const char *how);
// The handle now belongs to something else (fdopen) or is gone: stop
// tracking it without judging it.
void forget(Kind k, uint64_t handle);
// A stream/directory is about to be released with `how`. False if it was
// already released (reported): the caller must not release it again.
bool closing(Kind k, uint64_t handle, const char *how);
// The handle was released.
void closed(Kind k, uint64_t handle);
// close() said EBADF: a double close if we saw this descriptor closed.
void close_failed(uint64_t fd, const char *how);
// `how` ("read()") failed with EBADF on `fd`: a use after close if we saw
// this descriptor closed.
void used_closed(uint64_t fd, const char *how);
// `how` ("fread()") is about to use this FILE*. True if we saw it closed:
// the call must not be made, the stream's memory is freed. A later fopen
// that was given the same address is Open and is not this stream.
bool used_stream(uint64_t handle, const char *how, Kind kind = Kind::File);
// `call` ("connect()") failed on the socket `fd` with `err`: kept for the leak
// report, which then says why the socket was never used.
void socket_failed(uint64_t fd, const char *call, int err);
// `how` ("socket()") failed with EMFILE or ENFILE: report the descriptors
// still open and the call site that opened most of them, once per run.
void exhausted(const char *how);
// close_range(): every descriptor in [lo, hi] was released.
void closed_range(uint64_t lo, uint64_t hi);
// fcloseall(): every FILE* we still track is closed.
void streams_closed();
// A thread we started ends while still joinable.
void thread_exited(uint64_t self, uint32_t create_stack);
// waitid() returned 0 with `siginfo` (a siginfo_t): the child it names was
// reaped, unless `options` has WNOWAIT.
void waited_id(const void *siginfo, int options);

// A child program is about to be started by `how` ("system()"): report the
// descriptors it would inherit (open, created here, no close-on-exec).
// exec: this process is replacing itself (in a fork() child, typically):
// any descriptor it still has counts, and the report goes out even from an
// untraced child.
void check_inherited(const char *how, bool exec = false);

#ifdef _WIN32
// Is this handle a socket we saw made (socket, WSASocket, accept)?
bool is_socket(uint64_t handle);
// The kind a handle was recorded with (CloseHandle does not say), Fd if unknown.
Kind kind_of(uint64_t handle);
#endif

// End of the run: report everything the process opened and never released.
void report_at_exit();

void lock();
void unlock();
void reset_lock();

} // namespace lc::res
