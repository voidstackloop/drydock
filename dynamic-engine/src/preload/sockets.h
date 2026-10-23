#pragma once
// Socket and descriptor use that goes wrong at run time: send() while SIGPIPE
// can kill the process, a call on a descriptor that was closed, a read loop
// that never stops at end of file, bind() without SO_REUSEADDR, select() with
// nfds past FD_SETSIZE. The wrappers are in sockets.cpp (send family and
// select, with libc's headers) and fd_io.cpp (read, write, recv, connect,
// bind, writev, ...: header-less, like interpose_io.cpp).
#include "rt.h"

namespace lc::sockets {

// SIGPIPE's action or a thread's mask changed: each thread looks again on its
// next unprotected send.
void sigpipe_action_changed();

constexpr int kMaxFd = 4096;
extern uint32_t g_zero[kMaxFd]; // consecutive reads that returned 0, per descriptor
extern uint32_t g_again[kMaxFd]; // consecutive EAGAIN, per descriptor
// Per descriptor number: 0 anything else, kSocket made by socket(),
// socketpair(), accept() or accept4(), kDatagram such a socket found to be a
// datagram socket (SIGPIPE cannot come from it; asked once).
constexpr uint8_t kSocket = 1, kDatagram = 2;
extern uint8_t g_is_socket[kMaxFd];

// A descriptor number was closed: forget what was counted and noted for it.
void fd_changed(int fd);
// A descriptor number was created by `how` ("socket()").
void fd_opened(int fd, const char *how);

// write() or writev() (`how`, "write() on a socket") is about to run on a
// socket (g_is_socket): SIGPIPE can kill the process like it does after a
// send without MSG_NOSIGNAL.
void write_on_socket(int fd, const char *how);

// A call on `fd` returned -1 (errno is still set): remembers EBADF on a
// descriptor we saw closed.
void failed(int fd, const char *how);
// connect(), bind() or listen() (`how`) failed on `fd` with `err`: the
// socket's leak report will say so. Retryable results are not failures.
void call_failed(int fd, const char *how, int err);
// A read of a nonzero length returned 0 on `fd`. On a stream socket that is
// the end of the connection, and no data follows it, so the zeros of one
// descriptor number need no reset by a read that returns data.
void read_zero(int fd, const char *how);
// A call on fd returned EAGAIN (`how` is "recv()"). A thousand in a row on a
// stream socket is a busy loop. Any other result clears the count.
void read_again(int fd, const char *how);
inline void again_reset(int fd) {
    if (unsigned(fd) < unsigned(kMaxFd))
        g_again[fd] = 0;
}
// bind(fd, addr, len) is about to run.
void before_bind(int fd, const void *addr, unsigned len);
// recvmsg() returned n >= 0. Descriptors in msg (SCM_RIGHTS) are open from here.
void scm_rights(void *msg, long n);

} // namespace lc::sockets
