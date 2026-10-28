#include "behavior.h"
#include "init.h"
#include "protocol.h"
#include "report.h"
#include "resources.h"
#include "rt.h"
#include "sockets.h"
#include "stacks.h"

#include <cerrno>
#include <csignal>
#include <dlfcn.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>

// A send on a stream socket whose peer has closed raises SIGPIPE, and the
// default action of SIGPIPE ends the process: one client hanging up kills the
// server. MSG_NOSIGNAL on the call, or SIGPIPE ignored, blocked or handled,
// turns it into an EPIPE error the program can deal with. The program that
// gets away with it today is the one whose peer has not disconnected yet.
//
// A thread looks at the signal's action and its own mask on its first such
// send, and again after the program changes the action or its signal mask
// (sigprocmask / pthread_sigmask): one report per run, then one compare.
// write() and writev() on a socket get the same look (write_on_socket, below).
namespace lc::sockets {
namespace {

uint32_t g_epoch = 1;  // bumped when SIGPIPE's action or a thread's mask changes
uint8_t g_reported;    // the finding was emitted
LC_TLS uint32_t tl_seen; // g_epoch when this thread last looked

LC_NOINLINE void check_slow(int fd, const char *how) {
    if (tl_in_hook)
        return;
    if (unsigned(fd) < unsigned(kMaxFd) && g_is_socket[fd] == kDatagram)
        return; // asked before: no syscall for every send on a UDP socket
    ensure_init();
    if (!g_cfg.active)
        return;
    HookGuard hg;
    ErrnoSaver es;
    int type = 0;
    socklen_t n = sizeof type;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &n) != 0)
        return; // not a socket
    if (type != SOCK_STREAM && type != SOCK_SEQPACKET) { // datagrams: no SIGPIPE
        if (unsigned(fd) < unsigned(kMaxFd) && g_is_socket[fd])
            g_is_socket[fd] = kDatagram;
        return;
    }
#if defined(__APPLE__)
    // Darwin has no MSG_NOSIGNAL: per-call suppression is the SO_NOSIGPIPE
    // option instead. A socket that sets it gets EPIPE, not a signal.
    int nosigpipe = 0;
    socklen_t nn = sizeof nosigpipe;
    if (getsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, &nn) == 0 && nosigpipe)
        return;
#endif
    const uint32_t epoch = __atomic_load_n(&g_epoch, __ATOMIC_ACQUIRE);
    struct sigaction sa;
    sigset_t blocked;
    if (sigaction(SIGPIPE, nullptr, &sa) != 0)
        return;
    pthread_sigmask(SIG_BLOCK, nullptr, &blocked);
    tl_seen = epoch;
    if (sa.sa_handler != SIG_DFL || sigismember(&blocked, SIGPIPE) == 1)
        return;
    if (__atomic_exchange_n(&g_reported, 1, __ATOMIC_ACQ_REL))
        return;
    char m[224];
    Buf msg(m, sizeof m);
    msg.s(how).s(" while SIGPIPE has its default action: a peer that closes "
                 "the connection kills this process");
    report::Finding f;
    f.type = lcproto::kSigpipe;
    f.category = lcproto::kCatSignal;
    f.tid = current_tid();
    f.msg = msg.cstr();
    f.access_stack = stacks::capture();
    report::emit(f);
}

inline void note(int fd, int flags, const char *how) {
    if (LC_UNLIKELY(!(flags & MSG_NOSIGNAL) &&
                    tl_seen != __atomic_load_n(&g_epoch, __ATOMIC_RELAXED)))
        check_slow(fd, how);
}

template <class F> F real(F &slot, const char *name) {
    F f = __atomic_load_n(&slot, __ATOMIC_ACQUIRE);
    if (LC_UNLIKELY(!f)) {
        {
            HookGuard hg;
            f = reinterpret_cast<F>(dlsym(RTLD_NEXT, name));
        }
        if (!f)
            die("cannot find a libc function to forward to");
        __atomic_store_n(&slot, f, __ATOMIC_RELEASE);
    }
    return f;
}

} // namespace

void sigpipe_action_changed() { __atomic_add_fetch(&g_epoch, 1, __ATOMIC_RELEASE); }

// write() and writev() cannot take MSG_NOSIGNAL, so on a socket they are as
// exposed as a send without it. fd_io.cpp calls this for descriptors made by
// socket(), socketpair(), accept() and accept4() only: a pipe is meant to
// kill its writer when the reader is gone.
uint8_t g_is_socket[kMaxFd];

void write_on_socket(int fd, const char *how) {
    if (LC_UNLIKELY(tl_seen != __atomic_load_n(&g_epoch, __ATOMIC_RELAXED)))
        check_slow(fd, how);
}

void fd_opened(int fd, const char *how) {
    fd_changed(fd);
    if (unsigned(fd) < unsigned(kMaxFd) && how)
        g_is_socket[fd] = !__builtin_strcmp(how, "socket()") ||
                          !__builtin_strcmp(how, "socketpair()") ||
                          !__builtin_strcmp(how, "accept()") ||
                          !__builtin_strcmp(how, "accept4()");
}

// ---- a descriptor used after it was closed ---------------------------------
//
// The kernel answers EBADF when a closed descriptor number is used, so the
// check costs nothing until a call fails: then, if the resource table saw this
// number closed, it is a use after close. A number closed and opened again is
// a different file while that file stays open. Closed again, the later EBADF
// use is a double close of the first lifetime, at the second close.

void failed(int fd, const char *how) {
    const int err = errno;
    if (err != EBADF || tl_in_hook)
        return;
    ErrnoSaver es;
    ensure_init();
    if (!g_cfg.active)
        return;
    HookGuard hg;
    res::used_closed(fd, how);
}

void call_failed(int fd, const char *how, int err) {
    if (tl_in_hook || err == EBADF || err == EINPROGRESS || err == EINTR ||
        err == EALREADY || err == EISCONN || err == EAGAIN)
        return; // not a failure of the socket (or the descriptor is not one of ours)
    ErrnoSaver es;
    ensure_init();
    if (!g_cfg.active)
        return;
    HookGuard hg;
    res::socket_failed(fd, how, err);
}

// ---- a read loop that ignores end of file -----------------------------------
//
// read() returning 0 on a stream socket is the peer hanging up. A loop that
// does not stop there spins at full CPU, forever. A thousand zero reads in a
// row on one socket is that loop; a program that sees the 0 once closes the
// socket and never reaches the count.

uint32_t g_zero[kMaxFd];
uint32_t g_again[kMaxFd];

namespace {
constexpr uint32_t kSpin = 1000;
constexpr uint32_t kSpinReported = 1u << 30; // above any count: reported already
} // namespace

void fd_changed(int fd) {
    if (unsigned(fd) < unsigned(kMaxFd)) {
        g_zero[fd] = 0;
        g_again[fd] = 0;
        g_is_socket[fd] = 0;
    }
}

void read_zero(int fd, const char *how) {
    if (unsigned(fd) >= unsigned(kMaxFd) || tl_in_hook)
        return;
    if (__atomic_add_fetch(&g_zero[fd], 1, __ATOMIC_RELAXED) != kSpin)
        return;
    ErrnoSaver es;
    ensure_init();
    if (!g_cfg.active)
        return;
    HookGuard hg;
    int type = 0;
    socklen_t n = sizeof type;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &n) != 0 || type != SOCK_STREAM)
        return; // a file at its end is read the same way, and may be polled
    __atomic_store_n(&g_zero[fd], kSpinReported, __ATOMIC_RELAXED);
    char m[256];
    Buf msg(m, sizeof m);
    msg.s(how).s(" returned 0 (the peer closed the connection) ").u(kSpin);
    msg.s(" times in a row on socket ").u(uint64_t(fd));
    msg.s(", and the loop keeps reading it: stop at end of file and close the socket");
    report::Finding f;
    f.type = lcproto::kEofSpin;
    f.category = lcproto::kCatFd;
    f.addr = uint64_t(fd);
    f.tid = current_tid();
    f.msg = msg.cstr();
    f.access_stack = stacks::capture();
    report::emit(f);
}

void read_again(int fd, const char *how) {
    if (unsigned(fd) >= unsigned(kMaxFd) || tl_in_hook)
        return;
    if (__atomic_add_fetch(&g_again[fd], 1, __ATOMIC_RELAXED) != kSpin)
        return;
    ErrnoSaver es;
    ensure_init();
    if (!g_cfg.active)
        return;
    HookGuard hg;
    int type = 0;
    socklen_t n = sizeof type;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &n) != 0 || type != SOCK_STREAM)
        return;
    __atomic_store_n(&g_again[fd], kSpinReported, __ATOMIC_RELAXED);
    char m[256];
    Buf msg(m, sizeof m);
    msg.s(how).s(" returned EAGAIN ").u(kSpin);
    msg.s(" times in a row on socket ").u(uint64_t(fd));
    msg.s(": the socket is non-blocking and the loop does not wait. Use poll() or epoll_wait()");
    report::Finding f;
    f.type = lcproto::kEagain;
    f.category = lcproto::kCatFd;
    f.addr = uint64_t(fd);
    f.tid = current_tid();
    f.msg = msg.cstr();
    f.access_stack = stacks::capture();
    report::emit(f);
}

// ---- bind() to a fixed TCP port without SO_REUSEADDR ------------------------
//
// The kernel is asked, not a table: SO_REUSEADDR or SO_REUSEPORT set any time
// before this bind counts. One report per call site: the reporter merges
// findings with the same stack.

void scm_rights(void *msg, long n) {
    if (n < 0 || !msg || tl_in_hook)
        return;
    ensure_init();
    if (!g_cfg.active)
        return;
    auto *m = static_cast<struct msghdr *>(msg);
    if (!m->msg_control || m->msg_controllen < sizeof(struct cmsghdr))
        return;
    ErrnoSaver es;
    HookGuard hg;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(m); c; c = CMSG_NXTHDR(m, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
            c->cmsg_len < CMSG_LEN(sizeof(int)))
            continue;
        auto *fds = reinterpret_cast<int *>(CMSG_DATA(c));
        const int count = int((c->cmsg_len - CMSG_LEN(0)) / sizeof(int));
        for (int i = 0; i < count; ++i)
            if (fds[i] >= 0)
                res::opened(res::Kind::Fd, uint64_t(fds[i]), "recvmsg()");
    }
}

void before_bind(int fd, const void *addr, unsigned len) {
    if (!addr || len < sizeof(sa_family_t) || tl_in_hook)
        return;
    const auto *sa = static_cast<const struct sockaddr *>(addr);
    unsigned port = 0;
    if (sa->sa_family == AF_INET && len >= sizeof(struct sockaddr_in))
        port = __builtin_bswap16(static_cast<const struct sockaddr_in *>(addr)->sin_port);
    else if (sa->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6))
        port = __builtin_bswap16(static_cast<const struct sockaddr_in6 *>(addr)->sin6_port);
    if (port == 0) // an ephemeral port is never in TIME_WAIT trouble
        return;
    ErrnoSaver es;
    ensure_init();
    if (!g_cfg.active)
        return;
    HookGuard hg;
    int type = 0, reuse = 0, reuse_port = 0;
    socklen_t n = sizeof type;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &n) != 0 || type != SOCK_STREAM)
        return;
    n = sizeof reuse;
    getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, &n);
    n = sizeof reuse_port;
    getsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse_port, &n);
    if (reuse || reuse_port)
        return;
    char m[192];
    Buf msg(m, sizeof m);
    msg.s("bind() to TCP port ").u(port);
    msg.s(" without SO_REUSEADDR: after a restart the port may stay in TIME_WAIT "
          "and bind() fails with \"Address already in use\"");
    report::Finding f;
    f.type = lcproto::kBindReuse;
    f.category = lcproto::kCatFd;
    f.addr = uint64_t(fd);
    f.tid = current_tid();
    f.msg = msg.cstr();
    f.access_stack = stacks::capture();
    report::emit(f); // the same call site again only counts as an occurrence
}

// ---- select() with nfds past FD_SETSIZE --------------------------------------
//
// An fd_set is FD_SETSIZE bits. nfds tells the kernel how many of those bits
// to copy. Past FD_SETSIZE it reads and writes off the end of the set, which
// is the classic stack smash. One compare on the call; nothing until then.
// nfds within FD_SETSIZE, including exactly FD_SETSIZE, is silent.

void nfds_past_fdset(int nfds, const char *how) {
    if (tl_in_hook)
        return;
    ensure_init();
    if (!g_cfg.active)
        return;
    HookGuard hg;
    ErrnoSaver es;
    char m[256];
    Buf msg(m, sizeof m);
    msg.s(how).s(" with nfds ").u(uint64_t(nfds));
    msg.s(", past FD_SETSIZE (").u(uint64_t(FD_SETSIZE));
    msg.s("): an fd_set holds that many bits and the kernel copies nfds of them, "
          "which smashes the stack; use poll() or epoll_wait()");
    report::Finding f;
    f.type = lcproto::kSelectOverflow;
    f.category = lcproto::kCatFd;
    f.tid = current_tid();
    f.msg = msg.cstr();
    f.access_stack = stacks::capture();
    report::emit(f);
}

} // namespace lc::sockets

using namespace lc;
using namespace lc::sockets;

#include "lc_api.h"
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0 // Darwin has no per-call flag; the SIGPIPE check still runs
#endif
// ret name(params): look at the flags argument, then the real one; a failure
// goes to failed(), which only cares about EBADF
#define WRAP(ret, name, flags, params, args)                                   \
    LC_API ret LC_FN(name) params {                                            \
        static ret(*real_fn) params;                                           \
        note(fd, flags, "send() without MSG_NOSIGNAL");                        \
        const ret rc = real(real_fn, #name) args;                              \
        if (LC_UNLIKELY(rc < 0))                                               \
            failed(fd, #name "()");                                            \
        return rc;                                                             \
    }

WRAP(ssize_t, send, flags, (int fd, const void *buf, size_t len, int flags),
     (fd, buf, len, flags))
// sendto/sendmsg do not call connect(), so a UDP scan was invisible.
LC_API ssize_t LC_FN(sendto)(int fd, const void *buf, size_t len, int flags,
                             const struct sockaddr *addr, socklen_t alen) {
    behavior::connecting(addr, alen);
    static ssize_t (*real_fn)(int, const void *, size_t, int, const struct sockaddr *,
                              socklen_t);
    note(fd, flags, "send() without MSG_NOSIGNAL");
    const ssize_t rc = real(real_fn, "sendto")(fd, buf, len, flags, addr, alen);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "sendto()");
    return rc;
}
LC_API ssize_t LC_FN(sendmsg)(int fd, const struct msghdr *msg, int flags) {
    if (msg && msg->msg_name)
        behavior::connecting(msg->msg_name, msg->msg_namelen);
    static ssize_t (*real_fn)(int, const struct msghdr *, int);
    note(fd, flags, "send() without MSG_NOSIGNAL");
    const ssize_t rc = real(real_fn, "sendmsg")(fd, msg, flags);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "sendmsg()");
    return rc;
}

#if !defined(__APPLE__) // sendmmsg / mmsghdr are Linux
LC_API int LC_FN(sendmmsg)(int fd, struct mmsghdr *msgvec, unsigned vlen, int flags) {
    if (msgvec)
        for (unsigned i = 0; i < vlen && i < 256; ++i)
            if (msgvec[i].msg_hdr.msg_name)
                behavior::connecting(msgvec[i].msg_hdr.msg_name, msgvec[i].msg_hdr.msg_namelen);
    static int (*real_fn)(int, struct mmsghdr *, unsigned, int);
    note(fd, flags, "sendmmsg() without MSG_NOSIGNAL");
    const int rc = real(real_fn, "sendmmsg")(fd, msgvec, vlen, flags);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "sendmmsg()");
    return rc;
}
#endif

LC_API int LC_FN(select)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                  struct timeval *timeout) {
    if (LC_UNLIKELY(nfds > FD_SETSIZE)) // select()
        nfds_past_fdset(nfds, "select()");
    static int (*real_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
    return real(real_select, "select")(nfds, readfds, writefds, exceptfds, timeout);
}

LC_API int LC_FN(pselect)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                   const struct timespec *timeout, const sigset_t *mask) {
    if (LC_UNLIKELY(nfds > FD_SETSIZE)) // pselect()
        nfds_past_fdset(nfds, "pselect()");
    static int (*real_pselect)(int, fd_set *, fd_set *, fd_set *,
                               const struct timespec *, const sigset_t *);
    return real(real_pselect, "pselect")(nfds, readfds, writefds, exceptfds, timeout, mask);
}
