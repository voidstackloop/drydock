// Wrappers for the calls that use a descriptor: read, write, writev, recv, recvfrom,
// recvmsg, connect, bind, listen and shutdown. They add one thing to each call
// and cost nothing on the way: data came back, or the call worked. Only a
// failure with EBADF (use after close) and a read that returns 0 (end of file
// ignored) are looked at, in sockets.cpp. Like interpose_io.cpp this defines
// libc functions, so it includes none of their headers; ssize_t is long.
#include "init.h"
#include "rt.h"
#include "behavior.h"
#include "sockets.h"

#include <cerrno>
#include <cstdarg>
#include <dlfcn.h>
#include <sys/syscall.h>

#if !defined(__APPLE__)
extern "C" long syscall(long number, ...);
#endif
#if defined(__APPLE__)
// Bound to libSystem, not to lc_read/lc_write: those are the wrappers.
extern "C" long lc_sys_read(int, void *, unsigned long) __asm("_read");
extern "C" long lc_sys_write(int, const void *, unsigned long) __asm("_write");
extern "C" long lc_sys_writev(int, const void *, int) __asm("_writev");
#endif

#include "lc_api.h"

using namespace lc;
using namespace lc::sockets;

namespace {

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

using read_fn = long (*)(int, void *, unsigned long);
using write_fn = long (*)(int, const void *, unsigned long);
using writev_fn = long (*)(int, const void *, int);
using readv_fn = long (*)(int, const void *, int);
using preadv_fn = long (*)(int, const void *, int, long);
using preadv2_fn = long (*)(int, const void *, int, long, int);
using pread_fn = long (*)(int, void *, unsigned long, long);
using pwrite_fn = long (*)(int, const void *, unsigned long, long);
#if !defined(__APPLE__)
using sendfile_fn = long (*)(int, int, void *, unsigned long);
#endif
using recv_fn = long (*)(int, void *, unsigned long, int);
using recvfrom_fn = long (*)(int, void *, unsigned long, int, void *, unsigned *);
using recvmsg_fn = long (*)(int, void *, int);
using addr_fn = int (*)(int, const void *, unsigned);
using int2_fn = int (*)(int, int);

read_fn real_read;
write_fn real_write;
writev_fn real_writev;
readv_fn real_readv;
preadv_fn real_preadv, real_preadv64, real_pwritev, real_pwritev64;
preadv2_fn real_preadv2, real_preadv64v2, real_pwritev2, real_pwritev64v2;
pread_fn real_pread, real_pread64;
pwrite_fn real_pwrite, real_pwrite64;
#if !defined(__APPLE__)
sendfile_fn real_sendfile;
#endif
recv_fn real_recv;
recvfrom_fn real_recvfrom;
recvmsg_fn real_recvmsg;
addr_fn real_connect, real_bind;
int2_fn real_listen, real_shutdown;
using flock_fn = int (*)(int, int);
flock_fn real_flock;
using vdprintf_fn = int (*)(int, const char *, __builtin_va_list);
vdprintf_fn real_vdprintf;

// What a read call returned: data (the common case, nothing to do), an error
// or end of file.
inline long after_read(int fd, long rc, unsigned long n, const char *how) {
    if (LC_UNLIKELY(rc <= 0)) {
        if (rc < 0) {
            failed(fd, how);
            if (errno == EAGAIN)
                read_again(fd, how);
            else
                again_reset(fd);
        } else if (n) {
            read_zero(fd, how);
            again_reset(fd);
        }
    } else
        again_reset(fd);
    return rc;
}

inline long after_call(int fd, long rc, const char *how) {
    if (LC_UNLIKELY(rc < 0))
        failed(fd, how);
    return rc;
}

// connect, bind and listen set a socket up: when one fails, the leak report
// of that socket says so (a socket whose connect failed is the classic leak).
inline long after_setup_call(int fd, long rc, const char *how) {
    if (LC_UNLIKELY(rc < 0)) {
        failed(fd, how);
        call_failed(fd, how, errno);
    }
    return rc;
}

} // namespace

// The runtime's own report output goes through write(): inside a hook the
// raw system call is used, so nothing here can recurse or call dlsym.
LC_API long LC_FN(read)(int fd, void *buf, unsigned long n) {
    if (LC_UNLIKELY(tl_in_hook && !real_read))
#if defined(__APPLE__)
        return lc_sys_read(fd, buf, n);
#else
        return syscall(SYS_read, fd, buf, n);
#endif
    return after_read(fd, real(real_read, "read")(fd, buf, n), n, "read()");
}

LC_API long LC_FN(write)(int fd, const void *buf, unsigned long n) {
    if (LC_UNLIKELY(tl_in_hook && !real_write))
#if defined(__APPLE__)
        return lc_sys_write(fd, buf, n);
#else
        return syscall(SYS_write, fd, buf, n);
#endif
    if (LC_UNLIKELY(unsigned(fd) < unsigned(kMaxFd) && g_is_socket[fd] == kSocket))
        write_on_socket(fd, "write() on a socket");
    return after_call(fd, real(real_write, "write")(fd, buf, n), "write()");
}

LC_API long LC_FN(writev)(int fd, const void *iov, int n) {
    if (LC_UNLIKELY(tl_in_hook && !real_writev))
#if defined(__APPLE__)
        return lc_sys_writev(fd, iov, n);
#else
        return syscall(SYS_writev, fd, iov, n);
#endif
    if (LC_UNLIKELY(unsigned(fd) < unsigned(kMaxFd) && g_is_socket[fd] == kSocket))
        write_on_socket(fd, "writev() on a socket");
    return after_call(fd, real(real_writev, "writev")(fd, iov, n), "writev()");
}

// readv/pread/pwrite fail with EBADF on a closed descriptor. No EAGAIN count:
// that stays on read/recv.
LC_API long LC_FN(readv)(int fd, const void *iov, int n) {
    const long rc = real(real_readv, "readv")(fd, iov, n);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "readv()");
    return rc;
}

LC_API long LC_FN(pread)(int fd, void *buf, unsigned long n, long off) {
    const long rc = real(real_pread, "pread")(fd, buf, n, off);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "pread()");
    return rc;
}

LC_API long LC_FN(pread64)(int fd, void *buf, unsigned long n, long off) {
    const long rc = real(real_pread64, "pread64")(fd, buf, n, off);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "pread64()");
    return rc;
}

LC_API long LC_FN(pwrite)(int fd, const void *buf, unsigned long n, long off) {
    const long rc = real(real_pwrite, "pwrite")(fd, buf, n, off);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "pwrite()");
    return rc;
}

LC_API long LC_FN(pwrite64)(int fd, const void *buf, unsigned long n, long off) {
    const long rc = real(real_pwrite64, "pwrite64")(fd, buf, n, off);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "pwrite64()");
    return rc;
}

// preadv/pwritev fail with EBADF on a closed descriptor. No EAGAIN count.
LC_API long LC_FN(preadv)(int fd, const void *iov, int n, long off) {
    const long rc = real(real_preadv, "preadv")(fd, iov, n, off);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "preadv()");
    return rc;
}

LC_API long LC_FN(preadv64)(int fd, const void *iov, int n, long off) {
    const long rc = real(real_preadv64, "preadv64")(fd, iov, n, off);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "preadv64()");
    return rc;
}

LC_API long LC_FN(pwritev)(int fd, const void *iov, int n, long off) {
    const long rc = real(real_pwritev, "pwritev")(fd, iov, n, off);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "pwritev()");
    return rc;
}

LC_API long LC_FN(pwritev64)(int fd, const void *iov, int n, long off) {
    const long rc = real(real_pwritev64, "pwritev64")(fd, iov, n, off);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "pwritev64()");
    return rc;
}

LC_API long LC_FN(preadv2)(int fd, const void *iov, int n, long off, int flags) {
    const long rc = real(real_preadv2, "preadv2")(fd, iov, n, off, flags);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "preadv2()");
    return rc;
}

LC_API long LC_FN(preadv64v2)(int fd, const void *iov, int n, long off, int flags) {
    const long rc = real(real_preadv64v2, "preadv64v2")(fd, iov, n, off, flags);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "preadv64v2()");
    return rc;
}

LC_API long LC_FN(pwritev2)(int fd, const void *iov, int n, long off, int flags) {
    const long rc = real(real_pwritev2, "pwritev2")(fd, iov, n, off, flags);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "pwritev2()");
    return rc;
}

LC_API long LC_FN(pwritev64v2)(int fd, const void *iov, int n, long off, int flags) {
    const long rc = real(real_pwritev64v2, "pwritev64v2")(fd, iov, n, off, flags);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "pwritev64v2()");
    return rc;
}

using copy_fn = long (*)(int, void *, int, void *, unsigned long, unsigned);
copy_fn real_copy_file_range, real_splice;

LC_API long LC_FN(copy_file_range)(int in_fd, void *off_in, int out_fd, void *off_out,
                            unsigned long n, unsigned flags) {
    const long rc = real(real_copy_file_range, "copy_file_range")(
        in_fd, off_in, out_fd, off_out, n, flags);
    if (LC_UNLIKELY(rc < 0)) {
        failed(out_fd, "copy_file_range()");
        failed(in_fd, "copy_file_range()");
    }
    return rc;
}

LC_API long LC_FN(splice)(int in_fd, void *off_in, int out_fd, void *off_out,
                   unsigned long n, unsigned flags) {
    const long rc =
        real(real_splice, "splice")(in_fd, off_in, out_fd, off_out, n, flags);
    if (LC_UNLIKELY(rc < 0)) {
        failed(out_fd, "splice()");
        failed(in_fd, "splice()");
    }
    return rc;
}

// Same SIGPIPE gate as write(): only a descriptor socket()/accept() made.
#if defined(__APPLE__)
// Darwin: int sendfile(int fd, int socket, off_t offset, off_t *len, struct sf_hdtr *, int flags).
LC_API int LC_FN(sendfile)(int fd, int s, long offset, long *len, void *hdtr, int flags) {
    using Fn = int (*)(int, int, long, long *, void *, int);
    static Fn real_sf;
    if (LC_UNLIKELY(unsigned(s) < unsigned(kMaxFd) && g_is_socket[s] == kSocket))
        write_on_socket(s, "sendfile() on a socket");
    const int rc = real(real_sf, "sendfile")(fd, s, offset, len, hdtr, flags);
    if (LC_UNLIKELY(rc < 0))
        failed(s, "sendfile()");
    return rc;
}
#else
LC_API long LC_FN(sendfile)(int out_fd, int in_fd, void *off, unsigned long n) {
    if (LC_UNLIKELY(unsigned(out_fd) < unsigned(kMaxFd) && g_is_socket[out_fd] == kSocket))
        write_on_socket(out_fd, "sendfile() on a socket");
    const long rc = real(real_sendfile, "sendfile")(out_fd, in_fd, off, n);
    if (LC_UNLIKELY(rc < 0))
        failed(out_fd, "sendfile()");
    return rc;
}
#endif

LC_API long LC_FN(recv)(int fd, void *buf, unsigned long n, int flags) {
    return after_read(fd, real(real_recv, "recv")(fd, buf, n, flags), n, "recv()");
}

LC_API long LC_FN(recvfrom)(int fd, void *buf, unsigned long n, int flags, void *addr,
                     unsigned *alen) {
    return after_read(fd, real(real_recvfrom, "recvfrom")(fd, buf, n, flags, addr, alen),
                      n, "recvfrom()");
}

LC_API long LC_FN(recvmsg)(int fd, void *msg, int flags) {
    const long rc = real(real_recvmsg, "recvmsg")(fd, msg, flags);
    if (LC_UNLIKELY(rc >= 0))
        scm_rights(msg, rc);
    return after_call(fd, rc, "recvmsg()");
}

LC_API int LC_FN(connect)(int fd, const void *addr, unsigned len) {
    behavior::connecting(addr, len);
    return int(after_setup_call(fd, real(real_connect, "connect")(fd, addr, len), "connect()"));
}

LC_API int LC_FN(bind)(int fd, const void *addr, unsigned len) {
    before_bind(fd, addr, len);
    return int(after_setup_call(fd, real(real_bind, "bind")(fd, addr, len), "bind()"));
}

LC_API int LC_FN(listen)(int fd, int backlog) {
    return int(after_setup_call(fd, real(real_listen, "listen")(fd, backlog), "listen()"));
}

LC_API int LC_FN(shutdown)(int fd, int how) {
    return int(after_call(fd, real(real_shutdown, "shutdown")(fd, how), "shutdown()"));
}

LC_API int LC_FN(flock)(int fd, int op) {
    const int rc = real(real_flock, "flock")(fd, op);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "flock()");
    return rc;
}

LC_API int LC_FN(vdprintf)(int fd, const char *fmt, __builtin_va_list ap) {
    if (LC_UNLIKELY(unsigned(fd) < unsigned(kMaxFd) && g_is_socket[fd] == kSocket))
        write_on_socket(fd, "vdprintf() on a socket");
    const int rc = real(real_vdprintf, "vdprintf")(fd, fmt, ap);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "vdprintf()");
    return rc;
}

LC_API int LC_FN(dprintf)(int fd, const char *fmt, ...) {
    if (LC_UNLIKELY(unsigned(fd) < unsigned(kMaxFd) && g_is_socket[fd] == kSocket))
        write_on_socket(fd, "dprintf() on a socket");
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    const int rc = real(real_vdprintf, "vdprintf")(fd, fmt, ap);
    __builtin_va_end(ap);
    if (LC_UNLIKELY(rc < 0))
        failed(fd, "dprintf()");
    return rc;
}
