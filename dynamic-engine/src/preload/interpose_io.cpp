// Exported wrappers for the calls that create and release descriptors,
// streams, directories and child processes. Like interpose.cpp, this file
// defines libc functions itself, so it includes none of the headers that
// declare them: FILE * and DIR * are passed as void *, which C linkage does not
// mind.
#include "behavior.h"
#include "init.h"
#include "resources.h"
#include "rt.h"
#include "signals.h"
#include "sockets.h"

#include <cerrno>
#include <cstdarg>
#include <dlfcn.h>

#include "lc_api.h"

using namespace lc;
using res::Kind;

extern "C" int fileno(void *stream);
extern "C" int dirfd(void *dir);
extern "C" int getpid();

namespace {

#if defined(__APPLE__)
constexpr int kOCreat = 0x0200;       // O_CREAT
constexpr int kCreatFlags = 0x0601;   // creat(): O_WRONLY|O_CREAT|O_TRUNC
constexpr int kOTmpfile = 0;          // Darwin has no O_TMPFILE
constexpr int kCloseRangeCloexec = 0; // close_range is Linux
constexpr int kFDupfd = 0;            // F_DUPFD
constexpr int kFDupfdCloexec = 67;    // F_DUPFD_CLOEXEC
#else
constexpr int kOCreat = 0100;              // O_CREAT
constexpr int kCreatFlags = 01101;         // creat(): O_WRONLY|O_CREAT|O_TRUNC
constexpr int kOTmpfile = 020200000;       // O_TMPFILE (includes O_DIRECTORY)
constexpr int kCloseRangeCloexec = 1 << 2; // CLOSE_RANGE_CLOEXEC
constexpr int kFDupfd = 0;                 // F_DUPFD
constexpr int kFDupfdCloexec = 1030;       // F_DUPFD_CLOEXEC
#endif

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

#define REAL(name) real(real_##name, #name)

bool tracking() {
    if (tl_in_hook)
        return false;
    ensure_init();
    return g_cfg.active;
}

bool closed_dir(void *d, const char *how) {
    if (!d || !tracking())
        return false;
    bool closed;
    {
        ErrnoSaver es;
        HookGuard hg;
        closed = res::used_stream(uint64_t(uintptr_t(d)), how, Kind::Dir);
    }
    if (!closed)
        return false;
    errno = EBADF;
    return true;
}

bool needs_mode(int flags) {
#if defined(__APPLE__)
    return (flags & kOCreat) != 0;
#else
    return (flags & kOCreat) || (flags & kOTmpfile) == kOTmpfile;
#endif
}

// A call that makes a descriptor, stream or directory failed: if it ran out of
// descriptors, say who holds them. errno is left as the call set it.
void note_failed(const char *how) {
    const int err = errno;
    if (err != EMFILE && err != ENFILE)
        return;
    if (tracking()) {
        errno = err;
        ErrnoSaver es;
        HookGuard hg;
        res::exhausted(how);
    }
    errno = err;
}

int track_fd(int fd, const char *how) {
    if (fd >= 0 && tracking()) {
        ErrnoSaver es;
        HookGuard hg;
        res::opened(Kind::Fd, uint64_t(fd), how);
    } else if (fd < 0) {
        note_failed(how);
    }
    return fd;
}

int track_pair(int rc, const int *fds, const char *how) {
    if (rc == 0) {
        track_fd(fds[0], how);
        track_fd(fds[1], how);
    } else {
        note_failed(how);
    }
    return rc;
}

// A child program starts now with a copy of our descriptors.
void starting_child(const char *how) {
    if (tracking()) {
        ErrnoSaver es;
        HookGuard hg;
        res::check_inherited(how);
    }
}

// A new stream or directory, which owns descriptor `inner` from now on.
void *track_handle(void *h, Kind k, int inner, const char *how) {
    signals::unsafe_call(how); // allocates, and takes libc's stream list lock
    if (h && tracking()) {
        ErrnoSaver es;
        HookGuard hg;
        if (inner >= 0)
            res::forget(Kind::Fd, uint64_t(inner));
        res::opened(k, uint64_t(h), how);
    } else if (!h) {
        note_failed(how);
    }
    return h;
}

// Releases a stream or directory through `release`, unless it already was.
template <class F>
int close_handle(void *h, Kind k, const char *how, int (*inner_fd)(void *),
                 F release) {
    signals::unsafe_call(how);
    const bool track = h && tracking();
    int inner = -1;
    if (track) {
        bool ok;
        {
            ErrnoSaver es;
            HookGuard hg;
            ok = res::closing(k, uint64_t(h), how);
            if (ok)
                inner = inner_fd(h);
        }
        if (!ok) { // releasing it again would corrupt the heap: report only
            errno = EBADF;
            return -1;
        }
    }
    const int rc = release(h);
    if (track) {
        ErrnoSaver es;
        HookGuard hg;
        res::closed(k, uint64_t(h));
        if (inner >= 0)
            res::closed(Kind::Fd, uint64_t(inner));
    }
    return rc;
}

using open_fn = int (*)(const char *, int, ...);
using openat_fn = int (*)(int, const char *, int, ...);
using open2_fn = int (*)(const char *, int);
using openat2_fn = int (*)(int, const char *, int);
using creat_fn = int (*)(const char *, unsigned);
using int1_fn = int (*)(int);
using int2_fn = int (*)(int, int);
using int3_fn = int (*)(int, int, int);
using void_fn = int (*)();
using pair_fn = int (*)(int, int, int, int *);
using accept_fn = int (*)(int, void *, unsigned *);
using accept4_fn = int (*)(int, void *, unsigned *, int);
using pipe_fn = int (*)(int *);
using pipe2_fn = int (*)(int *, int);
using eventfd_fn = int (*)(unsigned, int);
using signalfd_fn = int (*)(int, const void *, int);
using memfd_fn = int (*)(const char *, unsigned);
using range_fn = int (*)(unsigned, unsigned, int);
using mkstemp_fn = int (*)(char *);
using mkstemp2_fn = int (*)(char *, int);
using mkstemp3_fn = int (*)(char *, int, int);
using fcntl_fn = int (*)(int, int, ...);
using fopen_fn = void *(*)(const char *, const char *);
using freopen_fn = void *(*)(const char *, const char *, void *);
using fdopen_fn = void *(*)(int, const char *);
using tmpfile_fn = void *(*)();
using fmemopen_fn = void *(*)(void *, size_t, const char *);
using memstream_fn = void *(*)(char **, size_t *);
using opendir_fn = void *(*)(const char *);
using fdopendir_fn = void *(*)(int);
using readdir_fn = void *(*)(void *);
using rewinddir_fn = void (*)(void *);
using seekdir_fn = void (*)(void *, long);
using telldir_fn = long (*)(void *);
using release_fn = int (*)(void *);

open_fn real_open, real_open64;
openat_fn real_openat, real_openat64;
open2_fn real___open_2, real___open64_2;
openat2_fn real___openat_2, real___openat64_2;
creat_fn real_creat, real_creat64;
int3_fn real_socket, real_dup3;
int2_fn real_dup2, real_timerfd_create;
int1_fn real_dup, real_epoll_create, real_epoll_create1, real_inotify_init1,
    real_close;
void_fn real_inotify_init;
pair_fn real_socketpair;
accept_fn real_accept;
accept4_fn real_accept4;
pipe_fn real_pipe;
pipe2_fn real_pipe2;
eventfd_fn real_eventfd;
signalfd_fn real_signalfd;
memfd_fn real_memfd_create;
range_fn real_close_range;
fopen_fn real_fopen, real_fopen64, real_popen;
freopen_fn real_freopen, real_freopen64;
fdopen_fn real_fdopen;
tmpfile_fn real_tmpfile, real_tmpfile64;
fmemopen_fn real_fmemopen;
memstream_fn real_open_memstream;
opendir_fn real_opendir;
fdopendir_fn real_fdopendir;
readdir_fn real_readdir;
rewinddir_fn real_rewinddir;
seekdir_fn real_seekdir;
telldir_fn real_telldir;
release_fn real_fclose, real_pclose, real_closedir;
void_fn real_fcloseall;
mkstemp_fn real_mkstemp, real_mkstemp64;
mkstemp2_fn real_mkostemp, real_mkostemp64, real_mkstemps, real_mkstemps64;
mkstemp3_fn real_mkostemps, real_mkostemps64;
fcntl_fn real_fcntl, real_fcntl64;

// fcntl's third argument is an int, a pointer or absent; like glibc's own
// wrapper, pass it on as a pointer-sized value.
int track_fcntl(int rc, int cmd) {
    return cmd == kFDupfd || cmd == kFDupfdCloexec ? track_fd(rc, "fcntl()")
                                                   : rc;
}

unsigned mode_arg(int flags, va_list ap) {
    return needs_mode(flags) ? va_arg(ap, unsigned) : 0u;
}

void created_loose(int flags, unsigned mode, const char *how) {
    if (!needs_mode(flags))
        return;
    if (mode & 0002)
        behavior::loose_mode(how, " creates the file writable by every user: another user "
                                   "can change what the program reads later");
    if (mode & 06000)
        behavior::setuid_bit(how);
}

} // namespace

// ---- descriptors ----------------------------------------------------------

LC_API int LC_FN(open)(const char *path, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    const unsigned mode = mode_arg(flags, ap);
    va_end(ap);
    behavior::opening(path, flags);
    created_loose(flags, mode, "open()");
    return track_fd(REAL(open)(path, flags, mode), "open()");
}

LC_API int LC_FN(open64)(const char *path, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    const unsigned mode = mode_arg(flags, ap);
    va_end(ap);
    behavior::opening(path, flags);
    created_loose(flags, mode, "open()");
    return track_fd(REAL(open64)(path, flags, mode), "open()");
}

LC_API int LC_FN(openat)(int dir, const char *path, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    const unsigned mode = mode_arg(flags, ap);
    va_end(ap);
    behavior::opening(path, flags);
    created_loose(flags, mode, "openat()");
    return track_fd(REAL(openat)(dir, path, flags, mode), "openat()");
}

LC_API int LC_FN(openat64)(int dir, const char *path, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    const unsigned mode = mode_arg(flags, ap);
    va_end(ap);
    behavior::opening(path, flags);
    created_loose(flags, mode, "openat()");
    return track_fd(REAL(openat64)(dir, path, flags, mode), "openat()");
}

// What _FORTIFY_SOURCE builds call for open() without a mode.
LC_API int LC_FN(__open_2)(const char *path, int flags) {
    behavior::opening(path, flags);
    return track_fd(REAL(__open_2)(path, flags), "open()");
}
LC_API int LC_FN(__open64_2)(const char *path, int flags) {
    behavior::opening(path, flags);
    return track_fd(REAL(__open64_2)(path, flags), "open()");
}
LC_API int LC_FN(__openat_2)(int dir, const char *path, int flags) {
    behavior::opening(path, flags);
    return track_fd(REAL(__openat_2)(dir, path, flags), "openat()");
}
LC_API int LC_FN(__openat64_2)(int dir, const char *path, int flags) {
    behavior::opening(path, flags);
    return track_fd(REAL(__openat64_2)(dir, path, flags), "openat()");
}

LC_API int LC_FN(creat)(const char *path, unsigned mode) {
    behavior::opening(path, kCreatFlags);
    created_loose(kCreatFlags, mode, "creat()");
    return track_fd(REAL(creat)(path, mode), "creat()");
}
LC_API int LC_FN(creat64)(const char *path, unsigned mode) {
    behavior::opening(path, kCreatFlags);
    created_loose(kCreatFlags, mode, "creat()");
    return track_fd(REAL(creat64)(path, mode), "creat()");
}

LC_API int LC_FN(socket)(int domain, int type, int protocol) {
    // SOCK_RAW is 3. AF_PACKET is 17. CLOEXEC lives in the high bits.
    if ((type & 0xf) == 3 || domain == 17)
        behavior::raw_socket("socket()");
    return track_fd(REAL(socket)(domain, type, protocol), "socket()");
}

LC_API int LC_FN(socketpair)(int domain, int type, int protocol, int *sv) {
    return track_pair(REAL(socketpair)(domain, type, protocol, sv), sv,
                      "socketpair()");
}

LC_API int LC_FN(accept)(int fd, void *addr, unsigned *len) {
    const int rc = REAL(accept)(fd, addr, len);
    if (rc < 0)
        lc::sockets::failed(fd, "accept()");
    return track_fd(rc, "accept()");
}

LC_API int LC_FN(accept4)(int fd, void *addr, unsigned *len, int flags) {
    const int rc = REAL(accept4)(fd, addr, len, flags);
    if (rc < 0)
        lc::sockets::failed(fd, "accept4()");
    return track_fd(rc, "accept4()");
}

LC_API int LC_FN(pipe)(int *fds) { return track_pair(REAL(pipe)(fds), fds, "pipe()"); }

LC_API int LC_FN(pipe2)(int *fds, int flags) {
    return track_pair(REAL(pipe2)(fds, flags), fds, "pipe2()");
}

LC_API int LC_FN(dup)(int fd) { return track_fd(REAL(dup)(fd), "dup()"); }

LC_API int LC_FN(dup2)(int fd, int to) {
    const int rc = REAL(dup2)(fd, to);
    return fd == to ? rc : track_fd(rc, "dup2()");
}

LC_API int LC_FN(dup3)(int fd, int to, int flags) {
    return track_fd(REAL(dup3)(fd, to, flags), "dup3()");
}

LC_API int LC_FN(eventfd)(unsigned count, int flags) {
    return track_fd(REAL(eventfd)(count, flags), "eventfd()");
}

LC_API int LC_FN(epoll_create)(int size) {
    return track_fd(REAL(epoll_create)(size), "epoll_create()");
}

LC_API int LC_FN(epoll_create1)(int flags) {
    return track_fd(REAL(epoll_create1)(flags), "epoll_create1()");
}

LC_API int LC_FN(timerfd_create)(int clock, int flags) {
    return track_fd(REAL(timerfd_create)(clock, flags), "timerfd_create()");
}

LC_API int LC_FN(signalfd)(int fd, const void *mask, int flags) {
    const int rc = REAL(signalfd)(fd, mask, flags);
    return fd == -1 ? track_fd(rc, "signalfd()") : rc; // -1: a new descriptor
}

LC_API int LC_FN(inotify_init)() {
    return track_fd(REAL(inotify_init)(), "inotify_init()");
}

LC_API int LC_FN(inotify_init1)(int flags) {
    return track_fd(REAL(inotify_init1)(flags), "inotify_init1()");
}

LC_API int LC_FN(memfd_create)(const char *name, unsigned flags) {
    // The name is what /proc shows. It does not call prctl(PR_SET_NAME).
    behavior::process_named(name, "memfd_create() names a file");
    return track_fd(REAL(memfd_create)(name, flags), "memfd_create()");
}

// mkstemp does not call the public open(). O_RDWR|O_CREAT, no O_TRUNC.
LC_API int LC_FN(mkstemp)(char *tmpl) {
    behavior::opening(tmpl, 2 | kOCreat);
    return track_fd(REAL(mkstemp)(tmpl), "mkstemp()");
}
LC_API int LC_FN(mkstemp64)(char *tmpl) {
    behavior::opening(tmpl, 2 | kOCreat);
    return track_fd(REAL(mkstemp64)(tmpl), "mkstemp()");
}
LC_API int LC_FN(mkostemp)(char *tmpl, int flags) {
    behavior::opening(tmpl, 2 | kOCreat);
    return track_fd(REAL(mkostemp)(tmpl, flags), "mkostemp()");
}
LC_API int LC_FN(mkostemp64)(char *tmpl, int flags) {
    behavior::opening(tmpl, 2 | kOCreat);
    return track_fd(REAL(mkostemp64)(tmpl, flags), "mkostemp()");
}
LC_API int LC_FN(mkstemps)(char *tmpl, int suffix) {
    behavior::opening(tmpl, 2 | kOCreat);
    return track_fd(REAL(mkstemps)(tmpl, suffix), "mkstemps()");
}
LC_API int LC_FN(mkstemps64)(char *tmpl, int suffix) {
    behavior::opening(tmpl, 2 | kOCreat);
    return track_fd(REAL(mkstemps64)(tmpl, suffix), "mkstemps()");
}
LC_API int LC_FN(mkostemps)(char *tmpl, int suffix, int flags) {
    behavior::opening(tmpl, 2 | kOCreat);
    return track_fd(REAL(mkostemps)(tmpl, suffix, flags), "mkostemps()");
}
LC_API int LC_FN(mkostemps64)(char *tmpl, int suffix, int flags) {
    behavior::opening(tmpl, 2 | kOCreat);
    return track_fd(REAL(mkostemps64)(tmpl, suffix, flags), "mkostemps()");
}

LC_API int LC_FN(fcntl)(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    return track_fcntl(REAL(fcntl)(fd, cmd, arg), cmd);
}

LC_API int LC_FN(fcntl64)(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    return track_fcntl(REAL(fcntl64)(fd, cmd, arg), cmd);
}

LC_API int LC_FN(close)(int fd) {
    const int rc = REAL(close)(fd);
    if (fd >= 0 && tracking()) {
        const int err = errno;
        ErrnoSaver es;
        HookGuard hg;
        // Linux releases the descriptor even when close() reports an error;
        // only EBADF means there was nothing to close.
        if (rc == 0 || err != EBADF)
            res::closed(Kind::Fd, uint64_t(fd));
        else
            res::close_failed(fd, "close()");
    }
    return rc;
}

LC_API int LC_FN(close_range)(unsigned lo, unsigned hi, int flags) {
    const int rc = REAL(close_range)(lo, hi, flags);
    if (rc == 0 && !(flags & kCloseRangeCloexec) && tracking()) {
        ErrnoSaver es;
        HookGuard hg;
        res::closed_range(lo, hi);
    }
    return rc;
}

// ---- streams ----------------------------------------------------------------

LC_API void *LC_FN(fopen)(const char *path, const char *mode) {
    behavior::opening_stream(path, mode);
    void *f = REAL(fopen)(path, mode);
    return track_handle(f, Kind::File, f ? fileno(f) : -1, "fopen()");
}

LC_API void *LC_FN(fopen64)(const char *path, const char *mode) {
    behavior::opening_stream(path, mode);
    void *f = REAL(fopen64)(path, mode);
    return track_handle(f, Kind::File, f ? fileno(f) : -1, "fopen()");
}

// The old stream is closed whenever the path is not null, even if the new
// open fails. A null path only changes the mode.
void *reopened(const char *path, void *old, void *n, const char *how) {
    // glibc reuses the FILE*. fileno before it is marked closed, or the
    // successful freopen looks like a use of the old stream.
    const int inner = n ? fileno(n) : -1;
    if (path && old && tracking()) {
        ErrnoSaver es;
        HookGuard hg;
        res::closed(Kind::File, uint64_t(uintptr_t(old)));
    }
    return n ? track_handle(n, Kind::File, inner, how) : n;
}

LC_API void *LC_FN(freopen)(const char *path, const char *mode, void *stream) {
    behavior::opening_stream(path, mode);
    return reopened(path, stream, REAL(freopen)(path, mode, stream), "freopen()");
}

LC_API void *LC_FN(freopen64)(const char *path, const char *mode, void *stream) {
    behavior::opening_stream(path, mode);
    return reopened(path, stream, REAL(freopen64)(path, mode, stream), "freopen64()");
}

LC_API void *LC_FN(fdopen)(int fd, const char *mode) {
    return track_handle(REAL(fdopen)(fd, mode), Kind::File, fd, "fdopen()");
}

LC_API void *LC_FN(tmpfile)() {
    void *f = REAL(tmpfile)();
    return track_handle(f, Kind::File, f ? fileno(f) : -1, "tmpfile()");
}

LC_API void *LC_FN(tmpfile64)() {
    void *f = REAL(tmpfile64)();
    return track_handle(f, Kind::File, f ? fileno(f) : -1, "tmpfile()");
}

LC_API void *LC_FN(fmemopen)(void *buf, size_t size, const char *mode) {
    return track_handle(REAL(fmemopen)(buf, size, mode), Kind::File, -1,
                        "fmemopen()");
}

LC_API void *LC_FN(open_memstream)(char **buf, size_t *size) {
    return track_handle(REAL(open_memstream)(buf, size), Kind::File, -1,
                        "open_memstream()");
}

LC_API void *LC_FN(popen)(const char *cmd, const char *mode) {
    behavior::command(cmd, "popen()");
    starting_child("popen()");
    void *f = REAL(popen)(cmd, mode);
    return track_handle(f, Kind::Pipe, f ? fileno(f) : -1, "popen()");
}

LC_API int LC_FN(fclose)(void *f) {
    return close_handle(f, Kind::File, "fclose()", fileno,
                        [](void *h) { return REAL(fclose)(h); });
}

LC_API int LC_FN(fcloseall)() {
    signals::unsafe_call("fcloseall()");
    const int rc = REAL(fcloseall)();
    if (rc == 0 && tracking()) {
        ErrnoSaver es;
        HookGuard hg;
        res::streams_closed();
    }
    return rc;
}

LC_API int LC_FN(pclose)(void *f) {
    return close_handle(f, Kind::Pipe, "pclose()", fileno,
                        [](void *h) { return REAL(pclose)(h); });
}

// ---- directories ------------------------------------------------------------

LC_API void *LC_FN(opendir)(const char *path) {
    void *d = REAL(opendir)(path);
    return track_handle(d, Kind::Dir, d ? dirfd(d) : -1, "opendir()");
}

LC_API void *LC_FN(fdopendir)(int fd) {
    void *d = REAL(fdopendir)(fd);
    if (!d)
        sockets::failed(fd, "fdopendir()");
    return track_handle(d, Kind::Dir, fd, "fdopendir()");
}

LC_API int LC_FN(closedir)(void *d) {
    return close_handle(d, Kind::Dir, "closedir()", dirfd,
                        [](void *h) { return REAL(closedir)(h); });
}

LC_API void *LC_FN(readdir)(void *d) {
    if (closed_dir(d, "readdir()"))
        return nullptr;
    return REAL(readdir)(d);
}

// Same libc address as readdir, different symbol. It goes through the wrapper
// so the closed-directory check is the same; this file includes no dirent.h to
// declare readdir itself.
LC_API void *LC_FN(readdir64)(void *d) { return LC_FN(readdir)(d); }

LC_API void LC_FN(rewinddir)(void *d) {
    if (closed_dir(d, "rewinddir()"))
        return;
    REAL(rewinddir)(d);
}

LC_API void LC_FN(seekdir)(void *d, long off) {
    if (closed_dir(d, "seekdir()"))
        return;
    REAL(seekdir)(d, off);
}

LC_API long LC_FN(telldir)(void *d) {
    if (closed_dir(d, "telldir()"))
        return -1;
    return REAL(telldir)(d);
}

// ---- child processes --------------------------------------------------------
// A child must be waited for, or it stays a zombie. (Children libc starts and
// waits for itself, in system() and popen(), never pass through here.)

namespace {

using fork_fn = int (*)();
using spawn_fn = int (*)(int *, const char *, const void *, const void *,
                         char *const *, char *const *);
using wait_fn = int (*)(int *);
using waitpid_fn = int (*)(int, int *, int);
using wait3_fn = int (*)(int *, int, void *);
using wait4_fn = int (*)(int, int *, int, void *);
using waitid_fn = int (*)(int, unsigned, void *, int);

fork_fn real_fork;
spawn_fn real_posix_spawn, real_posix_spawnp;
int (*real_system)(const char *);
wait_fn real_wait;
waitpid_fn real_waitpid;
wait3_fn real_wait3;
wait4_fn real_wait4;
waitid_fn real_waitid;

int track_child(int pid, const char *how) {
    if (pid > 0 && tracking()) {
        ErrnoSaver es;
        HookGuard hg;
        res::opened(Kind::Process, uint64_t(pid), how);
    }
    return pid;
}

int track_spawn(int rc, const int *pid, const char *how) {
    if (rc == 0 && pid)
        track_child(*pid, how);
    return rc;
}

int reaped(int pid) {
    if (pid > 0 && tracking()) {
        ErrnoSaver es;
        HookGuard hg;
        res::forget(Kind::Process, uint64_t(pid));
    }
    return pid;
}

using execve_fn = int (*)(const char *, char *const *, char *const *);
using execv_fn = int (*)(const char *, char *const *);
using fexecve_fn = int (*)(int, char *const *, char *const *);
using execveat_fn = int (*)(int, const char *, char *const *, char *const *, int);
execve_fn real_execve, real_execvpe;
execv_fn real_execv, real_execvp;
fexecve_fn real_fexecve;
execveat_fn real_execveat;

// This process is about to become another program, keeping every
// descriptor without close-on-exec (in a fork() child, typically). Not in a
// vfork() child: it runs on its parent's memory, where only exec is safe.
void replacing_self(const char *how) {
    if (uint32_t(getpid()) != g_self_pid || !tracking())
        return;
    ErrnoSaver es;
    HookGuard hg;
    res::check_inherited(how, true);
}

} // namespace

// execl(path, arg, ..., NULL): its arguments as an argv array named `argv`
// on this function's stack; `ap` is left after the NULL (execle's envp).
#define LC_EXECL_ARGV(arg)                                                     \
    va_list ap;                                                                \
    va_start(ap, arg);                                                         \
    size_t n = 0;                                                              \
    {                                                                          \
        va_list count;                                                         \
        va_copy(count, ap);                                                    \
        for (const char *a = arg; a; a = va_arg(count, const char *))          \
            ++n;                                                               \
        va_end(count);                                                         \
    }                                                                          \
    auto **argv = static_cast<const char **>(                                  \
        __builtin_alloca((n + 1) * sizeof(char *)));                           \
    argv[0] = arg;                                                             \
    for (size_t i = 1; i <= n; ++i)                                            \
    argv[i] = va_arg(ap, const char *)

LC_API int LC_FN(fork)() { return track_child(REAL(fork)(), "fork()"); }

LC_API int LC_FN(posix_spawn)(int *pid, const char *path, const void *actions,
                       const void *attr, char *const argv[],
                       char *const envp[]) {
    behavior::exec(path, argv, "posix_spawn()", actions);
    if (!actions) // file actions may close what the child must not keep
        starting_child("posix_spawn()");
    return track_spawn(REAL(posix_spawn)(pid, path, actions, attr, argv, envp),
                       pid, "posix_spawn()");
}

LC_API int LC_FN(posix_spawnp)(int *pid, const char *file, const void *actions,
                        const void *attr, char *const argv[],
                        char *const envp[]) {
    behavior::exec(file, argv, "posix_spawnp()", actions);
    if (!actions)
        starting_child("posix_spawnp()");
    return track_spawn(REAL(posix_spawnp)(pid, file, actions, attr, argv, envp),
                       pid, "posix_spawnp()");
}

LC_API int LC_FN(system)(const char *cmd) {
    if (cmd) { // system(NULL) only asks whether a shell exists
        behavior::command(cmd, "system()");
        starting_child("system()");
    }
    return REAL(system)(cmd);
}

LC_API int LC_FN(execve)(const char *path, char *const argv[], char *const envp[]) {
    behavior::exec(path, argv, "execve()");
    replacing_self("execve()");
    return REAL(execve)(path, argv, envp);
}

LC_API int LC_FN(execveat)(int dirfd, const char *path, char *const argv[],
                    char *const envp[], int flags) {
    if (path && path[0])
        behavior::exec(path, argv, "execveat()");
    else
        behavior::exec_fd(dirfd, argv, "execveat()");
    replacing_self("execveat()");
    return REAL(execveat)(dirfd, path, argv, envp, flags);
}

LC_API int LC_FN(execv)(const char *path, char *const argv[]) {
    behavior::exec(path, argv, "execv()");
    replacing_self("execv()");
    return REAL(execv)(path, argv);
}

LC_API int LC_FN(execvp)(const char *file, char *const argv[]) {
    behavior::exec(file, argv, "execvp()");
    replacing_self("execvp()");
    return REAL(execvp)(file, argv);
}

LC_API int LC_FN(execvpe)(const char *file, char *const argv[], char *const envp[]) {
    behavior::exec(file, argv, "execvpe()");
    replacing_self("execvpe()");
    return REAL(execvpe)(file, argv, envp);
}

LC_API int LC_FN(fexecve)(int fd, char *const argv[], char *const envp[]) {
    behavior::exec_fd(fd, argv, "fexecve()");
    replacing_self("fexecve()");
    return REAL(fexecve)(fd, argv, envp);
}

LC_API int LC_FN(execl)(const char *path, const char *arg, ...) {
    LC_EXECL_ARGV(arg);
    va_end(ap);
    behavior::exec(path, const_cast<char *const *>(argv), "execl()");
    replacing_self("execl()");
    return REAL(execv)(path, const_cast<char *const *>(argv));
}

LC_API int LC_FN(execlp)(const char *file, const char *arg, ...) {
    LC_EXECL_ARGV(arg);
    va_end(ap);
    behavior::exec(file, const_cast<char *const *>(argv), "execlp()");
    replacing_self("execlp()");
    return REAL(execvp)(file, const_cast<char *const *>(argv));
}

LC_API int LC_FN(execle)(const char *path, const char *arg, ...) {
    LC_EXECL_ARGV(arg);
    char *const *envp = va_arg(ap, char *const *);
    va_end(ap);
    behavior::exec(path, const_cast<char *const *>(argv), "execle()");
    replacing_self("execle()");
    return REAL(execve)(path, const_cast<char *const *>(argv), envp);
}

LC_API int LC_FN(wait)(int *status) { return reaped(REAL(wait)(status)); }

LC_API int LC_FN(waitpid)(int pid, int *status, int options) {
    return reaped(REAL(waitpid)(pid, status, options));
}

LC_API int LC_FN(wait3)(int *status, int options, void *usage) {
    return reaped(REAL(wait3)(status, options, usage));
}

LC_API int LC_FN(wait4)(int pid, int *status, int options, void *usage) {
    return reaped(REAL(wait4)(pid, status, options, usage));
}

LC_API int LC_FN(waitid)(int idtype, unsigned id, void *info, int options) {
    const int rc = REAL(waitid)(idtype, id, info, options);
    if (rc == 0 && info && tracking()) {
        ErrnoSaver es;
        HookGuard hg;
        res::waited_id(info, options);
    }
    return rc;
}
