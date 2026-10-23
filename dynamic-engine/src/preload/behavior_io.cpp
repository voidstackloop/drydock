// Exported wrappers for the calls that remove, replace and re-permission files,
// attach to other processes and ask for another user id: what behavior.cpp looks
// at besides open() and exec(). Like interpose.cpp, this file defines libc
// functions itself, so it includes none of the headers that declare them.
#include "behavior.h"
#include "init.h"
#include "rt.h"

#include <cstdarg>
#include <cstring>
#include <dlfcn.h>

#include "lc_api.h"

using namespace lc;

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

#define REAL(name) real(real_##name, #name)

int (*real_unlink)(const char *);
int (*real_unlinkat)(int, const char *, int);
int (*real_rmdir)(const char *);
int (*real_remove)(const char *);
int (*real_rename)(const char *, const char *);
int (*real_renameat)(int, const char *, int, const char *);
int (*real_renameat2)(int, const char *, int, const char *, unsigned);
int (*real_link)(const char *, const char *);
int (*real_linkat)(int, const char *, int, const char *, int);
int (*real_symlink)(const char *, const char *);
int (*real_symlinkat)(const char *, int, const char *);
int (*real_truncate)(const char *, long);
int (*real_truncate64)(const char *, long);
int (*real_ftruncate)(int, long);
int (*real_ftruncate64)(int, long);
int (*real_chmod)(const char *, unsigned);
int (*real_fchmod)(int, unsigned);
int (*real_fchmodat)(int, const char *, unsigned, int);
int (*real_chown)(const char *, unsigned, unsigned);
int (*real_lchown)(const char *, unsigned, unsigned);
int (*real_fchown)(int, unsigned, unsigned);
int (*real_fchownat)(int, const char *, unsigned, unsigned, int);
int (*real_mkdir)(const char *, unsigned);
int (*real_mkdirat)(int, const char *, unsigned);
int (*real_mkfifo)(const char *, unsigned);
int (*real_mkfifoat)(int, const char *, unsigned);
int (*real_mknod)(const char *, unsigned, unsigned long);
int (*real_mknodat)(int, const char *, unsigned, unsigned long);
void *(*real_sem_open)(const char *, int, unsigned, unsigned);
int (*real_msgget)(int, int);
int (*real_semget)(int, int, int);
int (*real_shmget)(int, unsigned long, int);
unsigned (*real_umask)(unsigned);
int (*real_shm_open)(const char *, int, unsigned);
int (*real_mq_open)(const char *, int, unsigned, void *);
long (*real_ptrace)(int, ...);
long (*real_process_vm_writev)(int, const void *, unsigned long, const void *,
                               unsigned long, unsigned long);
long (*real_process_vm_readv)(int, const void *, unsigned long, const void *,
                              unsigned long, unsigned long);
int (*real_prctl)(int, ...);
int (*real_personality)(unsigned long);
void *(*real_dlopen)(const char *, int);
#ifndef __APPLE__
void *(*real_dlmopen)(long, const char *, int);
#endif
int (*real_getaddrinfo)(const char *, const char *, const void *, void **);
int (*real_utime)(const char *, const void *);
int (*real_utimes)(const char *, const void *);
int (*real_lutimes)(const char *, const void *);
int (*real_utimensat)(int, const char *, const void *, int);
int (*real_futimens)(int, const void *);
int (*real_setenv)(const char *, const char *, int);
int (*real_putenv)(char *);
int (*real_unsetenv)(const char *);
int (*real_setuid)(unsigned);
int (*real_seteuid)(unsigned);
int (*real_setreuid)(unsigned, unsigned);
int (*real_setresuid)(unsigned, unsigned, unsigned);
int (*real_setfsuid)(unsigned);
int (*real_setgid)(unsigned);
int (*real_setegid)(unsigned);
int (*real_setregid)(unsigned, unsigned);
int (*real_setresgid)(unsigned, unsigned, unsigned);
int (*real_setfsgid)(unsigned);
int (*real_setgroups)(unsigned long, const unsigned *);
int (*real_initgroups)(const char *, unsigned);
#if defined(__APPLE__)
int (*real_pthread_setname_np)(const char *);
#else
int (*real_pthread_setname_np)(unsigned long, const char *);
#endif

} // namespace

LC_API int LC_FN(unlink)(const char *path) {
    behavior::deleting(path, "unlink()");
    return REAL(unlink)(path);
}

LC_API int LC_FN(unlinkat)(int dir, const char *path, int flags) {
    behavior::deleting(path, "unlinkat()");
    return REAL(unlinkat)(dir, path, flags);
}

// remove() does not call the public unlink(), so the wrapper above misses it.
LC_API int LC_FN(rmdir)(const char *path) {
    behavior::deleting(path, "rmdir()");
    return REAL(rmdir)(path);
}

LC_API int LC_FN(remove)(const char *path) {
    behavior::deleting(path, "remove()");
    return REAL(remove)(path);
}

// (Moving a file away is not looked at: log rotation and self-updaters do it.)
LC_API int LC_FN(rename)(const char *from, const char *to) {
    behavior::replacing(to, "rename()");
    behavior::renamed(from, to);
    return REAL(rename)(from, to);
}

LC_API int LC_FN(renameat)(int fromdir, const char *from, int todir, const char *to) {
    behavior::replacing(to, "renameat()");
    behavior::renamed(from, to);
    return REAL(renameat)(fromdir, from, todir, to);
}

LC_API int LC_FN(renameat2)(int fromdir, const char *from, int todir, const char *to,
                     unsigned flags) {
    behavior::replacing(to, "renameat2()");
    behavior::renamed(from, to);
    return REAL(renameat2)(fromdir, from, todir, to, flags);
}

LC_API int LC_FN(link)(const char *from, const char *to) {
    behavior::replacing(to, "link()");
    return REAL(link)(from, to);
}

LC_API int LC_FN(linkat)(int fromdir, const char *from, int todir, const char *to, int flags) {
    behavior::replacing(to, "linkat()");
    return REAL(linkat)(fromdir, from, todir, to, flags);
}

LC_API int LC_FN(symlink)(const char *target, const char *path) {
    behavior::replacing(path, "symlink()");
    return REAL(symlink)(target, path);
}

LC_API int LC_FN(symlinkat)(const char *target, int dir, const char *path) {
    behavior::replacing(path, "symlinkat()");
    return REAL(symlinkat)(target, dir, path);
}

LC_API int LC_FN(truncate)(const char *path, long len) {
    behavior::truncating(path, "truncate()");
    return REAL(truncate)(path, len);
}

LC_API int LC_FN(truncate64)(const char *path, long len) {
    behavior::truncating(path, "truncate64()");
    return REAL(truncate64)(path, len);
}

// ftruncate() does not call the public truncate().
LC_API int LC_FN(ftruncate)(int fd, long len) {
    behavior::truncating_fd(fd, "ftruncate()");
    return REAL(ftruncate)(fd, len);
}

LC_API int LC_FN(ftruncate64)(int fd, long len) {
    behavior::truncating_fd(fd, "ftruncate64()");
    return REAL(ftruncate64)(fd, len);
}

LC_API int LC_FN(chmod)(const char *path, unsigned mode) {
    behavior::chmoding(path, mode, "chmod()");
    return REAL(chmod)(path, mode);
}

LC_API int LC_FN(fchmod)(int fd, unsigned mode) {
    behavior::chmoding(nullptr, mode, "fchmod()");
    return REAL(fchmod)(fd, mode);
}

LC_API int LC_FN(fchmodat)(int dir, const char *path, unsigned mode, int flags) {
    behavior::chmoding(path, mode, "fchmodat()");
    return REAL(fchmodat)(dir, path, mode, flags);
}

// chown() does not call chmod().
LC_API int LC_FN(chown)(const char *path, unsigned owner, unsigned group) {
    behavior::chowning(path, "chown()");
    return REAL(chown)(path, owner, group);
}

// Linux mount() takes the target second. Darwin's mount() takes the directory second.
#if defined(__APPLE__)
int (*real_mount)(const char *, const char *, int, void *);
LC_API int LC_FN(mount)(const char *type, const char *dir, int flags, void *data) {
    behavior::mounting(dir, "mount()");
    return REAL(mount)(type, dir, flags, data);
}
#else
int (*real_mount)(const char *, const char *, const char *, unsigned long, const void *);
LC_API int LC_FN(mount)(const char *source, const char *target, const char *fstype,
                        unsigned long flags, const void *data) {
    behavior::mounting(target, "mount()");
    return REAL(mount)(source, target, fstype, flags, data);
}
int (*real_umount2)(const char *, int);
LC_API int LC_FN(umount2)(const char *target, int flags) {
    behavior::mounting(target, "umount2()");
    return REAL(umount2)(target, flags);
}
#endif
int (*real_umount)(const char *);
LC_API int LC_FN(umount)(const char *target) {
    behavior::mounting(target, "umount()");
    return REAL(umount)(target);
}

LC_API int LC_FN(lchown)(const char *path, unsigned owner, unsigned group) {
    behavior::chowning(path, "lchown()");
    return REAL(lchown)(path, owner, group);
}

LC_API int LC_FN(fchown)(int fd, unsigned owner, unsigned group) {
    behavior::chowning_fd(fd, "fchown()");
    return REAL(fchown)(fd, owner, group);
}

LC_API int LC_FN(fchownat)(int dir, const char *path, unsigned owner, unsigned group, int flags) {
    behavior::chowning(path, "fchownat()");
    return REAL(fchownat)(dir, path, owner, group, flags);
}

// mkdir() does not call chmod(). umask(0) is not a mode on one call.
LC_API int LC_FN(mkdir)(const char *path, unsigned mode) {
    if (mode & 0002)
        behavior::loose_mode("mkdir()", " creates the directory writable by every user: "
                                         "another user can change what the program reads later");
    return REAL(mkdir)(path, mode);
}

LC_API int LC_FN(mkdirat)(int dir, const char *path, unsigned mode) {
    if (mode & 0002)
        behavior::loose_mode("mkdirat()", " creates the directory writable by every user: "
                                           "another user can change what the program reads later");
    return REAL(mkdirat)(dir, path, mode);
}

// mkfifo() does not call mkdir() or chmod().
LC_API int LC_FN(mkfifo)(const char *path, unsigned mode) {
    if (mode & 0002)
        behavior::loose_mode("mkfifo()", " creates the pipe writable by every user: "
                                          "another user can change what the program reads later");
    return REAL(mkfifo)(path, mode);
}

LC_API int LC_FN(mkfifoat)(int dir, const char *path, unsigned mode) {
    if (mode & 0002)
        behavior::loose_mode("mkfifoat()", " creates the pipe writable by every user: "
                                            "another user can change what the program reads later");
    return REAL(mkfifoat)(dir, path, mode);
}

// mknod() does not call chmod(). The mode's other-write bit is the same check.
LC_API int LC_FN(mknod)(const char *path, unsigned mode, unsigned long dev) {
    if (mode & 0002)
        behavior::loose_mode("mknod()", " creates the node writable by every user: "
                                         "another user can change what the program reads later");
    return REAL(mknod)(path, mode, dev);
}

LC_API int LC_FN(mknodat)(int dir, const char *path, unsigned mode, unsigned long dev) {
    if (mode & 0002)
        behavior::loose_mode("mknodat()", " creates the node writable by every user: "
                                           "another user can change what the program reads later");
    return REAL(mknodat)(dir, path, mode, dev);
}

LC_API unsigned LC_FN(umask)(unsigned mode) {
    if (mode == 0)
        behavior::loose_mode("umask(0)", " lets every user write files this program creates");
    return REAL(umask)(mode);
}

// shm_open() does not call open(). O_CREAT is 0100 on Linux and 0x0200 on Darwin.
LC_API int LC_FN(shm_open)(const char *name, int flags, unsigned mode) {
#if defined(__APPLE__)
    constexpr int kCreate = 0x0200;
#else
    constexpr int kCreate = 0100;
#endif
    if ((flags & kCreate) && (mode & 0002))
        behavior::loose_mode("shm_open()", " creates the shared memory writable by every user: "
                                            "another user can change what the program reads later");
    return REAL(shm_open)(name, flags, mode);
}

// sem_open() does not call open(). The mode is only present with O_CREAT.
LC_API void *LC_FN(sem_open)(const char *name, int flags, ...) {
#if defined(__APPLE__)
    constexpr int kCreate = 0x0200;
#else
    constexpr int kCreate = 0100;
#endif
    va_list ap;
    va_start(ap, flags);
    unsigned mode = 0, value = 0;
    if (flags & kCreate) {
        mode = va_arg(ap, unsigned);
        value = va_arg(ap, unsigned);
    }
    va_end(ap);
    if ((flags & kCreate) && (mode & 0002))
        behavior::loose_mode("sem_open()", " creates the semaphore writable by every user: "
                                            "another user can change what the program reads later");
    return REAL(sem_open)(name, flags, mode, value);
}

// SysV IPC does not call chmod(). The low bits are the mode, beside IPC_CREAT.
LC_API int LC_FN(msgget)(int key, int flag) {
    if (flag & 0002)
        behavior::loose_mode("msgget()", " creates the queue writable by every user: "
                                         "another user can change what the program reads later");
    return REAL(msgget)(key, flag);
}

LC_API int LC_FN(semget)(int key, int nsems, int flag) {
    if (flag & 0002)
        behavior::loose_mode("semget()", " creates the set writable by every user: "
                                         "another user can change what the program reads later");
    return REAL(semget)(key, nsems, flag);
}

LC_API int LC_FN(shmget)(int key, unsigned long size, int flag) {
    if (flag & 0002)
        behavior::loose_mode("shmget()", " creates the segment writable by every user: "
                                         "another user can change what the program reads later");
    return REAL(shmget)(key, size, flag);
}

// mq_open() does not call open() either. The mode is only present with O_CREAT.
LC_API int LC_FN(mq_open)(const char *name, int flags, ...) {
#if defined(__APPLE__)
    constexpr int kCreate = 0x0200;
#else
    constexpr int kCreate = 0100;
#endif
    va_list ap;
    va_start(ap, flags);
    unsigned mode = 0;
    void *attr = nullptr;
    if (flags & kCreate) {
        mode = va_arg(ap, unsigned);
        attr = va_arg(ap, void *);
    }
    va_end(ap);
    if ((flags & kCreate) && (mode & 0002))
        behavior::loose_mode("mq_open()", " creates the queue writable by every user: "
                                          "another user can change what the program reads later");
    return REAL(mq_open)(name, flags, mode, attr);
}

// ptrace(request, pid, addr, data): the last three are read whether or not the
// request uses them, as the C library's own wrapper does.
LC_API long LC_FN(ptrace)(int request, ...) {
    va_list ap;
    va_start(ap, request);
    const int pid = va_arg(ap, int);
    void *addr = va_arg(ap, void *);
    void *data = va_arg(ap, void *);
    va_end(ap);
#if defined(__APPLE__)
    // ptrace_call's numbers are Linux's. Shared as-is: 0 (PT_TRACE_ME) and
    // 4/5/6 (PT_WRITE_I/D/U). PT_ATTACH is 10 → 16. PT_DENY_ATTACH is 31 → 0.
    // 13 is PT_THUPDATE, not SETREGS.
    const int seen = request == 10 ? 16 : request == 31 ? 0 : request == 13 ? -1 : request;
    behavior::ptrace_call(seen, pid);
#else
    behavior::ptrace_call(request, pid);
#endif
    return REAL(ptrace)(request, pid, addr, data);
}

LC_API long LC_FN(process_vm_writev)(int pid, const void *local, unsigned long lcnt,
                              const void *remote, unsigned long rcnt,
                              unsigned long flags) {
    behavior::vm_write(pid);
    return REAL(process_vm_writev)(pid, local, lcnt, remote, rcnt, flags);
}

LC_API long LC_FN(process_vm_readv)(int pid, const void *local, unsigned long lcnt,
                             const void *remote, unsigned long rcnt,
                             unsigned long flags) {
    behavior::vm_read(pid);
    return REAL(process_vm_readv)(pid, local, lcnt, remote, rcnt, flags);
}

LC_API int LC_FN(utime)(const char *path, const void *times) {
    behavior::dating(path, "utime()");
    return REAL(utime)(path, times);
}

LC_API int LC_FN(utimes)(const char *path, const void *times) {
    behavior::dating(path, "utimes()");
    return REAL(utimes)(path, times);
}

LC_API int LC_FN(lutimes)(const char *path, const void *times) {
    behavior::dating(path, "lutimes()");
    return REAL(lutimes)(path, times);
}

LC_API int LC_FN(utimensat)(int dir, const char *path, const void *times, int flags) {
    behavior::dating(path, "utimensat()");
    return REAL(utimensat)(dir, path, times, flags);
}

LC_API int LC_FN(futimens)(int fd, const void *times) {
    behavior::dating_fd(fd, "futimens()");
    return REAL(futimens)(fd, times);
}

LC_API int LC_FN(setenv)(const char *name, const char *value, int overwrite) {
    if (name && value && !strcmp(name, "PATH"))
        behavior::search_path("setenv()", value);
    if (name && value &&
        (!strcmp(name, "LD_LIBRARY_PATH") || !strcmp(name, "DYLD_LIBRARY_PATH")))
        behavior::library_path("setenv()", value);
    if (name && value &&
        ((!strcmp(name, "HISTFILE") && (!value[0] || !strcmp(value, "/dev/null"))) ||
         (!strcmp(name, "HISTSIZE") && !strcmp(value, "0"))))
        behavior::history_off("setenv()");
    return REAL(setenv)(name, value, overwrite);
}

LC_API int LC_FN(unsetenv)(const char *name) {
    if (name && !strcmp(name, "PATH"))
        behavior::search_path("unsetenv()", "");
    if (name && !strcmp(name, "HISTFILE"))
        behavior::history_off("unsetenv()");
    return REAL(unsetenv)(name);
}

LC_API int LC_FN(putenv)(char *string) {
    if (string && !strncmp(string, "PATH=", 5))
        behavior::search_path("putenv()", string + 5);
    if (string && !strncmp(string, "HISTFILE=", 9) &&
        (!string[9] || !strcmp(string + 9, "/dev/null")))
        behavior::history_off("putenv()");
    if (string && !strncmp(string, "HISTSIZE=", 9) && !strcmp(string + 9, "0"))
        behavior::history_off("putenv()");
    return REAL(putenv)(string);
}

LC_API int LC_FN(setuid)(unsigned uid) {
    if (uid == 0)
        behavior::setuid_root("setuid(0)");
    return REAL(setuid)(uid);
}

LC_API int LC_FN(seteuid)(unsigned uid) {
    if (uid == 0)
        behavior::setuid_root("seteuid(0)");
    return REAL(seteuid)(uid);
}

LC_API int LC_FN(setreuid)(unsigned ruid, unsigned euid) {
    if (ruid == 0 || euid == 0)
        behavior::setuid_root("setreuid(0)");
    return REAL(setreuid)(ruid, euid);
}

LC_API int LC_FN(setresuid)(unsigned ruid, unsigned euid, unsigned suid) {
    if (ruid == 0 || euid == 0 || suid == 0)
        behavior::setuid_root("setresuid(0)");
    return REAL(setresuid)(ruid, euid, suid);
}

LC_API int LC_FN(setfsuid)(unsigned uid) {
    if (uid == 0)
        behavior::setuid_root("setfsuid(0)");
    return REAL(setfsuid)(uid);
}

// These do not call setuid(). Group 0 is the same kind of attempt.
LC_API int LC_FN(setgid)(unsigned gid) {
    if (gid == 0)
        behavior::setgid_root("setgid(0)");
    return REAL(setgid)(gid);
}

LC_API int LC_FN(setegid)(unsigned gid) {
    if (gid == 0)
        behavior::setgid_root("setegid(0)");
    return REAL(setegid)(gid);
}

LC_API int LC_FN(setregid)(unsigned rgid, unsigned egid) {
    if (rgid == 0 || egid == 0)
        behavior::setgid_root("setregid(0)");
    return REAL(setregid)(rgid, egid);
}

LC_API int LC_FN(setresgid)(unsigned rgid, unsigned egid, unsigned sgid) {
    if (rgid == 0 || egid == 0 || sgid == 0)
        behavior::setgid_root("setresgid(0)");
    return REAL(setresgid)(rgid, egid, sgid);
}

LC_API int LC_FN(setfsgid)(unsigned gid) {
    if (gid == 0)
        behavior::setgid_root("setfsgid(0)");
    return REAL(setfsgid)(gid);
}

// setgroups() does not call setgid(). A zero in the list is group root.
LC_API int LC_FN(setgroups)(unsigned long n, const unsigned *groups) {
    if (groups)
        for (unsigned long i = 0; i < n && i < 64; ++i)
            if (groups[i] == 0) {
                behavior::setgid_root("setgroups(0)");
                break;
            }
    return REAL(setgroups)(n, groups);
}

LC_API int LC_FN(initgroups)(const char *user, unsigned group) {
    if (group == 0)
        behavior::setgid_root("initgroups(0)");
    return REAL(initgroups)(user, group);
}

// glibc's pthread_setname_np uses the prctl syscall, not the public prctl().
#if defined(__APPLE__)
LC_API int LC_FN(pthread_setname_np)(const char *name) {
    behavior::process_named(name);
    return REAL(pthread_setname_np)(name);
}
#else
LC_API int LC_FN(pthread_setname_np)(unsigned long thread, const char *name) {
    behavior::process_named(name);
    return REAL(pthread_setname_np)(thread, name);
}
#endif

// prctl(option, arg2, arg3, arg4, arg5): five words whether or not the option
// uses them, as the C library's own wrapper reads them.
LC_API int LC_FN(prctl)(int option, ...) {
    va_list ap;
    va_start(ap, option);
    const unsigned long a2 = va_arg(ap, unsigned long);
    const unsigned long a3 = va_arg(ap, unsigned long);
    const unsigned long a4 = va_arg(ap, unsigned long);
    const unsigned long a5 = va_arg(ap, unsigned long);
    va_end(ap);
    constexpr int kSetName = 15; // PR_SET_NAME
    constexpr int kSetMm = 35, kExeFile = 13;
    constexpr int kAmbient = 47, kAmbientRaise = 2;
    if (option == kSetName)
        behavior::process_named(reinterpret_cast<const char *>(a2));
    if (option == kSetMm && a2 == kExeFile)
        behavior::exe_claimed("prctl(PR_SET_MM_EXE_FILE)");
    if (option == kAmbient && a2 == kAmbientRaise)
        behavior::caps("prctl(PR_CAP_AMBIENT_RAISE)");
    return REAL(prctl)(option, a2, a3, a4, a5);
}

// iopl() and ioperm() do not call setuid(). Darwin has neither.
#ifndef __APPLE__
int (*real_pidfd_getfd)(int, int, unsigned);
LC_API int LC_FN(pidfd_getfd)(int pidfd, int targetfd, unsigned flags) {
    behavior::other_fd("pidfd_getfd()");
    return REAL(pidfd_getfd)(pidfd, targetfd, flags);
}
int (*real_capset)(void *, const void *);
LC_API int LC_FN(capset)(void *hdr, const void *data) {
    behavior::caps("capset()");
    return REAL(capset)(hdr, data);
}
int (*real_iopl)(int);
LC_API int LC_FN(iopl)(int level) {
    if (level != 0)
        behavior::raw_port("iopl()");
    return REAL(iopl)(level);
}
int (*real_ioperm)(unsigned long, unsigned long, int);
LC_API int LC_FN(ioperm)(unsigned long from, unsigned long num, int on) {
    if (on)
        behavior::raw_port("ioperm()");
    return REAL(ioperm)(from, num, on);
}
#endif

// ADDR_NO_RANDOMIZE. Not a public prctl request. Darwin has no personality().
LC_API int LC_FN(personality)(unsigned long persona) {
    if (persona & 0x0040000ul)
        behavior::aslr_off("personality()");
    return REAL(personality)(persona);
}

LC_API void *LC_FN(dlopen)(const char *path, int flags) {
    behavior::loading(path, "dlopen()");
    return REAL(dlopen)(path, flags);
}

// dlmopen() does not call dlopen(). Darwin has no dlmopen().
#ifndef __APPLE__
LC_API void *LC_FN(dlmopen)(long ns, const char *path, int flags) {
    behavior::loading(path, "dlmopen()");
    return REAL(dlmopen)(ns, path, flags);
}
#endif

LC_API int LC_FN(getaddrinfo)(const char *node, const char *service, const void *hints, void **res) {
    behavior::host(node, "getaddrinfo()");
    return REAL(getaddrinfo)(node, service, hints, res);
}

// getaddrinfo_a() does not call getaddrinfo(). The name is the first field of
// each gaicb. Darwin has no getaddrinfo_a().
#ifndef __APPLE__
struct LcGai {
    const char *name;
    const char *service;
    const void *request;
    void *result;
};
int (*real_getaddrinfo_a)(int, void *, int, void *);

LC_API int LC_FN(getaddrinfo_a)(int mode, void *list, int n, void *sevp) {
    auto cbs = static_cast<LcGai **>(list);
    if (cbs)
        for (int i = 0; i < n && i < 32; ++i)
            if (cbs[i])
                behavior::host(cbs[i]->name, "getaddrinfo_a()");
    return REAL(getaddrinfo_a)(mode, list, n, sevp);
}
#endif
