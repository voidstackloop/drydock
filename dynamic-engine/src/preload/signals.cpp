// sys_signame and the fseeko/ftello declarations live behind the full Darwin
// API level; ask for it before the first system header is pulled in.
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif

#include "signals.h"
#include "init.h"
#include "protocol.h"
#include "report.h"
#include "resources.h"
#include "sockets.h"
#include "stacks.h"

#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <dlfcn.h>
#include <setjmp.h>
#include <signal.h>
#if defined(__APPLE__)
// fseeko/ftello are declared in stdio, and Darwin does not pull it in for us.
// Not on Linux: there the wrappers below are the libc names themselves and
// deliberately take FILE* as void*, which the real declarations would reject.
#include <cstdio>
#endif

#if defined(__APPLE__)
// Darwin calls the handler type sig_t; glibc calls it sighandler_t. The
// wrapper's name is lc_signal either way (see lc_api.h).
using sighandler_t = sig_t;
#endif

namespace lc::signals {

LC_TLS int tl_signal;

namespace {

constexpr int kSignals = 65;

struct Handler {
    void *fn;               // the program's handler; null: none of ours
    bool info;              // it takes (int, siginfo_t *, void *)
    uint32_t install_stack; // where it was installed
};
Handler g_handlers[kSignals];
LC_TLS uint32_t tl_install_stack;
LC_TLS bool tl_reported; // this run of the handler was reported already

// "SEGV" for a signal, or null: glibc has sigabbrev_np, Darwin has the same
// names in sys_signame (both without the "SIG" prefix).
const char *signal_abbreviation(int sig) {
#if defined(__APPLE__)
    if (sig > 0 && sig < NSIG)
        return sys_signame[sig];
    return nullptr;
#else
    return sigabbrev_np(sig);
#endif
}

void trampoline(int sig, siginfo_t *si, void *ctx) {
    const Handler h = g_handlers[sig];
    if (!h.fn)
        return;
    const int prev = tl_signal;
    const uint32_t prev_stack = tl_install_stack;
    const bool prev_reported = tl_reported;
    tl_signal = sig;
    tl_install_stack = h.install_stack;
    tl_reported = false;
    if (h.info)
        reinterpret_cast<void (*)(int, siginfo_t *, void *)>(h.fn)(sig, si,
                                                                   ctx);
    else
        reinterpret_cast<void (*)(int)>(h.fn)(sig);
    tl_signal = prev;
    tl_install_stack = prev_stack;
    tl_reported = prev_reported;
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

#define REAL(name) real(real_##name, #name)

using sigaction_fn = int (*)(int, const struct sigaction *, struct sigaction *);
using jmp_fn = void (*)(void *, int);
using vprintf_fn = int (*)(const char *, va_list);
using vfprintf_fn = int (*)(void *, const char *, va_list);
using vprintf_chk_fn = int (*)(int, const char *, va_list);
using vfprintf_chk_fn = int (*)(void *, int, const char *, va_list);
using puts_fn = int (*)(const char *);
using fputs_fn = int (*)(const char *, void *);
using fwrite_fn = size_t (*)(const void *, size_t, size_t, void *);
using fread_fn = size_t (*)(void *, size_t, size_t, void *);
using fgets_fn = char *(*)(char *, int, void *);
using fgetc_fn = int (*)(void *);
using fputc_fn = int (*)(int, void *);
using getline_fn = long (*)(char **, unsigned long *, void *);
using getdelim_fn = long (*)(char **, unsigned long *, int, void *);
using fflush_fn = int (*)(void *);
using fseek_fn = int (*)(void *, long, int);
using ftell_fn = long (*)(void *);
using rewind_fn = void (*)(void *);

sigaction_fn real_sigaction;
jmp_fn real_longjmp, real_siglongjmp, real__longjmp, real___longjmp_chk;
vprintf_fn real_vprintf;
vfprintf_fn real_vfprintf;
vfprintf_fn real_vfscanf;
vfprintf_fn real___isoc23_vfscanf;
vprintf_chk_fn real___vprintf_chk;
vfprintf_chk_fn real___vfprintf_chk;
puts_fn real_puts;
fputs_fn real_fputs;
fwrite_fn real_fwrite;
fread_fn real_fread;
fgets_fn real_fgets;
fgetc_fn real_fgetc;
fputc_fn real_fputc;
getline_fn real_getline;
getdelim_fn real_getdelim;
fflush_fn real_fflush;
fseek_fn real_fseek, real_fseeko;
ftell_fn real_ftell, real_ftello;
rewind_fn real_rewind;
using ungetc_fn = int (*)(int, void *);
ungetc_fn real_ungetc;
using fileno_fn = int (*)(void *);
fileno_fn real_fileno;
using mask_fn = int (*)(int, const sigset_t *, sigset_t *);
mask_fn real_sigprocmask, real_pthread_sigmask;

// A mask that can change whether this thread receives SIGPIPE. A pure query
// (null set), and check_slow's own read of the mask, must not bump the epoch.
void note_mask(int how, const sigset_t *set) {
    if (!set || tl_in_hook)
        return;
    if (how == SIG_SETMASK ||
        ((how == SIG_BLOCK || how == SIG_UNBLOCK) && sigismember(set, SIGPIPE) == 1))
        sockets::sigpipe_action_changed();
}

bool tracking() {
    if (tl_in_hook)
        return false;
    ensure_init();
    return g_cfg.active;
}

// True if `f` is a FILE* we saw closed. The real call is not made: glibc has
// freed the stream, and a second use crashes. errno is EBADF afterwards.
bool closed_stream(void *f, const char *how) {
    if (!f || !tracking())
        return false;
    bool closed;
    {
        ErrnoSaver es;
        HookGuard hg;
        closed = res::used_stream(uint64_t(uintptr_t(f)), how);
    }
    if (!closed)
        return false;
    errno = EBADF;
    return true;
}

} // namespace

void unsafe_call_slow(const char *what) {
    // The first unsafe call says it; the rest (free() after malloc(), the
    // malloc() inside printf()) would repeat it.
    if (tl_reported)
        return;
    tl_reported = true;
    HookGuard hg;
    ErrnoSaver es;
    const int sig = tl_signal;
    char m[384];
    Buf msg(m, sizeof m);
    msg.s(what).s(" is called by the handler of signal ").u(uint64_t(sig));
    if (const char *abbrev = signal_abbreviation(sig))
        msg.s(" (SIG").s(abbrev).c(')');
    msg.s(", but it is not async-signal-safe: when the signal arrives while "
          "the program is inside it (or holds the same lock), the program "
          "deadlocks or corrupts memory. Set a volatile sig_atomic_t flag or "
          "write() to a pipe instead");
    report::Finding f;
    f.type = lcproto::kSignalUnsafe;
    f.category = lcproto::kCatSignal;
    f.addr = uintptr_t(sig);
    f.tid = current_tid();
    f.msg = msg.cstr();
    f.access_stack = stacks::capture();
    f.alloc_stack = tl_install_stack;
    f.fatal = true;
    report::emit(f);
}

} // namespace lc::signals

using namespace lc;
using namespace lc::signals;

#include "lc_api.h"

// ---- installing handlers ----------------------------------------------------

LC_API int LC_FN(sigaction)(int sig, const struct sigaction *act,
                     struct sigaction *old) noexcept {
    if (sig <= 0 || sig >= kSignals || !tracking())
        return REAL(sigaction)(sig, act, old);
    const Handler prev = g_handlers[sig];
    struct sigaction mine;
    const struct sigaction *use = act;
    if (act) {
        const bool info = act->sa_flags & SA_SIGINFO;
        void *fn = info ? reinterpret_cast<void *>(act->sa_sigaction)
                        : reinterpret_cast<void *>(act->sa_handler);
        Handler next{};
        if (act->sa_handler != SIG_DFL && act->sa_handler != SIG_IGN) {
            uint32_t stack;
            {
                HookGuard hg;
                stack = stacks::capture();
            }
            next = Handler{fn, info, stack};
            mine = *act;
            mine.sa_sigaction = trampoline;
            mine.sa_flags |= SA_SIGINFO;
            use = &mine;
        }
        g_handlers[sig] = next; // before the kernel can deliver through it
    }
    const int rc = REAL(sigaction)(sig, use, old);
    if (rc != 0) {
        g_handlers[sig] = prev;
        return rc;
    }
    if (sig == SIGPIPE && act)
        sockets::sigpipe_action_changed();
    // Report the program's own handler, not the trampoline.
    if (old && (old->sa_flags & SA_SIGINFO) && old->sa_sigaction == trampoline &&
        prev.fn) {
        if (prev.info) {
            old->sa_sigaction =
                reinterpret_cast<void (*)(int, siginfo_t *, void *)>(prev.fn);
        } else {
            old->sa_handler = reinterpret_cast<void (*)(int)>(prev.fn);
            old->sa_flags &= ~SA_SIGINFO;
        }
    }
    return rc;
}

// signal() installs through sigaction: go through our wrapper, not the real
// one, or the trampoline in g_handlers is not installed on Darwin (where the
// call would otherwise bind to libSystem).
LC_API sighandler_t LC_FN(signal)(int sig, sighandler_t handler) noexcept {
    struct sigaction act, old;
    memset(&act, 0, sizeof act);
    act.sa_handler = handler;
    act.sa_flags = SA_RESTART;
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask, sig);
    return LC_FN(sigaction)(sig, &act, &old) == 0 ? old.sa_handler : SIG_ERR;
}

LC_API int LC_FN(sigprocmask)(int how, const sigset_t *set, sigset_t *old) noexcept {
    const int rc = REAL(sigprocmask)(how, set, old);
    if (rc == 0)
        note_mask(how, set);
    return rc;
}

LC_API int LC_FN(pthread_sigmask)(int how, const sigset_t *set, sigset_t *old) noexcept {
    const int rc = REAL(pthread_sigmask)(how, set, old);
    if (rc == 0)
        note_mask(how, set);
    return rc;
}

// ---- leaving a handler by jumping out of it ---------------------------------

#if defined(__APPLE__)
#define LC_JMP void *
#else
#define LC_JMP struct __jmp_buf_tag
#endif

LC_API __attribute__((noreturn)) void LC_FN(longjmp)(LC_JMP env[1], int val) noexcept {
    tl_signal = 0;
    REAL(longjmp)(env, val);
    __builtin_unreachable();
}

LC_API __attribute__((noreturn)) void LC_FN(siglongjmp)(LC_JMP env[1],
                                    int val) noexcept {
    tl_signal = 0;
    REAL(siglongjmp)(env, val);
    __builtin_unreachable();
}

LC_API __attribute__((noreturn)) void LC_FN(_longjmp)(LC_JMP env[1], int val) noexcept {
    tl_signal = 0;
    REAL(_longjmp)(env, val);
    __builtin_unreachable();
}

#if !defined(__APPLE__)
LC_API __attribute__((noreturn)) void LC_FN(__longjmp_chk)(LC_JMP env[1], int val) noexcept {
    tl_signal = 0;
    REAL(__longjmp_chk)(env, val);
    __builtin_unreachable();
}
#endif

// ---- stdio: takes the stream's lock, may allocate ---------------------------
// Streams are passed as void *: <stdio.h> declares these with FILE *.

LC_API int LC_FN(printf)(const char *fmt, ...) {
    unsafe_call("printf()");
    va_list ap;
    va_start(ap, fmt);
    const int rc = REAL(vprintf)(fmt, ap);
    va_end(ap);
    return rc;
}

LC_API int LC_FN(fprintf)(void *f, const char *fmt, ...) {
    unsafe_call("fprintf()");
    if (closed_stream(f, "fprintf()"))
        return -1;
    va_list ap;
    va_start(ap, fmt);
    const int rc = REAL(vfprintf)(f, fmt, ap);
    va_end(ap);
    return rc;
}

// gcc 14+ compiles fscanf into __isoc23_fscanf. Both names are wrapped.
static int scan_fmt(void *f, const char *fmt, va_list ap, vfprintf_fn &slot,
                    const char *real_name, const char *how) {
    if (closed_stream(f, how))
        return -1;
    return real(slot, real_name)(f, fmt, ap);
}

LC_API int LC_FN(vfscanf)(void *f, const char *fmt, va_list ap) {
    return scan_fmt(f, fmt, ap, real_vfscanf, "vfscanf", "vfscanf()");
}

LC_API int LC_FN(__isoc23_vfscanf)(void *f, const char *fmt, va_list ap) {
    return scan_fmt(f, fmt, ap, real___isoc23_vfscanf, "__isoc23_vfscanf", "vfscanf()");
}

LC_API int LC_FN(fscanf)(void *f, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    const int rc = scan_fmt(f, fmt, ap, real_vfscanf, "vfscanf", "fscanf()");
    va_end(ap);
    return rc;
}

LC_API int LC_FN(__isoc23_fscanf)(void *f, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    const int rc = scan_fmt(f, fmt, ap, real___isoc23_vfscanf, "__isoc23_vfscanf", "fscanf()");
    va_end(ap);
    return rc;
}

LC_API int LC_FN(vprintf)(const char *fmt, va_list ap) {
    unsafe_call("vprintf()");
    return REAL(vprintf)(fmt, ap);
}

LC_API int LC_FN(vfprintf)(void *f, const char *fmt, va_list ap) {
    unsafe_call("vfprintf()");
    if (closed_stream(f, "vfprintf()"))
        return -1;
    return REAL(vfprintf)(f, fmt, ap);
}

LC_API int LC_FN(__printf_chk)(int flag, const char *fmt, ...) {
    unsafe_call("printf()");
    va_list ap;
    va_start(ap, fmt);
    const int rc = REAL(__vprintf_chk)(flag, fmt, ap);
    va_end(ap);
    return rc;
}

LC_API int LC_FN(__fprintf_chk)(void *f, int flag, const char *fmt, ...) {
    unsafe_call("fprintf()");
    if (closed_stream(f, "fprintf()"))
        return -1;
    va_list ap;
    va_start(ap, fmt);
    const int rc = REAL(__vfprintf_chk)(f, flag, fmt, ap);
    va_end(ap);
    return rc;
}

LC_API int LC_FN(__vprintf_chk)(int flag, const char *fmt, va_list ap) {
    unsafe_call("vprintf()");
    return REAL(__vprintf_chk)(flag, fmt, ap);
}

LC_API int LC_FN(__vfprintf_chk)(void *f, int flag, const char *fmt, va_list ap) {
    unsafe_call("vfprintf()");
    if (closed_stream(f, "vfprintf()"))
        return -1;
    return REAL(__vfprintf_chk)(f, flag, fmt, ap);
}

LC_API int LC_FN(puts)(const char *s) {
    unsafe_call("puts()");
    return REAL(puts)(s);
}

LC_API int LC_FN(fputs)(const char *s, void *f) {
    unsafe_call("fputs()");
    if (closed_stream(f, "fputs()"))
        return -1;
    return REAL(fputs)(s, f);
}

LC_API size_t LC_FN(fwrite)(const void *p, size_t size, size_t n, void *f) {
    unsafe_call("fwrite()");
    if (closed_stream(f, "fwrite()"))
        return 0;
    return REAL(fwrite)(p, size, n, f);
}

LC_API size_t LC_FN(fread)(void *p, size_t size, size_t n, void *f) {
    if (closed_stream(f, "fread()"))
        return 0;
    return REAL(fread)(p, size, n, f);
}

LC_API char *LC_FN(fgets)(char *s, int size, void *f) {
    if (closed_stream(f, "fgets()"))
        return nullptr;
    return REAL(fgets)(s, size, f);
}

LC_API int LC_FN(fgetc)(void *f) {
    if (closed_stream(f, "fgetc()"))
        return -1;
    return REAL(fgetc)(f);
}

LC_API int LC_FN(fputc)(int c, void *f) {
    unsafe_call("fputc()");
    if (closed_stream(f, "fputc()"))
        return -1;
    return REAL(fputc)(c, f);
}

LC_API long LC_FN(getline)(char **line, unsigned long *n, void *f) {
    if (closed_stream(f, "getline()"))
        return -1;
    return REAL(getline)(line, n, f);
}

LC_API long LC_FN(getdelim)(char **line, unsigned long *n, int delim, void *f) {
    if (closed_stream(f, "getdelim()"))
        return -1;
    return REAL(getdelim)(line, n, delim, f);
}

LC_API int LC_FN(fflush)(void *f) {
    unsafe_call("fflush()");
    if (closed_stream(f, "fflush()"))
        return -1;
    return REAL(fflush)(f);
}

LC_API int LC_FN(fseek)(void *f, long off, int whence) {
    if (closed_stream(f, "fseek()"))
        return -1;
    return REAL(fseek)(f, off, whence);
}

LC_API int LC_FN(fseeko)(void *f, long off, int whence) {
    if (closed_stream(f, "fseeko()"))
        return -1;
    return REAL(fseeko)(f, off, whence);
}

#if !defined(__APPLE__)
// Same address as fseeko in glibc, but a different symbol name.
LC_API int LC_FN(fseeko64)(void *f, long off, int whence) { return fseeko(f, off, whence); }
#endif

LC_API long LC_FN(ftell)(void *f) {
    if (closed_stream(f, "ftell()"))
        return -1;
    return REAL(ftell)(f);
}

LC_API long LC_FN(ftello)(void *f) {
    if (closed_stream(f, "ftello()"))
        return -1;
    return REAL(ftello)(f);
}

#if !defined(__APPLE__)
LC_API long LC_FN(ftello64)(void *f) { return ftello(f); }
#endif

LC_API void LC_FN(rewind)(void *f) {
    if (closed_stream(f, "rewind()"))
        return;
    REAL(rewind)(f);
}

LC_API int LC_FN(ungetc)(int c, void *f) {
    if (closed_stream(f, "ungetc()"))
        return -1;
    return REAL(ungetc)(c, f);
}

LC_API int LC_FN(fileno)(void *f) {
    if (closed_stream(f, "fileno()"))
        return -1;
    return REAL(fileno)(f);
}
