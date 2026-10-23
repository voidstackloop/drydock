#include "resources.h"
#include "protocol.h"
#include "report.h"
#include "sockets.h"
#include "stacks.h"

#include <cstring>
#include <initializer_list>
#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace lc::res {
namespace {

enum class St : uint8_t { None = 0, Open, Closed, Exited };

struct Rec {
    uint64_t key; // 0 = empty slot
    const char *how;
    uint32_t open_stack, close_stack;
    uint32_t tid, pid;
    Kind kind;
    St state;
    const char *failed; // "connect()": a call on this socket failed, and
    int32_t failed_errno; // with this errno (a leak report says so)
    // This open followed a close of the same descriptor number. The prior
    // stacks are that first lifetime; close_stack then is the second close.
    uint32_t prior_open, prior_close;
    uint8_t reused;
};

SpinLock g_lock;
uint8_t g_exhausted; // the descriptor limit was reported
Rec *g_slots;
size_t g_cap, g_count;
size_t g_purge_at = size_t(1) << 16;
// Set while this thread holds g_lock: a signal handler that closes a
// descriptor must not wait for the lock its own thread holds.
#ifdef _WIN32
#define tl_busy (ts().busy)
#else
LC_TLS uint8_t tl_busy;
#endif

class Locked {
  public:
    Locked() : ok_(!tl_busy) {
        if (ok_) {
            tl_busy = 1;
            g_lock.lock();
        }
    }
    ~Locked() {
        if (ok_) {
            g_lock.unlock();
            tl_busy = 0;
        }
    }
    Locked(const Locked &) = delete;
    Locked &operator=(const Locked &) = delete;
    explicit operator bool() const { return ok_; }

  private:
    bool ok_;
};

// One key space per handle type. Streams from fopen and popen share one, so
// closing either with the other's function is recognised.
uint64_t key_of(Kind k, uint64_t h) {
    const uint64_t cls = uint64_t(k == Kind::Pipe ? Kind::File : k);
    return (cls << 56) | (h & ((uint64_t(1) << 56) - 1));
}

uint64_t handle_of(const Rec &r) { return r.key & ((uint64_t(1) << 56) - 1); }

uint64_t mix(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

Rec *find(uint64_t key) {
    if (!g_cap)
        return nullptr;
    for (size_t i = mix(key) & (g_cap - 1);; i = (i + 1) & (g_cap - 1)) {
        if (g_slots[i].key == key)
            return &g_slots[i];
        if (!g_slots[i].key)
            return nullptr;
    }
}

Rec *place(Rec *slots, size_t cap, const Rec &r) {
    size_t i = mix(r.key) & (cap - 1);
    while (slots[i].key)
        i = (i + 1) & (cap - 1);
    slots[i] = r;
    return &slots[i];
}

// Copies the table into `cap` slots; drop_closed forgets released handles.
// ponytail: closed records exist only to name the first close of a double
// close; past g_purge_at records they are dropped wholesale.
void rebuild(size_t cap, bool drop_closed) {
    auto *ns = static_cast<Rec *>(map_pages(cap * sizeof(Rec)));
    if (!ns)
        die("out of memory for resource records");
    size_t n = 0;
    for (size_t i = 0; i < g_cap; ++i) {
        const Rec &r = g_slots[i];
        if (!r.key || (drop_closed && r.state == St::Closed))
            continue;
        place(ns, cap, r);
        ++n;
    }
    unmap_pages(g_slots, g_cap * sizeof(Rec));
    g_slots = ns;
    g_cap = cap;
    g_count = n;
}

Rec *put(uint64_t key) {
    if (Rec *r = find(key))
        return r;
    if (g_count >= g_purge_at) {
        rebuild(g_cap, true);
        if (g_count * 2 >= g_purge_at)
            g_purge_at *= 2;
    }
    if ((g_count + 1) * 2 > g_cap)
        rebuild(g_cap ? g_cap * 2 : 256, false);
    Rec r{};
    r.key = key;
    ++g_count;
    return place(g_slots, g_cap, r);
}

void erase(uint64_t key) {
    Rec *e = find(key);
    if (!e)
        return;
    const size_t mask = g_cap - 1;
    size_t i = size_t(e - g_slots);
    // Backward-shift deletion, as in the block table.
    for (size_t j = (i + 1) & mask; g_slots[j].key; j = (j + 1) & mask) {
        const size_t k = mix(g_slots[j].key) & mask;
        const bool stays = (i <= j) ? (i < k && k <= j) : (i < k || k <= j);
        if (!stays) {
            g_slots[i] = g_slots[j];
            i = j;
        }
    }
    g_slots[i].key = 0;
    --g_count;
}

#ifdef _WIN32
// On Windows a "descriptor" is a handle: of a file, a pipe, a socket, an event,
// a thread, a process.
constexpr const char *kFdWord = "handle";
#else
constexpr const char *kFdWord = "file descriptor";
#endif

const char *what(Kind k) {
    switch (k) {
    case Kind::Fd:
        return kFdWord;
    case Kind::File:
    case Kind::Pipe:
        return "FILE stream";
#ifdef _WIN32
    case Kind::Dir:
        return "directory search";
    case Kind::Thread:
        return "thread handle";
    case Kind::Process:
        return "process handle";
#else
    case Kind::Dir:
        return "directory stream";
    case Kind::Thread:
        return "thread";
    case Kind::Process:
        return "child process";
#endif
    }
    return "resource";
}

const char *category(Kind k) {
    switch (k) {
    case Kind::Fd:
        return lcproto::kCatFd;
    case Kind::File:
    case Kind::Pipe:
        return lcproto::kCatStream;
    case Kind::Dir:
        return lcproto::kCatDir;
    case Kind::Thread:
        return lcproto::kCatThread;
    case Kind::Process:
        return lcproto::kCatProcess;
    }
    return lcproto::kCatFd;
}

const char *closer(Kind k) {
#ifdef _WIN32
    switch (k) {
    case Kind::File:
        return "fclose()";
    case Kind::Pipe:
        return "_pclose()";
    case Kind::Dir:
        return "FindClose()";
    default:
        return "CloseHandle()";
    }
#else
    switch (k) {
    case Kind::Fd:
        return "close()";
    case Kind::File:
        return "fclose()";
    case Kind::Pipe:
        return "pclose()";
    case Kind::Dir:
        return "closedir()";
    case Kind::Thread:
        return "pthread_join()";
    case Kind::Process:
        return "waitpid()";
    }
    return "close()";
#endif
}

#ifndef _WIN32
// The child has exited and nobody has collected its status: a zombie.
// (One still running is not judged; one reaped behind our back, or with
// SIGCHLD ignored, is not our child any more.)
bool zombie(uint64_t pid) {
    siginfo_t si{};
    return waitid(P_PID, id_t(pid), &si, WEXITED | WNOHANG | WNOWAIT) == 0 &&
           uint64_t(si.si_pid) == pid;
}
#endif

void emit(const char *type, const Rec &r, const char *msg, uint32_t access,
          uint32_t tid, bool fatal, bool untraced_too = false) {
    report::Finding f;
    f.type = type;
    f.category = category(r.kind);
    f.addr = handle_of(r);
    f.tid = tid;
    f.msg = msg;
    f.access_stack = access;
    f.alloc_stack = r.open_stack;
    f.free_stack = type == lcproto::kResourceLeak ? 0 : r.close_stack;
    f.fatal = fatal;
    f.untraced_too = untraced_too;
    report::emit(f);
}

void report_double_close(const Rec &r, const char *how, uint32_t access) {
    char m[256];
    Buf msg(m, sizeof m);
    msg.s(how).s(" on ");
    if (r.kind == Kind::Fd)
        msg.s(kFdWord).c(' ').u(handle_of(r)).s(", which");
    else
        msg.s("a ").s(what(r.kind)).s(" that");
    msg.s(" was already closed");
    emit(lcproto::kDoubleClose, r, msg.cstr(), access, current_tid(), true);
}

} // namespace

void opened(Kind k, uint64_t handle, const char *how) {
    const uint32_t stack = stacks::capture();
    Locked l;
    if (!l)
        return;
    Rec *r = put(key_of(k, handle));
    // Close then open of the same number: the next close of it shuts the new
    // file and is a double close of this one, named at that close.
    const bool again = k == Kind::Fd && r->state == St::Closed;
    if (again) {
        r->prior_open = r->open_stack;
        r->prior_close = r->close_stack;
    } else {
        r->prior_open = r->prior_close = 0;
    }
    r->reused = again ? 1 : 0;
    r->how = how;
    r->open_stack = stack;
    r->close_stack = 0;
    r->tid = current_tid();
    r->pid = process_id();
    r->kind = k;
    r->state = St::Open;
    r->failed = nullptr;
#ifndef _WIN32
    if (k == Kind::Fd)
        sockets::fd_opened(int(handle), how);
#endif
}

void forget(Kind k, uint64_t handle) {
    Locked l;
    if (l)
        erase(key_of(k, handle));
}

bool closing(Kind k, uint64_t handle, const char *how) {
    Rec snap{};
    {
        Locked l;
        if (!l)
            return true;
        const Rec *r = find(key_of(k, handle));
        if (!r)
            return true;
        snap = *r;
    }
    if (snap.state == St::Closed) {
        report_double_close(snap, how, stacks::capture());
        return false;
    }
    if (snap.state == St::Open && snap.kind != k) {
        char m[256];
        Buf msg(m, sizeof m);
        msg.s(what(snap.kind)).s(" opened with ").s(snap.how);
        msg.s(" was closed with ").s(how).s("; use ").s(closer(snap.kind));
        emit(lcproto::kMismatch, snap, msg.cstr(), stacks::capture(),
             current_tid(), true);
    }
    return true;
}

void closed(Kind k, uint64_t handle) {
    const uint32_t stack = stacks::capture();
    Locked l;
    if (!l)
        return;
    Rec *r = put(key_of(k, handle));
    if (r->state == St::None) { // released without our seeing it opened
        r->kind = k;
        r->how = nullptr;
        r->open_stack = 0;
        r->tid = current_tid();
        r->pid = process_id();
    }
    r->state = St::Closed;
    r->close_stack = stack;
#ifndef _WIN32
    if (k == Kind::Fd)
        sockets::fd_changed(int(handle));
#endif
}

void close_failed(uint64_t fd, const char *how) {
    Rec snap{};
    {
        Locked l;
        if (!l)
            return;
        const Rec *r = find(key_of(Kind::Fd, fd));
        if (!r || r->state != St::Closed)
            return; // never seen: the program may just be closing blindly
        snap = *r;
    }
    report_double_close(snap, how, stacks::capture());
}

void used_closed(uint64_t fd, const char *how) {
    Rec snap{};
    {
        Locked l;
        if (!l)
            return;
        const Rec *r = find(key_of(Kind::Fd, fd));
        if (!r || r->state != St::Closed)
            return; // never seen: not ours to judge
        snap = *r;
    }
    // Closed, reopened, closed again: the second close shut the new file.
    // That is a double close of the first lifetime, at the second close, not
    // a use after close of the new owner.
    if (snap.reused) {
        Rec orig = snap;
        orig.open_stack = snap.prior_open;
        orig.close_stack = snap.prior_close;
        report_double_close(orig, "close()", snap.close_stack);
        return;
    }
    char m[256];
    Buf msg(m, sizeof m);
#ifdef _WIN32
    msg.s(how).s(" on handle ").u(fd);
    msg.s(", which was already closed (the call fails with ERROR_INVALID_HANDLE)");
#else
    msg.s(how).s(" on file descriptor ").u(fd);
    msg.s(", which was already closed (the call fails with EBADF)");
#endif
    emit(lcproto::kUseAfterClose, snap, msg.cstr(), stacks::capture(),
         current_tid(), false);
}

bool used_stream(uint64_t handle, const char *how, Kind kind) {
    Rec snap{};
    {
        Locked l;
        if (!l)
            return false;
        const Rec *r = find(key_of(kind, handle));
        // Open: still in use, or closed and handed out again by fopen.
        // Missing: we never saw it (stdin, or a close that was purged).
        if (!r || r->state != St::Closed)
            return false;
        snap = *r;
    }
    char m[256];
    Buf msg(m, sizeof m);
    msg.s(how).s(kind == Kind::Dir ? " on a directory that was already closed"
                                   : " on a FILE stream that was already closed");
    emit(lcproto::kUseAfterClose, snap, msg.cstr(), stacks::capture(),
         current_tid(), false);
    return true;
}

void socket_failed(uint64_t fd, const char *call, int err) {
    Locked l;
    if (!l)
        return;
    Rec *r = find(key_of(Kind::Fd, fd));
    if (r && r->state == St::Open) { // the last failure before the leak is the story
        r->failed = call;
        r->failed_errno = err;
    }
}

#ifndef _WIN32
void exhausted(const char *how) {
    if (__atomic_exchange_n(&g_exhausted, uint8_t(1), __ATOMIC_ACQ_REL))
        return;
    struct rlimit rl {};
    getrlimit(RLIMIT_NOFILE, &rl);
    // The call site (open stack) behind most of this process's open descriptors.
    constexpr size_t kMax = 2048;
    uint32_t ids[kMax];
    const Rec *recs[kMax];
    size_t n = 0;
    Rec best{};
    size_t best_count = 0;
    {
        Locked l;
        if (!l)
            return;
        const uint32_t pid = process_id();
        for (size_t i = 0; i < g_cap && n < kMax; ++i) {
            const Rec &r = g_slots[i];
            // a stream or directory holds a descriptor too
            if (r.key && r.pid == pid && r.state == St::Open &&
                (r.kind == Kind::Fd || r.kind == Kind::File ||
                 r.kind == Kind::Pipe || r.kind == Kind::Dir)) {
                ids[n] = r.open_stack;
                recs[n++] = &r;
            }
        }
        for (size_t i = 0; i < n; ++i) {
            size_t count = 0;
            for (size_t j = 0; j < n; ++j)
                count += ids[j] == ids[i];
            if (count > best_count) {
                best_count = count;
                best = *recs[i];
            }
        }
    }
    char m[320];
    Buf msg(m, sizeof m);
    msg.s(how).s(" failed: the process is out of file descriptors (limit ");
    msg.u(uint64_t(rl.rlim_cur)).s(", ").u(n).s(" open that were seen). ");
    if (best_count) {
        msg.u(best_count).s(" of them come from ").s(best.how ? best.how : "an unknown call");
        msg.s(" at the \"opened here\" location below: a descriptor leak");
    }
    best.kind = Kind::Fd; // reported as a descriptor problem, whoever holds them
    emit(lcproto::kFdLimit, best, msg.cstr(), stacks::capture(), current_tid(), false);
}
#endif

void streams_closed() {
    const uint32_t stack = stacks::capture();
    Locked l;
    if (!l)
        return;
    for (size_t i = 0; i < g_cap; ++i) {
        Rec &r = g_slots[i];
        if (r.key && r.state == St::Open &&
            (r.kind == Kind::File || r.kind == Kind::Pipe)) {
            r.state = St::Closed;
            r.close_stack = stack;
        }
    }
}

#ifndef _WIN32
void closed_range(uint64_t lo, uint64_t hi) {
    const uint32_t stack = stacks::capture();
    Locked l;
    if (!l)
        return;
    for (size_t i = 0; i < g_cap; ++i) {
        Rec &r = g_slots[i];
        if (r.key && r.kind == Kind::Fd && r.state == St::Open &&
            handle_of(r) >= lo && handle_of(r) <= hi) {
            r.state = St::Closed;
            r.close_stack = stack;
            sockets::fd_changed(int(handle_of(r)));
        }
    }
}

void thread_exited(uint64_t self, uint32_t create_stack) {
    Locked l;
    if (!l)
        return;
    Rec *r = put(key_of(Kind::Thread, self));
    r->how = "pthread_create()";
    r->open_stack = create_stack;
    r->close_stack = 0;
    r->tid = current_tid();
    r->pid = process_id();
    r->kind = Kind::Thread;
    r->state = St::Exited;
}
#endif

#ifdef _WIN32
bool is_socket(uint64_t handle) {
    Locked l;
    if (!l)
        return false;
    const Rec *r = find(key_of(Kind::Fd, handle));
    return r && r->state == St::Open && r->how &&
           (!strncmp(r->how, "socket", 6) || !strncmp(r->how, "WSASocket", 9) ||
            !strncmp(r->how, "accept", 6) || !strncmp(r->how, "WSAAccept", 9));
}

// Which kind of handle is this one? Closing does not say.
Kind kind_of(uint64_t handle) {
    Locked l;
    if (!l)
        return Kind::Fd;
    for (Kind k : {Kind::Fd, Kind::Thread, Kind::Process, Kind::Dir}) {
        const Rec *r = find(key_of(k, handle));
        if (r && r->state != St::None)
            return k;
    }
    return Kind::Fd;
}
#endif

void check_inherited(const char *how, bool exec) {
    const uint32_t pid = process_id();
    const uint32_t here = stacks::capture();
    Locked l;
    if (!l)
        return;
    for (size_t i = 0; i < g_cap; ++i) {
        const Rec &r = g_slots[i];
        // At an exec, whatever this process still has open (a fork() child's
        // table is its parent's): the kernel has the last word below.
        if (!r.key || (!exec && r.pid != pid) || r.kind != Kind::Fd ||
            r.state != St::Open)
            continue;
        const uint64_t h = handle_of(r);
#ifdef _WIN32
        DWORD flags = 0;
        if (!GetHandleInformation(HANDLE(h), &flags) || !(flags & HANDLE_FLAG_INHERIT))
            continue;
        char m[320];
        Buf msg(m, sizeof m);
        msg.s("handle ").u(h).s(" from ").s(r.how);
        msg.s(" is inherited by the program started by ").s(how);
        msg.s(", which keeps it open (a file stays locked, a pipe's reader "
              "never sees end of file); create it without bInheritHandle, or "
              "pass bInheritHandles=FALSE");
#else
        const int flags = fcntl(int(h), F_GETFD);
        if (h <= 2 || flags == -1 || (flags & FD_CLOEXEC))
            continue;
        char m[320];
        Buf msg(m, sizeof m);
        msg.s("file descriptor ").u(h).s(" from ").s(r.how);
        msg.s(" is inherited by the program started by ").s(how);
        msg.s(", which keeps it open (a port stays taken, a pipe's reader "
              "never sees end of file); create it with O_CLOEXEC");
#endif
        emit(lcproto::kInheritedFd, r, msg.cstr(), here, current_tid(), false,
             exec);
    }
}

#ifndef _WIN32
void waited_id(const void *siginfo, int options) {
    const auto *si = static_cast<const siginfo_t *>(siginfo);
    if (!(options & WNOWAIT) && si->si_pid > 0)
        forget(Kind::Process, uint64_t(si->si_pid));
}
#endif

void report_at_exit() {
    const uint32_t pid = process_id();
    Locked l;
    if (!l)
        return;
    for (size_t i = 0; i < g_cap; ++i) {
        const Rec &r = g_slots[i];
        // Only what this process opened: a forked child inherits the table.
        if (!r.key || r.pid != pid)
            continue;
#ifdef _WIN32
        if (r.state != St::Open)
            continue;
        const uint64_t h = handle_of(r);
        // A handle closed where we cannot see (inside the C runtime or Windows)
        // is not a leak: ask the system.
        DWORD hf;
        if (r.kind != Kind::File && r.kind != Kind::Pipe && r.kind != Kind::Dir &&
            !GetHandleInformation(HANDLE(h), &hf))
            continue;
        char m[256];
        Buf msg(m, sizeof m);
        msg.s(what(r.kind));
        if (r.kind != Kind::File && r.kind != Kind::Pipe && r.kind != Kind::Dir)
            msg.c(' ').u(h);
        msg.s(" from ").s(r.how);
        if (r.kind == Kind::Fd || r.kind == Kind::Thread || r.kind == Kind::Process) {
            msg.s(" is still open when the program ends");
            if (r.failed) // why it was never used: the usual reason for the leak
                msg.s(" (its ").s(r.failed).s(" failed with error ").u(uint64_t(r.failed_errno)).c(')');
        } else
            msg.s(" is never closed");
#else
        if (r.state != (r.kind == Kind::Thread ? St::Exited : St::Open))
            continue;
        const uint64_t h = handle_of(r);
        // The standard streams are the program's to keep; and a descriptor
        // may have been closed in a way we cannot see (inside libc).
        if (r.kind == Kind::Fd && (h <= 2 || fcntl(int(h), F_GETFD) == -1))
            continue;
        if (r.kind == Kind::Process && !zombie(h))
            continue;
        char m[256];
        Buf msg(m, sizeof m);
        msg.s(what(r.kind));
        if (r.kind == Kind::Fd || r.kind == Kind::Process)
            msg.c(' ').u(h);
        msg.s(" from ").s(r.how);
        if (r.kind == Kind::Process)
            msg.s(" exited but was never waited for, so it stays a zombie "
                  "until the program ends");
        else if (r.kind == Kind::Thread)
            msg.s(" finished but was never joined or detached, so its stack "
                  "and descriptor are never released");
        else if (r.kind == Kind::Fd) {
            msg.s(" is still open when the program ends");
            if (r.failed) // why it was never used: the usual reason for the leak
                msg.s(" (its ").s(r.failed).s(" failed: ").s(strerror(r.failed_errno)).c(')');
        } else
            msg.s(" is never closed");
#endif
        if (r.kind == Kind::Pipe)
            msg.s(" (the command is never waited for)");
        emit(lcproto::kResourceLeak, r, msg.cstr(), 0, r.tid, false);
    }
}

void lock() { g_lock.lock(); }
void unlock() { g_lock.unlock(); }
void reset_lock() { g_lock.reset(); }

} // namespace lc::res
