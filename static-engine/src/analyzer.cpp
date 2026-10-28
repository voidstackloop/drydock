#include "analyzer.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>

namespace lcstatic {
namespace {

using Toks = std::vector<Token>;

// Per allocation site, per program point: what the object may be.
enum : uint8_t {
    kNull = 1,
    kAlloc = 2,
    kFreed = 4,
    kEscaped = 8,
    kExternal = 16
};

enum class SiteKind {
    Unknown,
    Malloc,
    New,
    NewArray,
    External,
    Stack,
    Literal,
    File,   // FILE * from fopen and friends
    Pipe,   // FILE * from popen
    Dir,    // DIR *
    Fd,     // file descriptor
    Thread, // pthread_t from pthread_create, joined or detached once
    VaList, // va_list from va_start/va_copy, ended with va_end
    AddrList, // getaddrinfo()/getifaddrs() result, freeaddrinfo()/freeifaddrs()
    Lock      // a held mutex, under the pseudo path "lock:<mutex>"
};

bool is_memory(SiteKind k) {
    return k == SiteKind::Malloc || k == SiteKind::New ||
           k == SiteKind::NewArray;
}

bool is_handle(SiteKind k) {
    return k == SiteKind::File || k == SiteKind::Pipe || k == SiteKind::Dir ||
           k == SiteKind::Fd || k == SiteKind::Thread || k == SiteKind::VaList;
}

// Must be released by the function (or whoever it hands ownership to).
bool owned(SiteKind k) {
    return is_memory(k) || is_handle(k) || k == SiteKind::AddrList;
}

// The call that releases a kind of object, as releaser summaries name it.
const char *release_name(SiteKind k) {
    switch (k) {
    case SiteKind::Malloc:
        return "free";
    case SiteKind::New:
        return "delete";
    case SiteKind::NewArray:
        return "delete[]";
    case SiteKind::File:
        return "fclose";
    case SiteKind::Pipe:
        return "pclose";
    case SiteKind::Dir:
        return "closedir";
    case SiteKind::Fd:
        return "close";
    case SiteKind::AddrList:
        return "freeaddrinfo";
    default:
        return nullptr;
    }
}

SiteKind release_kind(const std::string &name) {
    for (SiteKind k :
         {SiteKind::Malloc, SiteKind::New, SiteKind::NewArray, SiteKind::File,
          SiteKind::Pipe, SiteKind::Dir, SiteKind::Fd, SiteKind::AddrList})
        if (name == release_name(k))
            return k;
    return SiteKind::Unknown;
}

struct Site {
    SiteKind kind = SiteKind::Unknown;
    int line = 0;
    std::string var; // first variable it was stored in
    std::string how; // allocator / local name
};

struct State {
    bool live = true;
    std::map<std::string, std::set<int>>
        pts; // variable or access path -> sites
    std::map<int, uint8_t> bits;
    std::map<int, int> freed_at;
    std::set<std::string> shifted; // pointer advanced since it was assigned
    std::set<int> unchecked;       // streams not yet tested for NULL

    bool same(const State &o) const {
        return live == o.live && pts == o.pts && bits == o.bits &&
               shifted == o.shifted && unchecked == o.unchecked;
    }
};

State dead_state() {
    State s;
    s.live = false;
    return s;
}

// Site 0 stands for "some value we do not track".
State join(const State &a, const State &b) {
    if (!a.live)
        return b;
    if (!b.live)
        return a;
    State r = a;
    for (auto &[k, v] : r.pts)
        if (!b.pts.count(k))
            v.insert(0);
    for (const auto &[k, v] : b.pts) {
        auto it = r.pts.find(k);
        if (it == r.pts.end()) {
            std::set<int> s = v;
            s.insert(0);
            r.pts[k] = s;
        } else {
            it->second.insert(v.begin(), v.end());
        }
    }
    for (const auto &[s, bb] : b.bits)
        r.bits[s] |= bb;
    r.unchecked.insert(b.unchecked.begin(), b.unchecked.end());
    for (const auto &[s, l] : b.freed_at)
        r.freed_at.emplace(s, l);
    std::set<std::string> both;
    for (const auto &x : a.shifted)
        if (b.shifted.count(x))
            both.insert(x);
    r.shifted = both;
    return r;
}

const std::set<std::string> kKeywords = {"if",
                                         "else",
                                         "while",
                                         "for",
                                         "do",
                                         "switch",
                                         "case",
                                         "default",
                                         "return",
                                         "break",
                                         "continue",
                                         "goto",
                                         "sizeof",
                                         "new",
                                         "delete",
                                         "throw",
                                         "try",
                                         "catch",
                                         "true",
                                         "false",
                                         "nullptr",
                                         "NULL",
                                         "const",
                                         "static",
                                         "struct",
                                         "class",
                                         "enum",
                                         "union",
                                         "typename",
                                         "template",
                                         "auto",
                                         "void",
                                         "int",
                                         "char",
                                         "short",
                                         "long",
                                         "float",
                                         "double",
                                         "signed",
                                         "unsigned",
                                         "bool",
                                         "volatile",
                                         "register",
                                         "extern",
                                         "inline",
                                         "operator",
                                         "decltype",
                                         "alignof",
                                         "typeid",
                                         "constexpr",
                                         "co_return",
                                         "co_await",
                                         "co_yield",
                                         "static_cast",
                                         "reinterpret_cast",
                                         "const_cast",
                                         "dynamic_cast",
                                         "noexcept",
                                         "using",
                                         "typedef",
                                         "public",
                                         "private",
                                         "protected",
                                         "virtual",
                                         "explicit",
                                         "friend",
                                         "mutable",
                                         "thread_local",
                                         "offsetof"};

const std::set<std::string> kSpecifiers = {
    "static", "const",  "constexpr",    "volatile", "register",
    "extern", "inline", "thread_local", "mutable",  "typename"};
const std::set<std::string> kBuiltinWords = {"unsigned", "signed", "long",
                                             "short"};

const std::set<std::string> kMallocFns = {"malloc",
                                          "calloc",
                                          "strdup",
                                          "strndup",
                                          "xmalloc",
                                          "xcalloc",
                                          "xstrdup",
                                          "xstrndup",
                                          "xasprintf",
                                          "aligned_alloc",
                                          "memalign",
                                          "valloc",
                                          "pvalloc",
                                          "wcsdup",
                                          "canonicalize_file_name",
                                          "get_current_dir_name"};
const std::set<std::string> kReallocFns = {"realloc", "reallocarray", "xreallocarray"};
// Calls that store what they make through their first argument, &p.
// minus_one says how the result reports failure: -1 (asprintf), or any
// nonzero value (posix_memalign).
struct OutAlloc {
    bool minus_one; // fails with -1 (else with a nonzero error code)
    SiteKind kind;
    size_t arg = 0; // which argument is the "&p" it fills
};
const std::map<std::string, OutAlloc> kOutAllocs = {
    {"asprintf", {true, SiteKind::Malloc}},
    {"vasprintf", {true, SiteKind::Malloc}},
    {"xasprintf", {true, SiteKind::Malloc}},
    {"xvasprintf", {true, SiteKind::Malloc}},
    {"posix_memalign", {false, SiteKind::Malloc}},
    {"pthread_create", {false, SiteKind::Thread}},
    {"getaddrinfo", {false, SiteKind::AddrList, 3}},
    {"getifaddrs", {true, SiteKind::AddrList, 0}}};
// Grow the buffer *p in place (or allocate it when it is null); it is the
// caller's to free even when the call fails.
const std::set<std::string> kOutGrows = {"getline", "getdelim"};

// Calls that return a handle the caller must close. The argument counts
// keep a C++ member such as file.open(path) from passing for POSIX open().
struct Opener {
    SiteKind kind;
    size_t min_args, max_args;
};
const std::map<std::string, Opener> kOpeners = {
    {"fopen", {SiteKind::File, 2, 2}},
    {"fopen64", {SiteKind::File, 2, 2}},
    {"fdopen", {SiteKind::File, 2, 2}},
    {"tmpfile", {SiteKind::File, 0, 0}},
    {"tmpfile64", {SiteKind::File, 0, 0}},
    {"fmemopen", {SiteKind::File, 3, 3}},
    {"open_memstream", {SiteKind::File, 2, 2}},
    {"popen", {SiteKind::Pipe, 2, 2}},
    {"opendir", {SiteKind::Dir, 1, 1}},
    {"fdopendir", {SiteKind::Dir, 1, 1}},
    {"open", {SiteKind::Fd, 2, 3}},
    {"open64", {SiteKind::Fd, 2, 3}},
    {"openat", {SiteKind::Fd, 3, 4}},
    {"openat64", {SiteKind::Fd, 3, 4}},
    {"creat", {SiteKind::Fd, 2, 2}},
    {"creat64", {SiteKind::Fd, 2, 2}},
    {"socket", {SiteKind::Fd, 3, 3}},
    {"accept", {SiteKind::Fd, 3, 3}},
    {"accept4", {SiteKind::Fd, 4, 4}},
    {"dup", {SiteKind::Fd, 1, 1}},
    {"eventfd", {SiteKind::Fd, 2, 2}},
    {"epoll_create", {SiteKind::Fd, 1, 1}},
    {"epoll_create1", {SiteKind::Fd, 1, 1}},
    {"timerfd_create", {SiteKind::Fd, 2, 2}},
    {"inotify_init", {SiteKind::Fd, 0, 0}},
    {"inotify_init1", {SiteKind::Fd, 1, 1}},
    {"memfd_create", {SiteKind::Fd, 2, 2}},
    {"mkstemp", {SiteKind::Fd, 1, 1}},
    {"mkstemp64", {SiteKind::Fd, 1, 1}},
    {"mkostemp", {SiteKind::Fd, 2, 2}},
    {"mkostemp64", {SiteKind::Fd, 2, 2}},
    {"mkstemps", {SiteKind::Fd, 2, 2}},
    {"mkstemps64", {SiteKind::Fd, 2, 2}},
    {"mkostemps", {SiteKind::Fd, 3, 3}},
    {"mkostemps64", {SiteKind::Fd, 3, 3}},
};
// Each handle kind's release function.
const std::map<std::string, SiteKind> kClosers = {
    {"fclose", SiteKind::File},         {"pclose", SiteKind::Pipe},
    {"closedir", SiteKind::Dir},        {"close", SiteKind::Fd},
    {"pthread_join", SiteKind::Thread}, {"pthread_detach", SiteKind::Thread},
    {"va_end", SiteKind::VaList},
    {"freeaddrinfo", SiteKind::AddrList},
    {"freeifaddrs", SiteKind::AddrList}};
// Calls that act on a descriptor: passing a closed one is a use. (Other
// calls, such as printing its number, are not.)
const std::set<std::string> kFdUsers = {
    "read",       "write",      "pread",       "pwrite",      "readv",
    "writev",     "send",       "recv",        "sendto",      "recvfrom",
    "sendmsg",    "recvmsg",    "lseek",       "fstat",       "fsync",
    "fdatasync",  "ftruncate",  "fchmod",      "fchown",      "ioctl",
    "fcntl",      "dup",        "dup2",        "dup3",        "connect",
    "bind",       "listen",     "accept",      "accept4",     "shutdown",
    "setsockopt", "getsockopt", "getsockname", "getpeername", "epoll_ctl",
    "epoll_wait", "fdopen",     "fdopendir",   "flock",       "sendfile"};
const std::set<std::string> kTerminators = {
    "exit",       "_exit",      "_Exit",
    "abort",      "quick_exit", "longjmp",
    "siglongjmp", "terminate",  "__builtin_unreachable",
    "err",        "errx",       "verr",
    "verrx",
    "fatal",      "fatal_f",    "fatal_fr",
    "sshfatal"};
// Calls that read their pointer arguments but never take ownership.
const std::set<std::string> kNonOwning = {
    "strlen", "strnlen", "strcpy", "strncpy", "strcat", "strncat", "strcmp",
    "strncmp", "strcasecmp", "strncasecmp", "strchr", "strrchr", "strstr",
    "strspn", "strcspn", "strpbrk", "strtok", "strtok_r", "strdup", "strndup",
    "memcpy", "memmove", "memset", "memcmp", "memchr", "printf", "fprintf",
    "sprintf", "snprintf", "vprintf", "vfprintf", "vsnprintf", "vsprintf",
    "puts", "fputs", "fwrite", "fread", "fgets", "sscanf", "fscanf", "scanf",
    "atoi", "atol", "atoll", "atof", "strtol", "strtoul", "strtoll", "strtoull",
    "strtod", "strtof", "write", "read", "send", "recv", "qsort", "bsearch",
    "perror", "fflush", "assert", "toupper", "tolower", "wcslen", "wcscpy",
    "bzero", "explicit_bzero", "fputc", "putc", "getc", "fgetc", "ungetc",
    "isalpha", "isdigit", "isspace", "isalnum", "pwrite", "pread", "abs",
    // streams, directories and descriptors: used, never adopted
    "fseek", "fseeko", "ftell", "ftello", "rewind", "feof", "ferror",
    "clearerr", "fileno", "setvbuf", "setbuf", "setlinebuf", "getline",
    "getdelim", "fgetpos", "fsetpos", "flockfile", "funlockfile", "readdir",
    "readdir_r", "rewinddir", "dirfd", "telldir", "seekdir", "lseek", "fstat",
    "fsync", "fdatasync", "ftruncate", "fchmod", "fchown", "ioctl", "fcntl",
    "setsockopt", "getsockopt", "bind", "listen", "connect", "shutdown",
    "sendto", "recvfrom", "sendmsg", "recvmsg", "epoll_ctl", "epoll_wait",
    "getsockname", "getpeername", "readv", "writev", "isatty", "flock", "lockf",
    "FD_SET", "FD_CLR", "FD_ISSET", "dup", "dup2", "dup3", "accept", "accept4",
    "open", "open64", "openat", "openat64", "creat", "fopen", "popen",
    "opendir", "sendfile", "pthread_cond_signal", "pthread_cond_broadcast",
    "va_arg"};
// Calls whose pointer arguments are not "uses" of the pointed-to memory.
// Calls that read or write through a FILE * or DIR *: NULL crashes them.
const std::set<std::string> kStreamUsers = {
    "fgets",   "fputs",    "fprintf",  "vfprintf",  "fscanf",  "vfscanf",
    "fread",   "fwrite",   "fgetc",    "fputc",     "getc",    "putc",
    "ungetc",  "getline",  "getdelim", "fseek",     "fseeko",  "ftell",
    "ftello",  "rewind",   "fflush",   "fclose",    "pclose",  "feof",
    "ferror",  "clearerr", "fileno",   "setvbuf",   "setbuf",  "fgetpos",
    "fsetpos", "readdir",  "closedir", "rewinddir", "telldir", "seekdir",
    "dirfd"};
const std::set<std::string> kNoUse = {
    "assert",   "sizeof",   "free",         "cfree",       "fclose",
    "pclose",   "closedir", "close",        "freeaddrinfo", "freeifaddrs"};
// Mutex acquire and release. C functions take the mutex's address; ".name"
// is a method call (std::mutex and friends).
const std::set<std::string> kLockFns = {"pthread_mutex_lock",
                                        "pthread_spin_lock",
                                        "pthread_rwlock_rdlock",
                                        "pthread_rwlock_wrlock",
                                        "mtx_lock",
                                        "EnterCriticalSection",
                                        "AcquireSRWLockExclusive",
                                        "AcquireSRWLockShared",
                                        ".lock",
                                        ".lock_shared"};
const std::set<std::string> kUnlockFns = {
    "pthread_mutex_unlock",  "pthread_spin_unlock",
    "pthread_rwlock_unlock", "mtx_unlock",
    "LeaveCriticalSection",  "ReleaseSRWLockExclusive",
    "ReleaseSRWLockShared",  ".unlock",
    ".unlock_shared"};
// Take a held mutex and give it back before returning.
const std::set<std::string> kCondWaits = {"pthread_cond_wait",
                                          "pthread_cond_timedwait",
                                          "pthread_cond_clockwait",
                                          "cnd_wait",
                                          "cnd_timedwait",
                                          "SleepConditionVariableCS",
                                          "SleepConditionVariableSRW"};

bool is_null_token(const Token &t) {
    return t.is("NULL") || t.is("nullptr") || t.is("0") || t.is("__null");
}

// t[b, e) is NULL, nullptr or 0.
bool is_null_arg(const Toks &t, size_t b, size_t e) {
    return b + 1 == e && is_null_token(t[b]);
}

// t[b, e) is "-1": what descriptor functions return on failure.
bool is_minus_one(const Toks &t, size_t b, size_t e) {
    // or a macro for it such as INVALID_SOCKET (macros are not expanded)
    return (b + 2 == e && t[b].is("-") && t[b + 1].is("1")) ||
           (b + 1 == e && t[b].kind == Tok::Ident &&
            t[b].text.rfind("INVALID_", 0) == 0);
}

// Argument n of the call t[open..close] when it is a single token.
const Token *single_arg(const Toks &t, size_t open, size_t close, size_t n) {
    size_t arg = 0, start = open + 1;
    int depth = 0;
    for (size_t k = open + 1; k <= close && k < t.size(); ++k) {
        if (k < close && (t[k].is("(") || t[k].is("[")))
            ++depth;
        else if (k < close && (t[k].is(")") || t[k].is("]")))
            --depth;
        else if (k == close || (depth == 0 && t[k].is(","))) {
            if (arg == n)
                return k == start + 1 ? &t[start] : nullptr;
            ++arg;
            start = k + 1;
        }
    }
    return nullptr;
}

// fcntl(fd, F_DUPFD, n) / F_DUPFD_CLOEXEC: the call returns a new descriptor.
bool dup_command(const Toks &t, size_t open, size_t close) {
    const Token *c = single_arg(t, open, close, 1);
    return c && (c->is("F_DUPFD") || c->is("F_DUPFD_CLOEXEC"));
}

// realpath(path, NULL), getcwd(NULL, 0): given no buffer, they return one
// from malloc. The value is which argument is the buffer.
const std::map<std::string, size_t> kBufferOrMalloc = {{"realpath", 1},
                                                       {"getcwd", 0}};

bool allocates_buffer(const std::string &fname, const Toks &t, size_t open,
                      size_t close) {
    auto it = kBufferOrMalloc.find(fname);
    const Token *buf = it == kBufferOrMalloc.end()
                           ? nullptr
                           : single_arg(t, open, close, it->second);
    return buf && is_null_token(*buf);
}

size_t count_args(const Toks &t, size_t open, size_t close) {
    if (close <= open + 1)
        return 0;
    size_t n = 1;
    int depth = 0;
    for (size_t k = open + 1; k < close; ++k) {
        if (t[k].is("(") || t[k].is("[") || t[k].is("{"))
            ++depth;
        else if (t[k].is(")") || t[k].is("]") || t[k].is("}"))
            --depth;
        else if (depth == 0 && t[k].is(","))
            ++n;
    }
    return n;
}

size_t match(const Toks &t, size_t i) {
    if (i >= t.size())
        return t.size();
    // Hot: compare the brackets as characters. Comparing std::string tokens
    // against the expected text strlen'd it on every punctuation token.
    const Token &open = t[i];
    if (open.kind == Tok::Punct && open.text.size() == 1) {
        const char oc = open.text[0];
        const bool angle = oc == '<';
        if (oc != '(' && oc != '[' && oc != '{' && !angle)
            return t.size(); // no closer for this character
        const char cc = oc == '(' ? ')' : oc == '[' ? ']' : oc == '{' ? '}' : '>';
        int depth = 0;
        for (size_t k = i; k < t.size(); ++k) {
            if (t[k].kind != Tok::Punct)
                continue;
            const std::string &s = t[k].text;
            if (s.size() == 1) {
                const char c = s[0];
                if (c == oc)
                    ++depth;
                else if (c == cc && --depth == 0)
                    return k;
            } else if (angle && s.size() == 2 && s[0] == '>' && s[1] == '>' &&
                       (depth -= 2) <= 0) {
                return k;
            }
        }
        return t.size();
    }
    // Rare: a multi-character or literal token. Same scan as before.
    const std::string &o = open.text;
    const std::string c = o == "("   ? ")"
                          : o == "[" ? "]"
                          : o == "{" ? "}"
                          : o == "<" ? ">"
                                     : "";
    if (c.empty())
        return t.size();
    int depth = 0;
    for (size_t k = i; k < t.size(); ++k) {
        if (t[k].kind != Tok::Punct)
            continue;
        if (t[k].text == o)
            ++depth;
        else if (t[k].text == c && --depth == 0)
            return k;
        else if (o == "<" && t[k].text == ">>" && (depth -= 2) <= 0)
            return k;
    }
    return t.size();
}

// The same match, searching backwards from a closing bracket.
size_t rmatch(const Toks &t, size_t close) {
    const Token &cl = t[close];
    if (cl.kind == Tok::Punct && cl.text.size() == 1) {
        const char cc = cl.text[0];
        const char oc = cc == ')' ? '(' : cc == ']' ? '[' : '{';
        int depth = 0;
        for (size_t k = close + 1; k-- > 0;) {
            if (t[k].kind != Tok::Punct || t[k].text.size() != 1)
                continue;
            const char c = t[k].text[0];
            if (c == cc)
                ++depth;
            else if (c == oc && --depth == 0)
                return k;
        }
        return t.size();
    }
    const std::string &c = cl.text;
    const std::string o = c == ")" ? "(" : c == "]" ? "[" : "{";
    int depth = 0;
    for (size_t k = close + 1; k-- > 0;) {
        if (t[k].kind != Tok::Punct)
            continue;
        if (t[k].text == c)
            ++depth;
        else if (t[k].text == o && --depth == 0)
            return k;
    }
    return t.size();
}

bool starts_path(const Toks &t, size_t i) {
    if (i >= t.size() || t[i].kind != Tok::Ident || kKeywords.count(t[i].text))
        return false;
    return !(i > 0 &&
             (t[i - 1].is(".") || t[i - 1].is("->") || t[i - 1].is("::")));
}

// Reads an access path ("p", "s->buf", "a.b") starting at i.
std::string path_at(const Toks &t, size_t i, size_t *end) {
    if (!starts_path(t, i))
        return {};
    std::string p = t[i].text;
    size_t k = i + 1;
    while (k + 1 < t.size() &&
           (t[k].is(".") || t[k].is("->") || t[k].is("::")) &&
           t[k + 1].kind == Tok::Ident) {
        p += t[k].text + t[k + 1].text;
        k += 2;
    }
    *end = k;
    return p;
}

bool unary_before(const Toks &t, size_t i) {
    if (i == 0)
        return true;
    const Token &p = t[i - 1];
    if (p.kind == Tok::Ident)
        return p.is("return") || p.is("case") || p.is("delete") ||
               p.is("throw");
    if (p.kind != Tok::Punct)
        return false;
    return !(p.is(")") || p.is("]") || p.is("++") || p.is("--"));
}

// Strips C casts, named casts, std::move and surrounding parens.
void strip(const Toks &t, size_t &b, size_t &e) {
    for (bool changed = true; changed && b < e;) {
        changed = false;
        if (t[b].is("(") && match(t, b) == e - 1) {
            ++b;
            --e;
            changed = true;
            continue;
        }
        if (t[b].is("(")) { // (T *) expr
            size_t m = match(t, b);
            if (m < e - 1) {
                bool type_like = true;
                for (size_t k = b + 1; k < m; ++k) {
                    const Token &x = t[k];
                    if (!(x.kind == Tok::Ident || x.is("*") || x.is("::") ||
                          x.is("<") || x.is(">") || x.is("&") || x.is(",")))
                        type_like = false;
                }
                if (type_like && m > b + 1) {
                    b = m + 1;
                    changed = true;
                    continue;
                }
            }
        }
        if (t[b].kind == Tok::Ident &&
            (t[b].is("static_cast") || t[b].is("reinterpret_cast") ||
             t[b].is("const_cast")) &&
            b + 1 < e && t[b + 1].is("<")) {
            size_t m = match(t, b + 1);
            if (m + 1 < e && t[m + 1].is("(") && match(t, m + 1) == e - 1) {
                b = m + 2;
                --e;
                changed = true;
            }
        }
    }
}

std::string call_name(const Toks &t, size_t b, size_t e, size_t *open) {
    size_t k = b;
    if (k + 1 < e && t[k].is("std") && t[k + 1].is("::"))
        k += 2;
    if (k + 1 < e && t[k].is("::"))
        ++k;
    if (k + 1 < e && t[k].kind == Tok::Ident && t[k + 1].is("(")) {
        *open = k + 1;
        return t[k].text;
    }
    return {};
}

// Calls that wait for another thread: once one returns, a thread started
// earlier is finished, or has said that it took its argument.
const std::set<std::string> kThreadWaits = {
    "pthread_join",          "pthread_timedjoin_np",
    "pthread_tryjoin_np",    "thrd_join",
    "sem_wait",              "sem_timedwait",
    "sem_clockwait",         "pthread_cond_wait",
    "pthread_cond_timedwait", "pthread_cond_clockwait",
    "pthread_barrier_wait",  "cnd_wait",
    "cnd_timedwait"};

bool calls_any(const Toks &t, const std::set<std::string> &names) {
    for (size_t i = 0; i + 1 < t.size(); ++i)
        if (t[i].kind == Tok::Ident && t[i + 1].is("(") &&
            names.count(t[i].text))
            return true;
    return false;
}

// f(tokens) for every token list of s and of the statements below it.
template <class F> void each_tokens(const Stmt &s, F &&f) {
    f(s.a);
    f(s.b);
    f(s.c);
    for (const auto &k : s.kids)
        each_tokens(*k, f);
    if (s.s1)
        each_tokens(*s.s1, f);
    if (s.s2)
        each_tokens(*s.s2, f);
}

bool has_goto(const Stmt &s) {
    if (s.kind == Stmt::Goto || s.kind == Stmt::Label)
        return true;
    for (const auto &k : s.kids)
        if (has_goto(*k))
            return true;
    return (s.s1 && has_goto(*s.s1)) || (s.s2 && has_goto(*s.s2));
}

// If t[i] opens a lambda, [captures](params) specifiers { body }: the index
// of its body's '{' (else 0), and *end = the matching '}'.
size_t lambda_body(const Toks &t, size_t i, size_t *end) {
    if (!t[i].is("[") ||
        !(i == 0 || t[i - 1].is("(") || t[i - 1].is(",") ||
          t[i - 1].is("=") || t[i - 1].is("{") || t[i - 1].is("return")))
        return 0;
    const size_t cap_end = match(t, i);
    if (cap_end >= t.size())
        return 0;
    size_t k = cap_end + 1;
    if (k < t.size() && t[k].is("("))
        k = match(t, k) + 1;
    while (k < t.size() && !t[k].is("{") && !t[k].is(";") && !t[k].is(")") &&
           !t[k].is(",") && !t[k].is("="))
        ++k; // mutable, noexcept, -> type
    if (k >= t.size() || !t[k].is("{"))
        return 0;
    *end = match(t, k);
    return k;
}

// "K_DEFER(guard) { delete p; };", "defer_cleanup(x) { ... }": a macro that
// runs its block when the scope ends. The statement starts t[0] = the name;
// returns the '{' of the block (else 0) and *end = its '}'.
size_t defer_block(const Toks &t, size_t *end) {
    if (t.size() < 3 || t[0].kind != Tok::Ident ||
        !(t[1].is("(") || t[1].is("{")))
        return 0;
    std::string name;
    for (char c : t[0].text)
        name += char(std::tolower(static_cast<unsigned char>(c)));
    bool defer = false;
    for (const char *word :
         {"defer", "scope_exit", "scope_guard", "finally", "on_exit"})
        defer = defer || name.find(word) != std::string::npos;
    const size_t open = t[1].is("(") ? match(t, 1) + 1 : 1; // K_DEFER(x) { or K_DEFER {
    if (!defer || open >= t.size() || !t[open].is("{"))
        return 0;
    *end = match(t, open);
    return open;
}

// t without the bodies of its lambdas (their braces stay, empty): what a
// lambda does happens later, if ever, not at the statement that makes it.
// A deferred block (defer_block) is treated the same way.
// `inside` gets the names the bodies mention. False if there is no lambda.
bool without_lambda_bodies(const Toks &t, Toks *out,
                           std::set<std::string> *inside) {
    bool any = false;
    // "struct Closer { FILE *f; ~Closer() { fclose(f); } } closer{f};": a
    // local type's members and member functions are not statements here.
    if (!t.empty() &&
        (t[0].is("struct") || t[0].is("class") || t[0].is("union"))) {
        size_t k = 1;
        while (k < t.size() && (t[k].kind == Tok::Ident || t[k].is("::") ||
                                t[k].is(":") || t[k].is(",")))
            ++k;
        if (k > 1 && k < t.size() && t[k].is("{")) {
            const size_t end = match(t, k);
            out->assign(t.begin(), t.begin() + long(k));
            if (end < t.size())
                out->insert(out->end(), t.begin() + long(end) + 1, t.end());
            return true;
        }
    }
    for (size_t i = 0; i < t.size(); ++i) {
        size_t end = 0;
        const size_t open =
            i == 0 && defer_block(t, &end) ? defer_block(t, &end)
                                           : lambda_body(t, i, &end);
        if (open) {
            if (!any) {
                out->assign(t.begin(), t.begin() + long(i));
                any = true;
            }
            out->insert(out->end(), t.begin() + long(i), t.begin() + long(open) + 1);
            if (inside)
                for (size_t k = open + 1; k < end && k < t.size(); ++k)
                    if (t[k].kind == Tok::Ident)
                        inside->insert(t[k].text);
            if (end < t.size())
                out->push_back(t[end]);
            i = end;
        } else if (any) {
            out->push_back(t[i]);
        }
    }
    return any;
}

// The variables written in t: v = x, v += x, v++, --v, v.field = x, v[i] = x.
// What a lambda's body writes is the thread's work, not the loop's.
void assigned_roots(const Toks &t, std::set<std::string> &out) {
    static const std::set<std::string> ops = {
        "=",  "+=", "-=", "*=", "/=", "%=",
        "|=", "&=", "^=", "<<=", ">>=", "++", "--"};
    for (size_t i = 0; i < t.size(); ++i) {
        size_t lambda_end = 0;
        if (lambda_body(t, i, &lambda_end)) {
            i = lambda_end;
            continue;
        }
        if (!starts_path(t, i))
            continue;
        size_t pe = 0;
        const std::string p = path_at(t, i, &pe);
        if (p.empty())
            continue;
        while (pe < t.size() && t[pe].is("["))
            pe = match(t, pe) + 1;
        const bool before = i > 0 && (t[i - 1].is("++") || t[i - 1].is("--"));
        if (before || (pe < t.size() && ops.count(t[pe].text)))
            out.insert(p.substr(0, p.find_first_of(".-:")));
    }
}

struct Declarator {
    std::string name;
    bool pointer = false;
    bool reference = false;
    bool array = false;
    size_t init_b = 0, init_e = 0;
    char init_kind = 0; // '=', '(', '{' or 0
};

// "std::thread t(f, x)", "std::thread t{f}", "std::thread t = ...": a thread
// starts here, and t must be joined or detached before it is destroyed.
bool starts_std_thread(const Toks &t, const Declarator &d) {
    if (d.array || !d.init_kind ||
        (d.init_kind != '=' && d.init_b >= d.init_e))
        return false; // "thread t;" and "thread t();" start nothing
    for (size_t j = 0; j + 1 < t.size(); ++j)
        if (t[j].is("thread") && t[j].kind == Tok::Ident &&
            (j == 0 || (j >= 2 && t[j - 1].is("::") && t[j - 2].is("std"))) &&
            t[j + 1].text == d.name)
            return true;
    return false;
}

// A declaration of a thread, or of a container of them.
bool mentions_thread_type(const Toks &t) {
    for (size_t j = 0; j < t.size(); ++j)
        if ((t[j].is("thread") || t[j].is("jthread")) &&
            t[j].kind == Tok::Ident &&
            (j == 0 || t[j - 1].is("::") || t[j - 1].is("<")))
            return true;
    return false;
}

// Calls like t.join(), f.get(): a loop that makes them waits for its work.
bool calls_member(const Toks &t, const std::set<std::string> &names) {
    for (size_t i = 1; i + 1 < t.size(); ++i)
        if (t[i].kind == Tok::Ident && t[i + 1].is("(") &&
            (t[i - 1].is(".") || t[i - 1].is("->")) && names.count(t[i].text))
            return true;
    return false;
}

class Analyzer {
  public:
    Analyzer(const Function &f, std::vector<LockOrder> *orders,
             Allocators *allocators, Releasers *releasers)
        : fn_(f), orders_(orders), allocators_(allocators),
          releasers_(releasers) {
        sites_.push_back(Site{});
        fn_has_goto_ = f.body && has_goto(*f.body);
    }

    // After run(): parameter position -> the call that releases it, for
    // pointer parameters released on every way out.
    std::map<size_t, std::string> releases() const {
        std::map<size_t, std::string> out;
        for (const auto &[s, param] : params_by_site_) {
            auto how = param_release_.find(s);
            if (released_somewhere_.count(param.first) &&
                !kept_.count(param.first) && how != param_release_.end())
                if (const char *name = release_name(how->second))
                    out[param.first] = name;
        }
        return out;
    }

    std::vector<Issue> run() {
        State st;
        declare_params(st);
        st = analyze(*fn_.body, st);
        if (st.live)
            exit_check(st, fn_.end_line, 0);
        // Lock findings stand only for a mutex this function also unlocks:
        // one it never unlocks is meant to stay held (a lock() wrapper).
        std::vector<Issue> out;
        for (size_t i = 0; i < issues_.size(); ++i)
            if (auto it = lock_issue_.find(i);
                it == lock_issue_.end() || unlocked_.count(it->second))
                out.push_back(std::move(issues_[i]));
        return out;
    }

    // After run(): how this function's results must be released, when every
    // return hands over memory it allocated itself; nullptr otherwise.
    const char *allocator_kind() const {
        if (!returns_fresh_ || returned_kind_ == SiteKind::Unknown)
            return nullptr;
        return returned_kind_ == SiteKind::New        ? "new"
               : returned_kind_ == SiteKind::NewArray ? "new[]"
                                                      : "malloc";
    }

  private:
    // ---- reporting ------------------------------------------------------
    void report(const char *rule, const std::string &msg, int line, int col,
                int alloc_line, int free_line) {
        std::string key = std::string(rule) + "|" + std::to_string(line) + "|" +
                          std::to_string(col) + "|" + msg;
        if (!reported_.insert(key).second)
            return;
        Issue is;
        is.rule = rule;
        is.message = msg;
        is.function = fn_.name;
        is.line = line;
        is.col = col;
        is.alloc_line = alloc_line;
        is.free_line = free_line;
        issues_.push_back(std::move(is));
    }

    void report_lock(const char *rule, const std::string &mutex,
                     const std::string &msg, int line, int col, int lock_line,
                     int unlock_line = 0) {
        const size_t n = issues_.size();
        report(rule, msg, line, col, lock_line, unlock_line);
        if (issues_.size() > n)
            lock_issue_[n] = mutex;
    }

    static const char *kind_text(SiteKind k) {
        switch (k) {
        case SiteKind::Malloc:
            return "malloc()";
        case SiteKind::New:
            return "new";
        case SiteKind::NewArray:
            return "new[]";
        default:
            return "an allocator";
        }
    }

    // "memory from malloc()", "the FILE stream from popen()", ...
    static std::string object_text(const Site &si) {
        switch (si.kind) {
        case SiteKind::File:
        case SiteKind::Pipe:
            return "the FILE stream from " + si.how;
        case SiteKind::Dir:
            return "the directory stream from " + si.how;
        case SiteKind::Fd:
            return "the file descriptor from " + si.how;
        case SiteKind::Thread:
            return "the thread from " + si.how;
        case SiteKind::VaList:
            return "the va_list from " + si.how;
        case SiteKind::AddrList:
            return "the address list from " + si.how;
        default:
            return std::string("memory from ") + kind_text(si.kind);
        }
    }

    // Leak wording: "memory allocated with malloc()" / "file descriptor
    // from open()", and what the program failed to do with it.
    static std::string leaked_text(const Site &si) {
        switch (si.kind) {
        case SiteKind::File:
        case SiteKind::Pipe:
            return "FILE stream from " + si.how;
        case SiteKind::Dir:
            return "directory stream from " + si.how;
        case SiteKind::Fd:
            return (is_socket_opener(si.how) ? "socket from "
                                             : "file descriptor from ") +
                   si.how;
        case SiteKind::Thread:
            return "thread from " + si.how;
        case SiteKind::VaList:
            return "va_list from " + si.how;
        case SiteKind::AddrList:
            return "address list from " + si.how;
        default:
            return "memory allocated with " + si.how;
        }
    }

    static const char *leak_rule(const Site &si) {
        return is_handle(si.kind) ? "resource-leak" : "memory-leak";
    }

    static bool is_socket_opener(const std::string &how) {
        return how == "socket()" || how == "accept()" || how == "accept4()" ||
               how == "socketpair()";
    }

    static const char *released(SiteKind k) {
        return k == SiteKind::Thread     ? "joined or detached"
               : k == SiteKind::VaList   ? "ended with va_end()"
               : k == SiteKind::AddrList ? "freed with freeaddrinfo()"
               : is_handle(k)            ? "closed"
                                         : "released";
    }
    static const char *released(const Site &si) {
        return si.kind == SiteKind::AddrList && si.how == "getifaddrs()"
                   ? "freed with freeifaddrs()"
                   : released(si.kind);
    }

    // ---- sites and state helpers ----------------------------------------
    int site_for(const Token &at, SiteKind kind, const std::string &var,
                 const std::string &how) {
        auto key = std::make_pair(at.line, at.col);
        auto it = site_at_.find(key);
        if (it != site_at_.end())
            return it->second;
        Site s;
        s.kind = kind;
        s.line = at.line;
        s.var = var;
        s.how = how;
        sites_.push_back(s);
        int id = int(sites_.size() - 1);
        site_at_[key] = id;
        return id;
    }

    int external_site(const std::string &path, int line) {
        auto it = external_.find(path);
        if (it != external_.end())
            return it->second;
        // The same place gives the same site on every pass over a loop:
        // fresh ones each time would keep its state from ever settling.
        int &id = external_ids_[{path, line}];
        if (!id) {
            Site s;
            s.kind = SiteKind::External;
            s.line = line;
            s.var = path;
            sites_.push_back(s);
            id = int(sites_.size() - 1);
        }
        external_[path] = id;
        return id;
    }

    std::set<int> pts(State &st, const std::string &path) {
        auto it = st.pts.find(path);
        if (it == st.pts.end())
            return {0};
        return it->second;
    }

    bool tracked(State &st, const std::string &path) {
        auto it = st.pts.find(path);
        return it != st.pts.end() &&
               !(it->second.size() == 1 && it->second.count(0));
    }

    void escape(State &st, const std::string &path) {
        auto it = st.pts.find(path);
        if (it == st.pts.end())
            return;
        for (int s : it->second)
            if (s && st.bits[s] != kNull) { // nothing of null to hand over
                st.bits[s] |= kEscaped;
                st.unchecked.erase(s);
            }
    }

    // A stream from fopen/popen/opendir handed to a stream call before any
    // test for NULL (on every path that reaches here): reported once.
    void check_unchecked(State &st, const std::string &p,
                         const std::string &fname, const Token &at) {
        auto it = st.pts.find(p);
        if (it == st.pts.end() || it->second.empty())
            return;
        int site = 0;
        for (int s : it->second) {
            if (!s || !st.unchecked.count(s) || st.bits[s] != kAlloc)
                return;
            site = s;
        }
        const Site &si = sites_[size_t(site)];
        report("unchecked-stream",
               "'" + p + "' from " + si.how + " at line " +
                   std::to_string(si.line) + " may be NULL here: " + fname +
                   "() uses it before any test, which crashes when the open "
                   "fails",
               at.line, at.col, si.line, 0);
        for (int s : it->second)
            st.unchecked.erase(s);
    }

    bool is_local(const std::string &path) const {
        return path.find_first_of(".-:") == std::string::npos &&
               locals_.count(path) && !statics_.count(path);
    }

    bool referenced_elsewhere(State &st, int site, const std::string &except) {
        for (const auto &[p, s] : st.pts)
            if (p != except && s.count(site))
                return true;
        return false;
    }

    // ---- declarations ---------------------------------------------------
    void declare_params(State &st) {
        const Toks &p = fn_.params;
        size_t b = 0, index = 0;
        for (size_t i = 0; i <= p.size(); ++i) {
            if (i < p.size() &&
                (p[i].is("(") || p[i].is("[") || p[i].is("<"))) {
                i = match(p, i);
                continue;
            }
            if (i < p.size() && !p[i].is(","))
                continue;
            // one parameter in [b, i): the last identifier is its name
            bool ptr = false, ref = false;
            std::string name;
            for (size_t k = b; k < i; ++k) {
                if (p[k].is("*") || p[k].is("["))
                    ptr = true;
                if (p[k].is("&") || p[k].is("&&"))
                    ref = true;
                if (p[k].is("="))
                    break;
                if (p[k].kind == Tok::Ident && !kKeywords.count(p[k].text))
                    name = p[k].text;
            }
            if (!name.empty() && i > b + 1) {
                locals_.insert(name);
                params_.insert(name);
                if (ref)
                    ref_locals_.insert(name);
                if (ptr) {
                    ptr_locals_.insert(name);
                    int s = external_site(name, fn_.line);
                    st.pts[name] = {s};
                    st.bits[s] = kExternal;
                    params_by_site_[s] = {index, name};
                }
            }
            b = i + 1;
            ++index;
        }
    }

    bool parse_decl(const Toks &t, std::vector<Declarator> &out,
                    bool *is_static) {
        size_t k = 0;
        bool builtin = false;
        *is_static = false;
        while (
            k < t.size() && t[k].kind == Tok::Ident &&
            (kSpecifiers.count(t[k].text) || kBuiltinWords.count(t[k].text))) {
            if (t[k].is("static") || t[k].is("thread_local") ||
                t[k].is("extern"))
                *is_static = true; // storage outlives the call
            if (kBuiltinWords.count(t[k].text))
                builtin = true;
            ++k;
        }
        if (k >= t.size() || t[k].kind != Tok::Ident)
            return false;
        static const std::set<std::string> not_types = {
            "return",    "delete",        "throw",    "goto",
            "case",      "new",           "sizeof",   "this",
            "co_return", "co_await",      "co_yield", "if",
            "while",     "for",           "switch",   "do",
            "else",      "using",         "typedef",  "template",
            "operator",  "static_assert", "asm",      "__asm__"};
        if (not_types.count(t[k].text))
            return false;
        if (t[k].is("struct") || t[k].is("class") || t[k].is("union") ||
            t[k].is("enum")) {
            k += 2;
        } else if (!(builtin && k + 1 < t.size() &&
                     (t[k + 1].is("=") || t[k + 1].is(";") ||
                      t[k + 1].is(",") || t[k + 1].is("[")))) {
            // Type words: "Foo", "std::map<K, V>", or several in a row as in
            // "unsigned long int" or Metal's "thread const uint8_t".
            for (;;) {
                ++k;
                while (k + 1 < t.size() && t[k].is("::") &&
                       t[k + 1].kind == Tok::Ident)
                    k += 2;
                if (k < t.size() && t[k].is("<"))
                    k = match(t, k) + 1;
                if (k + 1 >= t.size() || t[k].kind != Tok::Ident ||
                    not_types.count(t[k].text))
                    break;
                const Token &after = t[k + 1];
                if (after.kind == Tok::Ident || after.is("*") ||
                    after.is("&") || after.is("&&") || after.is("::") ||
                    after.is("<"))
                    continue; // t[k] is another type word
                break;
            }
        }
        for (;;) {
            Declarator d;
            while (k < t.size() &&
                   (t[k].is("*") || t[k].is("&") || t[k].is("&&") ||
                    t[k].is("const") || t[k].is("volatile") ||
                    t[k].is("restrict") || t[k].is("__restrict"))) {
                if (t[k].is("*"))
                    d.pointer = true;
                if (t[k].is("&") || t[k].is("&&"))
                    d.reference = true;
                ++k;
            }
            if (k >= t.size() || t[k].kind != Tok::Ident ||
                kKeywords.count(t[k].text))
                return !out.empty();
            d.name = t[k].text;
            ++k;
            while (k < t.size() && t[k].is("[")) {
                d.array = true;
                k = match(t, k) + 1;
            }
            if (k < t.size() && t[k].is("=")) {
                d.init_kind = '=';
                d.init_b = ++k;
                int depth = 0;
                while (k < t.size()) {
                    if (t[k].is("(") || t[k].is("[") || t[k].is("{"))
                        ++depth;
                    else if (t[k].is(")") || t[k].is("]") || t[k].is("}"))
                        --depth;
                    else if (depth == 0 && t[k].is(","))
                        break;
                    ++k;
                }
                d.init_e = k;
            } else if (k < t.size() && (t[k].is("(") || t[k].is("{"))) {
                d.init_kind = t[k].text[0];
                size_t m = match(t, k);
                d.init_b = k + 1;
                d.init_e = std::min(m, t.size());
                k = m + 1;
            } else if (k < t.size() && !t[k].is(",")) {
                return false;
            }
            out.push_back(d);
            if (k < t.size() && t[k].is(",")) {
                ++k;
                continue;
            }
            return k >= t.size();
        }
    }

    // ---- frees ----------------------------------------------------------
    void do_free(State &st, const Toks &t, size_t b, size_t e, const char *how,
                 SiteKind expect, const Token &at) {
        strip(t, b, e);
        if (b >= e)
            return;
        if (t[b].kind == Tok::String) {
            report("invalid-free", std::string(how) + " of a string literal",
                   at.line, at.col, 0, 0);
            return;
        }
        if (t[b].is("&")) {
            size_t pe;
            std::string p = path_at(t, b + 1, &pe);
            if (!p.empty())
                report("invalid-free",
                       std::string(how) + " of the address of '" + p +
                           "', which is not a heap block",
                       at.line, at.col, 0, 0);
            return;
        }
        size_t pe = 0;
        std::string p = path_at(t, b, &pe);
        if (p.empty())
            return;
        if (pe != e) {
            // free(p + 4): not the start of the block. Postfix ++/-- passes the original value.
            if (pe < e &&
                (t[pe].is("+") || t[pe].is("-")) &&
                tracked(st, p))
                report("invalid-free",
                       std::string(how) + " of '" + p +
                           "' plus an offset, which is not the start of a heap "
                           "block",
                       at.line, at.col, 0, 0);
            return;
        }
        if (is_local(p) && arrays_.count(p)) {
            report("invalid-free",
                   std::string(how) + " of local array '" + p + "'", at.line,
                   at.col, 0, 0);
            return;
        }
        if (st.shifted.count(p) && tracked(st, p)) {
            report("invalid-free",
                   std::string(how) + " of '" + p +
                       "', which was advanced past the start of its block",
                   at.line, at.col, 0, 0);
            return;
        }
        if (!tracked(st, p)) {
            // p holds a value we never saw released (on an earlier loop
            // iteration the same name may have held another one).
            int s = external_site(p, at.line);
            if (st.bits[s] & kFreed) {
                // Reassigned since that release: the earlier free consumed
                // that block, so this one is a new object. Reusing the site
                // would cry double free on reassignment between frees.
                Site ns;
                ns.kind = SiteKind::External;
                ns.line = at.line;
                ns.var = p;
                sites_.push_back(ns);
                s = int(sites_.size() - 1);
                external_[p] = s;
            }
            st.pts[p] = {s};
            st.bits[s] = kExternal;
        }
        std::set<int> sites = pts(st, p);
        bool all_freed = true, some_freed = false, all_null = true;
        int freed_line = 0, alloc_line = 0;
        int mismatched = 0, known = 0, mismatch_site = 0;
        for (int s : sites) {
            uint8_t bt = s ? st.bits[s] : uint8_t(kExternal);
            const Site &si = sites_[size_t(s)];
            if (si.kind == SiteKind::Stack || si.kind == SiteKind::Literal) {
                report("invalid-free",
                       std::string(how) + " of '" + p + "', which points to " +
                           (si.kind == SiteKind::Stack
                                ? "local '" + si.how + "'"
                                : std::string("a string literal")),
                       at.line, at.col, 0, 0);
                return;
            }
            if (!(bt & kNull) || (bt & ~kNull))
                all_null = false;
            if (bt & kFreed) {
                some_freed = true;
                if (st.freed_at.count(s))
                    freed_line = st.freed_at[s];
            }
            if (!(bt & kFreed) || (bt & (kAlloc | kExternal | kNull)))
                all_freed = false;
            if (owned(si.kind)) {
                ++known;
                alloc_line = si.line;
                if (si.kind != expect) {
                    ++mismatched;
                    mismatch_site = s;
                }
            }
        }
        if (all_null)
            return;
        const bool handle = is_handle(expect);
        const char *rule = expect == SiteKind::Thread ? "double-join"
                           : handle                   ? "double-close"
                                                      : "double-free";
        const std::string done = released(expect);
        if (some_freed) {
            std::string fl =
                freed_line ? " at line " + std::to_string(freed_line) : "";
            if (all_freed)
                report(rule,
                       "'" + p + "' is " + done + " again; it was already " +
                           done + fl,
                       at.line, at.col, alloc_line, freed_line);
            else if (!sites.count(0)) // with an untracked value the paths may
                                      // not correlate
                report(rule,
                       "'" + p + "' may be " + done +
                           " twice: on some paths it was already " + done + fl,
                       at.line, at.col, alloc_line, freed_line);
        } else if (known && mismatched == known &&
                   sites.size() == size_t(known)) {
            report("alloc-dealloc-mismatch",
                   object_text(sites_[size_t(mismatch_site)]) + " (line " +
                       std::to_string(alloc_line) + ") is released with " + how,
                   at.line, at.col, alloc_line, 0);
        }
        // Values that can only be null do not make the target ambiguous.
        size_t candidates = 0;
        for (int s : sites)
            if (!s || st.bits[s] != kNull)
                ++candidates;
        // With several candidates, one that nothing but p refers to is the
        // one released: had another been live here, assigning p would have
        // lost it (reported then).
        for (int s : sites) {
            if (!s || st.bits[s] == kNull)
                continue;
            const bool only_p =
                candidates == 1 || !referenced_elsewhere(st, s, p);
            st.bits[s] =
                only_p ? uint8_t(kFreed) : uint8_t(st.bits[s] | kFreed);
            st.freed_at[s] = at.line;
            if (params_by_site_.count(s)) // how this function releases it
                param_release_[s] = expect;
        }
        st.shifted.erase(p);
    }

    // ---- uses -----------------------------------------------------------
    // callee: the function p is passed to, if that is the use.
    void check_use(State &st, const std::string &p, const Token &at,
                   const std::string &callee = {}) {
        auto it = st.pts.find(p);
        if (it == st.pts.end() || it->second.empty())
            return;
        int freed_line = 0, alloc_line = 0;
        bool handles = true, fds = true;
        for (int s : it->second) {
            if (!s)
                return;
            uint8_t bt = st.bits[s];
            if (!(bt & kFreed) || (bt & (kAlloc | kNull | kExternal)))
                return;
            freed_line = st.freed_at.count(s) ? st.freed_at[s] : 0;
            const Site &si = sites_[size_t(s)];
            if (owned(si.kind))
                alloc_line = si.line;
            handles = handles && is_handle(si.kind);
            fds = fds && si.kind == SiteKind::Fd;
            if (si.kind == SiteKind::Thread || si.kind == SiteKind::VaList)
                return; // never "used": a number, or a va_list's own rules
        }
        // A descriptor is a number: only handing it to an I/O call uses it.
        if (fds && !kFdUsers.count(callee))
            return;
        const std::string when =
            freed_line ? " at line " + std::to_string(freed_line) : "";
        if (handles)
            report("use-after-close",
                   "'" + p + "' is used after it was closed" + when, at.line,
                   at.col, alloc_line, freed_line);
        else
            report("heap-use-after-free",
                   "'" + p + "' is used after it was released" + when, at.line,
                   at.col, alloc_line, freed_line);
    }

    // The variable stops holding its current value (reassigned, or declared
    // again on the next loop iteration). Blocks only it referenced are lost.
    void lose_value(State &st, const std::string &var,
                    const std::set<int> &keep, bool self_ref, const Token &at,
                    const char *why) {
        auto it = st.pts.find(var);
        if (it == st.pts.end())
            return;
        for (int s : it->second) {
            if (!s || keep.count(s))
                continue;
            if (self_ref) { // p = p + 1, p = p->next: still reachable in some
                            // form, unless another variable (the head the
                            // traversal started from) holds it as well
                if (!referenced_elsewhere(st, s, var))
                    st.bits[s] |= kEscaped;
                continue;
            }
            const Site &si = sites_[size_t(s)];
            if (owned(si.kind) && st.bits[s] == kAlloc &&
                !referenced_elsewhere(st, s, var) && !leak_reported_.count(s)) {
                leak_reported_.insert(s);
                report(leak_rule(si),
                       leaked_text(si) + " at line " + std::to_string(si.line) +
                           " is leaked when '" + var + "' " + why,
                       at.line, at.col, si.line, 0);
                st.bits[s] |= kEscaped;
            }
        }
    }

    // A site created again (next loop iteration) is a new object: variables
    // other than `holder` still hold the previous one, no longer tracked.
    void renew(State &st, int s, const std::string &holder) {
        for (auto &[p, pt] : st.pts)
            if (p != holder && pt.erase(s))
                pt.insert(0);
    }

    // The binding lhs is replaced, or its block ends: lhs->field named
    // the old object. Forget those keys (self moves keep the traversal
    // merged) and the sites nothing still names: an earlier
    // loop pass may have released them, while the next pass reuses the same
    // site for a new object.
    void forget_binding(State &st, const std::string &lhs, bool self_ref) {
        if (self_ref || lhs.find_first_of(".-:[") != std::string::npos)
            return;
        std::set<int> parked;
        for (const auto &[loc, s] : parked_)
            parked.insert(s);
        auto dead = [&](const std::string &key) {
            auto itp = st.pts.find(key);
            if (itp == st.pts.end())
                return;
            for (int s : itp->second)
                if (s && !referenced_elsewhere(st, s, key) &&
                    !parked.count(s)) {
                    st.bits.erase(s);
                    st.freed_at.erase(s);
                }
        };
        dead(lhs);
        for (auto it = st.pts.begin(); it != st.pts.end();) {
            const std::string &k = it->first;
            if (k.size() > lhs.size() && k.compare(0, lhs.size(), lhs) == 0 &&
                (k[lhs.size()] == '.' || k[lhs.size()] == '-' ||
                 k[lhs.size()] == '[')) {
                dead(k);
                st.shifted.erase(k);
                it = st.pts.erase(it);
            } else {
                ++it;
            }
        }
        st.shifted.erase(lhs);
    }

    // The local p in an argument written "&p", or "".
    std::string out_target(const Toks &t, std::pair<size_t, size_t> arg) {
        auto [b, e] = arg;
        strip(t, b, e);
        if (b + 1 >= e || !t[b].is("&"))
            return {};
        size_t pe;
        std::string p = path_at(t, b + 1, &pe);
        return !p.empty() && pe == e && is_local(p) ? p : std::string();
    }

    // t[b, e) is exactly asprintf(&p, ...) or another kOutAllocs call:
    // returns p, and whether the call fails with -1 (else with nonzero).
    std::string out_alloc_call(const Toks &t, size_t b, size_t e,
                               bool *minus_one) {
        size_t open = 0;
        auto o = kOutAllocs.find(call_name(t, b, e, &open));
        if (o == kOutAllocs.end() || match(t, open) != e - 1)
            return {};
        *minus_one = o->second.minus_one;
        // the argument that is "&p": skip the ones before it
        size_t ab = open + 1, ae = open + 1;
        for (size_t arg = 0;; ++arg) {
            ae = ab;
            for (int depth = 0;
                 ae < e - 1 && !(depth == 0 && t[ae].is(",")); ++ae)
                depth += t[ae].is("(") || t[ae].is("[")   ? 1
                         : t[ae].is(")") || t[ae].is("]") ? -1
                                                          : 0;
            if (arg == o->second.arg || ae >= e - 1)
                break;
            ab = ae + 1;
        }
        return o->second.arg == 0 || ae < e ? out_target(t, {ab, ae})
                                            : std::string();
    }

    // ---- releaser summaries ---------------------------------------------
    // Arguments a call to a same-file releaser releases: position -> how.
    const std::map<size_t, std::string> *
    released_by(const std::string &fname) const {
        if (!releasers_)
            return nullptr;
        auto it = releasers_->find(fname);
        return it == releasers_->end() ? nullptr : &it->second;
    }

    // ---- allocator summaries --------------------------------------------
    // A function of this file, analyzed earlier, that returns fresh memory.
    SiteKind summarized(const std::string &fname) const {
        if (!allocators_)
            return SiteKind::Unknown;
        auto it = allocators_->find(fname);
        if (it == allocators_->end())
            return SiteKind::Unknown;
        return it->second == "new"     ? SiteKind::New
               : it->second == "new[]" ? SiteKind::NewArray
                                       : SiteKind::Malloc;
    }

    void returned_fresh(SiteKind k) {
        if (returned_kind_ == SiteKind::Unknown)
            returned_kind_ = k;
        else if (returned_kind_ != k) // released two ways: no single rule
            returns_fresh_ = false;
    }

    // Does this return hand the caller memory only this function allocated
    // (or NULL)? Every return must, for the function to be an allocator.
    void note_return(const Toks &t, State &st) {
        size_t b = 0, e = t.size();
        strip(t, b, e);
        if (b >= e) { // a void return
            returns_fresh_ = false;
            return;
        }
        if (b + 1 == e && is_null_token(t[b]))
            return;
        if (t[b].is("new")) { // new T(...) / new T[n]; not placement new
            if (b + 1 < e && t[b + 1].is("(")) {
                returns_fresh_ = false;
                return;
            }
            bool array = false;
            for (size_t k = b + 1; k < e && !t[k].is("(") && !t[k].is("{"); ++k)
                array = array || t[k].is("[");
            returned_fresh(array ? SiteKind::NewArray : SiteKind::New);
            return;
        }
        size_t open = 0;
        const std::string fname = call_name(t, b, e, &open);
        if (!fname.empty() && match(t, open) == e - 1) {
            const SiteKind k =
                kMallocFns.count(fname) ? SiteKind::Malloc : summarized(fname);
            if (k == SiteKind::Unknown)
                returns_fresh_ = false;
            else
                returned_fresh(k);
            return;
        }
        size_t pe;
        const std::string p = path_at(t, b, &pe);
        if (p.empty() || pe != e || !tracked(st, p)) {
            returns_fresh_ = false;
            return;
        }
        for (int s : pts(st, p)) {
            const uint8_t bt = s ? st.bits[s] : 0;
            if (bt == kNull)
                continue;
            // Kept somewhere else too (a list, a global), freed, or not
            // ours: the caller does not simply own it.
            if (!s || !is_memory(sites_[size_t(s)].kind) || !(bt & kAlloc) ||
                (bt & (kFreed | kEscaped | kExternal))) {
                returns_fresh_ = false;
                return;
            }
            returned_fresh(sites_[size_t(s)].kind);
        }
    }

    // ---- assignment -----------------------------------------------------
    enum class Lhs { Local, NonLocal, None };

    // Effects of "lhs = rhs" where rhs is t[b, e). outlives: the storage
    // written to survives this function (global, static, or reached through
    // a pointer), so addresses of locals stored there will dangle.
    // p = malloc(strlen(a) + strlen(b)): no room for the terminating NUL
    // that strcpy/strcat then write. Remembers the strlen arguments of p's
    // size when it is made of nothing else (a "+ 1" anywhere forgets it).
    void note_strlen_alloc(const std::string &p, const Toks &t, size_t b,
                           size_t e) {
        std::vector<std::string> terms;
        size_t i = b;
        while (i < e) {
            if (!t[i].is("strlen") || i + 1 >= e || !t[i + 1].is("("))
                return;
            const size_t close = match(t, i + 1);
            size_t pe = 0;
            const std::string a = i + 2 < close ? path_at(t, i + 2, &pe) : "";
            if (close >= e || a.empty() || pe != close)
                return;
            terms.push_back(a);
            i = close + 1;
            if (i == e)
                break;
            if (!t[i].is("+")) // nothing but a sum of strlens
                return;
            ++i;
        }
        if (!terms.empty())
            strlen_alloc_[p] = {terms, t[b].line};
    }

    // strcpy(p, s) into a block sized strlen(s), or the strcat that writes
    // the last of a strlen sum: one byte too many.
    void check_strlen_overflow(const Toks &t, const std::string &fname,
                               const std::vector<std::pair<size_t, size_t>> &args,
                               const Token &at) {
        auto path_of = [&](std::pair<size_t, size_t> a) {
            auto [b, e] = a;
            strip(t, b, e);
            size_t pe = 0;
            const std::string p = b < e ? path_at(t, b, &pe) : std::string();
            return pe == e ? p : std::string();
        };
        const std::string dst = path_of(args[0]), src = path_of(args[1]);
        const auto it = strlen_alloc_.find(dst);
        if (it == strlen_alloc_.end() || src.empty())
            return;
        const auto &terms = it->second.first;
        if (std::find(terms.begin(), terms.end(), src) == terms.end())
            return;
        if (terms.size() == 1 ? fname == "strcat" : fname != "strcat")
            return;
        report("heap-buffer-overflow",
               "'" + dst + "' was allocated with malloc(strlen(" +
                   terms.back() + ")" + (terms.size() > 1 ? " + ..." : "") +
                   ") at line " + std::to_string(it->second.second) + ", " +
                   "which has no room for the terminating NUL: " + fname +
                   "() writes one byte past the end",
               at.line, at.col, it->second.second, 0);
    }

    void assign(State &st, const std::string &lhs, Lhs where, bool lhs_pointer,
                bool outlives, const Toks &t, size_t b, size_t e,
                const Token &at) {
        strip(t, b, e);
        // rc = posix_memalign(&p, ...): testing rc tells whether p was set.
        bool minus_one = false;
        if (const std::string p = out_alloc_call(t, b, e, &minus_one);
            !p.empty())
            out_result_[lhs] = {minus_one, p};
        else
            out_result_.erase(lhs);
        strlen_alloc_.erase(lhs);
        // What does the right-hand side evaluate to?
        std::set<int> value = {0};
        bool fresh_alloc = false;
        if (b < e) {
            size_t open = 0;
            std::string fname = call_name(t, b, e, &open);
            const bool whole_call = !fname.empty() && match(t, open) == e - 1;
            if (whole_call && fname == "malloc")
                note_strlen_alloc(lhs, t, open + 1, e - 1);
            if (t[b].is("new")) {
                size_t k = b + 1;
                bool placement = false;
                if (k < e && t[k].is("(")) {
                    size_t m = match(t, k);
                    bool nothrow = false;
                    for (size_t q = k + 1; q < m; ++q)
                        if (t[q].is("nothrow"))
                            nothrow = true;
                    placement = !nothrow;
                    k = m + 1;
                }
                bool array = false;
                for (size_t q = k; q < e; ++q) {
                    if (t[q].is("(") || t[q].is("{"))
                        break;
                    if (t[q].is("[")) {
                        array = true;
                        break;
                    }
                }
                if (!placement) {
                    value = {site_for(
                        t[b], array ? SiteKind::NewArray : SiteKind::New, lhs,
                        array ? "new[]" : "new")};
                    fresh_alloc = true;
                }
            } else if (whole_call &&
                       (kMallocFns.count(fname) ||
                        allocates_buffer(fname, t, open, e - 1))) {
                // xasprintf fills through &p in OpenSSH but returns a string
                // in busybox: the &p form is an out-param call, and this
                // variable keeps the unknown value {0} for it.
                bool mo = false;
                const bool is_out =
                    kOutAllocs.count(fname) > 0 &&
                    !out_alloc_call(t, b, e, &mo).empty();
                if (!is_out) {
                    value = {site_for(t[open - 1], SiteKind::Malloc, lhs,
                                      fname + "()")};
                    fresh_alloc = true;
                }
            } else if (const SiteKind k =
                           whole_call ? summarized(fname) : SiteKind::Unknown;
                       k != SiteKind::Unknown) {
                value = {site_for(t[open - 1], k, lhs, fname + "()")};
                fresh_alloc = true;
            } else if (whole_call && kReallocFns.count(fname)) {
                size_t ae = open + 1;
                int depth = 0;
                while (ae < e - 1 && !(depth == 0 && t[ae].is(","))) {
                    if (t[ae].is("(") || t[ae].is("["))
                        ++depth;
                    else if (t[ae].is(")") || t[ae].is("]"))
                        --depth;
                    ++ae;
                }
                size_t pe;
                std::string old = path_at(t, open + 1, &pe);
                if (!old.empty() && pe == ae && tracked(st, old)) {
                    if (old == lhs)
                        report("memory-leak",
                               "if " + fname +
                                   "() fails, the original block is leaked "
                                   "because '" +
                                   lhs +
                                   "' is overwritten with NULL; assign to a "
                                   "temporary first",
                               at.line, at.col, 0, 0);
                    // The old block is released only if realloc succeeds,
                    // which we cannot see: hand it over rather than free it,
                    // so "if (!q) free(p);" is not a double free.
                    check_use(st, old, t[open + 1]);
                    escape(st, old);
                }
                value = {
                    site_for(t[open - 1], SiteKind::Malloc, lhs, fname + "()")};
                fresh_alloc = true;
            } else if (auto op = kOpeners.find(fname);
                       whole_call && op != kOpeners.end() &&
                       count_args(t, open, e - 1) >= op->second.min_args &&
                       count_args(t, open, e - 1) <= op->second.max_args) {
                value = {
                    site_for(t[open - 1], op->second.kind, lhs, fname + "()")};
                fresh_alloc = true;
                if (op->second.kind != SiteKind::Fd) // NULL on failure
                    st.unchecked.insert(*value.begin());
            } else if (whole_call && fname == "fcntl" &&
                       dup_command(t, open, e - 1)) {
                value = {site_for(t[open - 1], SiteKind::Fd, lhs, "fcntl()")};
                fresh_alloc = true;
            } else if ((b + 1 == e && is_null_token(t[b])) ||
                       is_minus_one(t, b, e)) {
                int s = site_for(t[b], SiteKind::Unknown, lhs, "null");
                st.bits[s] = kNull;
                value = {s};
            } else if (t[b].kind == Tok::String && b + 1 == e) {
                int s = site_for(t[b], SiteKind::Literal, lhs, "literal");
                st.bits[s] = kExternal;
                value = {s};
            } else if (t[b].is("&") && b + 2 == e &&
                       t[b + 1].kind == Tok::Ident && is_local(t[b + 1].text)) {
                int s = site_for(t[b], SiteKind::Stack, lhs, t[b + 1].text);
                st.bits[s] = kExternal;
                value = {s};
                // Judged at exit: code often parks a local's address in an
                // outer object temporarily and restores it before returning.
                if (outlives && !ref_locals_.count(t[b + 1].text) &&
                    where == Lhs::NonLocal)
                    parked_[lhs] = s;
            } else {
                size_t pe;
                std::string src = path_at(t, b, &pe);
                if (!src.empty() && pe == e) {
                    if (arrays_.count(src) && is_local(src)) {
                        // Not reported when stored: the target may copy it
                        // (std::string, std::array). Freeing it still is.
                        int s = site_for(t[b], SiteKind::Stack, lhs, src);
                        st.bits[s] = kExternal;
                        value = {s};
                    } else if (tracked(st, src)) {
                        value = pts(st, src);
                        if (where == Lhs::NonLocal)
                            escape(st, src);
                        else if (where == Lhs::Local && !lhs_pointer)
                            escape(st, src); // e.g. a smart pointer adopting it
                        if (st.shifted.count(src))
                            st.shifted.insert(lhs);
                    }
                }
            }
        }
        if (where == Lhs::None)
            return;
        bool self_ref = false; // p = p + 1, p = strdup(p)
        for (size_t k = b; k < e; ++k)
            if (t[k].kind == Tok::Ident && t[k].text == lhs)
                self_ref = true;
        if (fresh_alloc)
            for (int s : value)
                if (s) {
                    // Made again (a later loop iteration) while lhs still
                    // holds the previous one: that one is lost, unless some
                    // other variable has it, which renew is about to forget.
                    // (p = strdup(p) loses it too: the copy is new.)
                    std::set<int> others = pts(st, lhs);
                    if (where == Lhs::Local && others.erase(s) && lhs_pointer)
                        lose_value(st, lhs, others, false, at,
                                   "is overwritten");
                    renew(st, s, lhs);
                }
        // A descriptor lives in an int: that variable owns it, and -1 is its
        // null.
        bool holds_handle = where == Lhs::Local && is_minus_one(t, b, e);
        for (int s : value)
            if (s && fresh_alloc && where == Lhs::Local &&
                is_handle(sites_[size_t(s)].kind))
                holds_handle = true;
        if (holds_handle) {
            lhs_pointer = true;
            ptr_locals_.insert(lhs);
        }
        if (where == Lhs::NonLocal || !lhs_pointer) {
            // Stored somewhere that outlives this function, or adopted by an
            // object: ownership leaves our view. Keep tracking for misuse.
            for (int s : value)
                if (s && fresh_alloc)
                    st.bits[s] = kAlloc | kEscaped;
            if (where == Lhs::NonLocal || fresh_alloc)
                forget_binding(st, lhs, self_ref);
            if (where == Lhs::NonLocal || fresh_alloc)
                st.pts[lhs] = value;
            st.shifted.erase(lhs);
            return;
        }
        // Local pointer: is the old value lost?
        lose_value(st, lhs, value, self_ref, at, "is overwritten");
        const std::set<int> old = pts(st, lhs);
        for (int s : value)
            if (s && fresh_alloc)
                st.bits[s] = kAlloc;
        forget_binding(st, lhs, self_ref);
        st.pts[lhs] = value;
        st.shifted.erase(lhs);
        // A released object nothing refers to any more is gone. Forgetting
        // it keeps a join with this path from making it look released on
        // paths where it is still held ("close(fd); fd = -1;").
        for (int s : old)
            if (s && !value.count(s) && st.bits[s] == kFreed &&
                !referenced_elsewhere(st, s, lhs)) {
                st.bits.erase(s);
                st.freed_at.erase(s);
            }
    }

    // ---- one expression / declaration statement -------------------------
    // `a = b = malloc(n)` as "b = malloc(n); a = b".
    static bool split_chain(const Toks &t, std::vector<Toks> *pieces) {
        std::vector<size_t> eq; // top-level '=' tokens
        int depth = 0;
        for (size_t i = 0; i < t.size(); ++i) {
            if (t[i].is("(") || t[i].is("[") || t[i].is("{"))
                ++depth;
            else if (t[i].is(")") || t[i].is("]") || t[i].is("}"))
                --depth;
            else if (depth == 0 && t[i].is("="))
                eq.push_back(i);
            else if (depth == 0 && (t[i].is(",") || t[i].is("?")))
                return false;
        }
        if (eq.size() < 2)
            return false;
        // every target before the last '=' is a plain path
        size_t from = 0;
        std::vector<std::pair<size_t, size_t>> targets;
        for (size_t k = 0; k < eq.size(); ++k) {
            size_t pe = 0;
            if (!starts_path(t, from) || path_at(t, from, &pe).empty() ||
                pe != eq[k])
                return false;
            targets.emplace_back(from, eq[k]);
            from = eq[k] + 1;
        }
        const Toks rhs(t.begin() + long(from), t.end());
        const Token eq_tok = t[eq.back()];
        auto line_of = [&](size_t k) {
            Toks p(t.begin() + long(targets[k].first),
                   t.begin() + long(targets[k].second));
            return p;
        };
        Toks last = line_of(targets.size() - 1);
        last.push_back(eq_tok);
        last.insert(last.end(), rhs.begin(), rhs.end());
        pieces->push_back(std::move(last));
        for (size_t k = targets.size() - 1; k-- > 0;) {
            Toks p = line_of(k);
            p.push_back(eq_tok);
            const Toks src = line_of(k + 1);
            p.insert(p.end(), src.begin(), src.end());
            pieces->push_back(std::move(p));
        }
        return true;
    }

    // One statement. A lambda's body is not part of it (it runs later, and
    // its own declarations shadow ours): what it names counts as handed over.
    void exec(const Toks &t0, State &st, bool is_return, const Token *ret_tok) {
        if (!st.live || t0.empty())
            return;
        Toks clean;
        std::set<std::string> inside;
        const bool lambdas = without_lambda_bodies(t0, &clean, &inside);
        const Toks &t = lambdas ? clean : t0;
        // A deferred block that assigns a global ("exec_call = prev_call")
        // puts it back when the scope ends: whatever was stored in it by
        // then is not left behind.
        if (size_t defer_end = 0; const size_t open = defer_block(t0, &defer_end))
            assigned_roots(Toks(t0.begin() + long(open) + 1,
                                t0.begin() + long(defer_end)),
                           restored_by_defer_);
        std::vector<Toks> pieces;
        if (!is_return && split_chain(t, &pieces)) {
            for (const Toks &piece : pieces)
                exec_tokens(piece, st, false, nullptr, nullptr);
        } else {
            exec_tokens(t, st, is_return, ret_tok, lambdas ? &t0 : nullptr);
        }
        for (const std::string &name : inside)
            if (st.pts.count(name))
                escape(st, name);
    }

    void exec_tokens(const Toks &t, State &st, bool is_return,
                     const Token *ret_tok, const Toks *with_bodies) {
        if (!st.live || t.empty())
            return;
        std::vector<Declarator> decls;
        bool is_static = false;
        const bool decl =
            !is_return && parse_decl(t, decls, &is_static) && !decls.empty();
        // Areas excluded from "use" scanning.
        std::vector<char> skip(t.size(), 0);
        for (size_t i = 0; i < t.size(); ++i) {
            if ((t[i].is("sizeof") || t[i].is("decltype") ||
                 t[i].is("alignof") || t[i].is("typeid") ||
                 t[i].is("offsetof")) &&
                i + 1 < t.size() && t[i + 1].is("(")) {
                size_t m = match(t, i + 1);
                for (size_t k = i; k <= m && k < t.size(); ++k)
                    skip[k] = 1;
            }
        }

        check_thread_lambdas(with_bodies ? *with_bodies : t,
                             decl && decls.size() == 1 &&
                                     starts_std_thread(t, decls[0])
                                 ? decls[0].name
                                 : std::string());

        // 1. Uses of freed memory: dereferences and arguments.
        for (size_t i = 0; i < t.size(); ++i) {
            if (skip[i])
                continue;
            size_t pe;
            std::string p = path_at(t, i, &pe);
            if (p.empty())
                continue;
            // Each prefix followed by -> or [ is dereferenced.
            std::string prefix = t[i].text;
            for (size_t k = i + 1; k <= pe; k += 2) {
                if (k < t.size() &&
                    (t[k].is("->") ||
                     (k == pe && (t[k].is("[") || t[k].is("(")))))
                    check_use(st, prefix, t[i]);
                if (k + 1 < pe)
                    prefix += t[k].text + t[k + 1].text;
            }
            if (i > 0 && t[i - 1].is("*") && unary_before(t, i - 1))
                check_use(st, p, t[i]);
            i = pe - 1;
        }
        // Whole-argument uses of calls.
        for_each_call(t,
                      [&](const std::string &fname, size_t,
                          const std::vector<std::pair<size_t, size_t>> &args) {
                          if (kNoUse.count(fname))
                              return;
                          const auto *released = released_by(fname);
                          for (size_t i = 0; i < args.size(); ++i) {
                              if (released && released->count(i))
                                  continue; // a release, checked below
                              auto [ab, ae] = args[i];
                              strip(t, ab, ae);
                              size_t pe;
                              std::string p =
                                  ab < ae ? path_at(t, ab, &pe) : std::string();
                              if (!p.empty() && pe == ae && !skip[ab])
                                  check_use(st, p, t[ab], fname);
                          }
                      });

        // 1b. Streams used before any test for NULL. A test in this very
        // statement counts ("ok = f != NULL && fwrite(.., f)", "!f").
        for (size_t k = 0; k < t.size(); ++k) {
            auto is_test = [&](size_t j) {
                return t[j].is("==") || t[j].is("!=") || t[j].is("&&") ||
                       t[j].is("||");
            };
            if (t[k].kind == Tok::Ident && st.pts.count(t[k].text) &&
                ((k > 0 && (t[k - 1].is("!") || is_test(k - 1))) ||
                 (k + 1 < t.size() && (is_test(k + 1) || t[k + 1].is("?")))))
                for (int s : st.pts[t[k].text])
                    st.unchecked.erase(s);
        }
        for_each_call(t,
                      [&](const std::string &fname, size_t name_at,
                          const std::vector<std::pair<size_t, size_t>> &args) {
                          if (!kStreamUsers.count(fname))
                              return;
                          for (auto [ab, ae] : args) {
                              strip(t, ab, ae);
                              size_t pe;
                              std::string p =
                                  ab < ae ? path_at(t, ab, &pe) : std::string();
                              if (!p.empty() && pe == ae)
                                  check_unchecked(st, p, fname, t[name_at]);
                          }
                      });

        // 2. Releases.
        for (size_t i = 0; i < t.size(); ++i) {
            if (t[i].is("delete")) {
                size_t k = i + 1;
                bool arr = false;
                if (k + 1 < t.size() && t[k].is("[") && t[k + 1].is("]")) {
                    arr = true;
                    k += 2;
                }
                size_t e = k;
                int depth = 0;
                while (e < t.size() &&
                       !(depth == 0 &&
                         (t[e].is(",") || t[e].is(";") || t[e].is(")")))) {
                    if (t[e].is("(") || t[e].is("["))
                        ++depth;
                    else if (t[e].is(")") || t[e].is("]"))
                        --depth;
                    ++e;
                }
                do_free(st, t, k, e, arr ? "delete[]" : "delete",
                        arr ? SiteKind::NewArray : SiteKind::New, t[i]);
            }
        }
        for_each_call(
            t, [&](const std::string &fname, size_t name_at,
                   const std::vector<std::pair<size_t, size_t>> &args) {
                if ((fname == "free" || fname == "cfree") && args.size() == 1)
                    do_free(st, t, args[0].first, args[0].second, "free()",
                            SiteKind::Malloc, t[name_at]);
                if (auto c = kClosers.find(fname);
                    c != kClosers.end() &&
                    args.size() == (fname == "pthread_join" ? 2u : 1u))
                    do_free(st, t, args[0].first, args[0].second,
                            (fname + "()").c_str(), c->second, t[name_at]);
                if (const auto *released = released_by(fname))
                    for (const auto &[i, how] : *released)
                        if (i < args.size())
                            do_free(st, t, args[i].first, args[i].second,
                                    (fname + "()").c_str(), release_kind(how),
                                    t[name_at]);
                if (kCondWaits.count(fname) && args.size() >= 2) {
                    // The wait gives the mutex back, so it must be held.
                    const std::string m =
                        mutex_of(t, fname, name_at, {args[1]});
                    bool all = false;
                    if (const int s =
                            m.empty() ? 0 : released_lock(st, m, &all))
                        report_lock(
                            "unlocked-wait", m,
                            (all ? "waits with '" + m + "' unlocked:"
                                 : "may wait with '" + m +
                                       "' unlocked: on some paths") +
                                " this function unlocked it at line " +
                                std::to_string(st.freed_at[s]) +
                                "; a signal sent before the wait starts is "
                                "lost",
                            t[name_at].line, t[name_at].col,
                            sites_[size_t(s)].line, st.freed_at[s]);
                    return;
                }
                if (!kUnlockFns.count(fname))
                    return;
                const std::string m = mutex_of(t, fname, name_at, args);
                if (m.empty())
                    return;
                unlocked_.insert(m);
                bool all = false;
                if (const int s = released_lock(st, m, &all))
                    report_lock("foreign-unlock", m,
                                "'" + m +
                                    (all ? "' is unlocked again:"
                                         : "' may be unlocked twice: on some "
                                           "paths") +
                                    " it was already unlocked at line " +
                                    std::to_string(st.freed_at[s]) +
                                    "; unlocking a mutex nobody holds is "
                                    "undefined",
                                t[name_at].line, t[name_at].col,
                                sites_[size_t(s)].line, st.freed_at[s]);
                if (auto it = st.pts.find("lock:" + m); it != st.pts.end()) {
                    // Unlocked under an if where some paths already unlocked
                    // it: the condition is likely the flag that tells them
                    // apart ("if (locked)"), so the mutex is judged no more.
                    uint8_t done = kFreed;
                    for (int s : it->second)
                        if (s && guarded_ && (st.bits[s] & kFreed))
                            done = kFreed | kEscaped;
                    for (int s : it->second)
                        if (s) {
                            st.bits[s] = done;
                            st.freed_at[s] = t[name_at].line;
                        }
                }
            });

        // std::thread: t.join() and t.detach() release it; t.joinable() is
        // a test the program makes, so it is judged no more.
        for (size_t i = 0; i + 3 < t.size(); ++i) {
            if (!starts_path(t, i) ||
                !(t[i + 1].is(".") || t[i + 1].is("->")) ||
                t[i + 2].kind != Tok::Ident || !t[i + 3].is("(") ||
                !st.pts.count(t[i].text))
                continue;
            bool threads = false, other = false;
            for (int s : st.pts[t[i].text])
                if (s)
                    (sites_[size_t(s)].kind == SiteKind::Thread ? threads
                                                                : other) = true;
            if (!threads || other)
                continue;
            const Token &m = t[i + 2];
            if (m.is("join") || m.is("detach")) {
                if (m.is("detach"))
                    if (auto r = ref_threads_.find(t[i].text);
                        r != ref_threads_.end())
                        report("thread-stack-argument",
                               "'" + t[i].text +
                                   "' is detached, but its lambda (line " +
                                   std::to_string(r->second.first) +
                                   ") captures local " + r->second.second +
                                   " by reference: the thread can outlive "
                                   "them",
                               t[i].line, t[i].col, r->second.first, 0);
                const Toks just_t{t[i]}; // path_at would run on into ".join"
                do_free(st, just_t, 0, 1, (m.text + "()").c_str(),
                        SiteKind::Thread, t[i]);
            } else if (m.is("joinable")) {
                escape(st, t[i].text);
            }
        }

        // 3. Declarations and assignments.
        if (decl) {
            for (const Declarator &d : decls) {
                // A variable of an enclosing block is hidden, not lost.
                const bool hides = enter_scope(st, d.name);
                locals_.insert(d.name);
                if (is_static)
                    statics_.insert(d.name);
                if (d.array)
                    arrays_.insert(d.name);
                if (d.reference)
                    ref_locals_.insert(d.name);
                bool ptr = d.pointer && !d.array;
                bool auto_alloc = false;
                if (!ptr && d.init_kind == '=' && t[0].is("auto")) {
                    size_t ib = d.init_b, ie = d.init_e;
                    strip(t, ib, ie);
                    size_t open = 0;
                    std::string fn =
                        ib < ie ? call_name(t, ib, ie, &open) : std::string();
                    auto_alloc =
                        ib < ie && (t[ib].is("new") || kMallocFns.count(fn) ||
                                    kReallocFns.count(fn));
                }
                if (ptr || auto_alloc)
                    ptr_locals_.insert(d.name);
                // Normally the block's end released the previous binding;
                // one left over came round a loop through continue/goto.
                if (!hides) {
                    lose_value(st, d.name, {}, false, t[0],
                               "goes out of scope (loop iteration ends)");
                    // A new object: the old one's members are gone with it.
                    forget_binding(st, d.name, false);
                }
                st.pts.erase(d.name);
                st.shifted.erase(d.name);
                external_.erase(
                    d.name); // a new variable: not the object an old one named
                if (d.init_kind == '=' || (ptr && d.init_kind)) {
                    assign(st, d.name, is_static ? Lhs::NonLocal : Lhs::Local,
                           ptr || auto_alloc, is_static, t, d.init_b, d.init_e,
                           t[d.init_b < t.size() ? d.init_b : 0]);
                } else if (d.init_kind) {
                    escape_range(st, t, d.init_b,
                                 d.init_e); // Foo f(p), Foo f{p}
                }
                if (mentions_thread_type(t))
                    thread_vars_.insert(d.name);
                if (starts_std_thread(t, d)) {
                    const int s = site_for(t[0], SiteKind::Thread, d.name,
                                           "std::thread");
                    st.bits[s] = kAlloc;
                    st.pts[d.name] = {s};
                }
            }
        } else {
            for (size_t i = 1; i < t.size(); ++i) {
                if (!t[i].is("="))
                    continue;
                size_t e = rhs_end(t, i);
                std::string lhs;
                Lhs where = Lhs::None;
                bool lhs_ptr = false, outlives = true;
                size_t name_end = i;
                if (t[i - 1].is("]")) {
                    size_t open = rmatch(t, i - 1);
                    if (open < t.size() && open > 0) {
                        where = Lhs::NonLocal;
                        lhs = "[element]";
                        name_end = open;
                    }
                }
                if (name_end > 0 && t[name_end - 1].kind == Tok::Ident) {
                    size_t s = name_end - 1;
                    while (s >= 2 &&
                           (t[s - 1].is(".") || t[s - 1].is("->") ||
                            t[s - 1].is("::")) &&
                           t[s - 2].kind == Tok::Ident)
                        s -= 2;
                    size_t pe;
                    std::string path = path_at(t, s, &pe);
                    if (!path.empty() && pe == name_end) {
                        const std::string root = t[s].text;
                        // The local variable itself, or a member/element of a
                        // local struct or array, dies with the function. Going
                        // through a local pointer (p->x, p[i]) reaches outside.
                        const bool via_pointer = ptr_locals_.count(root) > 0;
                        const bool local_storage =
                            is_local(root) &&
                            ((path == root && name_end == i) ||
                             (!via_pointer &&
                              (t[s + 1].is(".") || name_end != i)));
                        bool deref =
                            s > 0 && t[s - 1].is("*") && unary_before(t, s - 1);
                        outlives = deref || !local_storage;
                        if (name_end != i)
                            lhs = path + "[]";
                        if (name_end ==
                            i) { // not an element: classify the path itself
                            if (deref)
                                where = Lhs::NonLocal, lhs = "*" + path;
                            else if (is_local(path))
                                where = Lhs::Local, lhs = path,
                                lhs_ptr = ptr_locals_.count(path) > 0;
                            else
                                where = Lhs::NonLocal, lhs = path;
                        }
                    }
                }
                if (where == Lhs::None) {
                    escape_range(st, t, i + 1, e);
                    continue;
                }
                assign(st, lhs, where, lhs_ptr, outlives, t, i + 1, e, t[i]);
            }
            // Pointer arithmetic on a tracked local.
            for (size_t i = 0; i < t.size(); ++i) {
                size_t pe;
                std::string p = path_at(t, i, &pe);
                if (p.empty() || !is_local(p) || !tracked(st, p))
                    continue;
                bool inc =
                    (pe < t.size() && (t[pe].is("++") || t[pe].is("--") ||
                                       t[pe].is("+=") || t[pe].is("-="))) ||
                    (i > 0 && (t[i - 1].is("++") || t[i - 1].is("--")));
                if (inc) {
                    st.shifted.insert(p);
                    escape(st, p);
                }
            }
        }

        // 4. Ownership leaving through calls, address-of, initializers.
        std::set<size_t> out_args; // tokens of the "&p" an out-call fills
        for_each_call(t, [&](const std::string &fname, size_t name_at,
                             const std::vector<std::pair<size_t, size_t>>
                                 &args) {
            // va_start(ap, x) / va_copy(ap, src): ap must reach va_end.
            if ((fname == "va_start" || fname == "va_copy") && !args.empty()) {
                auto [ab, ae] = args[0];
                strip(t, ab, ae);
                size_t pe;
                const std::string p =
                    ab < ae ? path_at(t, ab, &pe) : std::string();
                if (!p.empty() && pe == ae && is_local(p)) {
                    const int s =
                        site_for(t[name_at], SiteKind::VaList, p, fname + "()");
                    lose_value(st, p, {}, false, t[name_at], "is overwritten");
                    st.bits[s] = kAlloc;
                    st.pts[p] = {s};
                    return;
                }
            }
            if (fname == "pthread_create" && args.size() == 4)
                check_thread_argument(t, args[3], t[name_at]);
            if ((fname == "strcpy" || fname == "strcat" ||
                 fname == "stpcpy") &&
                args.size() == 2 && !strlen_alloc_.empty())
                check_strlen_overflow(t, fname, args, t[name_at]);
            // sqlite3ParseObjectReset(&sParse): a local whose address was
            // parked in an outer object, handed to a call that undoes things
            if (!parked_.empty()) {
                std::string low;
                for (char c : fname)
                    low += char(std::tolower(static_cast<unsigned char>(c)));
                bool undoes = false;
                for (const char *word :
                     {"reset", "restore", "release", "cleanup", "destroy",
                      "free", "pop", "exit", "finish", "done", "close",
                      "unlink", "detach", "clear", "teardown", "end"})
                    undoes = undoes || low.find(word) != std::string::npos;
                if (undoes)
                    for (auto [ab, ae] : args) {
                        strip(t, ab, ae);
                        if (ab + 1 < ae && t[ab].is("&") &&
                            t[ab + 1].kind == Tok::Ident)
                            for (auto it = parked_.begin(); it != parked_.end();)
                                it = sites_[size_t(it->second)].how ==
                                             t[ab + 1].text
                                         ? parked_.erase(it)
                                         : std::next(it);
                    }
            }
            // node's ObjectWrap::Wrap(obj): the JavaScript object owns it now
            if (fname == ".Wrap" && name_at >= 2 &&
                t[name_at - 2].kind == Tok::Ident)
                escape(st, t[name_at - 2].text);
            // One wait, no loop: a spurious wakeup passes it.
            // (cv.wait(lk) with a unique_lock and no predicate is the C++ one)
            bool cxx_wait = false;
            if (fname == ".wait" && args.size() == 1) {
                size_t wb = args[0].first, we = args[0].second;
                strip(t, wb, we);
                cxx_wait = wb + 1 == we && guard_mutex_.count(t[wb].text);
            }
            if ((fname == "pthread_cond_wait" || fname == "cnd_wait" ||
                 cxx_wait) &&
                !in_loop() && !fn_has_goto_)
                report("spurious-wakeup",
                       (cxx_wait ? std::string("wait") : fname) +
                           "() is not inside a loop that tests the condition "
                           "again: a spurious wakeup, or another thread "
                           "taking what the signal announced, lets this "
                           "thread go on with the condition false",
                       t[name_at].line, t[name_at].col, 0, 0);
            // A call made while certainly holding a mutex: what the callee
            // locks comes after it (with_calls).
            if (orders_ && fname[0] != '.' && !kLockFns.count(fname) &&
                !kUnlockFns.count(fname) && !kCondWaits.count(fname))
                for (const auto &[var, sites] : st.pts)
                    if (var.rfind("lock:", 0) == 0 && sites.size() == 1 &&
                        !sites.count(0) && st.bits[*sites.begin()] == kAlloc)
                        orders_->push_back(
                            {var.substr(5), "", fn_.name, t[name_at].line,
                             sites_[size_t(*sites.begin())].line, "", fname});
            // A stream handed to anything but a stream call (assert(f),
            // GGML_ASSERT(f), a helper) counts as tested.
            if (!kStreamUsers.count(fname))
                for (auto [ab, ae] : args) {
                    strip(t, ab, ae);
                    size_t pe;
                    std::string p =
                        ab < ae ? path_at(t, ab, &pe) : std::string();
                    if (!p.empty() && pe == ae)
                        for (int s : pts(st, p))
                            st.unchecked.erase(s);
                }
            const bool grows = kOutGrows.count(fname) > 0;
            const auto out = kOutAllocs.find(fname);
            const SiteKind kind =
                out != kOutAllocs.end() ? out->second.kind : SiteKind::Malloc;
            // A thread started with attributes may be detached already.
            const bool attrs = kind == SiteKind::Thread &&
                               (args.size() != 4 ||
                                !is_null_arg(t, args[1].first, args[1].second));
            const size_t out_idx =
                out != kOutAllocs.end() ? out->second.arg : 0;
            if (const std::string p = (grows || out != kOutAllocs.end()) &&
                                              args.size() > out_idx && !attrs
                                          ? out_target(t, args[out_idx])
                                          : std::string();
                !p.empty()) {
                {
                    auto [ob, oe] = args[out_idx];
                    strip(t, ob, oe);
                    out_args.insert(ob); // the "&": not an address taken
                }
                const int s = site_for(t[name_at], kind, p, fname + "()");
                if (grows) // the old buffer lives on in the new one
                    escape(st, p);
                else { // {}: what an earlier loop iteration made here is lost too
                    lose_value(st, p, {}, false, t[name_at], "is overwritten");
                    // The new object replaces the old one, like an assignment
                    // does (unless the call also reads it, as in
                    // xasprintf(&p, "%s", p)).
                    bool self = false;
                    for (size_t ai = 0; ai < args.size() && !self; ++ai) {
                        if (ai == out_idx)
                            continue;
                        auto abae = args[ai];
                        for (size_t k = abae.first; k < abae.second; ++k)
                            if (t[k].kind == Tok::Ident && t[k].text == p) {
                                self = true;
                                break;
                            }
                    }
                    forget_binding(st, p, self);
                }
                renew(st, s, p);
                st.bits[s] = kAlloc;
                st.pts[p] = {s};
                ptr_locals_.insert(p);
                return;
            }
            if (kTerminators.count(fname))
                terminate_ = true;
            // A mutex handed to some other function may be unlocked there
            // (a lock guard's declaration "std::lock_guard<..> g(m)" looks
            // like a call g(m) and does not do that).
            if (!kLockFns.count(fname) && !kUnlockFns.count(fname) &&
                !kCondWaits.count(fname) && !is_lock_guard_decl(t))
                for (auto [ab, ae] : args) {
                    strip(t, ab, ae);
                    if (ab < ae && t[ab].is("&"))
                        ++ab;
                    size_t pe;
                    std::string p =
                        ab < ae ? path_at(t, ab, &pe) : std::string();
                    if (!p.empty() && pe == ae)
                        escape(st, "lock:" + p);
                }
            // A mutex this function unlocked may be held again after a
            // lock whose result is tested (acquire does not follow it),
            // or after a call that reaches the mutex: a global or member
            // one, or one under an argument ("ctx_lock(c)" for c->mu).
            if (!kUnlockFns.count(fname) && !kCondWaits.count(fname) &&
                !kNonOwning.count(fname) && !kNoUse.count(fname) &&
                !kMallocFns.count(fname) && !kReallocFns.count(fname) &&
                !kClosers.count(fname) && !kTerminators.count(fname))
                for (const auto &[var, sites] : st.pts) {
                    if (var.rfind("lock:", 0) != 0)
                        continue;
                    const std::string m = var.substr(5);
                    const std::string root =
                        m.substr(0, m.find_first_of(".-["));
                    bool reach = kLockFns.count(fname)
                                     ? mutex_of(t, fname, name_at, args) == m
                                     : fname[0] == '.' || !locals_.count(root);
                    for (auto [ab, ae] : args)
                        for (size_t k = ab; k < ae && !reach; ++k)
                            reach = t[k].kind == Tok::Ident &&
                                    t[k].text == root && !kLockFns.count(fname);
                    if (reach)
                        for (int s : sites)
                            if (s && (st.bits[s] & kFreed))
                                st.bits[s] |= kEscaped;
                }
            if (kNonOwning.count(fname) || kMallocFns.count(fname) ||
                kReallocFns.count(fname) || fname == "free" ||
                fname == "cfree" || kClosers.count(fname))
                return;
            const auto *released = released_by(fname);
            for (size_t i = 0; i < args.size(); ++i) {
                if (released && released->count(i))
                    continue; // released, not handed over
                auto [ab, ae] = args[i];
                strip(t, ab, ae);
                size_t pe;
                std::string p = ab < ae ? path_at(t, ab, &pe) : std::string();
                if (!p.empty() && pe == ae)
                    escape(st, p);
            }
        });
        for (size_t i = 0; i + 1 < t.size(); ++i) {
            const bool out_arg = // asprintf(&p, ...): handled above
                out_args.count(i) ||
                (i >= 2 && t[i - 1].is("(") &&
                 (kOutAllocs.count(t[i - 2].text) ||
                  kOutGrows.count(t[i - 2].text)));
            if (t[i].is("&") && unary_before(t, i) && !out_arg) {
                size_t pe;
                std::string p = path_at(t, i + 1, &pe);
                if (!p.empty() && tracked(st, p)) {
                    escape(st, p);
                    if (!decl)
                        st.pts[p] = {0};
                }
            }
            if (t[i].is("{")) { // initializer list or lambda body
                size_t m = match(t, i);
                escape_range(st, t, i + 1, m);
                i = m < t.size() ? m : i;
            }
        }
        for (size_t i = 0; i + 1 < t.size(); ++i) // lambda captures [p], [&p]
            if (t[i].is("[") && (i == 0 || !starts_path(t, i - 1)) &&
                !(i > 0 && t[i - 1].is("]")))
                if (size_t m = match(t, i);
                    m + 1 < t.size() && t[m + 1].is("("))
                    escape_range(st, t, i + 1, m);

        // 5. Returns hand ownership to the caller.
        if (is_return)
            note_return(t, st);
        if (is_return) {
            for (size_t i = 0; i < t.size(); ++i) {
                size_t pe;
                std::string p = path_at(t, i, &pe);
                if (p.empty())
                    continue;
                bool deref =
                    (pe < t.size() &&
                     (t[pe].is("->") || t[pe].is("[") || t[pe].is("."))) ||
                    (i > 0 && t[i - 1].is("*") && unary_before(t, i - 1));
                bool addr = i > 0 && t[i - 1].is("&") && unary_before(t, i - 1);
                // Parameters are skipped: their type may be a reference
                // typedef.
                if (addr && is_local(p) && pe == t.size() && i == 1 &&
                    !ref_locals_.count(p) && !params_.count(p))
                    report("dangling-pointer",
                           "returns the address of local '" + p + "'",
                           ret_tok->line, ret_tok->col, 0, 0);
                else if (!deref && !addr && i == 0 && pe == t.size() &&
                         is_local(p) && arrays_.count(p) &&
                         !statics_.count(p) && fn_.returns_pointer)
                    report("dangling-pointer",
                           "returns local array '" + p + "'", ret_tok->line,
                           ret_tok->col, 0, 0);
                else if (!deref && i == 0 && pe == t.size() && tracked(st, p)) {
                    bool all_stack = true;
                    std::string target;
                    for (int s : pts(st, p)) {
                        if (!s || sites_[size_t(s)].kind != SiteKind::Stack)
                            all_stack = false;
                        else
                            target = sites_[size_t(s)].how;
                    }
                    if (all_stack)
                        report("dangling-pointer",
                               "returns '" + p + "', which points to local '" +
                                   target + "'",
                               ret_tok->line, ret_tok->col, 0, 0);
                }
                if (!deref)
                    escape(st, p);
                i = pe - 1;
            }
        }
        if (t[0].is("throw"))
            st.live = false;
    }

    void escape_range(State &st, const Toks &t, size_t b, size_t e) {
        for (size_t i = b; i < e && i < t.size(); ++i) {
            size_t pe;
            std::string p = path_at(t, i, &pe);
            if (!p.empty()) {
                escape(st, p);
                i = pe - 1;
            }
        }
    }

    static size_t rhs_end(const Toks &t, size_t eq) {
        int depth = 0;
        size_t k = eq + 1;
        for (; k < t.size(); ++k) {
            if (t[k].is("(") || t[k].is("[") || t[k].is("{"))
                ++depth;
            else if (t[k].is(")") || t[k].is("]") || t[k].is("}")) {
                if (--depth < 0)
                    break;
            } else if (depth == 0 && (t[k].is(",") || t[k].is(";")))
                break;
        }
        return k;
    }

    // Calls f(name, index of name, argument ranges). Method calls get a
    // leading '.' and non-std qualified names keep their qualifier, so they
    // never match the C library names.
    template <class F> void for_each_call(const Toks &t, F f) {
        for (size_t i = 0; i + 1 < t.size(); ++i) {
            if (t[i].kind != Tok::Ident || kKeywords.count(t[i].text))
                continue;
            // The paren: right after the name, or after the template
            // arguments of a smart pointer made from a raw one,
            // std::shared_ptr<T>(p), which takes ownership of it.
            size_t open = i + 1;
            if (t[i + 1].is("<") &&
                (t[i].is("shared_ptr") || t[i].is("unique_ptr") ||
                 t[i].is("intrusive_ptr") || t[i].is("scoped_ptr"))) {
                const size_t close = match(t, i + 1);
                if (close + 1 < t.size() && t[close + 1].is("("))
                    open = close + 1;
            }
            if (!t[open].is("("))
                continue;
            std::string name = t[i].text;
            if (i > 0 && (t[i - 1].is(".") || t[i - 1].is("->")))
                name = "." + name;
            else if (i > 1 && t[i - 1].is("::") && !t[i - 2].is("std"))
                name = t[i - 2].text + "::" + name;
            size_t m = match(t, open);
            std::vector<std::pair<size_t, size_t>> args;
            size_t b = open + 1;
            int depth = 0;
            for (size_t k = open + 1; k < m && k < t.size(); ++k) {
                if (t[k].is("(") || t[k].is("[") || t[k].is("{"))
                    ++depth;
                else if (t[k].is(")") || t[k].is("]") || t[k].is("}"))
                    --depth;
                else if (depth == 0 && t[k].is(",")) {
                    args.emplace_back(b, k);
                    b = k + 1;
                }
            }
            if (b < m && m <= t.size())
                args.emplace_back(b, m);
            f(name, i, args);
        }
    }

    // ---- condition refinement -------------------------------------------
    // Narrows "p is null" / "p is not null" for simple conditions.
    void refine(const Toks &t, size_t b, size_t e, State &st, bool truth) {
        if (!st.live || b >= e)
            return;
        // A condition that mentions a stream tests it ("if (!f)",
        // "if ((f = fopen(...)) == NULL)"); its uses there came first.
        for (size_t k = b; k < e; ++k)
            if (t[k].kind == Tok::Ident && st.pts.count(t[k].text))
                for (int s : st.pts[t[k].text])
                    st.unchecked.erase(s);
        while (b < e && t[b].is("(") && match(t, b) == e - 1)
            ++b, --e;
        // while (0), while (1), if (false): one way out is impossible
        if (e == b + 1) {
            const std::string &v = t[b].text;
            if (((v == "0" || v == "false") && truth) ||
                ((v == "1" || v == "true") && !truth)) {
                st = dead_state();
                return;
            }
        }
        // a && b (true) / a || b (false): both halves hold
        int depth = 0;
        for (size_t k = b; k < e; ++k) {
            if (t[k].is("(") || t[k].is("["))
                ++depth;
            else if (t[k].is(")") || t[k].is("]"))
                --depth;
            else if (depth == 0 && (t[k].is("&&") || t[k].is("||"))) {
                if ((t[k].is("&&") && truth) || (t[k].is("||") && !truth)) {
                    refine(t, b, k, st, truth);
                    refine(t, k + 1, e, st, truth);
                }
                return;
            }
        }
        bool negate = false;
        while (b < e && t[b].is("!")) {
            negate = !negate;
            ++b;
        }
        while (b < e && t[b].is("(") && match(t, b) == e - 1)
            ++b, --e;
        // p == NULL, NULL == p, p != NULL; for a descriptor fd < 0,
        // fd == -1, fd <= -1 (failed) and fd >= 0, fd != -1, fd > -1.
        // cmp_eq: the comparison holds when the value is "null".
        bool cmp_null = false, cmp_fd = false, cmp_eq = false, cmp_std = false;
        for (size_t k = b; k < e; ++k) {
            if (t[k].is("(") || t[k].is("["))
                k = match(t, k);
            else if (t[k].is("<") || t[k].is("<=") || t[k].is(">") ||
                     t[k].is(">=") || t[k].is("==") || t[k].is("!=")) {
                std::string op = t[k].text;
                bool zero = k + 2 == e && t[k + 1].is("0");
                bool minus1 = is_minus_one(t, k + 1, e);
                bool left = false; // the constant comes first: -1 == fd
                if (!zero && !minus1) {
                    zero = k == b + 1 && t[b].is("0");
                    minus1 = is_minus_one(t, b, k);
                    left = zero || minus1;
                    if (left) // read it the other way round: fd OP' c
                        op = op == "<"    ? ">"
                             : op == ">"  ? "<"
                             : op == "<=" ? ">="
                             : op == ">=" ? "<="
                                          : op;
                }
                const bool eq = op == "==" || op == "!=";
                if ((op == "<" && zero) ||
                    ((op == "==" || op == "<=") && minus1))
                    cmp_fd = cmp_eq = true;
                else if ((op == ">=" && zero) ||
                         ((op == "!=" || op == ">") && minus1))
                    cmp_fd = true;
                if (cmp_fd) { // keep just the variable
                    if (left)
                        b = k + 1;
                    else
                        e = k;
                } else if (eq && k + 2 == e &&
                           (t[k + 1].is("stdout") || t[k + 1].is("stderr") ||
                            t[k + 1].is("stdin"))) {
                    cmp_std = true; // out == stdout: not a stream of ours
                    cmp_eq = t[k].is("==");
                    e = k;
                } else if (eq && k + 2 == e && is_null_token(t[k + 1])) {
                    cmp_null = true;
                    cmp_eq = t[k].is("==");
                    e = k;
                } else if (eq && k == b + 1 && is_null_token(t[b])) {
                    cmp_null = true;
                    cmp_eq = t[k].is("==");
                    b = k + 1;
                }
                break;
            }
        }
        while (b < e && t[b].is("(") && match(t, b) == e - 1)
            ++b, --e;
        const bool cmp = cmp_null || cmp_fd;
        // The tested value is its "null": 0 or NULL, or -1 for cmp_fd.
        bool is_null = cmp ? (cmp_eq == truth) : (negate == truth);
        if (negate && cmp)
            is_null = !is_null;
        // asprintf(&p, ...) < 0, posix_memalign(&p, ...) != 0, or a variable
        // holding such a result: where the call failed, p holds nothing.
        bool minus_one = false;
        std::string target = out_alloc_call(t, b, e, &minus_one);
        if (target.empty() && b + 1 == e)
            if (auto r = out_result_.find(t[b].text); r != out_result_.end())
                minus_one = r->second.first, target = r->second.second;
        if (!target.empty()) {
            // failed: a nonzero result; a -1 result also by "< 0"/"== -1"
            if ((minus_one && cmp_fd && is_null) || (!cmp_fd && !is_null))
                for (int s : pts(st, target))
                    if (s && st.bits[s] == kAlloc)
                        st.bits[s] = kNull;
            return;
        }
        // (p = expr): the assigned variable is what is tested; so is the
        // one a condition declares, if (FILE *f = fopen(..))
        for (size_t k = b; k < e; ++k) {
            if (t[k].is("(") || t[k].is("["))
                k = match(t, k);
            else if (t[k].is("=")) {
                e = k;
                if (k > b + 1 && t[k - 1].kind == Tok::Ident &&
                    !(t[k - 2].is(".") || t[k - 2].is("->") ||
                      t[k - 2].is("::")))
                    b = k - 1;
                break;
            }
        }
        size_t pe;
        std::string p = b < e ? path_at(t, b, &pe) : std::string();
        if (p.empty() || pe != e || !tracked(st, p))
            return;
        if (cmp_std) {
            // "out = ok ? fopen(..) : stdout; ... if (out == stdout)": where
            // it is stdout, it is none of the streams this function opened
            if (cmp_eq == (negate ? !truth : truth)) {
                for (int s : pts(st, p)) // the opening did not happen here
                    if (s && (st.bits[s] & kAlloc) &&
                        !referenced_elsewhere(st, s, p))
                        st.bits[s] = kNull;
                st.pts[p] = {0};
            }
            return;
        }
        std::set<int> sites = pts(st, p);
        // A descriptor fails as -1, so only sign tests say whether it is
        // open; a pointer is tested for null.
        bool fd_sites = false, ptr_sites = false;
        for (int s : sites) {
            const SiteKind k = sites_[size_t(s)].kind;
            if (k == SiteKind::Fd)
                fd_sites = true;
            else if (s && k != SiteKind::Unknown && k != SiteKind::External)
                ptr_sites = true;
        }
        if (cmp_fd ? (ptr_sites || !fd_sites) : fd_sites)
            return;
        // Values that can only be null do not make the target ambiguous.
        std::vector<int> real;
        for (int s : sites)
            if (!s || st.bits[s] != kNull)
                real.push_back(s);
        if (is_null) {
            // p is null here, so whichever of its allocations it holds
            // failed. With several candidates, only those nothing else
            // refers to can be judged that way.
            for (int s : real) {
                if (!s || (real.size() > 1 && referenced_elsewhere(st, s, p)))
                    continue;
                if (st.bits[s] & kNull)
                    st.bits[s] = kNull;
                else if (!(st.bits[s] & (kExternal | kEscaped)) &&
                         st.bits[s] == kAlloc)
                    st.bits[s] = kNull; // allocation failed on this path
                else if (st.bits[s] == kExternal && params_by_site_.count(s))
                    st.bits[s] = kNull; // "if (!p) return;" in a releaser
            }
        } else {
            bool any = false;
            for (int s : sites) {
                if (!s) {
                    any = true;
                    continue;
                }
                uint8_t bt = st.bits[s] & uint8_t(~kNull);
                if (bt)
                    any = true;
                if (real.size() == 1)
                    st.bits[s] = bt ? bt : st.bits[s];
            }
            if (!any)
                st.live =
                    false; // p is known to be null here: branch unreachable
        }
    }

    // ---- exits ----------------------------------------------------------
    // ---- locks ----------------------------------------------------------
    // The mutex a lock or unlock call acts on, as written ("m", "s->mu"),
    // or "" when it is not a plain path.
    std::string mutex_of(const Toks &t, const std::string &fname, size_t at,
                         const std::vector<std::pair<size_t, size_t>> &args) {
        size_t b, e;
        if (fname[0] == '.') { // m.lock(), s->mu.unlock()
            if (!args.empty() || at < 2 || t[at - 2].kind != Tok::Ident)
                return {};
            e = at - 1;
            b = at - 2;
            while (b >= 2 && (t[b - 1].is(".") || t[b - 1].is("->")) &&
                   t[b - 2].kind == Tok::Ident)
                b -= 2;
            // A local object is a lock guard (std::unique_lock): its
            // destructor releases the mutex. lk.lock() and lk.unlock() act
            // on the mutex it was made with.
            if (b + 1 == e && is_local(t[b].text)) {
                const auto g = guard_mutex_.find(t[b].text);
                return g == guard_mutex_.end() ? std::string() : g->second;
            }
            std::string p;
            for (size_t k = b; k < e; ++k)
                p += t[k].text;
            return p;
        } else { // pthread_mutex_lock(&m)
            if (args.size() != 1)
                return {};
            b = args[0].first, e = args[0].second;
            strip(t, b, e);
            if (b < e && t[b].is("&"))
                ++b;
        }
        if (b >= e)
            return {}; // no argument: not a name at all
        size_t pe;
        const std::string p = path_at(t, b, &pe);
        return pe == e ? p : std::string();
    }

    // A lock site of m when this function unlocked m on every path that
    // reaches here (*all) or on some, with no path that never locked it here
    // and no unseen relock (escaped); 0 otherwise. "Some" is not judged under
    // an if, whose condition may be the flag that tells the paths apart
    // ("if (locked) unlock(&m);").
    int released_lock(const State &st, const std::string &m, bool *all) const {
        auto it = st.pts.find("lock:" + m);
        if (it == st.pts.end() || it->second.count(0))
            return 0;
        int freed = 0;
        *all = true;
        for (int s : it->second) {
            auto b = st.bits.find(s);
            const uint8_t bt = b == st.bits.end() ? 0 : b->second;
            if (bt & kEscaped)
                return 0;
            if (bt & kFreed)
                freed = s;
            if (bt != kFreed)
                *all = false;
        }
        return *all || !guarded_ ? freed : 0;
    }

    // "lock(&m);" as a whole statement: m is held from here on. A lock
    // whose result is tested may have failed, so it is not followed.
    void acquire(const Toks &t0, State &st) {
        if (!st.live)
            return;
        Toks clean; // a lambda's body locks when it runs, not here
        const Toks &t = without_lambda_bodies(t0, &clean, nullptr) ? clean : t0;
        acquire_guard(t, st);
        for_each_call(
            t, [&](const std::string &fname, size_t at,
                   const std::vector<std::pair<size_t, size_t>> &args) {
                if (!kLockFns.count(fname))
                    return;
                for (size_t k = 0; k < at; ++k) // only "(void)" or the receiver
                    if (!(t[k].kind == Tok::Ident || t[k].is(".") ||
                          t[k].is("->") || t[k].is("::") ||
                          (k < 3 && (t[k].is("(") || t[k].is(")")))))
                        return;
                const std::string m = mutex_of(t, fname, at, args);
                if (m.empty())
                    return;
                // lk.lock() on a unique_lock: its destructor lets go again
                const bool of_guard = fname[0] == '.' && at >= 2 &&
                                      guard_mutex_.count(t[at - 2].text);
                if (of_guard)
                    if (auto d = guard_depth_.find(t[at - 2].text);
                        d != guard_depth_.end() && d->second >= 1 &&
                        d->second <= scopes_.size())
                        scopes_[d->second - 1].guards.push_back(m);
                take_lock(st, t[at], m,
                          (fname[0] == '.' ? fname.substr(1) : fname) + "()",
                          !of_guard, of_guard);
            });
    }

    // m is locked at `at`: by a lock call, or by a lock guard's declaration.
    void take_lock(State &st, const Token &at, const std::string &m,
                   const std::string &how, bool check_double, bool guard) {
        const std::string var = "lock:" + m;
        if (auto it = st.pts.find(var);
            check_double && it != st.pts.end() && it->second.size() == 1) {
            const int held = *it->second.begin();
            if (held && st.bits[held] == kAlloc)
                report_lock("double-lock", m,
                            "'" + m +
                                "' is locked again while already "
                                "held (locked at line " +
                                std::to_string(sites_[size_t(held)].line) +
                                "); a non-recursive mutex deadlocks here",
                            at.line, at.col, sites_[size_t(held)].line);
        }
        // Locked while others are certainly held: an order, judged
        // across the file's functions (lock_inversions).
        if (orders_)
            for (const auto &[other, sites] : st.pts)
                if (other.rfind("lock:", 0) == 0 && other != var &&
                    sites.size() == 1 && !sites.count(0) &&
                    st.bits[*sites.begin()] == kAlloc)
                    orders_->push_back({other.substr(5), m, fn_.name, at.line,
                                        sites_[size_t(*sites.begin())].line, "", ""});
        if (orders_) // what this function locks, for its callers
            orders_->push_back({"", m, fn_.name, at.line, 0, "", ""});
        const int s = site_for(at, SiteKind::Lock, m, how);
        if (guard)
            guard_sites_.insert(s);
        st.bits[s] = kAlloc;
        st.pts[var] = {s};
    }

    // A lock guard declared as a whole statement:
    //   std::lock_guard<std::mutex> g(m);   std::unique_lock<std::mutex> lk(m);
    //   std::scoped_lock lk(m);   lk(m, std::defer_lock);   lk(m, std::adopt_lock);
    // It holds m until its block ends (or lk.unlock()), without a lock-leak.
    static bool is_lock_guard_decl(const Toks &t) {
        size_t i = t.size() > 2 && t[0].is("std") && t[1].is("::") ? 2 : 0;
        return i < t.size() && (t[i].is("lock_guard") || t[i].is("unique_lock") ||
                                t[i].is("scoped_lock"));
    }

    void acquire_guard(const Toks &t, State &st) {
        if (!is_lock_guard_decl(t))
            return;
        size_t i = t[0].is("std") ? 2 : 0;
        const Token &kind = t[i++];
        std::string targs;
        if (i < t.size() && t[i].is("<")) {
            const size_t e = match(t, i);
            for (size_t k = i + 1; k < e && k < t.size(); ++k)
                targs += t[k].text;
            i = e + 1;
        }
        if (i + 2 >= t.size() || t[i].kind != Tok::Ident ||
            !(t[i + 1].is("(") || t[i + 1].is("{")))
            return;
        const std::string var = t[i].text;
        const size_t open = i + 1, close = match(t, open);
        std::vector<std::pair<size_t, size_t>> args;
        for (size_t b = open + 1, k = open + 1, depth = 0; k <= close && k < t.size();
             ++k) {
            if (t[k].is("(") || t[k].is("[") || t[k].is("{"))
                ++depth;
            else if (k == close || (depth == 0 && t[k].is(","))) {
                args.emplace_back(b, k);
                b = k + 1;
            } else if (t[k].is(")") || t[k].is("]") || t[k].is("}"))
                --depth;
        }
        if (args.empty() || args.size() > 2)
            return;
        auto [b, e] = args[0];
        strip(t, b, e);
        if (b < e && t[b].is("&"))
            ++b;
        size_t pe = 0;
        const std::string m = b < e ? path_at(t, b, &pe) : std::string();
        if (m.empty() || pe != e)
            return;
        bool acquiring = true, adopting = false;
        if (args.size() == 2) {
            const Token &tag = t[args[1].second - 1];
            if (tag.is("defer_lock"))
                acquiring = false;
            else if (tag.is("adopt_lock"))
                acquiring = false, adopting = true;
            else
                return; // try_to_lock and friends: it may not hold the lock
        }
        guard_mutex_[var] = m;
        guard_depth_[var] = scopes_.size();
        unlocked_.insert(m); // released by the guard
        if (acquiring || adopting)
            if (!scopes_.empty())
                scopes_.back().guards.push_back(m);
        if (acquiring)
            take_lock(st, kind, m, kind.text + " " + var,
                      targs.find("mutex") != std::string::npos &&
                          targs.find("recursive") == std::string::npos,
                      true);
    }

    // A block ends (or a break leaves it): its guards let go.
    void release_lock(State &st, const std::string &m, int line) {
        if (!st.live)
            return;
        if (auto it = st.pts.find("lock:" + m); it != st.pts.end())
            for (int s : it->second)
                if (s) {
                    st.bits[s] = kFreed;
                    st.freed_at[s] = line;
                }
    }
    void release_guards(State &st, size_t from_scope, int line) {
        for (size_t k = scopes_.size(); k-- > from_scope;)
            for (const std::string &m : scopes_[k].guards)
                release_lock(st, m, line);
    }

    // Held on every path that reaches this point by a lock this function
    // took (paths that never locked it make no claim).
    void lock_exit_check(State &st, int line, int col) {
        for (const auto &[var, sites] : st.pts) {
            if (var.rfind("lock:", 0) != 0 || sites.size() != 1 ||
                sites.count(0))
                continue;
            const int s = *sites.begin();
            const uint8_t bt = st.bits[s];
            if (!(bt & kAlloc) || (bt & kEscaped) || leak_reported_.count(s) ||
                guard_sites_.count(s))
                continue;
            leak_reported_.insert(s);
            const Site &si = sites_[size_t(s)];
            report_lock("lock-leak", si.var,
                        "'" + si.var + "' locked at line " +
                            std::to_string(si.line) + " is " +
                            (bt & kFreed ? "not unlocked on every path that "
                                           "reaches this point"
                             : col       ? "still held at this return"
                                         : "still held when the function ends"),
                        line, col, si.line);
        }
    }

    void exit_check(State &st, int line, int col) {
        lock_exit_check(st, line, col);
        // A pointer parameter released on every way out (or null there):
        // this function is a releaser of that argument for its callers.
        for (const auto &[s, param] : params_by_site_) {
            const uint8_t bt = st.bits[s];
            if (bt == kFreed)
                released_somewhere_.insert(param.first);
            else if (bt != kNull)
                kept_.insert(param.first);
        }
        for (const auto &[path, site] : parked_) {
            auto it = st.pts.find(path);
            if (it == st.pts.end() || it->second != std::set<int>{site} ||
                restored_by_defer_.count(path.substr(0, path.find_first_of(".-["))))
                continue;
            const Site &si = sites_[size_t(site)];
            report("dangling-pointer",
                   "'" + path + "' still holds the address of local '" +
                       si.how + "' when the function returns",
                   si.line, 0, 0, 0);
        }
        for (const auto &[s, bt] : st.bits) {
            if (!s || leak_reported_.count(s))
                continue;
            const Site &si = sites_[size_t(s)];
            if (!owned(si.kind) || !(bt & kAlloc) || (bt & kEscaped))
                continue;
            leak_reported_.insert(s);
            std::string msg = leaked_text(si) + " at line " +
                              std::to_string(si.line) +
                              (si.var.empty() ? "" : " ('" + si.var + "')");
            const std::string verb = released(si);
            if (bt & kFreed)
                msg += " is not " + verb +
                       " on every path that reaches this point";
            else if (col)
                msg += " is not " + verb + " before this return";
            else
                msg += " is never " + verb + " before the function ends";
            report(leak_rule(si), msg, line, col, si.line, 0);
        }
    }

    // ---- statements -----------------------------------------------------
    struct Loop {
        State brk = dead_state();
        State cont = dead_state();
        bool is_switch = false;
        std::set<std::string> modified; // variables the loop assigns or steps
        bool waits = false;             // calls join, sem_wait, cond_wait, ...
        size_t scopes = 0;              // blocks open when it was entered
    };

    // What a loop changes from one iteration to the next: assignments,
    // steps, and declarations with an initializer inside it.
    void note_modified(const Stmt &s, std::set<std::string> &out) {
        assigned_roots(s.a, out);
        assigned_roots(s.b, out);
        assigned_roots(s.c, out);
        std::vector<Declarator> ds;
        bool is_static = false;
        if ((s.kind == Stmt::Simple || (s.kind == Stmt::For && s.range_for)) &&
            parse_decl(s.a, ds, &is_static) && !is_static)
            for (const Declarator &d : ds)
                if (d.init_kind || s.kind == Stmt::For)
                    out.insert(d.name);
        for (const auto &k : s.kids)
            note_modified(*k, out);
        if (s.s1)
            note_modified(*s.s1, out);
        if (s.s2)
            note_modified(*s.s2, out);
    }

    // pthread_create(&t, attr, fn, &v): v is a local the loop keeps changing,
    // and nothing in the loop waits for the thread: it reads a later value.
    void check_thread_argument(const Toks &t,
                               std::pair<size_t, size_t> arg,
                               const Token &at) {
        auto [b, e] = arg;
        strip(t, b, e);
        if (b + 1 >= e || !t[b].is("&"))
            return;
        size_t pe;
        const std::string v = path_at(t, b + 1, &pe);
        if (v.empty() || pe != e || !is_local(v) || ref_locals_.count(v))
            return;
        for (auto it = loops_.rbegin(); it != loops_.rend(); ++it) {
            if (it->is_switch || !it->modified.count(v))
                continue;
            if (!it->waits)
                report("thread-stack-argument",
                       "the address of local '" + v +
                           "' is passed to each thread this loop starts, but "
                           "the loop changes '" +
                           v +
                           "': a thread reads the value of a later iteration "
                           "(or a stack slot already reused)",
                       at.line, at.col, 0, 0);
            return;
        }
    }

    bool in_loop() const {
        for (const Loop &l : loops_)
            if (!l.is_switch)
                return true;
        return false;
    }

    // A lambda given to a thread (std::thread, std::async, or a container of
    // threads) that captures a local by reference: in a loop that changes it,
    // a thread reads a later iteration's value; detached, the thread outlives
    // it. `declared` names the thread this statement declares, if any.
    void check_thread_lambdas(const Toks &t, const std::string &declared) {
        bool starts = false, detaches = false;
        for (size_t i = 0; i < t.size(); ++i) {
            if (t[i].kind != Tok::Ident)
                continue;
            if ((t[i].is("thread") || t[i].is("jthread") ||
                 t[i].is("async")) &&
                (i == 0 || t[i - 1].is("::")))
                starts = true;
            else if ((t[i].is("emplace_back") || t[i].is("push_back") ||
                      t[i].is("emplace")) &&
                     i >= 2 && (t[i - 1].is(".") || t[i - 1].is("->")) &&
                     thread_vars_.count(t[i - 2].text))
                starts = true;
            else if (t[i].is("detach") && i > 0 &&
                     (t[i - 1].is(".") || t[i - 1].is("->")))
                detaches = true;
        }
        if (!starts)
            return;
        static const std::set<std::string> not_a_type = {
            "return", "case", "throw", "else", "delete", "co_return",
            "co_yield", "goto", "new", "sizeof"};
        // "'a', 'b' and 2 more"
        auto names = [](const std::vector<std::string> &v) {
            std::string s;
            for (size_t n = 0; n < v.size() && n < 3; ++n)
                s += (n ? ", '" : "'") + v[n] + "'";
            return v.size() > 3 ? s + " and " + std::to_string(v.size() - 3) +
                                      " more"
                                : s;
        };
        for (size_t i = 0; i < t.size(); ++i) {
            size_t body_end = 0;
            const size_t k = lambda_body(t, i, &body_end);
            if (!k)
                continue;
            const size_t cap_end = match(t, i);
            // The captures: [&], [&x], [=, &x], [x]
            bool all_ref = false;
            std::set<std::string> by_ref, by_copy;
            size_t b = i + 1;
            for (size_t j = i + 1; j <= cap_end; ++j) {
                if (j < cap_end && !t[j].is(","))
                    continue;
                if (j > b) {
                    if (t[b].is("&")) {
                        if (j == b + 1)
                            all_ref = true;
                        else if (t[b + 1].kind == Tok::Ident &&
                                 !(b + 2 < j && t[b + 2].is("=")))
                            by_ref.insert(t[b + 1].text);
                    } else if (t[b].kind == Tok::Ident) {
                        by_copy.insert(t[b].text);
                    }
                }
                b = j + 1;
            }
            // The locals its body names (not those it declares itself).
            std::set<std::string> used, own;
            for (size_t j = k + 1; j < body_end && j < t.size(); ++j) {
                if (!starts_path(t, j))
                    continue;
                size_t pe;
                const std::string p = path_at(t, j, &pe);
                if (p.empty())
                    continue;
                const std::string root = p.substr(0, p.find_first_of(".-:"));
                if (j > 0 && t[j - 1].kind == Tok::Ident &&
                    !not_a_type.count(t[j - 1].text))
                    own.insert(root);
                else
                    used.insert(root);
                j = pe - 1;
            }
            std::vector<std::string> changing, captured;
            for (const std::string &v : used) {
                if (own.count(v) || !is_local(v) || ref_locals_.count(v) ||
                    !((all_ref && !by_copy.count(v)) || by_ref.count(v)))
                    continue;
                captured.push_back(v);
                for (auto it = loops_.rbegin(); it != loops_.rend(); ++it) {
                    if (it->is_switch || !it->modified.count(v))
                        continue;
                    if (!it->waits)
                        changing.push_back(v);
                    break;
                }
            }
            if (!changing.empty())
                report("thread-stack-argument",
                       "the lambda given to the thread captures local " +
                           names(changing) +
                           " by reference, and the loop changes it: a thread "
                           "reads the value of a later iteration (or a stack "
                           "slot already reused)",
                       t[i].line, t[i].col, 0, 0);
            if (!captured.empty()) {
                if (detaches)
                    report("thread-stack-argument",
                           "the thread is detached, but its lambda captures "
                           "local " +
                               names(captured) +
                               " by reference: the thread can outlive them",
                           t[i].line, t[i].col, 0, 0);
                else if (!declared.empty() && !ref_threads_.count(declared))
                    ref_threads_[declared] = {t[i].line, names(captured)};
            }
            i = body_end;
        }
    }

    // ---- block scopes ---------------------------------------------------
    // The variables a braced block declares, and what the ones it hides
    // were bound to.
    struct Hidden {
        bool bound, shifted, ptr, array, is_static, ref;
        std::set<int> pts;
    };
    struct Scope {
        std::vector<std::string> names;
        std::map<std::string, Hidden> hidden;
        std::vector<std::string> guards; // mutexes its lock guards hold
    };

    // Records a declaration in the innermost block. True if it hides a
    // variable of an enclosing block (or a parameter), whose binding is
    // saved for the block's end.
    bool enter_scope(State &st, const std::string &name) {
        if (scopes_.empty())
            return false;
        Scope &cur = scopes_.back();
        if (std::find(cur.names.begin(), cur.names.end(), name) !=
            cur.names.end())
            return false;
        cur.names.push_back(name);
        bool outer = params_.count(name) > 0;
        for (size_t k = 0; k + 1 < scopes_.size() && !outer; ++k)
            outer = std::find(scopes_[k].names.begin(), scopes_[k].names.end(),
                              name) != scopes_[k].names.end();
        if (!outer)
            return false;
        Hidden h;
        h.bound = st.pts.count(name) > 0;
        if (h.bound)
            h.pts = st.pts[name];
        h.shifted = st.shifted.count(name) > 0;
        h.ptr = ptr_locals_.erase(name) > 0;
        h.array = arrays_.erase(name) > 0;
        h.is_static = statics_.erase(name) > 0;
        h.ref = ref_locals_.erase(name) > 0;
        cur.hidden[name] = h;
        st.pts.erase(name);
        st.shifted.erase(name);
        return true;
    }

    // The block ends: what only its variables held is lost, and hidden
    // variables are visible again.
    void leave_scope(State &st, Scope &sc, int line) {
        const bool body = scopes_.empty(); // the function's end judges those
        const Token at{Tok::Punct, "}", line, 0};
        for (const std::string &m : sc.guards)
            release_lock(st, m, line);
        for (const std::string &name : sc.names) {
            if (st.live && !body)
                lose_value(st, name, {}, false, at, "goes out of scope");
            auto it = sc.hidden.find(name);
            if (it == sc.hidden.end()) {
                if (st.live && !body) {
                    // Only this block named these: an earlier loop pass may
                    // have released them, while the next pass reuses the
                    // same sites for new objects.
                    forget_binding(st, name, false);
                    st.pts.erase(name);
                    st.shifted.erase(name);
                }
                continue;
            }
            const Hidden &h = it->second;
            for (auto [set, had] :
                 {std::pair{&ptr_locals_, h.ptr}, std::pair{&arrays_, h.array},
                  std::pair{&statics_, h.is_static},
                  std::pair{&ref_locals_, h.ref}})
                if (had)
                    set->insert(name);
                else
                    set->erase(name);
            if (!st.live)
                continue;
            if (h.bound)
                st.pts[name] = h.pts;
            else
                st.pts.erase(name);
            if (h.shifted)
                st.shifted.insert(name);
            else
                st.shifted.erase(name);
        }
    }

    State analyze_kids(const Stmt &s, State st) {
        for (const auto &k : s.kids)
            st = analyze(*k, std::move(st));
        return st;
    }

    State analyze(const Stmt &s, State st) {
        if (!st.live && s.kind != Stmt::Label && s.kind != Stmt::Case)
            return st;
        switch (s.kind) {
        case Stmt::Block: {
            if (!s.end_line) { // grouping made up by the parser, not braces
                st = analyze_kids(s, std::move(st));
                return st;
            }
            scopes_.push_back({});
            st = analyze_kids(s, std::move(st));
            Scope sc = std::move(scopes_.back());
            scopes_.pop_back();
            leave_scope(st, sc, s.end_line);
            return st;
        }
        case Stmt::Simple:
            terminate_ = false;
            exec(s.a, st, false, nullptr);
            acquire(s.a, st);
            if (terminate_)
                st.live = false;
            return st;
        case Stmt::Return: {
            Token at{Tok::Ident, "return", s.line, s.col};
            exec(s.a, st, true, &at);
            if (st.live)
                exit_check(st, s.line, s.col);
            st.live = false;
            return st;
        }
        case Stmt::If: {
            exec(s.a, st, false, nullptr);
            State t = st, f = st;
            refine(s.a, 0, s.a.size(), t, true);
            refine(s.a, 0, s.a.size(), f, false);
            ++guarded_;
            t = analyze(*s.s1, std::move(t));
            if (s.s2)
                f = analyze(*s.s2, std::move(f));
            --guarded_;
            return join(t, f);
        }
        case Stmt::While:
        case Stmt::For:
        case Stmt::DoWhile:
            return loop(s, std::move(st));
        case Stmt::Switch: {
            exec(s.a, st, false, nullptr);
            const State entry = st;
            loops_.push_back(Loop{});
            loops_.back().is_switch = true;
            loops_.back().scopes = scopes_.size();
            State cur = dead_state();
            const Stmt &body = *s.s1;
            auto run_one = [&](const Stmt &k) {
                if (k.kind == Stmt::Case)
                    cur = join(cur, entry);
                else
                    cur = analyze(k, std::move(cur));
            };
            if (body.kind == Stmt::Block)
                for (const auto &k : body.kids)
                    run_one(*k);
            else
                run_one(body);
            const bool has_default = switch_has_default(body);
            State out = join(cur, loops_.back().brk);
            loops_.pop_back();
            if (!has_default)
                out = join(out, entry);
            return out;
        }
        case Stmt::Break:
            if (!loops_.empty()) {
                release_guards(st, loops_.back().scopes, s.line);
                loops_.back().brk = join(loops_.back().brk, st);
            }
            st.live = false;
            return st;
        case Stmt::Continue:
            for (auto it = loops_.rbegin(); it != loops_.rend(); ++it) {
                if (it->is_switch)
                    continue;
                it->cont = join(it->cont, st);
                break;
            }
            st.live = false;
            return st;
        case Stmt::Goto:
            gotos_[s.label] = join(
                gotos_.count(s.label) ? gotos_[s.label] : dead_state(), st);
            st.live = false;
            return st;
        case Stmt::Label:
            if (auto it = gotos_.find(s.label); it != gotos_.end())
                return join(st, it->second);
            return st;
        case Stmt::Try: {
            State before = st;
            State after = analyze(*s.s1, st);
            State out = after;
            for (const auto &h : s.kids)
                out = join(out, analyze(*h, join(before, after)));
            return out;
        }
        case Stmt::Case:
        case Stmt::Empty:
            return st;
        }
        return st;
    }

    static bool switch_has_default(const Stmt &body) {
        if (body.kind != Stmt::Block)
            return body.label == "default";
        for (const auto &k : body.kids)
            if (k->kind == Stmt::Case && k->label == "default")
                return true;
        return false;
    }

    State loop(const Stmt &s, State st) {
        const bool is_for = s.kind == Stmt::For;
        const bool is_do = s.kind == Stmt::DoWhile;
        if (is_for && !s.range_for)
            exec(s.a, st, false, nullptr);
        if (is_for && s.range_for)
            exec(s.b, st, false, nullptr);
        const Toks &cond = is_for ? (s.range_for ? empty_ : s.b) : s.a;
        State head = st;
        State exit_state = dead_state();
        Loop info;
        info.scopes = scopes_.size();
        note_modified(s, info.modified);
        static const std::set<std::string> member_waits = {
            "join", "get", "wait", "wait_for", "wait_until"};
        each_tokens(s, [&](const Toks &toks) {
            info.waits = info.waits || calls_any(toks, kThreadWaits) ||
                         calls_member(toks, member_waits);
        });
        // Passes until the state stops changing (normally two). A state
        // that never settles must not cost 6^depth: loops inside loops get
        // fewer passes, and a function that has already cost a lot gets two,
        // then one. (Fresh sites on every pass were such a case once.)
        int depth = 0;
        for (const Loop &l : loops_)
            depth += !l.is_switch;
        int max_iter = depth == 0 ? 6 : depth == 1 ? 4 : 3;
        if (loop_passes_ > 100000)
            max_iter = 1;
        else if (loop_passes_ > 20000)
            max_iter = std::min(max_iter, 2);
        for (int iter = 0; iter < max_iter; ++iter) {
            ++loop_passes_;
            // head: where the condition is tested (for a do-while, the body's
            // entry: its condition is tested at the bottom, below).
            State body_in = head;
            State leave = dead_state();
            if (!is_do) {
                exec(cond, body_in, false, nullptr);
                leave = body_in;
                refine(cond, 0, cond.size(), body_in, true);
                if (!cond.empty())
                    refine(cond, 0, cond.size(), leave, false);
                else if (!s.range_for)
                    leave = dead_state(); // for(;;)
            }
            if (s.range_for) // the loop variable is bound afresh each iteration
                exec(s.a, body_in, false, nullptr);
            loops_.push_back(info);
            State body_out = analyze(*s.s1, std::move(body_in));
            Loop l = std::move(loops_.back());
            loops_.pop_back();
            body_out = join(body_out, l.cont);
            if (is_for && !s.range_for)
                exec(s.c, body_out, false, nullptr);
            if (is_do) {
                exec(cond, body_out, false, nullptr);
                leave = body_out;
                refine(cond, 0, cond.size(), leave, false);
                refine(cond, 0, cond.size(), body_out, true);
            }
            exit_state = join(leave, l.brk);
            State next = join(head, body_out);
            if (next.same(head))
                break;
            head = std::move(next);
        }
        return exit_state;
    }

    const Function &fn_;
    std::vector<LockOrder> *orders_;
    Allocators *allocators_;
    Releasers *releasers_;
    bool returns_fresh_ = true;                  // every return so far
    SiteKind returned_kind_ = SiteKind::Unknown; // and what they returned
    // Pointer parameters: site -> (position, name); how each was released;
    // positions released on some exit, and kept on some exit.
    std::map<int, std::pair<size_t, std::string>> params_by_site_;
    std::map<int, SiteKind> param_release_;
    std::set<size_t> released_somewhere_, kept_;
    std::vector<Site> sites_;
    std::map<std::pair<int, int>, int> site_at_;
    std::map<std::string, int> external_;
    std::map<std::pair<std::string, int>, int> external_ids_;
    std::set<std::string> locals_, ptr_locals_, arrays_, statics_, ref_locals_,
        params_;
    std::map<std::string, int>
        parked_; // outer location -> stack site stored there
    std::vector<Issue> issues_;
    std::set<std::string> reported_;
    std::set<int> leak_reported_;
    std::map<size_t, std::string> lock_issue_; // issue index -> its mutex
    // rc -> (fails with -1, p) after "rc = asprintf(&p, ...)"
    std::map<std::string, std::pair<bool, std::string>> out_result_;
    std::set<std::string> unlocked_; // mutexes this function unlocks
    int guarded_ = 0;                // depth of if branches being analyzed
    bool fn_has_goto_ = false;       // a retry may be written with goto
    long loop_passes_ = 0;           // loop bodies analyzed so far
    // p -> (the strlen() arguments its malloc size is the sum of, the line)
    std::map<std::string, std::pair<std::vector<std::string>, int>>
        strlen_alloc_;
    // Lock guards (std::lock_guard, std::unique_lock): the lock sites they
    // made, the mutex each variable guards, and how many blocks were open
    // where it was declared.
    std::set<int> guard_sites_;
    std::map<std::string, std::string> guard_mutex_;
    std::map<std::string, size_t> guard_depth_;
    std::set<std::string> restored_by_defer_; // assigned in a deferred block
    std::set<std::string> thread_vars_; // locals that are threads or hold them
    // A std::thread local -> (line of its lambda, a local that lambda names
    // by reference): detaching it later leaves the thread with a dead local.
    std::map<std::string, std::pair<int, std::string>> ref_threads_;
    std::vector<Loop> loops_;
    std::vector<Scope> scopes_;
    std::map<std::string, State> gotos_;
    bool terminate_ = false;
    const Toks empty_;
};

} // namespace

std::vector<Issue> analyze_function(const Function &fn,
                                    std::vector<LockOrder> *orders,
                                    Allocators *allocators,
                                    Releasers *releasers) {
    if (!fn.body)
        return {};
    Analyzer a(fn, orders, allocators, releasers);
    std::vector<Issue> issues = a.run();
    // Member functions of different classes share names: free functions
    // only.
    if (fn.name.find(':') != std::string::npos)
        return issues;
    if (allocators)
        if (const char *how = a.allocator_kind())
            (*allocators)[fn.name] = how;
    if (releasers)
        if (auto r = a.releases(); !r.empty())
            (*releasers)[fn.name] = std::move(r);
    return issues;
}

std::set<std::string> file_scope_names(const std::vector<Token> &t,
                                       bool shared_only) {
    std::set<std::string> out;
    int braces = 0, parens = 0;
    bool is_static = false; // the current file-scope declaration
    for (size_t i = 0; i < t.size(); ++i) {
        if (t[i].is("{"))
            ++braces;
        else if (t[i].is("}")) {
            if (!--braces) // a function body ends with no ";"
                is_static = false;
        } else if (t[i].is("("))
            ++parens;
        else if (t[i].is(")"))
            --parens;
        else if (!braces && !parens && t[i].is(";"))
            is_static = false;
        else if (!braces && !parens && t[i].is("static"))
            is_static = true;
        else if (!braces && !parens && t[i].kind == Tok::Ident &&
                 i + 1 < t.size() &&
                 (t[i + 1].is(";") || t[i + 1].is("=") || t[i + 1].is(",") ||
                  t[i + 1].is("[")) &&
                 !(i > 0 && (t[i - 1].is(".") || t[i - 1].is("->"))) &&
                 !(shared_only && is_static))
            out.insert(t[i].text);
    }
    return out;
}

std::vector<LockOrder> with_calls(const std::vector<LockOrder> &facts) {
    std::map<std::string, std::set<std::string>> locks; // function -> mutexes
    for (const LockOrder &o : facts)
        if (!o.taken.empty())
            locks[o.function].insert(o.taken);
    std::vector<LockOrder> out;
    for (const LockOrder &o : facts) {
        if (!o.held.empty() && !o.taken.empty())
            out.push_back(o);
        else if (!o.via.empty())
            if (auto it = locks.find(o.via); it != locks.end())
                for (const std::string &b : it->second) {
                    LockOrder d = o;
                    d.taken = b;
                    out.push_back(std::move(d));
                }
    }
    return out;
}

namespace {
// One object in every function: a file-scope name, or a field of a file-scope
// object ("account.mu"; not "p->mu" or "accounts[i].mu").
bool is_global_mutex(const std::string &m,
                     const std::set<std::string> &globals) {
    if (globals.count(m))
        return true;
    const size_t dot = m.find('.');
    return dot != std::string::npos &&
           m.find_first_of("-[") == std::string::npos &&
           globals.count(m.substr(0, dot));
}
} // namespace

// ponytail: pairs only (A -> B against B -> A), quadratic in the file's
// orders; a cycle through three mutexes is not looked for.
std::vector<std::pair<LockOrder, LockOrder>>
lock_inversions(const std::vector<LockOrder> &orders,
                const std::set<std::string> &globals) {
    std::vector<std::pair<LockOrder, LockOrder>> out;
    std::set<std::pair<std::string, std::string>> seen;
    for (const LockOrder &a : orders) {
        // Only file-scope mutexes: "s->mu" in two functions may be two
        // objects, and so may members of `this` in two classes.
        if (a.held >= a.taken || !is_global_mutex(a.held, globals) ||
            !is_global_mutex(a.taken, globals) || seen.count({a.held, a.taken}))
            continue;
        for (const LockOrder &b : orders)
            if (b.held == a.taken && b.taken == a.held) {
                seen.insert({a.held, a.taken});
                out.push_back(b.line < a.line ? std::pair(b, a)
                                              : std::pair(a, b));
                break;
            }
    }
    return out;
}

namespace {
// The dynamic engine's list: they take a libc lock or touch the heap, so a
// handler that calls one while the program is inside another deadlocks or
// corrupts the heap.
const std::set<std::string> kSignalUnsafeFns = {
    "malloc",  "calloc",   "realloc", "free",     "printf", "fprintf",
    "vprintf", "vfprintf", "puts",    "fputs",    "fwrite", "fflush",
    "fopen",   "fclose",   "opendir", "closedir", "exit"};

// The handler named by t[b, e): one identifier, "&" allowed before it.
std::string handler_at(const Toks &t, size_t b, size_t e) {
    if (b < e && t[b].is("&"))
        ++b;
    return b + 1 == e && t[b].kind == Tok::Ident ? t[b].text : std::string();
}
} // namespace

std::vector<Issue> signal_unsafe_calls(const std::vector<Token> &t,
                                       const std::vector<Function> &fns) {
    std::map<std::string, int> installed; // handler -> line
    for (size_t i = 0; i + 2 < t.size(); ++i) {
        const bool member = i > 0 && (t[i - 1].is(".") || t[i - 1].is("->"));
        if (t[i].is("signal") && t[i + 1].is("(") && !member) {
            const size_t close = match(t, i + 1);
            size_t comma = i + 2;
            for (int depth = 0; comma < close; ++comma) {
                depth += t[comma].is("(") ? 1 : t[comma].is(")") ? -1 : 0;
                if (depth == 0 && t[comma].is(","))
                    break;
            }
            if (comma < close)
                if (std::string h = handler_at(t, comma + 1, close); !h.empty())
                    installed.emplace(h, t[i].line);
        }
        if ((t[i].is("sa_handler") || t[i].is("sa_sigaction")) && member &&
            t[i + 1].is("="))
            if (std::string h = handler_at(
                    t, i + 2,
                    i + 3 < t.size() && t[i + 2].is("&") ? i + 4 : i + 3);
                !h.empty())
                installed.emplace(h, t[i].line);
    }
    // Plain calls (not member calls), in order. Each function takes the
    // slice of this list on its lines; scanning the file per function was
    // most of this check.
    std::vector<size_t> calls;
    for (size_t i = 0; i + 1 < t.size(); ++i)
        if (t[i].kind == Tok::Ident && t[i + 1].is("(") &&
            !(i > 0 && (t[i - 1].is(".") || t[i - 1].is("->"))))
            calls.push_back(i);
    auto calls_in = [&](const Function &f, auto &&fn) {
        auto b = std::lower_bound(calls.begin(), calls.end(), f.line,
                                   [&](size_t i, int line) { return t[i].line < line; });
        auto e = std::upper_bound(b, calls.end(), f.end_line,
                                   [&](int line, size_t i) { return line < t[i].line; });
        for (; b != e; ++b)
            fn(*b);
    };
    // Functions of the file that call an unsafe one directly: which.
    std::map<std::string, std::string> unsafe_inside;
    for (const Function &f : fns)
        calls_in(f, [&](size_t i) {
            if (kSignalUnsafeFns.count(t[i].text))
                unsafe_inside.emplace(f.name, t[i].text);
        });
    std::vector<Issue> out;
    for (const Function &f : fns) {
        auto h = installed.find(f.name);
        if (h == installed.end())
            continue;
        calls_in(f, [&](size_t i) {
            // Directly, or through a function of this file (one level).
            std::string unsafe = t[i].text, via;
            if (!kSignalUnsafeFns.count(unsafe)) {
                auto u = unsafe_inside.find(unsafe);
                // (f's own name opens its definition: not a call)
                if (u == unsafe_inside.end() || unsafe == f.name)
                    return;
                via = unsafe;
                unsafe = u->second;
            }
            Issue is;
            is.rule = "signal-unsafe-call";
            is.message = unsafe +
                         "() is not async-signal-safe, and the signal "
                         "handler '" +
                         f.name + "' (installed at line " +
                         std::to_string(h->second) + ") calls it" +
                         (via.empty() ? "" : " through " + via + "()") +
                         ": a signal that arrives while the "
                         "program is inside it deadlocks or corrupts the heap";
            is.function = f.name;
            is.line = t[i].line;
            is.col = t[i].col;
            is.alloc_line = h->second;
            out.push_back(std::move(is));
        });
    }
    return out;
}

} // namespace lcstatic
