#include "behavior.h"
#include "init.h"
#include "protocol.h"
#include "report.h"
#include "rt.h"
#include "rules.h"
#include "stacks.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <initializer_list>
#include <sys/stat.h>
#include <time.h>
#ifdef _WIN32
#include "resources.h"
#include "win_hooks.h"
#include <windows.h>
#ifndef O_ACCMODE
#define O_ACCMODE 3
#endif
#else
#include <unistd.h>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
#endif

// A trojan, backdoor or dropper is known by what it does to the machine, not by
// how it is written: it opens a shell for whoever connects, writes itself into
// the files that run at login, reads the keys and password files, starts a file
// it has just written, hides from a debugger, wipes the log of what it did. Each
// of those is a call into the C library, so the run-time engine sees them all.
// None of them is an error in itself (an installer writes ~/.bashrc, ssh reads
// ~/.ssh/id_rsa): the report says what happened and where, and the person who
// reads it knows whether the program was meant to.
//
// Everything here runs on the program's own threads inside its calls, so it
// uses no heap, only fixed buffers and the plain string functions.
namespace lc::behavior {
namespace {

using namespace lcrules;

bool trusted(const char *n) {
#ifdef _WIN32
    return trusted_name(n) || windows_name(n);
#elif defined(__APPLE__)
    return trusted_name(n) || mac_name(n);
#else
    return trusted_name(n);
#endif
}

bool on() {
    if (tl_in_hook)
        return false;
    ensure_init();
    return g_cfg.active;
}

// Reports the parts (joined, on one line) as a finding of `type`.
LC_NOINLINE void found(const char *type, const char *a, const char *b = "",
                       const char *c = "", const char *d = "", const char *e = "",
                       const char *f2 = "", const char *g = "", const char *h = "") {
    HookGuard hg;
    ErrnoSaver es;
    char m[768];
    Buf msg(m, sizeof m);
    msg.line(a).line(b).line(c).line(d).line(e).line(f2).line(g).line(h);
    report::Finding f;
    f.type = type;
    f.category = lcproto::kCatSecurity;
    f.tid = current_tid();
    f.msg = msg.cstr();
    f.access_stack = stacks::capture();
    // A shell is started by a forked child that is about to exec: it would
    // never get to write a report of its own.
    f.untraced_too = true;
    report::emit(f);
}

// The first `n` bytes of `s`, as a short quotation.
struct Quote {
    char text[104];
    explicit Quote(const char *s) {
        Buf b(text, sizeof text);
        b.line(s);
        b.cstr();
    }
};

// ---- paths ------------------------------------------------------------------

struct Rule {
    const char *needle; // starts with '/'
    const char *what;
    bool at_end; // a file name: the path must end with it, not only contain it
};

constexpr const char *kLogin = "a shell start-up file, which runs at every login";

// Writing these makes the program run again, or lets someone in, later.
constexpr Rule kStartup[] = {
    {"/.bashrc", kLogin, true},
    {"/.bash_profile", kLogin, true},
    {"/.bash_login", kLogin, true},
    {"/.bash_logout", kLogin, true},
    {"/.profile", kLogin, true},
    {"/.zshrc", kLogin, true},
    {"/.zprofile", kLogin, true},
    {"/.zshenv", kLogin, true},
    {"/.zlogin", kLogin, true},
    {"/.ssh/authorized_keys", "the keys that may log in without a password",
     false},
    {"/.config/autostart/", "an autostart entry, started at every login", false},
    {"/.config/systemd/user/", "a user service", false},
    {"/etc/rc.local", "the boot script", false},
    {"/etc/profile", "a login script run for every user", false},
    {"/etc/crontab", "the system cron table", false},
    {"/etc/cron.", "a cron job", false},
    {"/var/spool/cron/", "a user's cron table", false},
    {"/etc/init.d/", "a boot script", false},
    {"/etc/systemd/system/", "a system service", false},
    {"/lib/systemd/system/", "a system service", false},
    {"/etc/xdg/autostart/", "an autostart entry, started at every login", false},
    {"/etc/ld.so.preload", "a library loaded into every program", false},
    {"/etc/ld.so.conf", "the library search path", false},
    {"/etc/sudoers", "who may become root", false},
    {"/etc/passwd", "the account list", false},
    {"/etc/shadow", "the password hashes", false},
    {"/etc/pam.d/", "the login rules", false},
};

// Reading these takes passwords, keys or what is typed.
constexpr Rule kSecrets[] = {
    {"/etc/shadow", "the password hashes", false},
    {"/etc/gshadow", "the group password hashes", false},
    {"/.ssh/id_", "an SSH private key", false},
    {"/.aws/credentials", "the AWS access keys", false},
    {"/.docker/config.json", "the container registry logins", false},
    {"/.git-credentials", "the stored git passwords", false},
    {"/.kube/config", "the cluster credentials", false},
    {"/.gnupg/", "the GnuPG keyring", false},
    {"/.config/gcloud/", "the Google Cloud credentials", false},
    {"/.azure/", "the Azure credentials", false},
    {"/logins.json", "a browser's saved logins", false},
    {"/key4.db", "a browser's password key", false},
    {"/cookies.sqlite", "a browser's cookies", false},
    {"/Login Data", "a browser's saved logins", false},
    {"/wallet.dat", "a cryptocurrency wallet", false},
    {"/.electrum/", "a cryptocurrency wallet", false},
    {"/proc/kcore", "the kernel's memory", false},
    {"/dev/mem", "physical memory", false},
    {"/dev/kmem", "kernel memory", false},
    {"/dev/port", "the I/O ports", false},
    {"/dev/input/event", "every key pressed (what a key logger reads)", false},
    {"/dev/input/mice", "the mouse", false},
    {"/dev/uinput", "fake keyboard and mouse input", false},
};

// Changing these redirects where the machine's connections go.
constexpr Rule kNameResolution[] = {
    {"/etc/hosts", "the local name table: names can be pointed at other machines",
     false},
    {"/etc/resolv.conf", "the DNS server list: queries can be pointed at other machines",
     false},
};

// Removing or emptying these hides what happened.
constexpr Rule kLogs[] = {
    {"/var/log/", "a system log", false},
    {"/.bash_history", "the shell history", true},
    {"/.zsh_history", "the shell history", true},
    {"/var/run/utmp", "the record of who is logged in", false},
    {"/run/utmp", "the record of who is logged in", false},
    {"/var/run/wtmp", "the record of past logins", false},
};

// A relative path counts as if it began with '/': "etc/shadow" names the same
// file as the rule "/etc/shadow" (when the program runs in "/").
#ifdef _WIN32
// Paths reach the rules with '/' for the separator, and Windows does not care
// about case.
char lower1(char c) { return c >= 'A' && c <= 'Z' ? char(c | 0x20) : c; }
const char *path_find(const char *h, const char *n) {
    const size_t nl = strlen(n);
    for (; *h; ++h) {
        size_t i = 0;
        while (i < nl && h[i] && lower1(h[i]) == lower1(n[i]))
            ++i;
        if (i == nl)
            return h;
    }
    return nullptr;
}
bool path_starts(const char *s, const char *p) {
    for (; *p; ++s, ++p)
        if (lower1(*s) != lower1(*p))
            return false;
    return true;
}
bool path_ends(const char *s, const char *t) {
    const size_t n = strlen(s), m = strlen(t);
    return n >= m && path_starts(s + n - m, t);
}
#else
const char *path_find(const char *h, const char *n) { return strstr(h, n); }
bool path_starts(const char *s, const char *p) { return !strncmp(s, p, strlen(p)); }
bool path_ends(const char *s, const char *t) { return ends_with(s, t); }
#endif

bool matches(const char *path, const Rule &r) {
    if (r.at_end)
        return path_ends(path, r.needle) || !strcmp(path, r.needle + 1);
    return path_find(path, r.needle) || (path[0] != '/' && path_starts(path, r.needle + 1));
}

template <size_t N> const Rule *find(const char *path, const Rule (&rules)[N]) {
    for (const Rule &r : rules)
        if (matches(path, r))
            return &r;
    return nullptr;
}

template <size_t N, size_t M>
const Rule *find2(const char *path, const Rule (&a)[N], const Rule (&b)[M]) {
    if (const Rule *r = find(path, a))
        return r;
    return find(path, b);
}

#ifdef _WIN32
constexpr Rule kStartupWin[] = {
    {"/start menu/programs/startup/", "the Startup folder: what is in it starts at every login", false},
    {"/windows/system32/tasks/", "a scheduled task", false},
    {"/windows/system.ini", "an old start-up file of Windows", false},
    {"/windows/win.ini", "an old start-up file of Windows", false},
};
constexpr Rule kSecretsWin[] = {
    {"/user data/default/login data", "a browser's saved logins", false},
    {"/user data/default/cookies", "a browser's cookies", false},
    {"/user data/default/network/cookies", "a browser's cookies", false},
    {"/user data/local state", "the key to a browser's saved logins", false},
    {"/microsoft/credentials/", "the Windows credential store", false},
    {"/microsoft/protect/", "the keys that protect the stored credentials", false},
    {"/microsoft/vault/", "the Windows vault", false},
    {"/windows/system32/config/sam", "the account database with the password hashes", false},
    {"/windows/system32/config/security", "the security database", false},
    {"/windows/system32/config/system", "the key that decrypts the account database", false},
    {"/windows/repair/sam", "a copy of the account database", false},
    {"/ntds/ntds.dit", "the domain's database of password hashes", false},
    {"/filezilla/recentservers.xml", "saved FTP logins", false},
    {"/filezilla/sitemanager.xml", "saved FTP logins", false},
    {"/lsass.dmp", "a dump of the log-in process's memory", false},
    {"/electrum/wallets/", "a cryptocurrency wallet", false},
};
constexpr Rule kLogsWin[] = {
    {"/windows/system32/winevt/logs/", "a Windows event log", false},
    {"/windows/system32/logfiles/", "a system log", false},
    {"/consolehost_history.txt", "the PowerShell history", true},
};
constexpr Rule kNameResolutionWin[] = {
    {"/drivers/etc/hosts", "the local name table: names can be pointed at other machines", true},
};
#define FIND(path, T) find2(path, T, T##Win)
#elif defined(__APPLE__)
// macOS has no registry and no single Startup folder: a program is started again
// by a property list under Library, not by a line added to a file.
constexpr Rule kStartupMac[] = {
    {"/Library/LaunchAgents/", "a launch agent: what is in it starts at every login", false},
    {"/Library/LaunchDaemons/", "a launch daemon: what is in it starts at boot, as root", false},
    {"/Library/Preferences/com.apple.loginitems.plist", "the login items list: a program there starts at every login", false},
};
constexpr Rule kSecretsMac[] = {
    {"/Library/Keychains/", "a keychain: the passwords, keys and certificates macOS stores for the user or the system", false},
    {"/Library/Application Support/com.apple.TCC/TCC.db",
     "the privacy-permission database: writing to it directly can grant camera, microphone or "
     "screen-recording access without asking",
     false},
    {"/Library/Messages/chat.db", "the iMessage history", false},
    {"/Library/Cookies/Cookies.binarycookies", "Safari's cookies", false},
};
constexpr Rule kLogsMac[] = {
    {"/Library/Logs/", "a system or application log", false},
    {"/private/var/log/", "a system log", false}, // /var/log is a symlink to this
};
// /etc/hosts and /etc/resolv.conf are the same path on macOS (the base table
// already matches them, through the /private/etc symlink too): nothing extra here.
constexpr Rule kNameResolutionMac[] = {
    {"/etc/hosts", "the local name table: names can be pointed at other machines", false},
};
#define FIND(path, T) find2(path, T, T##Mac)
#else
#define FIND(path, T) find(path, T)
#endif

// The path of the running program, found on first use ("" if unknown).
const char *exe_path() {
    static char path[1024];
    static uint8_t ready;
    if (!__atomic_load_n(&ready, __ATOMIC_ACQUIRE)) {
#ifdef _WIN32
        win::exe_path(path, sizeof path);
        for (char *c = path; *c; ++c)
            if (*c == '\\')
                *c = '/';
#elif defined(__APPLE__)
        uint32_t sz = sizeof path;
        if (_NSGetExecutablePath(path, &sz) != 0)
            path[0] = 0;
#else
        const ssize_t n = readlink("/proc/self/exe", path, sizeof path - 1);
        path[n > 0 ? n : 0] = 0;
        static const char kDeleted[] = " (deleted)";
        if (ends_with(path, kDeleted))
            path[strlen(path) - (sizeof kDeleted - 1)] = 0;
#endif
        __atomic_store_n(&ready, 1, __ATOMIC_RELEASE);
    }
    return path;
}

// The file name of the running program.
const char *exe_name() { return base_name(exe_path()); }

// "/proc/<pid>/mem" (1) or ".../environ" (2) of another process.
int proc_of_other(const char *path) {
#ifdef _WIN32
    (void)path; // there is no /proc
    return 0;
#endif
    if (strncmp(path, "/proc/", 6))
        return 0;
    const char *p = path + 6;
    uint32_t pid = 0;
    int digits = 0;
    for (; *p >= '0' && *p <= '9' && digits < 10; ++p, ++digits)
        pid = pid * 10 + uint32_t(*p - '0');
    if (!digits || pid == g_self_pid)
        return 0;
    return !strcmp(p, "/mem") ? 1 : !strcmp(p, "/environ") ? 2 : 0;
}

// The process's own memory map, as "/proc/self/maps" or "/proc/<pid>/maps"
// with its own pid: what a program reads for ordinary self-inspection.
bool own_maps(const char *path) {
    if (strncmp(path, "/proc/", 6))
        return false;
    const char *p = path + 6;
    if (!strncmp(p, "self/", 5))
        p += 5;
    else {
        uint32_t pid = 0;
        int digits = 0;
        for (; *p >= '0' && *p <= '9' && digits < 10; ++p, ++digits)
            pid = pid * 10 + uint32_t(*p - '0');
        if (!digits || pid != g_self_pid || *p != '/')
            return false;
        ++p;
    }
    return !strcmp(p, "maps");
}

// ---- files this program wrote -------------------------------------------------
//
// A dropper writes a file and runs it. The names (not the directories, which a
// relative path would not match) of the last 512 files opened for writing are
// kept as hashes.

constexpr uint32_t kWritten = 512;
uint64_t g_written[kWritten];
uint32_t g_written_n;

uint64_t name_hash(const char *path) {
    uint64_t h = 1469598103934665603ull;
    for (const char *p = base_name(path); *p; ++p)
        h = (h ^ uint8_t(*p)) * 1099511628211ull;
    return h | 1;
}

void remember_written(const char *path) {
    const uint32_t i = __atomic_fetch_add(&g_written_n, 1, __ATOMIC_RELAXED);
    __atomic_store_n(&g_written[i % kWritten], name_hash(path), __ATOMIC_RELAXED);
}

bool was_written(const char *path) {
    const uint64_t h = name_hash(path);
    for (uint32_t i = 0; i < kWritten; ++i)
        if (__atomic_load_n(&g_written[i], __ATOMIC_RELAXED) == h)
            return true;
    return false;
}

void file_touched(const char *path, bool write, bool trunc, const char *how) {
    if (write) {
        remember_written(path);
        if (hiding_place(path) && trusted(base_name(path)) && !system_dir(path))
            found(lcproto::kMasquerade, how, " creates \"", path,
                  "\": a file with the name of a program the system trusts, in a place "
                  "any user can write: malware hides under such names in the process "
                  "list and in PATH");
        if (system_file(path) && !find(path, kNameResolution)) // (the hosts file has its own words)
            found(lcproto::kSystemTamper, how, " opens \"", path,
                  "\" for writing: this changes a program or library the whole system "
                  "trusts (a package manager does it; so does a trojan or a rootkit that "
                  "replaces a tool with its own)");
        if (const Rule *r = FIND(path, kStartup))
            found(lcproto::kPersistence, how, " opens \"", path, "\" for writing: ",
                  r->what);
        if (const Rule *r = find(path, kNameResolution))
            found(lcproto::kSystemTamper, how, " opens \"", path,
                  "\" for writing: it changes ", r->what, " (so traffic meant for "
                  "one machine goes to another)");
    }
    if (const Rule *r = FIND(path, kSecrets);
        r && !(!strcmp(r->needle, "/.ssh/id_") && ends_with(path, ".pub")))
        found(lcproto::kCredAccess, how, " opens \"", path, "\": ", r->what);
    if (write && trunc)
        if (const Rule *r = FIND(path, kLogs))
            found(lcproto::kLogTamper, how, " empties \"", path, "\": ", r->what);
    // Reading a process's memory map: what injection helpers and
    // anti-debugging code walk to see what is loaded where (and whether it
    // was modified).
    // A program the system runs reading its own map is ordinary
    // self-inspection, not evasion: the interpreters the system ships read
    // /proc/self/maps (or /proc/<pid>/maps) at startup (CPython 3.13+ finds
    // its library there; libffi checks its trampolines there), and a daemon
    // may not be told apart from them. Another program's map stays a tell,
    // as does any map read outside a system directory.
    if (!write && !strncmp(path, "/proc/", 6) && ends_with(path, "/maps") &&
        !(own_maps(path) && system_dir(exe_path())))
        found(lcproto::kAntiAnalysis, how, " opens \"", path,
              "\": reads a process's memory map, which injection helpers and "
              "anti-debugging code walk to find what is loaded where");
    if (const int k = proc_of_other(path)) {
        if (k == 1 && write)
            found(lcproto::kInjection, how, " opens \"", path,
                  "\" for writing: it changes the code of another running "
                  "program");
        else
            found(lcproto::kCredAccess, how, " opens \"", path, "\": ",
                  k == 1 ? "the memory of another program"
                         : "the environment (passwords, tokens) of another "
                           "program");
    }
}

// ---- commands -----------------------------------------------------------------
//
// A shell command line is lower-level text than it looks, so it is first made
// regular: quotes, parentheses and braces become spaces, runs of spaces one, and
// '|' and ';' get a space on each side, so " | sh " finds a pipe into a shell
// wherever it is written. The rules then ask for every needle of a row.

// A command line that starts a file this program wrote ("/tmp/x/payload.sh",
// "sh payload.sh"). Only the word that begins a command counts, and the script
// after an interpreter: `cat data` after writing data is ordinary.
void starts_written_file(const char *norm, const char *how) {
    bool command = true; // the next word begins a command
    bool script = false; // the word before was an interpreter: this one is its script
    for (const char *p = norm; *p;) {
        while (*p == ' ')
            ++p;
        const char *w = p;
        while (*p && *p != ' ')
            ++p;
        const size_t len = size_t(p - w);
        if (!len)
            break;
        // (normalize() has already split "||" into two '|')
        if ((len == 1 && (*w == '|' || *w == ';')) ||
            (len == 2 && !memcmp(w, "&&", 2))) {
            command = true;
            script = false;
            continue;
        }
        char word[256];
        const size_t n = len < sizeof word - 1 ? len : sizeof word - 1;
        memcpy(word, w, n);
        word[n] = 0;
        if (command) {
            command = false;
            script = is_interpreter(word, n);
        } else if (script && word[0] != '-' && !(word[0] == '/' && n == 2)) {
            script = false;
        } else {
            continue;
        }
        if (was_written(word))
            found(lcproto::kDropper, how, " runs a command that starts \"", word,
                  "\", a file this program has written itself");
    }
}

// Every "scheme://host/..." of a command line whose host imitates a trusted one.
void imitated_hosts(const char *norm, const char *how, const char *shown) {
    for (const char *p = norm; (p = strstr(p, "://")); p += 3) {
        const char *h = p + 3;
        const size_t len = strcspn(h, "/?# ");
        char host[256];
        const size_t n = len < sizeof host - 1 ? len : sizeof host - 1;
        memcpy(host, h, n);
        host[n] = 0;
        const char *at = strrchr(host, '@'); // user:password@host
        if (const char *t = imitates(at ? at + 1 : host))
            found(lcproto::kMasquerade, how, " runs a command that uses the host name \"",
                  at ? at + 1 : host, "\", made to look like ", t, ": ", shown);
    }
}

void command_line(const char *cmd, const char *how) {
    char norm[1024];
    normalize(cmd, norm, sizeof norm);
    starts_written_file(norm, how);
    const Quote shown(cmd);
    imitated_hosts(norm, how, shown.text);
    // (A command that several rows match is one finding: the reporter merges
    // findings of one type from one place.)
    for (const Cmd &c : kCmds)
        if (has_all(norm, c))
            found(c.type, how, " runs a command that ", c.what, ": ", shown.text);
    // Lower case: Windows does not care about case, and the --malware rows (shared
    // with the file scanner) are all written in lower case.
    char low[sizeof norm];
    size_t li = 0;
    for (; norm[li]; ++li)
        low[li] = norm[li] >= 'A' && norm[li] <= 'Z' ? char(norm[li] | 0x20) : norm[li];
    low[li] = 0;
#ifdef _WIN32
    for (const Cmd &c : kWinCmds)
        if (has_all(low, c))
            found(c.type, how, " runs a command that ", c.what, ": ", shown.text);
#endif
    if (g_cfg.malware)
        for (const MalCmd &c : kMalCmds)
            if (has_all_mal(low, c))
                found(c.type, how, " runs a command that ", c.what, ": ", shown.text);
    if (downloads_into_interpreter(norm))
        found(kDropper, how, " runs a command that downloads or decodes code and "
              "runs it at once: ", shown.text);
}

// ---- programs -----------------------------------------------------------------

bool is_shell(const char *name) {
    static const char *const kShells[] = {"sh",  "bash", "dash", "zsh",
                                          "ksh", "ash",  "csh",  "tcsh",
                                          "fish", "busybox",
                                          "cmd", "powershell", "pwsh", "wsl"};
    char low[40];
    size_t n = strlen(name);
    if (n > 4 && !strcmp(name + n - 4, ".exe"))
        n -= 4;
    if (n >= sizeof low)
        return false;
    for (size_t i = 0; i < n; ++i)
        low[i] = name[i] >= 'A' && name[i] <= 'Z' ? char(name[i] | 0x20) : name[i];
    low[n] = 0;
    for (const char *s : kShells)
        if (!strcmp(low, s))
            return true;
    return false;
}

#ifdef _WIN32
// Standard input, output or error of the new program is a network socket.
bool socket_stdio(const void *startup) {
    const auto *si = static_cast<const STARTUPINFOA *>(startup);
    if (!si || !(si->dwFlags & STARTF_USESTDHANDLES))
        return false;
    for (HANDLE h : {si->hStdInput, si->hStdOutput, si->hStdError})
        if (h && h != INVALID_HANDLE_VALUE && res::is_socket(uint64_t(uintptr_t(h))))
            return true;
    return false;
}
#endif

#ifndef _WIN32
// glibc 2.39 posix_spawn_file_actions: 32-byte records, tag then two ints.
// ponytail: this layout, not the POSIX opaque type. Another libc needs a re-check.
struct SpawnAct {
    int tag;
    int pad;
    int fd;
    int newfd;
    char rest[16];
};
struct SpawnFa {
    int allocated;
    int used;
    SpawnAct *actions;
};
static_assert(sizeof(SpawnAct) == 32, "glibc spawn action stride");

// Standard input, output or error is (or a spawn file action leaves it) a socket.
bool socket_stdio(const void *actions) {
    bool on[3];
    for (int fd = 0; fd <= 2; ++fd) {
        struct stat st;
        on[fd] = fstat(fd, &st) == 0 && S_ISSOCK(st.st_mode);
    }
#if !defined(__APPLE__) // glibc's posix_spawn_file_actions layout
    const auto *fa = static_cast<const SpawnFa *>(actions);
    if (fa && fa->used > 0 && fa->used <= 64 && fa->actions) {
        for (int i = 0; i < fa->used; ++i) {
            const SpawnAct &a = fa->actions[i];
            if ((a.tag == 0 || a.tag == 2) && a.fd >= 0 && a.fd <= 2) // close, open
                on[a.fd] = false;
            else if (a.tag == 1 && a.newfd >= 0 && a.newfd <= 2) { // dup2
                struct stat st;
                on[a.newfd] = fstat(a.fd, &st) == 0 && S_ISSOCK(st.st_mode);
            }
        }
    }
#endif
    (void)actions;
    return on[0] || on[1] || on[2];
}

// `target` is what a /proc/self/fd/N path points to.
bool memory_file(const char *target) {
    return !strncmp(target, "/memfd:", 7) || ends_with(target, " (deleted)");
}

void starting(const char *path, char *const argv[], const char *how,
              const void *spawn_actions) {
    // fexecve(fd) and "/proc/self/fd/N" name the program by a descriptor: what
    // it points to is the file.
    char to[256];
    const char *file = path;
    if (!strncmp(path, "/proc/self/fd/", 14) || !strncmp(path, "/dev/fd/", 8)) {
        const ssize_t n = readlink(path, to, sizeof to - 1);
        if (n > 0) {
            to[n] = 0;
            file = to;
            if (memory_file(to))
                found(lcproto::kFileless, how, " starts the program in \"", path,
                      "\", which lives only in memory (memfd_create) or was "
                      "deleted: nothing on disk for a scanner to find");
        }
    }
    // started under a name that is not its own
    if (argv && argv[0] && strcmp(base_name(argv[0]), base_name(file)) &&
        (kernel_thread_name(argv[0]) ||
         (trusted(base_name(argv[0])) && strchr(file, '/') && !system_dir(file))))
        found(lcproto::kMasquerade, how, " starts \"", file, "\" under the name \"",
              argv[0], "\": in the process list it looks like something the system runs");
    if (was_written(file))
        found(lcproto::kDropper, how, " starts \"", file,
              "\", a file this program has written itself: a program that drops "
              "a file and runs it is what a downloader does");
    if (is_shell(base_name(file))) {
        if (socket_stdio(spawn_actions))
            found(lcproto::kReverseShell, how, " starts the shell \"", file,
                  "\" with its standard input or output on a network socket: "
                  "whoever is at the other end gets a command line on this "
                  "machine");
        if (argv && argv[0] && argv[1] && !strcmp(argv[1], "-c") && argv[2])
            command_line(argv[2], how);
    }
}
#endif

} // namespace

void opening(const char *path, int flags) {
    if (!path || !on())
        return;
    const bool write = (flags & O_ACCMODE) != O_RDONLY || (flags & (O_CREAT | O_TRUNC));
    file_touched(path, write, flags & O_TRUNC, "open()");
}

void opening_stream(const char *path, const char *mode) {
    if (!path || !mode || !on())
        return;
    const bool write = mode[0] == 'w' || mode[0] == 'a' || strchr(mode, '+');
    file_touched(path, write, mode[0] == 'w', "fopen()");
}

void name_resolution(const char *path, const char *how);

void deleting(const char *path, const char *how) {
    if (!path || !on())
        return;
    name_resolution(path, how);
    if (const Rule *r = FIND(path, kStartup))
        found(lcproto::kPersistence, how, " removes \"", path, "\": ", r->what);
    if (const Rule *r = FIND(path, kLogs))
        found(lcproto::kLogTamper, how, " removes \"", path, "\": ", r->what);
    if (system_file(path))
        found(lcproto::kSystemTamper, how, " removes \"", path,
              "\", a program or library the whole system trusts");
    // The program removes the file it is running from. Only a file with the
    // program's name is looked at: stat() on every unlink would slow rm -rf.
#ifdef _WIN32
    if (!exe_name()[0] || !path_ends(path, exe_name()) ||
        (strchr(path, '/') && !path_ends(exe_path(), path)))
        return;
    found(lcproto::kAntiAnalysis, how, " removes \"", path,
          "\", the program's own file: it leaves nothing on disk to examine "
          "once it runs");
#else
    struct stat victim, self;
    if (!exe_name()[0] || strcmp(base_name(path), exe_name()))
        return;
#if defined(__APPLE__)
    if (stat(path, &victim) == 0 && exe_path()[0] && stat(exe_path(), &self) == 0 &&
#else
    if (stat(path, &victim) == 0 && stat("/proc/self/exe", &self) == 0 &&
#endif
        victim.st_dev == self.st_dev && victim.st_ino == self.st_ino)
        found(lcproto::kAntiAnalysis, how, " removes \"", path,
              "\", the program's own file: it leaves nothing on disk to examine "
              "once it runs");
#endif
}

void truncating(const char *path, const char *how) {
    if (!path || !on())
        return;
    name_resolution(path, how);
    if (const Rule *r = FIND(path, kStartup))
        found(lcproto::kPersistence, how, " empties \"", path, "\": ", r->what);
    if (const Rule *r = FIND(path, kLogs))
        found(lcproto::kLogTamper, how, " empties \"", path, "\": ", r->what);
}

void history_off(const char *how) {
    if (!how || !on())
        return;
    found(lcproto::kLogTamper, how,
          " turns off the shell history: what was typed can be denied");
}

void dating(const char *path, const char *how) {
    if (!path || !how || !on())
        return;
    if (const Rule *r = FIND(path, kLogs))
        found(lcproto::kLogTamper, how, " changes the time on \"", path, "\": ", r->what);
}

#ifndef _WIN32
// The path a descriptor refers to, or false. ftruncate and fchown have no path argument.
static bool path_of_fd(int fd, char *path, size_t cap) {
    if (fd < 0 || cap < 2)
        return false;
#if defined(__APPLE__)
    (void)cap;
    return fcntl(fd, F_GETPATH, path) == 0;
#else
    char link[48];
    Buf b(link, sizeof link);
    b.s("/proc/self/fd/").u(uint64_t(fd));
    const ssize_t n = readlink(b.cstr(), path, cap - 1);
    if (n <= 0)
        return false;
    path[n] = 0;
    return true;
#endif
}

// ftruncate() has no path. truncate() is a different symbol, so it is not wrapped above.
void truncating_fd(int fd, const char *how) {
    char path[1024];
    if (!path_of_fd(fd, path, sizeof path))
        return;
    truncating(path, how);
}

void dating_fd(int fd, const char *how) {
    char path[1024];
    if (!path_of_fd(fd, path, sizeof path))
        return;
    dating(path, how);
}
#endif

void replacing(const char *path, const char *how) {
    if (!path || !on())
        return;
    remember_written(path);
    if (const Rule *r = FIND(path, kStartup))
        found(lcproto::kPersistence, how, " puts a file at \"", path, "\": ",
              r->what);
    if (system_file(path))
        found(lcproto::kSystemTamper, how, " puts a file at \"", path,
              "\", among the programs and libraries the whole system trusts");
    if (hiding_place(path) && trusted(base_name(path)) && !system_dir(path))
        found(lcproto::kMasquerade, how, " puts a file at \"", path,
              "\": a file with the name of a program the system trusts, in a place any "
              "user can write");
}

void name_resolution(const char *path, const char *how) {
    if (!path)
        return;
    if (const Rule *r = FIND(path, kNameResolution))
        found(lcproto::kSystemTamper, how, " changes \"", path, "\": ", r->what);
}

void chmoding(const char *path, unsigned mode, const char *how) {
    if (!on())
        return;
    name_resolution(path, how);
    if (path)
        if (const Rule *r = FIND(path, kStartup))
            found(lcproto::kPersistence, how, " changes \"", path, "\": ", r->what);
    if (path && system_file(path))
        found(lcproto::kSystemTamper, how, " changes the permissions of \"", path,
              "\", a program or library the whole system trusts");
    if (mode & 0002)
        loose_mode(how, " makes the file writable by every user: another user can change "
                        "what the program reads later");
    if (mode & 06000)
        found(lcproto::kPrivEsc, how, " sets the setuid or setgid bit",
              path ? " on \"" : "", path ? path : "",
              path ? "\": whoever runs that file runs it with the owner's "
                     "rights, a way to keep root access"
                   : ": whoever runs that file runs it with the owner's rights");
}

// chown() does not call chmod(). Only a system program or library: chown of a
// file the user owns is ordinary.
void loose_mode(const char *how, const char *rest) {
    if (!on())
        return;
    found(lcproto::kBadPermissions, how, rest);
}

// open() and creat() do not call chmod(). The bit is the same one chmod() reports.
void caps(const char *how) {
    if (!how || !on())
        return;
    found(lcproto::kPrivEsc, how,
          " changes the process's capabilities: a capability is a root privilege "
          "kept after the user id is dropped");
}

void raw_socket(const char *how) {
    if (!how || !on())
        return;
    found(lcproto::kCredAccess, how,
          " opens a raw socket: it can read or forge packets on the network");
}

void raw_port(const char *how) {
    if (!how || !on())
        return;
    found(lcproto::kPrivEsc, how,
          " asks for direct access to hardware ports: that reaches the machine "
          "past the operating system");
}

void search_path(const char *how, const char *value) {
    if (!how || !value || !on())
        return;
    if (!value[0]) {
        found(lcproto::kCmdInjection, how,
              " clears PATH: a later command that is named, not given as a full path, "
              "starts from the current directory");
        return;
    }
    const bool loose = value[0] == '.' || !strncmp(value, "/tmp", 4) ||
                       !strncmp(value, "/var/tmp", 8) || !strncmp(value, "/dev/shm", 8);
    if (loose)
        found(lcproto::kCmdInjection, how, " puts \"", value,
              "\" first on PATH: a later command that is named, not given as a full path, "
              "starts a program anyone can write there");
}

void library_path(const char *how, const char *value) {
    if (!how || !value || !on())
        return;
    const bool loose = !value[0] || value[0] == '.' || !strncmp(value, "/tmp", 4) ||
                       !strncmp(value, "/var/tmp", 8) || !strncmp(value, "/dev/shm", 8);
    if (loose)
        found(lcproto::kInjection, how, " puts \"", value,
              "\" first on the library search path: the next library is loaded from a "
              "directory anyone can write");
}

void setuid_bit(const char *how) {
    if (!how || !on())
        return;
    found(lcproto::kPrivEsc, how,
          " sets the setuid or setgid bit: whoever runs that file runs it with the "
          "owner's rights, a way to keep root access");
}

void chowning(const char *path, const char *how) {
    if (!path || !on())
        return;
    name_resolution(path, how);
    if (const Rule *r = FIND(path, kStartup))
        found(lcproto::kPersistence, how, " changes the owner of \"", path, "\": ", r->what);
    if (system_file(path))
        found(lcproto::kSystemTamper, how, " changes the owner of \"", path,
              "\", a program or library the whole system trusts");
}

// mount() does not call open() or chown(). Hiding a system path is the same kind of change.
void mounting(const char *target, const char *how) {
    if (!target || !how || !on())
        return;
    if (system_file(target) || system_dir(target))
        found(lcproto::kSystemTamper, how, " changes where \"", target,
              "\" is mounted: a program or directory the whole system trusts");
}

#ifndef _WIN32
void chowning_fd(int fd, const char *how) {
    char path[1024];
    if (!path_of_fd(fd, path, sizeof path))
        return;
    chowning(path, how);
}
#endif

#ifndef _WIN32
void exec(const char *path, char *const argv[], const char *how,
          const void *spawn_actions) {
    // A vfork() child runs on its parent's memory: nothing but exec is safe.
    if (!path || !on() || process_id() != g_self_pid)
        return;
    HookGuard hg;
    ErrnoSaver es;
    starting(path, argv, how, spawn_actions);
}

void exec_fd(int fd, char *const argv[], const char *how) {
    if (!on() || process_id() != g_self_pid)
        return;
    HookGuard hg;
    ErrnoSaver es;
#if defined(__APPLE__)
    char to[1024];
    if (fd >= 0 && fcntl(fd, F_GETPATH, to) == 0)
        starting(to, argv, how, nullptr);
#else
    char link[48];
    Buf b(link, sizeof link);
    b.s("/proc/self/fd/").u(uint64_t(fd < 0 ? 0 : fd));
    starting(b.cstr(), argv, how, nullptr);
#endif
}

#endif

void command(const char *cmd, const char *how) {
    if (!cmd || !on() || process_id() != g_self_pid)
        return;
    HookGuard hg;
    ErrnoSaver es;
    command_line(cmd, how);
}

void loading(const char *path, const char *how) {
    if (!path || !how || !on())
        return;
    if (was_written(path))
        found(lcproto::kDropper, how, " loads \"", path,
              "\", a file this program has written itself");
}

void started(int argc, char **argv) {
    if (!on())
        return;
    HookGuard hg;
    ErrnoSaver es;
    const char *exe = exe_path();
    if (!exe[0])
        return;
    const char *name = base_name(exe);
    if (trusted(name) && !system_dir(exe) && hiding_place(exe))
        found(lcproto::kMasquerade, "the program is called \"", name,
              "\" like something the system trusts, but it runs from \"", exe,
              "\", a place any user can write: malware hides in the process list "
              "under such a name");
    if (argc > 0 && argv && argv[0] && strcmp(base_name(argv[0]), name) &&
        (kernel_thread_name(argv[0]) ||
         (trusted(base_name(argv[0])) && !system_dir(exe))))
        found(lcproto::kMasquerade, "the program \"", exe, "\" was started as \"", argv[0],
              "\": in the process list it looks like something the system runs");
}

void process_named(const char *name, const char *how) {
    if (!name || !how || !on())
        return;
    char n[17];
    const size_t len = strnlen(name, 16);
    memcpy(n, name, len);
    n[len] = 0;
    if (trusted(n) && !system_dir(exe_path()))
        found(lcproto::kMasquerade, how, " \"", n, "\", the name of "
              "something the system runs, though its program is \"", exe_path()[0] ? exe_path() : "?",
              "\": in the process list nobody looks at it twice");
}

void host(const char *name, const char *how) {
    if (!name || !on())
        return;
    if (const char *t = imitates(name))
        found(lcproto::kMasquerade, how, " looks up \"", name, "\", a host name made to "
              "look like ", t, ": malware names its servers after the sites you trust");
}

// Twenty renames that add the same new ending to a name: ransomware marking the
// files it has encrypted. Endings that backups and rotation add are not counted.
void renamed(const char *from, const char *to) {
    constexpr uint32_t kFiles = 20;
    if (!from || !to || !on())
        return;
    const size_t lf = strlen(from);
    if (strlen(to) <= lf + 1 || strncmp(to, from, lf) || to[lf] != '.')
        return;
    const char *suffix = to + lf;
    for (const char *ok : {".bak", ".old", ".orig", ".tmp", ".swp", ".save", ".new", ".part",
                           ".gz", ".xz", ".zst", ".bz2", ".lock", ".1", ".2", ".3", ".dist"})
        if (!strcmp(suffix, ok))
            return;
    static uint64_t g_suffix; // the ending being counted
    static uint32_t g_count;
    uint64_t h = 1469598103934665603ull;
    for (const char *p = suffix; *p; ++p)
        h = (h ^ uint8_t(*p)) * 1099511628211ull;
    h |= 1;
    uint64_t none = 0;
    if (!__atomic_compare_exchange_n(&g_suffix, &none, h, false, __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE) &&
        none != h)
        return;
    if (__atomic_add_fetch(&g_count, 1, __ATOMIC_ACQ_REL) == kFiles)
        found(lcproto::kRansom, "rename() has renamed ", "20 files by adding \"", suffix,
              "\" to their names: this is how ransomware marks the files it has encrypted");
}

// A hundred different addresses and ports within ten seconds: a scan.
void connecting(const void *addr, unsigned len) {
    constexpr int kRing = 128, kDistinct = 100, kSeconds = 10;
    if (!addr || len < 8 || !on())
        return;
    const uint16_t family = *static_cast<const uint16_t *>(addr);
#ifdef _WIN32
    if (family != 2 && family != 23) // AF_INET, AF_INET6
        return;
#else
    if (family != 2 && family != 10) // AF_INET, AF_INET6
        return;
#endif
    uint64_t h = 1469598103934665603ull;
    const uint8_t *b = static_cast<const uint8_t *>(addr);
    for (unsigned i = 2; i < len && i < 24; ++i)
        h = (h ^ b[i]) * 1099511628211ull;
    h |= 1;
#ifdef _WIN32
    struct {
        long tv_sec;
    } now = {long(GetTickCount64() / 1000)};
#else
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
#endif
    static SpinLock lock;
    static struct {
        uint64_t h;
        long sec;
    } ring[kRing];
    static uint32_t pos;
    static uint8_t reported;
    bool report = false;
    {
        LockGuard g(lock);
        int distinct = 0;
        bool seen = false;
        for (const auto &e : ring) {
            const bool fresh = e.sec && now.tv_sec - e.sec <= kSeconds;
            seen |= fresh && e.h == h;
            distinct += fresh;
        }
        if (!seen) {
            ring[pos++ % kRing] = {h, now.tv_sec ? now.tv_sec : 1};
            ++distinct;
        }
        if (distinct >= kDistinct && !reported) {
            reported = 1;
            report = true;
        }
    }
    if (report)
        found(lcproto::kNetScan, "connect() has tried 100 different addresses and ports "
              "within ten seconds: a port or network scan, as a worm or a bot looking for "
              "victims does (nmap does it on purpose)");
}

#ifndef _WIN32
void aslr_off(const char *how) {
    if (!on())
        return;
    found(lcproto::kAntiAnalysis, how, " turns off address randomization: the next program "
          "starts at a fixed address, which is how a later exploit is aimed");
}

void ptrace_call(int request, int pid) {
    constexpr int kTraceMe = 0, kPeekText = 1, kPeekData = 2, kPeekUser = 3,
                  kPokeText = 4, kPokeData = 5, kPokeUser = 6, kSetRegs = 13,
                  kGetRegset = 0x4204, kSetRegset = 0x4205, kAttach = 16, kSeize = 0x4206;
    if (!on())
        return;
    const bool attach = request == kAttach || request == kSeize;
    // SETREGSET writes registers (the modern SETREGS). POKE* is unchanged.
    const bool poke = request == kPokeText || request == kPokeData ||
                      request == kPokeUser || request == kSetRegs ||
                      request == kSetRegset;
    const bool peek = request == kPeekText || request == kPeekData ||
                      request == kPeekUser || request == kGetRegset;
    if (request == kTraceMe) {
        // A debugger starting its child does this in the forked child; a program
        // that does it in its own first process only keeps a debugger out.
        if (g_self_pid == g_cfg.root_pid)
            found(lcproto::kAntiAnalysis, "ptrace(PTRACE_TRACEME) in the program's "
                  "own process: nothing else can attach a debugger to it "
                  "afterwards, which is how malware keeps itself from being "
                  "analysed");
    } else if (attach && pid > 0 && pid == getppid()) {
        found(lcproto::kAntiAnalysis, "ptrace attaches to the program's parent: "
              "no debugger can then trace it, a trick that malware uses to keep "
              "itself from being analysed");
    } else if (attach && pid > 0 && uint32_t(pid) != g_self_pid) {
        found(lcproto::kInjection, "ptrace() attaches to another running "
              "program: its code and data can then be read and rewritten, which "
              "is how code is injected into it");
    } else if (peek && pid > 0 && uint32_t(pid) != g_self_pid) {
        found(lcproto::kCredAccess, "ptrace() reads the memory of another "
              "running program");
    } else if (poke && pid > 0 && uint32_t(pid) != g_self_pid) {
        found(lcproto::kInjection, "ptrace() writes into the memory of another "
              "running program: the way code is injected into it");
    }
}

void vm_write(int pid) {
    if (!on() || pid <= 0 || uint32_t(pid) == g_self_pid)
        return;
    found(lcproto::kInjection, "process_vm_writev() writes into the memory of "
          "another running program: the way code is injected into it");
}

void exe_claimed(const char *how) {
    if (!how || !on())
        return;
    found(lcproto::kMasquerade, how,
          " changes the program the process claims to be: /proc shows a different executable");
}

void other_fd(const char *how) {
    if (!how || !on())
        return;
    found(lcproto::kCredAccess, how, " takes a file another process has open");
}

void vm_read(int pid) {
    if (!on() || pid <= 0 || uint32_t(pid) == g_self_pid)
        return;
    found(lcproto::kCredAccess, "process_vm_readv() reads the memory of another "
          "running program");
}

void setuid_root(const char *how) {
    if (!on() || getuid() == 0 || geteuid() == 0)
        return;
    found(lcproto::kPrivEsc, how, " asks to become user 0 (root) in a program "
          "that does not run as root: an attempt to take over the machine");
}

// setgid() does not call setuid(). A process that is already root (sudo) is
// silent: it becomes group 0 as part of being root.
void setgid_root(const char *how) {
    if (!on() || getuid() == 0 || geteuid() == 0 || getgid() == 0 || getegid() == 0)
        return;
    found(lcproto::kPrivEsc, how, " asks to become group 0 (root) in a program "
          "that does not run as root: an attempt to take over the machine");
}
#endif

#ifdef _WIN32
// ---- what only Windows has ------------------------------------------------------------------------

// A program is about to be started: `file` is its path (or the first word of the
// line), `line` the command line, with '/' for the separator.
void process_start(const char *file, const char *line, const char *how, const void *startup) {
    if (!on())
        return;
    HookGuard hg;
    ErrnoSaver es;
    const char *name = base_name(file);
    if (name[0] && windows_name(name) && strchr(file, '/') && !system_dir(file))
        found(lcproto::kMasquerade, how, " starts \"", file,
              "\", named like a Windows system process but not in the Windows directory: "
              "in the process list it looks like something Windows runs");
    if (file[0] && was_written(file))
        found(lcproto::kDropper, how, " starts \"", file,
              "\", a file this program has written itself: a program that drops a file "
              "and runs it is what a downloader does");
    if (name[0] && is_shell(name) && socket_stdio(startup))
        found(lcproto::kReverseShell, how, " starts the shell \"", file,
              "\" with its standard input or output on a network socket: whoever is at "
              "the other end gets a command line on this machine");
    if (line && line[0])
        command_line(line, how);
}

void injected(const char *how) {
    if (!on())
        return;
    found(lcproto::kInjection, how,
          " writes into, or starts code inside, another running program: the way code is "
          "injected into it");
}

void read_other_process(const char *how) {
    if (!on())
        return;
    found(lcproto::kCredAccess, how, " reads the memory of another running program");
}

void debugger_probe(const char *how) {
    if (!on())
        return;
    found(lcproto::kAntiAnalysis, how,
          " asks whether a debugger is attached: malware uses the answer to behave "
          "differently when it is being analysed");
}

void privilege_enabled(const char *name) {
    if (!on())
        return;
    found(lcproto::kPrivEsc, "the program turns on the privilege ", name,
          ", which lets it read and write other programs' memory, load drivers or act as "
          "the system: an attempt to take over the machine");
}

void registry(const char *path, bool write, const char *how) {
    if (!path || !on())
        return;
    if (write) {
        for (const char *k : {"/currentversion/run", "/currentversion/policies/explorer/run"})
            if (path_find(path, k)) {
                found(lcproto::kPersistence, how, " writes \"", path,
                      "\": a program listed there starts at every login");
                return;
            }
        for (const char *k : {"/winlogon", "/image file execution options", "/appinit_dlls",
                              "/windows nt/currentversion/windows"})
            if (path_find(path, k)) {
                found(lcproto::kPersistence, how, " writes \"", path,
                      "\": a setting Windows uses to start programs or load libraries into "
                      "every program");
                return;
            }
        if (path_find(path, "/currentcontrolset/services/") || path_find(path, "/controlset001/services/")) {
            found(lcproto::kPersistence, how, " writes \"", path, "\": a service, started when the "
                  "machine starts");
            return;
        }
        if (path_find(path, "/windows defender") || path_find(path, "/security center")) {
            found(lcproto::kSystemTamper, how, " writes \"", path,
                  "\": it changes the settings of Windows' antivirus or firewall");
            return;
        }
    } else if (path_starts(path, "hklm/sam") || path_starts(path, "hklm/security") ||
               path_find(path, "/control/lsa")) {
        found(lcproto::kCredAccess, how, " opens \"", path,
              "\": the account database or the secrets of the log-in process");
    }
}

void elevation(const char *file, const char *how) {
    if (!on())
        return;
    found(lcproto::kPrivEsc, how, " asks Windows to run \"", file,
          "\" as the administrator (runas): an attempt to take over the machine, "
          "or an installer that needs the rights");
}

void event_log_cleared(const char *how) {
    if (!on())
        return;
    found(lcproto::kLogTamper, how, " erases a Windows event log: the record of what was done on this machine");
}

// A file fetched from the network (URLDownloadToFile): the host may imitate a trusted
// one, and the file is one this program wrote.
void downloads(const char *url, const char *path, const char *how) {
    if (!on())
        return;
    HookGuard hg;
    ErrnoSaver es;
    if (path)
        remember_written(path);
    if (url) {
        const char *p = strstr(url, "://");
        if (p) {
            char host[256];
            const char *h = p + 3;
            const size_t len = strcspn(h, "/?# ");
            const size_t n = len < sizeof host - 1 ? len : sizeof host - 1;
            memcpy(host, h, n);
            host[n] = 0;
            const char *at = strrchr(host, '@');
            if (const char *t = imitates(at ? at + 1 : host))
                found(lcproto::kMasquerade, how, " downloads from \"", at ? at + 1 : host,
                      "\", a host name made to look like ", t);
        }
    }
}
#endif

} // namespace lc::behavior
