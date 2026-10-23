#pragma once
// Rules shared by the run-time engine (behavior.cpp) and the file scanner: the
// names a program takes to look like part of the system, the places that are
// the system's and the places that hide a file, host names that imitate trusted
// ones, and the command lines a trojan runs. No heap, no exceptions: the
// preload library is the process's allocator.
#include "protocol.h"

#include <cstddef>
#include <cstring>
#include <initializer_list>

namespace lcrules {

using namespace lcproto;

inline bool ends_with(const char *s, const char *tail) {
    const size_t n = strlen(s), m = strlen(tail);
    return n >= m && !memcmp(s + n - m, tail, m);
}

inline const char *base_name(const char *path) {
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

// ---- pretending to be the system -----------------------------------------------
//
// Malware takes the name of something the system trusts so that nobody looks at
// it twice: a process called "kworker/0:1" or "sshd" in the list, a file called
// "systemd" in /tmp, a download from "github.com.update.example". A name proves
// nothing; where the file lives does. The system's own programs live in a few
// directories only the administrator can write.

inline constexpr const char *kTrusted[] = {
    "init", "systemd", "kthreadd", "kworker", "ksoftirqd", "migration", "kswapd",
    "cron", "crond", "sshd", "ssh", "ssh-agent", "sudo", "su", "login", "passwd",
    "bash", "sh", "dash", "zsh", "rsyslogd", "syslogd", "dbus-daemon", "udevd",
    "NetworkManager", "dhclient", "ntpd", "chronyd", "auditd", "firewalld",
    "polkitd", "Xorg", "gdm", "ls", "ps", "top", "netstat", "ifconfig", "lsof",
    "ss", "ip", "mount", "journald", "logind", "rcu_sched", "watchdogd", "khugepaged",
};

// "[kworker/0:1]" and the other names of kernel threads: no user program has one.
inline bool kernel_thread_name(const char *n) {
    if (n[0] == '[')
        return true;
    for (const char *p : {"kworker/", "ksoftirqd/", "migration/", "kthreadd", "rcu_sched",
                          "rcu_preempt", "kswapd", "khugepaged", "watchdog/", "jbd2/"})
        if (!strncmp(n, p, strlen(p)))
            return true;
    return false;
}

// Windows' own processes: a program with one of these names that is not in the
// Windows directory is not that process. Lower case, without ".exe".
inline constexpr const char *kWindowsNames[] = {
    "svchost", "explorer", "lsass", "csrss", "winlogon", "services", "smss", "taskhost",
    "taskhostw", "taskmgr", "conhost", "dwm", "spoolsv", "wininit", "rundll32", "regsvr32",
    "cmd", "powershell", "notepad", "searchindexer", "wuauclt", "msiexec", "ctfmon",
    "dllhost", "sihost", "fontdrvhost", "audiodg", "userinit", "winlogon", "lsm"};

// Is `n` (a file name, any case, ".exe" or not) one of them?
inline bool windows_name(const char *n) {
    char b[64];
    size_t len = strlen(n);
    if (len > 4 && (n[len - 4] == '.') && (n[len - 3] | 0x20) == 'e' && (n[len - 2] | 0x20) == 'x' &&
        (n[len - 1] | 0x20) == 'e')
        len -= 4;
    if (len >= sizeof b)
        return false;
    for (size_t i = 0; i < len; ++i)
        b[i] = n[i] >= 'A' && n[i] <= 'Z' ? char(n[i] | 0x20) : n[i];
    b[len] = 0;
    for (const char *w : kWindowsNames)
        if (!strcmp(b, w))
            return true;
    return false;
}

// macOS's own processes: a program with one of these names that is not inside
// /System, /usr or /sbin is not that process. Case-folded, the same reasoning as
// windows_name(): a lower-case "windowserver" pretending to be "WindowServer" in
// Activity Monitor has no legitimate reason to differ only in case.
inline constexpr const char *kMacNames[] = {
    "launchd", "WindowServer", "loginwindow", "Finder", "SystemUIServer", "Dock",
    "mds", "mdworker", "mdworker_shared", "mds_stores", "coreaudiod", "coreservicesd",
    "cfprefsd", "distnoted", "UserEventAgent", "UserNotificationCenter", "syslogd",
    "diskarbitrationd", "securityd", "trustd", "amfid", "opendirectoryd", "notifyd",
    "logd", "powerd", "bluetoothd", "biometrickitd", "tccd", "nsurlsessiond",
    "cloudd", "akd", "awacsd", "softwareupdated",
};

// Is `n` (any case) one of macOS's own process names?
inline bool mac_name(const char *n) {
    char b[64];
    const size_t len = strlen(n);
    if (len >= sizeof b)
        return false;
    for (size_t i = 0; i < len; ++i)
        b[i] = n[i] >= 'A' && n[i] <= 'Z' ? char(n[i] | 0x20) : n[i];
    b[len] = 0;
    for (const char *w : kMacNames) {
        char folded[64];
        size_t wl = strlen(w);
        for (size_t i = 0; i < wl; ++i)
            folded[i] = w[i] >= 'A' && w[i] <= 'Z' ? char(w[i] | 0x20) : w[i];
        folded[wl] = 0;
        if (!strcmp(b, folded))
            return true;
    }
    return false;
}

inline bool trusted_name(const char *n) {
    if (kernel_thread_name(n) || !strncmp(n, "systemd-", 8))
        return true;
    for (const char *t : kTrusted)
        if (!strcmp(n, t))
            return true;
    return false;
}

// Windows paths reach these rules with forward slashes ("C:/Windows/System32/x.exe")
// and in any case: the part after the drive letter, or nullptr.
inline const char *drive_rest(const char *p) {
    const char c = p[0] | 0x20;
    return c >= 'a' && c <= 'z' && p[1] == ':' && p[2] == '/' ? p + 3 : nullptr;
}

// Does `s` begin with `prefix` (lower case), ignoring the case of `s`?
inline bool starts_nocase(const char *s, const char *prefix) {
    for (; *prefix; ++s, ++prefix)
        if (!*s || (*s >= 'A' && *s <= 'Z' ? *s | 0x20 : *s) != *prefix)
            return false;
    return true;
}

// Where `needle` (lower case) occurs in `s`, ignoring the case of `s`.
inline bool has_nocase(const char *s, const char *needle) {
    for (; *s; ++s)
        if (starts_nocase(s, needle))
            return true;
    return false;
}

// Where the system keeps its programs and libraries.
inline bool system_dir(const char *p) {
    for (const char *d : {"/bin/", "/sbin/", "/usr/", "/lib/", "/lib32/", "/lib64/", "/opt/",
                          "/snap/", "/nix/", "/boot/", "/app/",
                          // macOS: the sealed system volume (/System/Library holds every Apple
                          // daemon and framework).
                          "/System/"})
        if (!strncmp(p, d, strlen(d)))
            return true;
    if (const char *r = drive_rest(p))
        for (const char *d : {"windows/", "program files/", "program files (x86)/"})
            if (starts_nocase(r, d) && !starts_nocase(r, "windows/temp/"))
                return true;
    return false;
}

// Where any user can leave a file out of sight: the temporary directories, and
// any directory or file whose name starts with a dot.
inline bool hiding_place(const char *p) {
    for (const char *d : {"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/var/run/user/",
                          // macOS: /tmp and /var/tmp are symlinks into these, and /var/folders is
                          // the per-app temporary directory every sandboxed app actually gets.
                          "/private/tmp/", "/private/var/tmp/", "/var/folders/"})
        if (!strncmp(p, d, strlen(d)))
            return true;
    if (const char *r = drive_rest(p)) {
        for (const char *d : {"temp/", "windows/temp/", "users/public/", "$recycle.bin/"})
            if (starts_nocase(r, d))
                return true;
        if (has_nocase(r, "/appdata/local/temp/"))
            return true;
    }
    for (const char *c = p; *c; ++c)
        if (*c == '/' && c[1] == '.' && c[2] && !(c[2] == '.' && (!c[3] || c[3] == '/')) &&
            c[2] != '/')
            return true;
    return false;
}

// A file under a system directory that is a program or a library, as the
// directory tells: not the byte-code a language writes next to its modules.
inline bool system_file(const char *p) {
    if (!system_dir(p) || !strncmp(p, "/opt/", 5) || !strncmp(p, "/snap/", 6) ||
        !strncmp(p, "/nix/", 5) || !strncmp(p, "/app/", 5))
        return false;
    if (strstr(p, "/__pycache__/") || ends_with(p, ".pyc") || ends_with(p, ".pyo") ||
        !strncmp(p, "/usr/share/", 11) || !strncmp(p, "/usr/include/", 13) ||
        !strncmp(p, "/usr/src/", 9) || !strncmp(p, "/usr/local/", 11))
        return false;
    return true;
}

// ---- host names that imitate trusted ones -------------------------------------

inline constexpr const char *kTrustedHosts[] = {
    "google.com", "microsoft.com", "apple.com", "github.com", "githubusercontent.com",
    "amazon.com", "amazonaws.com", "paypal.com", "facebook.com", "whatsapp.com",
    "instagram.com", "twitter.com", "linkedin.com", "dropbox.com", "adobe.com",
    "mozilla.org", "ubuntu.com", "debian.org", "kernel.org", "gnu.org", "python.org",
    "pypi.org", "npmjs.com", "docker.com", "cloudflare.com", "nvidia.com", "oracle.com",
    "redhat.com", "fedoraproject.org", "archlinux.org", "windowsupdate.com", "office.com",
    "icloud.com", "gitlab.com", "bitbucket.org", "sourceforge.net", "openssl.org",
    "openssh.com", "wikipedia.org", "youtube.com", "netflix.com", "telegram.org",
    "discord.com", "slack.com", "zoom.us",
};

inline bool host_is(const char *h, size_t hl, const char *t) {
    const size_t tl = strlen(t);
    return hl == tl ? !memcmp(h, t, tl)
                    : hl > tl && h[hl - tl - 1] == '.' && !memcmp(h + hl - tl, t, tl);
}

// Letters that look like others, folded: "paypa1" is "paypal", "rnicrosoft" is
// "microsoft".
inline void fold_lookalikes(const char *in, size_t n, char *out, size_t cap) {
    size_t o = 0;
    for (size_t i = 0; i < n && o + 1 < cap; ++i) {
        char c = in[i];
        if (c == 'r' && i + 1 < n && in[i + 1] == 'n') {
            c = 'm';
            ++i;
        } else if (c == 'v' && i + 1 < n && in[i + 1] == 'v') {
            c = 'w';
            ++i;
        } else {
            c = c == '0' ? 'o' : c == '1' ? 'l' : c == '3' ? 'e' : c == '4' ? 'a'
                : c == '5' ? 's' : c == '7' ? 't' : c;
        }
        out[o++] = c;
    }
    out[o] = 0;
}

// Is one edit (insert, delete, change) enough to turn a into b?
inline bool one_edit(const char *a, const char *b) {
    const size_t la = strlen(a), lb = strlen(b);
    if (la > lb + 1 || lb > la + 1 || a == b)
        return false;
    size_t i = 0;
    while (i < la && i < lb && a[i] == b[i])
        ++i;
    if (i == la && i == lb)
        return false;
    if (la == lb)
        return !strcmp(a + i + 1, b + i + 1);
    return la < lb ? !strcmp(a + i, b + i + 1) : !strcmp(a + i + 1, b + i);
}

// The trusted host `host` imitates, or nullptr.
inline bool host_alnum(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

inline bool host_char(unsigned char c) { return host_alnum(c) || c == '.' || c == '-'; }

inline const char *imitates(const char *host) {
    char h[256];
    size_t hl = 0;
    // A host ends at the first character that cannot be in one: the '{' of a
    // format, the ')' of a sentence, a backslash. Otherwise "api.github.com{"
    // and "www.python.org)" are read as different names.
    for (size_t i = 0; host[i] && hl + 1 < sizeof h; ++i) {
        unsigned char c = (unsigned char)host[i];
        if (c >= 'A' && c <= 'Z')
            c = (unsigned char)(c + 32);
        if (!host_char(c))
            break;
        h[hl++] = char(c);
    }
    if (hl && h[hl - 1] == '.')
        --hl;
    h[hl] = 0;
    if (hl < 5)
        return nullptr;
    for (const char *t : kTrustedHosts)
        if (host_is(h, hl, t))
            return nullptr; // the real one, or a name under it
    // the trusted name inside a longer one, on a boundary: github.com.evil.example,
    // paypal.com-login.xyz. Not pyopenssl.org, which only contains the letters.
    for (const char *t : kTrustedHosts) {
        const char *at = strstr(h, t);
        if (!at)
            continue;
        const bool left = at == h || !host_alnum((unsigned char)at[-1]);
        const char after = at[strlen(t)];
        const bool right = after == 0 || after == '.' || after == '-';
        if (left && right)
            return t;
    }
    // the registrable name with one letter changed or a look-alike letter
    const char *dot = strrchr(h, '.');
    if (!dot || dot == h)
        return nullptr;
    const char *start = h;
    for (const char *c = h; c < dot; ++c)
        if (*c == '.')
            start = c + 1;
    char label[128];
    const size_t ll = size_t(dot - start);
    if (ll >= sizeof label)
        return nullptr;
    memcpy(label, start, ll);
    label[ll] = 0;
    char folded[128];
    fold_lookalikes(label, ll, folded, sizeof folded);
    for (const char *t : kTrustedHosts) {
        const char *tdot = strchr(t, '.');
        const size_t tl = size_t(tdot - t);
        if (strcmp(tdot, dot) || tl < 5)
            continue;
        char tl_label[64];
        memcpy(tl_label, t, tl);
        tl_label[tl] = 0;
        // The first letter has to agree. ipython.org and cython.org are one
        // edit from python.org and are real names; gooogle.com is not.
        if (label[0] != tl_label[0] && folded[0] != tl_label[0])
            continue;
        if (strcmp(label, tl_label) && (!strcmp(folded, tl_label) ||
                                        (tl >= 6 && one_edit(label, tl_label))))
            return t;
    }
    return nullptr;
}

inline void normalize(const char *s, char *out, size_t cap) {
    size_t n = 0;
    auto put = [&](char c) {
        if (n + 2 < cap && !(c == ' ' && out[n - 1] == ' '))
            out[n++] = c;
    };
    out[n++] = ' ';
    for (; *s; ++s) {
        const char c = *s;
        if (c == '|' || c == ';') {
            put(' ');
            put(c);
            put(' ');
        } else if (c == '\t' || c == '\n' || c == '\r' || c == '(' || c == ')' ||
                   c == '`' || c == '\'' || c == '"' || c == '{' || c == '}') {
            put(' ');
        } else {
            put(c);
        }
    }
    put(' ');
    out[n] = 0;
}

struct Cmd {
    const char *type;
    const char *what;
    const char *all[3]; // every one must be present
    const char *none;   // and this one must not
};


inline constexpr const char *kNc = "gives a shell to a network connection (netcat)";
inline constexpr const char *kPlainShell = "opens a shell on a network connection";
inline constexpr const char *kScript = "opens a socket and starts a shell";
inline constexpr const char *kOneLiner = "starts a shell from an interpreter one-liner";
inline constexpr const char *kSubShell = "downloads code and runs it at once";
inline constexpr const char *kChmodX = "makes a file in a temporary directory executable";
inline constexpr const char *kSetuid = "sets the setuid bit";
inline constexpr const char *kHist = "wipes the record of what was done";
inline constexpr const char *kRmLog = "erases a system log";
inline constexpr const char *kRmRoot = "erases the whole file system";
inline constexpr const char *kDisk = "overwrites a disk";
inline constexpr const char *kMine = "starts a cryptocurrency miner";

inline constexpr Cmd kCmds[] = {
    {kReverseShell, kPlainShell, {"/dev/tcp/"}, nullptr},
    {kReverseShell, kPlainShell, {"/dev/udp/"}, nullptr},
    {kReverseShell, kNc, {" nc ", " -e "}, nullptr},
    {kReverseShell, kNc, {" nc ", " -c "}, nullptr},
    {kReverseShell, kNc, {" ncat ", " -e "}, nullptr},
    {kReverseShell, kNc, {" ncat ", " -c "}, nullptr},
    {kReverseShell, kNc, {" ncat ", " --exec "}, nullptr},
    {kReverseShell, kNc, {" ncat ", " --sh-exec "}, nullptr},
    {kReverseShell, kNc, {" netcat ", " -e "}, nullptr},
    {kReverseShell, kNc, {" netcat ", " -c "}, nullptr},
    {kReverseShell, "gives a shell to a network connection (socat)",
     {" socat ", "exec:"}, nullptr},
    {kReverseShell, "gives a shell to a network connection (socat)",
     {" socat ", "EXEC:"}, nullptr},
    {kReverseShell, "gives a shell to a network connection (socat)",
     {" socat ", "system:"}, nullptr},
    // s_client -quiet piped into a shell. TCP-LISTEN with no shell is not one.
    {kReverseShell, "gives a shell to a TLS connection (openssl s_client)",
     {"openssl s_client", "-quiet", "| sh"}, nullptr},
    {kReverseShell, "gives a shell to a TLS connection (openssl s_client)",
     {"openssl s_client", "-quiet", "| /bin/sh"}, nullptr},
    {kReverseShell, "redirects an interactive shell to a network connection",
     {" bash -i ", ">&"}, nullptr},
    {kReverseShell, "redirects an interactive shell to a network connection",
     {" sh -i ", ">&"}, nullptr},
    {kReverseShell, "connects a named pipe to netcat", {" mkfifo ", " nc "},
     nullptr},
    {kReverseShell, "connects a named pipe to netcat", {" mkfifo ", " ncat "},
     nullptr},
    {kReverseShell, kScript, {"socket", "connect", "dup2"}, nullptr},
    {kReverseShell, kScript, {"socket", "connect", "pty.spawn"}, nullptr},
    {kReverseShell, kScript, {"socket", "connect", "/bin/sh"}, nullptr},
    {kReverseShell, kScript, {"socket", "connect", "/bin/bash"}, nullptr},
    {kReverseShell, kScript, {"fsockopen", "/bin/sh"}, nullptr},
    // python -c / perl -e / ruby -e: a socket or a subprocess call that runs /bin/sh.
    // "connect" is not required (TCPSocket.open, IO::Socket->new, subprocess.call).
    // "python -c" is not a prefix of "python3 -c", so both names are rows.
    {kReverseShell, kOneLiner, {"python3 -c", "subprocess", "/bin/sh"}, nullptr},
    {kReverseShell, kOneLiner, {"python -c", "subprocess", "/bin/sh"}, nullptr},
    {kReverseShell, kOneLiner, {"python3 -c", "socket", "/bin/sh"}, nullptr},
    {kReverseShell, kOneLiner, {"python -c", "socket", "/bin/sh"}, nullptr},
    {kReverseShell, kOneLiner, {"perl -e", "socket", "/bin/sh"}, nullptr},
    {kReverseShell, kOneLiner, {"perl -e", " exec ", "/bin/sh"}, nullptr},
    {kReverseShell, kOneLiner, {"ruby -e", "socket", "/bin/sh"}, nullptr},
    {kReverseShell, kOneLiner, {"ruby -e", "popen", "/bin/sh"}, nullptr},
    // sh -c "$(curl ...)" has no pipe, so the "| sh" rule does not see it.
    // "sh -c " is also the tail of "bash -c ".
    {kDropper, kSubShell, {"sh -c ", "$ curl"}, nullptr},
    {kDropper, kSubShell, {"sh -c ", "$ wget"}, nullptr},
    {kDropper, kChmodX, {"chmod", "/tmp/", "+x"}, nullptr},
    {kDropper, kChmodX, {"chmod", "/tmp/", " 755 "}, nullptr},
    {kDropper, kChmodX, {"chmod", "/dev/shm/", "+x"}, nullptr},
    {kDropper, kChmodX, {"chmod", "/dev/shm/", " 755 "}, nullptr},
    {kDropper, kChmodX, {"chmod", "/var/tmp/", "+x"}, nullptr},
    {kPersistence, "installs a cron job", {" crontab "}, " -l "},
    {kPersistence, "installs a cron job", {" | crontab "}, nullptr},
    {kPersistence, "enables a service", {" systemctl ", " enable "}, nullptr},
    {kPersistence, "enables a service", {" update-rc.d "}, nullptr},
    {kPersistence, "enables a service", {" chkconfig ", " on "}, nullptr},
    {kPersistence, "appends to a shell start-up file", {">>", ".bashrc"}, nullptr},
    {kPersistence, "appends to a shell start-up file", {">>", ".profile"}, nullptr},
    {kPersistence, "appends to a shell start-up file", {">>", ".zshrc"}, nullptr},
    {kPersistence, "adds a key that may log in", {">>", "authorized_keys"}, nullptr},
    {kPersistence, "loads a library into every program", {"ld.so.preload"}, nullptr},
    {kPersistence, "loads a kernel module", {" insmod "}, nullptr},
    {kPrivEsc, kSetuid, {" chmod ", " u+s "}, nullptr},
    {kPrivEsc, kSetuid, {" chmod ", " +s "}, nullptr},
    {kPrivEsc, kSetuid, {" chmod ", " a+s "}, nullptr},
    {kPrivEsc, kSetuid, {" chmod ", " g+s "}, nullptr},
    {kPrivEsc, kSetuid, {" chmod ", " 4755 "}, nullptr},
    {kPrivEsc, kSetuid, {" chmod ", " 6755 "}, nullptr},
    {kPrivEsc, kSetuid, {" chmod ", " 4777 "}, nullptr},
    {kPrivEsc, kSetuid, {" chmod ", " 6777 "}, nullptr},
    {kPrivEsc, "lets a user run anything as root without a password",
     {"NOPASSWD"}, nullptr},
    {kPrivEsc, "lets a program change its user id", {" setcap ", "cap_setuid"},
     nullptr},
    {kLogTamper, kHist, {"history -c"}, nullptr},
    {kLogTamper, kHist, {"unset HISTFILE"}, nullptr},
    {kLogTamper, kHist, {"HISTFILE=/dev/null"}, nullptr},
    {kLogTamper, kHist, {"HISTSIZE=0"}, nullptr},
    {kLogTamper, kRmLog, {" rm ", "/var/log/"}, nullptr},
    {kLogTamper, kRmLog, {" shred ", "/var/log/"}, nullptr},
    {kLogTamper, kRmLog, {" truncate ", "/var/log/"}, nullptr},
    {kLogTamper, kRmLog, {"> /var/log/"}, nullptr},
    {kLogTamper, kHist, {" rm ", ".bash_history"}, nullptr},
    {kCredAccess, "reads the password hashes", {"/etc/shadow"}, nullptr},
    {kCredAccess, "reads an SSH private key", {".ssh/id_rsa"}, nullptr},
    {kCredAccess, "reads an SSH private key", {".ssh/id_ed25519"}, nullptr},
    {kCredAccess, "reads the AWS access keys", {".aws/credentials"}, nullptr},
    {kDestructive, kRmRoot, {" rm ", " -rf / "}, nullptr},
    {kDestructive, kRmRoot, {" rm ", " -rf /* "}, nullptr},
    {kDestructive, kRmRoot, {" rm ", " -fr / "}, nullptr},
    {kDestructive, kRmRoot, {" rm ", "--no-preserve-root"}, nullptr},
    {kDestructive, kDisk, {" dd ", "of=/dev/sd"}, nullptr},
    {kDestructive, kDisk, {" dd ", "of=/dev/nvme"}, nullptr},
    {kDestructive, kDisk, {" dd ", "of=/dev/hd"}, nullptr},
    {kDestructive, kDisk, {" dd ", "of=/dev/vd"}, nullptr},
    {kDestructive, "formats a disk", {" mkfs", " /dev/sd"}, nullptr},
    {kDestructive, "formats a disk", {" mkfs", " /dev/nvme"}, nullptr},
    {kDestructive, "is a fork bomb", {" | :& "}, nullptr},
    {kMiner, kMine, {"stratum+tcp://"}, nullptr},
    {kMiner, kMine, {"stratum+ssl://"}, nullptr},
    {kMiner, kMine, {" xmrig "}, nullptr},
    {kMiner, kMine, {"/xmrig "}, nullptr},
    {kMiner, kMine, {" minerd "}, nullptr},
    {kMiner, kMine, {" cpuminer "}, nullptr},
    {kMiner, kMine, {"--donate-level"}, nullptr},
};

// The same for Windows batch files, PowerShell and VBScript. Windows does not
// care about case, so these are matched against a lower-case copy of the line
// (the needles are lower case) by the scanner; no Linux process runs them.
inline constexpr Cmd kWinCmds[] = {
    {kPersistence, "starts a program at every log-in (Run key)",
     {"reg add", "\\currentversion\\run"}, nullptr},
    {kPersistence, "schedules a task", {"schtasks", "/create"}, nullptr},
    {kPersistence, "installs a service", {" sc ", " create "}, nullptr},
    {kPersistence, "puts a program in the Startup folder", {"\\start menu\\programs\\startup"},
     nullptr},
    {kDropper, "downloads a file with certutil", {"certutil", "-urlcache"}, nullptr},
    {kDropper, "downloads a file with bitsadmin", {"bitsadmin", "/transfer"}, nullptr},
    {kDropper, "runs a script from the network with mshta", {"mshta", "http"}, nullptr},
    {kDropper, "runs a scriptlet from the network with regsvr32", {"regsvr32", "/i:http"}, nullptr},
    {kDropper, "downloads text and runs it in PowerShell", {"downloadstring", " iex "}, nullptr},
    {kDropper, "downloads text and runs it in PowerShell", {"downloadstring", "invoke-expression"},
     nullptr},
    {kDropper, "downloads a program with PowerShell", {"downloadfile", ".exe"}, nullptr},
    {kReverseShell, "opens a TCP connection from PowerShell and runs what comes back",
     {"powershell", "net.sockets.tcpclient"}, nullptr},
    {kLogTamper, "erases a Windows event log", {"wevtutil", " cl "}, nullptr},
    {kLogTamper, "erases a Windows event log", {"clear-eventlog"}, nullptr},
    {kDestructive, "deletes the shadow copies (what ransomware does before it encrypts)",
     {"vssadmin", "delete", "shadows"}, nullptr},
    {kDestructive, "deletes the shadow copies (what ransomware does before it encrypts)",
     {"wmic", "shadowcopy", "delete"}, nullptr},
    {kDestructive, "turns off Windows recovery", {"bcdedit", "recoveryenabled", " no"}, nullptr},
    {kDestructive, "turns off Windows recovery", {"bcdedit", "ignoreallfailures"}, nullptr},
    {kSystemTamper, "turns off the antivirus", {"set-mppreference", "disablerealtimemonitoring"},
     nullptr},
    {kSystemTamper, "turns off the firewall", {"netsh", "advfirewall", "state off"}, nullptr},
    {kCredAccess, "dumps the memory of the log-in process", {"procdump", "lsass"}, nullptr},
    {kCredAccess, "dumps the memory of a process", {"comsvcs.dll", "minidump"}, nullptr},
    {kCredAccess, "saves the registry hive that holds the password hashes",
     {"reg", " save ", "hklm\\sam"}, nullptr},
};

inline bool has_all(const char *norm, const Cmd &c) {
    for (const char *n : c.all)
        if (n && !strstr(norm, n))
            return false;
    return !c.none || !strstr(norm, c.none);
}

// ---- command lines of the malware families (--malware) ----------------------------------------
//
// Matched against the lower-case copy of a normalized line, both by the scanner and by the
// run-time engine, on both systems. A needle is "a|b|c": any one of them (a space counts, so
// " rm " is the word). Every needle of a row must be present.

struct MalCmd {
    const char *type;
    const char *what;
    const char *all[4];
};

inline bool has_one_of(const char *norm, const char *alternatives) {
    for (const char *p = alternatives;;) {
        const char *bar = strchr(p, '|');
        const size_t len = bar ? size_t(bar - p) : strlen(p);
        char piece[128];
        if (len && len < sizeof piece) {
            memcpy(piece, p, len);
            piece[len] = 0;
            if (strstr(norm, piece))
                return true;
        }
        if (!bar)
            return false;
        p = bar + 1;
    }
}

inline bool has_all_mal(const char *norm, const MalCmd &c) {
    for (const char *n : c.all)
        if (n && !has_one_of(norm, n))
            return false;
    return true;
}

inline constexpr MalCmd kMalCmds[] = {
    // living off the land: the system's own tools used to run something else
    {kLotl, "runs a script from a URL or inline through mshta", {" mshta ", "http|vbscript:|javascript:"}},
    {kLotl, "runs a remote scriptlet through regsvr32 (squiblydoo)", {" regsvr32 ", "/i:http|/i:\\\\|scrobj.dll"}},
    {kLotl, "runs script through rundll32 (javascript:, RunHTMLApplication, OpenURL, LaunchINFSection)",
     {" rundll32 ", "javascript:|mshtml,runhtmlapplication|url.dll,openurl|url.dll,fileprotocolhandler|zipfldr.dll,routethecall|advpack.dll,launchinfsection|ieadvpack.dll,launchinfsection|pcwutl.dll,launchapplication"}},
    {kLotl, "starts a process through WMI (wmic process call create)", {" wmic ", "process call create"}},
    {kLotl, "loads a remote XSL script through wmic", {" wmic ", "/format:http|/format:\\\\|/format:\"http|.xsl"}},
    {kLotl, "builds and runs a project file with msbuild from a user folder", {" msbuild ", ".xml|.csproj|.proj|.vbproj|.targets", "temp|appdata|public|programdata|downloads"}},
    {kLotl, "runs code through installutil, regasm or regsvcs", {"installutil|regasm|regsvcs", " /u|/logfile=|/logtoconsole=false"}},
    {kLotl, "installs a connection profile silently with cmstp", {" cmstp ", " /s| /ni| /au"}},
    {kLotl, "runs a command through forfiles", {" forfiles ", " /c"}},
    {kLotl, "runs a program through the Program Compatibility Assistant", {" pcalua ", " -a"}},
    {kLotl, "decodes a file with certutil", {" certutil ", "-decode|-decodehex|-encode"}},
    {kLotl, "runs PowerShell hidden, without a profile or with the policy bypassed",
     {" powershell ", "-w hidden|-windowstyle hidden|-windowstyle h|-w h ", "-nop|-noprofile|-ep bypass|-executionpolicy bypass|-exec bypass"}},
    {kLotl, "spawns a shell from python with pty.spawn", {" python", " -c ", "pty.spawn"}},
    {kLotl, "starts a shell from a perl one-liner", {" perl ", " -e ", "/bin/sh|/bin/bash"}},
    {kLotl, "starts a shell from awk (BEGIN {system(...)})", {" awk ", "begin", "system("}},
    {kLotl, "starts a shell from find -exec", {" find ", " -exec ", "/bin/sh|/bin/bash|sh -p|bash -p"}},
    {kLotl, "starts a shell from an editor or an archiver (vim -c :!sh, tar --checkpoint-action=exec)",
     {" vim | vi | tar ", ":!sh|:!bash|--checkpoint-action=exec"}},

    // worm, network-propagating
    {kPropagation, "copies its own file to another machine with scp", {" scp ", " $0 |/proc/self/exe"}},
    {kPropagation, "logs in to another machine without checking the host key and writes or starts a file",
     {" ssh ", "stricthostkeychecking=no", "cat >|chmod +x|bash -s"}},
    {kPropagation, "connects to the administrative share of another machine (net use \\\\host\\ipc$)",
     {" net use ", "\\\\", "ipc$|admin$|c$"}},
    {kPropagation, "starts a program on another machine with PsExec", {"psexec", "\\\\", "-accepteula|-s |-u "}},
    {kPropagation, "starts a program on another machine through WMI", {" wmic ", "/node:", "process call create"}},
    {kPropagation, "creates a scheduled task on another machine", {" schtasks ", " /s ", "/create"}},
    {kPropagation, "creates a service on another machine", {" sc ", "\\\\", " create | start "}},
    {kPropagation, "copies files to the administrative share of another machine", {"xcopy |copy ", "\\\\", "admin$|c$|ipc$"}},
    {kPropagation, "writes an autorun.inf for removable drives", {"autorun.inf", "echo|copy|attrib"}},
    {kPropagation, "puts a file on another machine with smbclient", {" smbclient ", " -c ", "put |mput "}},

    // ransomware: what it does before it encrypts
    {kRansom, "deletes the shadow copies and backups so that files cannot be restored", {"vssadmin", "delete", "shadows"}},
    {kRansom, "deletes the shadow copies through wmic", {"wmic", "shadowcopy", "delete"}},
    {kRansom, "deletes the backup catalog or the system-state backups", {"wbadmin", "delete", "catalog|systemstatebackup|backup"}},
    {kRansom, "turns off Windows recovery", {"bcdedit", "recoveryenabled", " no"}},
    {kRansom, "kills the virtual machines of an ESXi host", {"esxcli", "vm process", "kill"}},

    // wipers and file wipers
    {kWiper, "overwrites a disk device with zeros or random data", {" dd ", "of=/dev/sd|of=/dev/nvme|of=/dev/vd|of=/dev/hd|of=/dev/mmcblk", "if=/dev/zero|if=/dev/urandom|if=/dev/random"}},
    {kWiper, "overwrites a disk device with shred", {" shred ", "/dev/sd|/dev/nvme|/dev/vd|/dev/hd|/dev/mmcblk"}},
    {kWiper, "writes zeros or random data onto a disk device through a redirect",
     {"/dev/zero > /dev/sd|/dev/urandom > /dev/sd|/dev/zero > /dev/nvme|/dev/urandom > /dev/nvme|/dev/zero >/dev/sd|/dev/urandom >/dev/sd"}},
    {kWiper, "erases the signatures or the partition table of a disk", {" wipefs | sgdisk | blkdiscard ", "-a|--zap-all| -z |/dev/"}},
    {kWiper, "erases a disk with its firmware's secure erase", {" hdparm | nvme ", "--security-erase| format ", "/dev/"}},
    {kWiper, "cleans a disk or formats a drive", {" diskpart | format ", " clean all| clean |c: |d: |e: ", "/fs|/y|/q|/p|clean"}},
    {kWiper, "deletes the boot configuration", {"bcdedit", "/delete"}},
    {kFileWiper, "deletes the home directory or a whole drive recursively",
     {" rm ", "-rf|-fr", " ~ | ~/ | ~/*| $home | $home/| /home | /home/* | /root | /root/*| /mnt | /media | /srv "}},
    {kFileWiper, "deletes every file under / with find", {" find ", " / ", "-delete|-exec rm|-exec shred"}},
    {kFileWiper, "deletes files recursively and quietly from a drive or the user profile",
     {" del | rd | rmdir ", "/s", "/q", "c:\\|%userprofile%|%systemdrive%|%homepath%"}},
    {kFileWiper, "removes a drive or the user profile with PowerShell", {"remove-item", "-recurse", "-force", "c:\\|$env:userprofile|$home"}},
    {kFileWiper, "overwrites the free space or the files of a drive (cipher /w, sdelete)", {" cipher | sdelete ", "/w:| -z| -c| -p|/z|/c|/p"}},

    // dns, proxy, browser
    {kDnsHijack, "changes the DNS servers of an interface (netsh)", {"netsh", "interface", "set dns|add dns|set dnsserver"}},
    {kDnsHijack, "changes the DNS servers with PowerShell", {"set-dnsclientserveraddress|set-dnsclientserver"}},
    {kDnsHijack, "changes the DNS servers on macOS", {"networksetup", "-setdnsservers"}},
    {kDnsHijack, "changes the DNS servers with NetworkManager", {"nmcli", " mod ", "ipv4.dns"}},
    {kDnsHijack, "writes a nameserver into /etc/resolv.conf", {"nameserver", "/etc/resolv.conf", ">"}},
    {kDnsHijack, "appends a host name to the hosts file", {"/etc/hosts", ">>", "echo|printf|tee"}},
    {kDnsHijack, "appends to the hosts file with tee -a", {" tee ", " -a ", "/etc/hosts"}},
    {kDnsHijack, "writes into the Windows hosts file", {"drivers\\etc\\hosts", ">>|add-content|set-content|out-file|copy |xcopy |attrib -r"}},
    {kDnsHijack, "edits the resolver or hosts file in place with sed", {" sed ", " -i", "/etc/resolv.conf|/etc/hosts"}},
    {kDnsHijack, "redirects DNS traffic with iptables", {"iptables", "--dport 53", "redirect|dnat|--to-destination|--to-ports"}},
    {kProxy, "sets the system's WinHTTP proxy", {"netsh", " winhttp ", " set proxy |import proxy"}},
    {kProxy, "forwards a port to another machine with netsh portproxy", {"netsh", "interface portproxy", " add "}},
    {kProxy, "sets the Internet Settings proxy in the registry", {"reg add|set-itemproperty|new-itemproperty", "internet settings", "proxyserver|proxyenable|autoconfigurl"}},
    {kProxy, "opens a SOCKS or reverse tunnel with ssh", {" ssh ", " -d | -r ", " -n | -fn| -nf| -f "}},
    {kProxy, "relays one connection to another with socat", {" socat ", "tcp-listen", "tcp:"}},
    {kProxy, "redirects traffic in the NAT table", {"iptables", "-t nat", "prerouting", "dnat|redirect"}},
    {kProxy, "starts a tunnelling or proxy tool (chisel, ligolo, revsocks, 3proxy, microsocks, redsocks, tinyproxy)",
     {" chisel | ligolo | revsocks | rsocks | 3proxy | microsocks | redsocks | tinyproxy "}},
    {kBrowserHijack, "sets Internet Explorer's start page or search page", {"reg add", "internet explorer\\main", "start page|default_page_url|search page"}},
    {kBrowserHijack, "sets browser policies for the home page, the extensions or the search engine",
     {"reg add", "policies\\google\\chrome|policies\\microsoft\\edge", "homepagelocation|extensioninstallforcelist|restoreonstartupurls|defaultsearchprovider"}},
    {kBrowserHijack, "writes Firefox preferences from a shell", {"user_pref", "browser.startup.homepage|network.proxy|keyword.url|browser.search", ">>|echo|printf|tee"}},
    {kBrowserHijack, "starts a browser with a hidden extension", {"chrome|chromium|msedge", "--load-extension|--disable-extensions-except"}},

    // rootkit, bootkit, firmware
    {kRootkit, "loads a kernel module from a temporary or user location", {" insmod ", ".ko", "/tmp/|/dev/shm/|/var/tmp/|/root/|/home/| ./"}},
    {kRootkit, "names a known rootkit (Diamorphine, Reptile, Azazel, Jynx, Beurk, bdvl, Suterusu, Knark, Adore-ng, KBeast, Vlany)",
     {"diamorphine|reptile|azazel|jynx2|beurk|bdvl|suterusu|knark|adore-ng|kbeast|vlany|libprocesshider"}},
    {kRootkit, "bind-mounts over /proc/<pid> to hide a process", {"mount", "--bind|-o bind", "/proc/"}},
    {kRootkit, "writes /etc/ld.so.preload, loading a library into every program", {"ld.so.preload", ">"}},
    {kRootkit, "installs a kernel driver service", {" sc ", " create ", ".sys|type= kernel|type=kernel"}},
    {kBootkit, "turns off the check on unsigned drivers in the boot configuration", {"bcdedit", "testsigning|nointegritychecks|disable_integrity_checks", " on|yes"}},
    {kBootkit, "writes the first 512 bytes of a disk (the MBR) with dd", {" dd ", "of=/dev/sd|of=/dev/nvme0n1|of=/dev/mmcblk0|of=/dev/vda", "bs=512", "count=1"}},
    {kFirmware, "writes the flash chip of the machine with flashrom", {" flashrom ", " -w |--write"}},
    {kFirmware, "makes the UEFI variables writable (chattr -i on efivars)", {"chattr", " -i", "/sys/firmware/efi/efivars"}},
    {kFirmware, "deletes the UEFI variables", {" rm ", "/sys/firmware/efi/efivars"}},
    {kFirmware, "erases or writes a flash memory device", {"flash_erase |flashcp |nandwrite | mtd ", "/dev/mtd| write "}},

    // cryptojacker, infostealer, credential stealer
    {kMiner, "starts a miner by name", {" nbminer | t-rex | lolminer | gminer | phoenixminer | teamredminer | nanominer | srbminer | ethminer | ccminer | cgminer | bfgminer "}},
    {kInfostealer, "copies a browser's stored logins or cookies somewhere it can be sent from",
     {"copy |cp |xcopy |robocopy ", "login data|logins.json|key4.db|cookies.sqlite", "http|ftp|\\\\|tmp|temp"}},
    {kInfostealer, "reads a browser's stored logins or cookies with sqlite3", {"sqlite3", "login data|logins.json|cookies.sqlite|places.sqlite|key4.db", "select"}},
    {kInfostealer, "uploads a browser store, a wallet or a key", {"curl|wget|invoke-webrequest", "login data|cookies|wallet.dat|key4.db|logins.json|id_rsa", "-f |--upload-file|-t |--data-binary|-d @|-infile"}},
    {kCredAccess, "dumps credentials with a known tool", {"secretsdump|lazagne|mimikatz|crackmapexec|nanodump|sharpdump"}},
    {kCredAccess, "lists the Windows credential vault", {"vaultcmd|cmdkey", "/list"}},
    {kCredAccess, "reads the macOS keychain", {" security ", "find-generic-password|find-internet-password|dump-keychain"}},
    {kCredAccess, "copies the domain's password database", {"ntdsutil|esentutl", "ifm|ac i ntds|activate instance ntds|ntds.dit"}},

    // botnet, ddos, iot
    {kDdos, "floods a target with hping3", {"hping3", "--flood|--rand-source|-i u"}},
    {kDdos, "starts a flood tool by name", {" slowloris | slowhttptest | torshammer | goldeneye | xerxes | ufonet |hulk.py"}},
    {kIot, "downloads a program with busybox and makes it executable (how router malware installs itself)", {"/bin/busybox", "wget|tftp", "chmod"}},
    {kIot, "changes to a writable directory, downloads a program and runs it (router malware)",
     {"cd /tmp|cd /var/run|cd /mnt|cd /root|cd /dev/shm", "wget|tftp|curl|busybox", "chmod 777|chmod +x|sh "}},
    {kDropper, "writes the bytes of an ELF header with echo or printf (a shell dropper)", {"echo -ne|printf", "\\x7f\\x45\\x4c\\x46|\\x7felf", ">>|>"}},

    // logic bomb, spyware, keylogger, script malware, supply chain
    {kLogicBomb, "tests the date and then deletes or wipes", {"date +%y", "-gt|-ge|-eq|>=|>", "rm -rf|rm -fr|shred|mkfs|dd if=|wipefs"}},
    {kKeylogger, "records the keyboard with a logger tool and writes it to a file", {"logkeys|xinput test|evtest|showkey -a", ">"}},
    {kSpyware, "records the webcam, the screen or the microphone with ffmpeg", {"ffmpeg", "-f video4linux2|-f v4l2|-f dshow|-f avfoundation|-f x11grab|-f gdigrab|-f alsa|-f pulse", "-i "}},
    {kSpyware, "takes screenshots to a file in a temporary folder", {"scrot|import -window root|screencapture -x|gnome-screenshot -f|xwd -root|maim|grim", "/tmp/|/dev/shm/|.png|.jpg"}},
    {kScriptMalware, "runs a script engine silently with an encoded or hidden script", {"wscript|cscript", "//e:|//b"}},
    {kScriptMalware, "runs PowerShell hidden with a download or an encoded command",
     {"powershell", "-w hidden|-windowstyle hidden", "-enc|-encodedcommand|downloadstring|iex|invoke-expression|frombase64string"}},
    {kSupplyChain, "installs packages from a different index over plain http or from an extra index", {" pip", " install", "--extra-index-url|--index-url http|-i http|--trusted-host"}},

    // new categories: recovery blocker, event log wiper, security disabler, BYOVD, cloud malware, container escape, MBR locker
    {kRecoveryBlock, "disables Windows recovery in the boot configuration", {"bcdedit", "recoveryenabled", " no"}},
    {kRecoveryBlock, "disables Windows safe mode in the boot configuration", {"bcdedit", "safeboot", "minimal|network"}},
    {kLogWiper, "clears an event log with wevtutil", {"wevtutil", " cl ", "security|system|application"}},
    {kLogWiper, "clears event logs with PowerShell Clear-EventLog", {"clear-eventlog", "-logname", "security|system|application"}},
    {kSecurityDisabler, "disables real-time monitoring in Windows Defender", {"set-mppreference", "-disablerealtimemonitoring", "true"}},
    {kSecurityDisabler, "disables Microsoft Defender antivirus", {"set-mppreference", "-disableantispyware", "true"}},
    {kSecurityDisabler, "stops the Windows Defender service", {"sc stop|net stop", "windefend"}},
    {kByovd, "creates a driver service for a vulnerable signed driver (BYOVD)", {" sc ", " create ", "gdrv|rtcore|dbutil|mhyprot|procexp"}},
    {kCloudMalware, "queries instance metadata to extract cloud credentials", {"curl|wget|invoke-webrequest", "169.254.169.254", "meta-data|security-credentials"}},
    {kContainerEscape, "mounts the host root filesystem into a container", {"docker run|podman run", "-v /:|--volume /:", "/host|/mnt"}},
    {kMbrLocker, "overwrites the Master Boot Record from dd", {" dd ", "of=\\\\.\\\\physicaldrive0|of=/dev/sda|of=/dev/nvme0n1", "bs=512", "count=1"}},

    // macOS: Gatekeeper and SIP bypass, launchd persistence, privilege-prompt abuse
    {kAntiAnalysis, "strips the quarantine flag that Gatekeeper checks before a downloaded app runs",
     {"xattr", "-d |-c |-cr |--delete", "com.apple.quarantine"}},
    {kSystemTamper, "turns Gatekeeper off for the whole machine", {"spctl", "--master-disable"}},
    {kSystemTamper, "turns off System Integrity Protection (only possible from recovery mode)", {"csrutil", "disable"}},
    {kSystemTamper, "resets the privacy-permission database", {"tccutil", "reset"}},
    {kPersistence, "loads a launch agent or daemon by hand", {"launchctl", "load |bootstrap |-w "}},
    {kPrivEsc, "asks the user for administrator rights through an AppleScript dialog",
     {"osascript", "do shell script", "administrator privileges|with prompt"}},
    {kPrivEsc, "changes a user's password with dscl", {"dscl", " . ", "-passwd |-create "}},
};

inline bool is_interpreter(const char *w, size_t len) {
    static const char *const kNames[] = {"sh",     "bash", "dash", "zsh",
                                         "ksh",    "ash",  "python", "python3",
                                         "perl",   "ruby", "php",  "node",
                                         "cmd",    "cmd.exe", "powershell", "powershell.exe",
                                         "pwsh",   "wscript.exe", "cscript.exe", "mshta.exe"};
    const char *slash = nullptr; // the last '/' (memrchr is a glibc extension)
    for (size_t i = 0; i < len; ++i)
        if (w[i] == '/')
            slash = w + i;
    if (slash) {
        len -= size_t(slash + 1 - w);
        w = slash + 1;
    }
    for (const char *k : kNames)
        if (strlen(k) == len && !memcmp(w, k, len))
            return true;
    return false;
}

// "... | sh" with something fetched or decoded in front of it.
inline bool downloads_into_interpreter(const char *norm) {
    // A leading '/' so /usr/bin/base64 and /usr/bin/curl count, not only the bare name.
    bool fetched = strstr(norm, " curl ") || strstr(norm, "/curl ") ||
                   strstr(norm, " wget ") || strstr(norm, "/wget ") ||
                   strstr(norm, " fetch ") || strstr(norm, "/fetch ") ||
                   strstr(norm, " base64 ") || strstr(norm, "/base64 ") ||
                   strstr(norm, " xxd -r ") || strstr(norm, "/xxd -r ") ||
                   strstr(norm, " openssl enc ") || strstr(norm, "/openssl enc ");
    if (!fetched)
        return false;
    for (const char *p = norm; (p = strstr(p, " | ")); p += 3) {
        const char *w = p + 3;
        size_t len = strcspn(w, " ");
        if (len == 4 && !memcmp(w, "sudo", 4)) { // "| sudo sh"
            w += 5;
            len = strcspn(w, " ");
        }
        if (len && is_interpreter(w, len))
            return true;
    }
    return false;
}


} // namespace lcrules
