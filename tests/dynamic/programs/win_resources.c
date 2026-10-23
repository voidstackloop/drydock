// Windows handles: one case per argument. The same bug classes as resources.c.
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char tmp_path[MAX_PATH];

static const char *temp_file(void) {
    if (!tmp_path[0]) {
        char dir[MAX_PATH];
        GetTempPathA(sizeof dir, dir);
        GetTempFileNameA(dir, "lcr", 0, tmp_path);
    }
    return tmp_path;
}

static HANDLE open_file(SECURITY_ATTRIBUTES *sa) {
    return CreateFileA(temp_file(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, sa,
                       OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

static void file_leak(void) {
    HANDLE h = open_file(NULL);
    (void)h;
}

static void file_closed(void) {
    HANDLE h = open_file(NULL);
    CloseHandle(h);
}

static void double_close(void) {
    HANDLE h = open_file(NULL);
    CloseHandle(h);
    CloseHandle(h);
}

static void use_after_close(void) {
    char buf[4];
    DWORD got;
    HANDLE h = open_file(NULL);
    CloseHandle(h);
    ReadFile(h, buf, sizeof buf, &got, NULL);
}

static void stream_leak(void) {
    FILE *f = fopen(temp_file(), "r");
    (void)f;
}

static void stream_closed(void) {
    FILE *f = fopen(temp_file(), "r");
    fclose(f);
}

static void stream_double_close(void) {
    FILE *f = fopen(temp_file(), "r");
    fclose(f);
    fclose(f);
}

static void stream_use_after_close(void) {
    char buf[4];
    FILE *f = fopen(temp_file(), "r");
    fclose(f);
    fread(buf, 1, sizeof buf, f);
}

static void dir_leak(void) {
    WIN32_FIND_DATAA d;
    HANDLE h = FindFirstFileA("C:\\Windows\\*", &d);
    (void)h;
}

static void dir_closed(void) {
    WIN32_FIND_DATAA d;
    HANDLE h = FindFirstFileA("C:\\Windows\\*", &d);
    FindClose(h);
}

static DWORD WINAPI quick(LPVOID p) {
    (void)p;
    return 0;
}

static void thread_leak(void) {
    HANDLE t = CreateThread(NULL, 0, quick, NULL, 0, NULL);
    WaitForSingleObject(t, INFINITE);
}

static void thread_closed(void) {
    HANDLE t = CreateThread(NULL, 0, quick, NULL, 0, NULL);
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
}

static void run_child(int close_handles, int inherit) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[] = "cmd.exe /c exit 0";
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, inherit, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return;
    WaitForSingleObject(pi.hProcess, INFINITE);
    if (close_handles) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

// this program again, with a case that leaks a handle in the child
static void spawn_self(const char *self) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[MAX_PATH + 32];
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    snprintf(cmd, sizeof cmd, "\"%s\" file-leak", self);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return;
    WaitForSingleObject(pi.hProcess, 20000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

static void process_leak(void) { run_child(0, FALSE); }
static void process_closed(void) { run_child(1, FALSE); }

// a handle that may be inherited, still open when a program is started
static void inherited(void) {
    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
    HANDLE h = open_file(&sa);
    run_child(1, TRUE);
    CloseHandle(h);
}

static void inherited_not_inheritable(void) {
    HANDLE h = open_file(NULL);
    run_child(1, TRUE); // bInheritHandles is TRUE, but the handle is not inheritable
    CloseHandle(h);
}

static void event_leak(void) {
    HANDLE e = CreateEventA(NULL, TRUE, FALSE, NULL);
    (void)e;
}

static void mutex_and_pipe_leak(void) {
    HANDLE m = CreateMutexA(NULL, FALSE, NULL);
    HANDLE r, w;
    CreatePipe(&r, &w, NULL, 0);
    (void)m;
    CloseHandle(r); // the write end is left open
}

static void everything_released(void) {
    HANDLE e = CreateEventA(NULL, TRUE, FALSE, NULL);
    HANDLE r, w;
    CreatePipe(&r, &w, NULL, 0);
    CloseHandle(r);
    CloseHandle(w);
    CloseHandle(e);
    file_closed();
    stream_closed();
    dir_closed();
    thread_closed();
    process_closed();
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        const char *c = argv[i];
        if (!strcmp(c, "file-leak")) file_leak();
        else if (!strcmp(c, "file-closed")) file_closed();
        else if (!strcmp(c, "double-close")) double_close();
        else if (!strcmp(c, "use-after-close")) use_after_close();
        else if (!strcmp(c, "stream-leak")) stream_leak();
        else if (!strcmp(c, "stream-closed")) stream_closed();
        else if (!strcmp(c, "stream-double-close")) stream_double_close();
        else if (!strcmp(c, "stream-use-after-close")) stream_use_after_close();
        else if (!strcmp(c, "dir-leak")) dir_leak();
        else if (!strcmp(c, "dir-closed")) dir_closed();
        else if (!strcmp(c, "thread-leak")) thread_leak();
        else if (!strcmp(c, "thread-closed")) thread_closed();
        else if (!strcmp(c, "process-leak")) process_leak();
        else if (!strcmp(c, "process-closed")) process_closed();
        else if (!strcmp(c, "spawn-self")) spawn_self(argv[0]);
        else if (!strcmp(c, "inherited")) inherited();
        else if (!strcmp(c, "not-inheritable")) inherited_not_inheritable();
        else if (!strcmp(c, "event-leak")) event_leak();
        else if (!strcmp(c, "mutex-pipe-leak")) mutex_and_pipe_leak();
        else if (!strcmp(c, "clean")) everything_released();
        else {
            fprintf(stderr, "unknown case %s\n", c);
            return 64;
        }
    }
    if (tmp_path[0])
        DeleteFileA(tmp_path);
    return 0;
}
