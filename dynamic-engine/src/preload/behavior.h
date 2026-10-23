#pragma once
// Run-time look at what the program does to the machine, for the things a
// trojan, backdoor or dropper does (see behavior.cpp). Every function is a
// no-op in the runtime's own code and in a process that is not traced.

namespace lc::behavior {

// open()/creat(): `flags` as for open(2).
void opening(const char *path, int flags);
// fopen(): `mode` is "r", "w+", "a", ...
void opening_stream(const char *path, const char *mode);

// A file is removed, truncated, replaced by a rename, link or symlink, or gets
// new permissions.
void deleting(const char *path, const char *how);
void truncating(const char *path, const char *how);
// utime()/utimensat() of a log or a shell history. They do not call truncate().
void dating(const char *path, const char *how);
// setenv("HISTFILE", "/dev/null") or HISTSIZE=0. Not a file operation.
void history_off(const char *how);
#ifndef _WIN32
void truncating_fd(int fd, const char *how); // ftruncate: the path is the descriptor's
void dating_fd(int fd, const char *how);     // futimens: the path is the descriptor's
#endif
void replacing(const char *path, const char *how);
void chmoding(const char *path, unsigned mode, const char *how);
// mode has the other-write bit, or umask(0). `rest` is the sentence after `how`.
void loose_mode(const char *how, const char *rest);
// open()/creat() with a mode that has the setuid or setgid bit. chmod() has its own.
void setuid_bit(const char *how);
// setenv("PATH", ...) or putenv("PATH=...") when the first directory is one anyone can write.
void search_path(const char *how, const char *value);
// setenv("LD_LIBRARY_PATH", ...) when the first directory is one anyone can write.
void library_path(const char *how, const char *value);
void chowning(const char *path, const char *how);
// mount()/umount() of a system program or directory. Neither calls chown().
void mounting(const char *target, const char *how);
#ifndef _WIN32
void chowning_fd(int fd, const char *how);
#endif

// The program is about to start another one (or replace itself).
// spawn_actions: a posix_spawn_file_actions_t, when the child is started that way.
#ifndef _WIN32
void exec(const char *path, char *const argv[], const char *how,
          const void *spawn_actions = nullptr);
void exec_fd(int fd, char *const argv[], const char *how);
#endif
// system()/popen(): a shell command line.
void command(const char *cmd, const char *how);
// dlopen() or dlmopen() of a file this program wrote. It does not go through exec().
void loading(const char *path, const char *how);

// The program's main() is about to run: is it called, or was it started as,
// something it is not?
void started(int argc, char **argv);
// prctl(PR_SET_NAME) and pthread_setname_np. memfd_create passes its own words.
void process_named(const char *name, const char *how = "the process renames itself");
// A host name about to be looked up.
void host(const char *name, const char *how);

// rename(from, to): many of them adding one ending is ransomware
void renamed(const char *from, const char *to);
// connect(): many different destinations in a short time is a scan
void connecting(const void *addr, unsigned len);

#ifdef _WIN32
// Only Windows: a program started, other programs written into, and the rest.
void process_start(const char *file, const char *line, const char *how, const void *startup);
void injected(const char *how);
void read_other_process(const char *how);
void debugger_probe(const char *how);
void privilege_enabled(const char *name);
void registry(const char *path, bool write, const char *how);
void event_log_cleared(const char *how);
void downloads(const char *url, const char *path, const char *how);
void elevation(const char *file, const char *how);
#else
void ptrace_call(int request, int pid);
void aslr_off(const char *how);
void vm_write(int pid);
void vm_read(int pid);
// pidfd_getfd(). It does not call process_vm_readv(). Linux only.
void other_fd(const char *how);
// prctl(PR_SET_MM_EXE_FILE). Linux only.
void exe_claimed(const char *how);
// The program asked to become user 0 (id: the first id it passed).
void setuid_root(const char *how);
void setgid_root(const char *how);
// iopl()/ioperm(). Not a setuid call. Linux only.
void raw_port(const char *how);
// socket(AF_PACKET) or SOCK_RAW. It does not call iopl().
void raw_socket(const char *how);
// capset() and prctl(PR_CAP_AMBIENT_RAISE). Linux only.
void caps(const char *how);
#endif

} // namespace lc::behavior
