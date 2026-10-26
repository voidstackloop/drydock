#include "dynamic_engine.h"
#include "command.h"
#include "protocol.h"
#include "report.h"

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

namespace {

std::string get_selfpath() {
    char buff[PATH_MAX];
#if defined(__APPLE__)
    uint32_t sz = sizeof buff;
    if (_NSGetExecutablePath(buff, &sz) != 0)
        return "";
    return std::string(buff);
#else
    ssize_t len = ::readlink("/proc/self/exe", buff, sizeof(buff) - 1);
    if (len != -1) {
        buff[len] = '\0';
        return std::string(buff);
    }
    return "";
#endif
}

// libleakcheck_preload.so is built alongside the leakcheck binary itself,
// so its path is derived from leakcheck's own path, not hardcoded.
std::string get_preload_path() {
    std::string self = get_selfpath();
    if (self.empty()) {
        return "";
    }
    size_t slash = self.find_last_of('/');
    std::string dir =
        (slash == std::string::npos) ? "." : self.substr(0, slash);
    return dir + "/" + lcproto::kLibName;
}

std::vector<char *> get_as_char(const Command &command) {
    std::vector<char *> chars = {};
    chars.push_back(const_cast<char *>(command.target.c_str()));
    for (size_t i = 0; i < command.target_args.size(); i++) {
        chars.push_back(const_cast<char *>(command.target_args[i].c_str()));
    }
    chars.push_back(nullptr);
    return chars;
}

std::string make_report_file() {
    const char *dir = getenv("TMPDIR");
    std::string tmpl =
        std::string(dir && *dir ? dir : "/tmp") + "/leakcheck-XXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    int fd = mkstemp(buf.data());
    if (fd < 0)
        return "";
    close(fd);
    return buf.data();
}

// Runs in the forked child, before exec: only the target sees these.
void setup_child_env(const Command &command, const std::string &preload,
                     const std::string &report) {
    std::string value = preload;
#if defined(__APPLE__)
    const char *preload_env = "DYLD_INSERT_LIBRARIES";
#else
    const char *preload_env = "LD_PRELOAD";
#endif
    if (const char *old = getenv(preload_env); old && *old)
        value += std::string(":") + old;
    setenv(preload_env, value.c_str(), 1);
    setenv(lcproto::kEnvReport, report.c_str(), 1);
    setenv(lcproto::kEnvRootPid, std::to_string(getpid()).c_str(), 1);
    setenv(lcproto::kEnvQuarantineMb,
           std::to_string(command.quarantine_mb).c_str(), 1);
    setenv(lcproto::kEnvStackDepth, std::to_string(command.stack_depth).c_str(),
           1);
    setenv(lcproto::kEnvGuardEvery, std::to_string(command.guard_every).c_str(),
           1);
    setenv(lcproto::kEnvAbort, command.abort_on_error ? "1" : "0", 1);
    setenv(lcproto::kEnvFastUnwind, command.fast_unwind ? "1" : "0", 1);
    setenv(lcproto::kEnvLeaks, command.leak_check ? "1" : "0", 1);
    setenv(lcproto::kEnvReachable, command.show_reachable ? "1" : "0", 1);
    setenv(lcproto::kEnvTraceChildren, command.trace_children ? "1" : "0", 1);
    setenv(lcproto::kEnvMalware, command.malware ? "1" : "0", 1);
}

struct Outcome {
    bool started = false;
    int exec_errno = 0;
    int status = 0;
};

Outcome launch(const Command &command, const std::string &preload,
               const std::string &report) {
    Outcome out;
    std::vector<char *> argv = get_as_char(command);
    int errpipe[2];
#if defined(__APPLE__)
    if (pipe(errpipe) != 0) {
        out.exec_errno = errno;
        return out;
    }
    fcntl(errpipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(errpipe[1], F_SETFD, FD_CLOEXEC);
#else
    if (pipe2(errpipe, O_CLOEXEC) != 0) {
        out.exec_errno = errno;
        return out;
    }
#endif

    // Like a shell waiting for a foreground job: Ctrl-C stops the target,
    // and leakcheck stays alive to report what happened.
    struct sigaction ignore {
    }, old_int{}, old_quit{};
    ignore.sa_handler = SIG_IGN;
    sigaction(SIGINT, &ignore, &old_int);
    sigaction(SIGQUIT, &ignore, &old_quit);

    pid_t c_pid = fork();
    if (c_pid == -1) {
        out.exec_errno = errno;
        close(errpipe[0]);
        close(errpipe[1]);
    } else if (c_pid == 0) {
        sigaction(SIGINT, &old_int, nullptr);
        sigaction(SIGQUIT, &old_quit, nullptr);
        close(errpipe[0]);
        setup_child_env(command, preload, report);
        execvp(argv[0], argv.data());
        int err = errno;
        ssize_t ignored = write(errpipe[1], &err, sizeof err);
        (void)ignored;
        _exit(127);
    } else {
        close(errpipe[1]);
        int err = 0;
        ssize_t n;
        while ((n = read(errpipe[0], &err, sizeof err)) < 0 && errno == EINTR) {
        }
        close(errpipe[0]);
        while (waitpid(c_pid, &out.status, 0) < 0 && errno == EINTR) {
        }
        if (n == ssize_t(sizeof err))
            out.exec_errno = err;
        else
            out.started = true;
    }
    sigaction(SIGINT, &old_int, nullptr);
    sigaction(SIGQUIT, &old_quit, nullptr);
    return out;
}

} // namespace

int run_dynamic_analysis(const Command &command) {
    std::string preload_so = get_preload_path();
    if (preload_so.empty() || access(preload_so.c_str(), R_OK) != 0) {
        fprintf(stderr,
                "leakcheck: cannot find %s next to the leakcheck executable\n",
                lcproto::kLibName);
        return 1;
    }
    std::string report_path = make_report_file();
    if (report_path.empty()) {
        fprintf(stderr,
                "leakcheck: cannot create a temporary report file: %s\n",
                strerror(errno));
        return 1;
    }

    Outcome run = launch(command, preload_so, report_path);
    if (!run.started) {
        unlink(report_path.c_str());
        fprintf(stderr, "leakcheck: cannot run '%s': %s\n",
                command.target.c_str(), strerror(run.exec_errno));
        return 127;
    }

    lcreport::Report report;
    report.mode = "dynamic";
    report.min_severity = command.min_severity;
    report.command.push_back(command.target);
    report.command.insert(report.command.end(), command.target_args.begin(),
                          command.target_args.end());
    report.ran = true;
    if (WIFSIGNALED(run.status))
        report.signal = WTERMSIG(run.status);
    else
        report.exit_code = WEXITSTATUS(run.status);

    lcreport::parse_runtime_stream(report_path, report);
    unlink(report_path.c_str());
    if (report.processes.empty())
        report.notes.push_back(
#if defined(__APPLE__)
            "the target produced no data: it may be statically linked, "
            "setuid, restricted by the hardened runtime, or it cleared "
            "DYLD_INSERT_LIBRARIES");
#else
            "the target produced no data: it may be statically linked, "
            "setuid, or it cleared LD_PRELOAD");
#endif
    lcreport::symbolize(report);
    lcreport::apply_default_suppressions(report);
    lcreport::apply_rule_policy(report, command.rule_policy, command.strict);

    std::string error;
    if (!command.suppressions.empty() &&
        !lcreport::apply_suppressions(command.suppressions, report, &error)) {
        fprintf(stderr, "leakcheck: %s\n", error.c_str());
        return kExitConfig;
    }
    if (!command.baseline_path.empty()) {
        if (command.baseline_mode == "write") {
            if (!lcreport::write_baseline(command.baseline_path, report, &error)) {
                fprintf(stderr, "leakcheck: %s\n", error.c_str());
                return kExitConfig;
            }
            report.notes.push_back("baseline written: " + std::to_string(report.findings.size()) +
                                   " finding(s) to " + command.baseline_path);
        } else {
            size_t known = 0;
            if (!lcreport::apply_baseline(command.baseline_path, report, &known, &error)) {
                fprintf(stderr, "leakcheck: %s\n", error.c_str());
                return kExitConfig;
            }
        }
    }
    if (!lcreport::write_report(report, command.format, command.output,
                                &error)) {
        fprintf(stderr, "leakcheck: %s\n", error.c_str());
        return kExitCouldNotAnalyse;
    }

    size_t problems = 0;
    for (const auto &f : report.findings)
        problems += lcreport::is_problem_at(f, command.min_severity);
    if (!command.output.empty())
        fprintf(stderr,
                "leakcheck: %zu problem(s) found; report written to %s\n",
                problems, command.output.c_str());

    // Writing a baseline is setup, not a verdict.
    if (command.baseline_mode == "write" && !command.baseline_path.empty())
        return kExitClean;
    // Problems outrank the program's own status: a leak that exits 1 is still
    // the error code, and a clean program that exits 2 keeps 2.
    if (problems)
        return command.error_exitcode;
    if (report.signal)
        return 128 + report.signal;
    if (report.exit_code != 0)
        return report.exit_code;
    if (report.processes.empty())
        return 1; // nothing was analysed: never report success
    return 0;
}
