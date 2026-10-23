#pragma once
// Findings model shared by both engines, plus everything that turns findings
// into output: runtime-stream parsing, symbolization, suppressions, renderers.
#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>

namespace lcreport {

inline constexpr const char *kToolName = "leakcheck";
inline constexpr const char *kToolVersion = "1.0.0";

struct Frame {
    std::string module;
    uint64_t offset = 0;
    std::string function;
    std::string file;
    int line = 0;
    int column = 0;
    bool inlined = false;
    // Flow steps only (see Finding::flow): what this step is, "argv", "cmd",
    // "system()". A stack frame leaves it empty.
    std::string what;
};

struct Finding {
    std::string type;     // e.g. "double-free", "memory-leak", "static-leak"
    std::string category; // leaks: definite | indirect | possible | reachable
    std::string message;
    std::string key; // stable identity for dedupe and SARIF fingerprints
    uint64_t address = 0;
    uint64_t size = 0;
    uint64_t blocks = 0;
    uint64_t bytes = 0;
    uint64_t occurrences = 1;
    uint32_t pid = 0;
    uint32_t tid = 0;
    std::vector<Frame> access; // where it happened / was detected
    std::vector<Frame> alloc;
    std::vector<Frame> freed;
    // static: how text from outside reached the dangerous call that was
    // reported, in order: where it entered the program, what it was called on
    // the way (a variable, a call site), and the call itself.
    std::vector<Frame> flow;
};

struct HeapStats {
    uint64_t allocs = 0, frees = 0, bytes = 0, live_blocks = 0, live_bytes = 0,
             peak_bytes = 0;
    uint64_t dropped = 0;
};

struct Process {
    uint32_t pid = 0;
    std::string exe;
    bool complete = false; // runtime wrote its end-of-stream record
    bool scanned = false;  // leak scan ran
    HeapStats stats;
};

struct Report {
    std::string mode; // "dynamic" | "static"
    std::vector<std::string> command;
    std::vector<Finding> findings;
    std::vector<Process> processes;
    std::vector<std::string> notes;
    // dynamic: how the target ended
    bool ran = false;
    int exit_code = 0;
    int signal = 0;
    // static: files analysed
    size_t files_analyzed = 0;
};

// Severity used by every output format: "error", "warning" or "note".
std::string severity_of(const Finding &f);
// Counts towards the non-zero exit status.
bool is_problem(const Finding &f);
// The most useful source location: first frame in user code, if any.
const Frame *primary_frame(const Finding &f);

// Runtime stream (see shared/include/protocol.h) -> findings + processes.
bool parse_runtime_stream(const std::string &path, Report &out);
// Fills function/file/line using addr2line; trims frames below main().
void symbolize(Report &r);
// Loads "type:pattern" rules; returns false (with *error) on a bad file.
bool apply_suppressions(const std::string &path, Report &r, std::string *error);
// Drops leaks of the dynamic loader's own bookkeeping (dlopen data).
void apply_default_suppressions(Report &r);
// --malware: adds the families that are defined by what is found together (a
// disguise plus harm is a trojan horse; a remote shell plus spying is a RAT; ...)
// and the families that are another's other name (a file infector is a virus).
void add_composite_findings(Report &r);

void render_console(const Report &r, std::ostream &os);
void render_json(const Report &r, std::ostream &os);
void render_sarif(const Report &r, std::ostream &os);
// Writes in the requested format to the file, or stdout when path is empty.
bool write_report(const Report &r, const std::string &format,
                  const std::string &path, std::string *error);

} // namespace lcreport
