#pragma once
// Findings model shared by both engines, plus everything that turns findings
// into output: runtime-stream parsing, symbolization, suppressions, renderers.
#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>
#include "command.h"

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
    bool reachable = false;
    std::string key; // stable identity for dedupe and SARIF fingerprints
    std::string severity_override; // optional configured severity override
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
    // The weakest severity that fails the gate; renderers count problems the
    // same way the exit status does.
    std::string min_severity = "warning";
};

// Severity used by every output format: "error", "warning" or "note".
std::string severity_of(const Finding &f);
// Counts towards the non-zero exit status.
bool is_problem(const Finding &f);
// The most useful source location: first frame in user code, if any.
const Frame *primary_frame(const Finding &f);

// Shell glob (`*`, `?`, `[a-z]`), no special case for '/': the same matching
// in exclude patterns and suppression rules.
bool glob_match(const char *pattern, const char *text);

// FNV-1a over the bytes. std::hash is not specified and differs between the
// standard libraries, so two machines would give the same finding different
// SARIF fingerprints; this gives them the same number.
uint64_t stable_hash(const std::string &text);

// Runtime stream (see shared/include/protocol.h) -> findings + processes.
bool parse_runtime_stream(const std::string &path, Report &out);
// Fills function/file/line using addr2line; trims frames below main().
void symbolize(Report &r);
// Loads "type:pattern" rules; returns false (with *error) on a bad file.
// A rule may carry reason="..." and expires=YYYY-MM-DD; an expired rule is an
// error, because a silence nobody renewed is how a finding stays hidden.
bool apply_suppressions(const std::string &path, Report &r, std::string *error);
// One rule as written, for --audit-suppressions.
struct SuppressionRule
{
    int line = 0;
    std::string type, pattern, reason, expires;
};
bool load_suppressions(const std::string &path, std::vector<SuppressionRule> *out,
                       std::string *error);
// The same parse and expiry check without a report, so a bad file can be
// rejected before the target is run.
bool check_suppressions(const std::string &path, std::string *error);
// Prints every rule with its reason and how long it has left. False (with
// *error) when a rule is malformed or expired.
bool audit_suppressions(const std::string &path, std::ostream &os, std::string *error);

// Stable identity of a finding for --baseline: type, file relative to the
// baseline's directory, enclosing function and message, no line numbers, so
// formatting and edits above the finding do not break it.
std::string fingerprint(const Finding &f, const std::string &root);
// Writes every finding to the baseline file, sorted, one per line.
bool write_baseline(const std::string &path, const Report &r, std::string *error);
// Removes findings already in the baseline. False (with *error) when the file
// cannot be read: a gate must not pass because its baseline broke.
bool apply_baseline(const std::string &path, Report &r, size_t *known, std::string *error);

// What counts as a problem at the configured threshold: severity error,
// warning or note.
bool is_problem_at(const Finding &f, const std::string &min_severity);

// A rule that did not meet the false-alarm budget on the reference corpus
// (eval/PRECISION.md) and is therefore only reported with --strict.
bool strict_rule(const std::string &type);
// True for an ID accepted by --enable-rule and --disable-rule.
bool known_rule(const std::string &type);
// Applies strict defaults and ordered config/CLI overrides. Disabled findings
// are removed before suppressions and baselines see the report.
void apply_rule_policy(Report &r, const std::vector<RulePolicy> &policy, bool strict);
// Drops leaks of the dynamic loader's own bookkeeping (dlopen data).
void apply_default_suppressions(Report &r);
// --malware: adds the families that are defined by what is found together (a
// disguise plus harm is a trojan horse; a remote shell plus spying is a RAT; ...)
// and the families that are another's other name (a file infector is a virus).
void add_composite_findings(Report &r);
void mark_reachable(Report &r);
bool apply_custom_rules(Report &r, const std::vector<std::string> &files,
                         const std::string &rules_path, std::string *error);
void apply_ownership_summaries(Report &r,
                                const std::vector<std::string> &files);
void gen_fuzz_harnesses(const Report &r, const std::string &dir,
                        std::vector<std::string> &notes);
void emit_vcxproj(const std::vector<std::string> &files, const std::string &path,
                  std::vector<std::string> &notes);
void write_fix_commit(Report &r, const std::string &path);
void audit_dependencies(const std::string &target, const std::vector<ExcludeRule> &excludes,
                        Report &r);
void prove_findings(Report &r);
int run_lsp(const Command &command);
int run_trend(const Command &command);


void render_console(const Report &r, std::ostream &os);
void render_json(const Report &r, std::ostream &os);
void render_sarif(const Report &r, std::ostream &os);
void render_junit(const Report &r, std::ostream &os);
void render_html(const Report &r, std::ostream &os);
void render_markdown(const Report &r, std::ostream &os);
void render_csv(const Report &r, std::ostream &os);
void render_gitlab(const Report &r, std::ostream &os);
void render_sonarqube(const Report &r, std::ostream &os);
void render_patch(const Report &r, std::ostream &os);
void render_metrics(const Report &r, std::ostream &os);
// --rule-list: every rule with its CWE, summary and default severity. JSON for
// inventory tools, text for people.
void render_rule_list(bool json, std::ostream &os);
// Writes in the requested format to the file, or stdout when path is empty.
bool write_report(const Report &r, const std::string &format,
                  const std::string &path, std::string *error);

} // namespace lcreport
