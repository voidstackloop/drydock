#pragma once
#include <map>
#include <string>
#include <vector>

// Exit status, the contract a gate can rely on (docs/REFERENCE.md).
inline constexpr int kExitClean = 0;
inline constexpr int kExitCouldNotAnalyse = 1;
inline constexpr int kExitProblems = 2;
inline constexpr int kExitConfig = 3;

// One exclude pattern and the directory it is relative to. Patterns come from
// leakcheck.toml, .leakcheckignore and --exclude; keeping the directory with
// the pattern lets a config two levels up still say "vendor/**".
struct ExcludeRule
{
    std::string base;
    std::string pattern;
    bool negated = false;
};

struct RulePolicy
{
    std::string id;
    bool enabled = true;
};

struct Command
{
    std::string mode;
    std::string target;
    std::string output;
    std::string format = "console";
    std::vector<std::string> target_args;

    std::string suppressions;
    int error_exitcode = kExitProblems;
    bool show_reachable = false;
    bool leak_check = true;
    int quarantine_mb = 64;
    int stack_depth = 24;
    int guard_every = 0;
    bool abort_on_error = false;
    bool fast_unwind = false;
    bool trace_children = false;
    int timeout_sec = 0;  // --timeout: kill the target after N seconds (0: no limit)
    bool malware = false; // --malware: the deep scan for the 100 malware families
    int jobs = 0;         // scan/static: files read and analysed at the same time (0: one per CPU)

    bool ai = false;              // --ai: also ask the trained PE classifier
    std::string ai_model;         // --ai-model <file> (default: model/pe-malware.ai)
    double ai_threshold = -1.0;   // --ai-threshold (default: the threshold the model was exported with)

    // ---- Phase 1: the gate a team turns on ---------------------------------
    // Which of these a flag set. The config file fills the rest, so a flag
    // always wins over the file.
    bool format_set = false;
    bool jobs_set = false;
    bool suppressions_set = false;
    bool error_exitcode_set = false;
    bool min_severity_set = false;
    bool baseline_set = false;

    std::string baseline_mode; // "write" | "compare"
    std::string baseline_path;
    std::string min_severity = "warning"; // error | warning | note
    std::vector<ExcludeRule> excludes;
    // Ordered global, mode and CLI overrides; the last setting for an ID wins.
    std::vector<RulePolicy> rule_policy;

    std::string config_file; // --config, or the file found upwards
    bool no_config = false;
    bool print_config = false;
    bool audit_suppressions = false;
    std::string changed_only; // git ref: only files changed against it
    bool no_cache = false;    // do not read or write the incremental cache
    bool rule_list = false;   // print the rule inventory and exit
    bool list_only = false;   // --list: print the targets and exit, analyse nothing
    bool strict = false;      // also report the rules that did not meet the false-alarm budget
    bool metrics = false;     // print codebase security metrics & debt score
    std::string diff_base;
    std::string custom_rules;
    std::string gen_fuzz;
    std::string vcxproj;   // static: write a VS project listing scanned files
    std::string fix_commit; // static: write auto-fix patch, `git apply --check` it
    std::string backend = "preload";
    std::string record_path;
    bool prove = false;
    bool audit_deps = false;
    std::string profile;
    std::string trend_db;
    // git ref: only fail on findings touching changed lines
    std::map<std::string, std::string> rule_severities; // [rules.<id>] severity overrides
};
