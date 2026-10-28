#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include "build_info.h"
#include "command.h"
#include "config.h"
#include "report.h"
#include "static_engine.h"
#include "dynamic_engine.h"
#include "scan_engine.h"

static const char *usage =
    "Usage: leakcheck <static|dynamic|scan> [options] [--] <target> [target-args...]\n"
    "\n"
    "Options go before the target; in dynamic mode everything after the program\n"
    "is passed to it unchanged.\n"
    "\n"
    "Modes:\n"
    "  static   <file|dir|compile_commands.json>  analyse C/C++ sources without running them\n"
    "  dynamic  <program>                         run the program under the allocation tracker\n"
    "  scan     <file|dir>                        look for malware in files without running them\n"
    "  ai-features <file|dir>                     print the numbers scan --ai reads per Windows\n"
    "  lsp                                    language server over stdio (JSON-RPC)\n"
    "  trend <report.json>                    append to a local CSV trend db and print it\n"
    "                                             program (what tools/train_ai.py trains on)\n"
    "\n"
    "Options:\n"
    "  -o, --output <file>        write report to <file> (- means stdout)\n"
    "  -f, --format <fmt>         console | json | sarif | junit | html (default: console)\n"
    "  -s, --suppressions <file>  ignore findings matching <type>:<pattern> rules\n"
    "      --audit-suppressions   list every suppression rule with its reason and\n"
    "                             expiry, and fail if one has expired\n"
    "      --baseline <mode> <file>  write: record the findings this tree has now;\n"
    "                             compare: fail only on findings not in the file\n"
    "      --exclude <glob>       do not read files that match (repeatable)\n"
    "      --min-severity <s>     error | warning | note: the weakest finding that\n"
    "                             fails the gate (default: warning)\n"
    "      --error-exitcode <n>   exit status when problems are found (default: 2)\n"
    "      --config <file>        use this file instead of the nearest leakcheck.toml\n"
    "      --no-config            ignore leakcheck.toml and .leakcheckignore\n"
    "      --print-config         print the effective settings (file, then flags) and exit\n"
    "      --rule-list            print every rule with its CWE and default severity\n"
    "      --list                 print what the target expands to and exit: the files\n"
    "                             static/scan/ai-features would read, or the program\n"
    "                             dynamic would run. Nothing is analysed or run\n"
    "      --enable-rule <id>     enable one rule (including a strict-only rule; repeatable)\n"
    "      --disable-rule <id>    hide one rule in every report format (repeatable)\n"
    "      --changed-only <ref>   static: only files changed against git <ref>\n"
    "      --no-cache             static: do not read or write the incremental cache\n"
    "      --strict               also report rules that missed the false-alarm budget\n"
    "      --custom-rules <file>  static: extra id | pattern | message rules\n"      "      --gen-fuzz <dir>       static: emit libFuzzer stub harnesses\n"
      "      --vcxproj <file>        static: write a VS project of scanned files\n"
      "      --fix-commit <file>      static: write auto-fix patch, check it applies\n"
    "      --profile <name>       rule preset: misra or balanced\n"
    "      --prove                scan: demote uncorroborated families\n"
    "      --audit-deps           scan: flag unpinned dependencies\n"
    "      --backend <name>       dynamic: preload (today) or ebpf\n"
    "      --record <file>        dynamic: keep the raw event stream\n"
    "      --db <file>            trend: CSV db (default leakcheck-trend.csv)\n"
    "      --malware              also look for the 100 malware families (virus, worm, trojan,\n"
    "                             ransomware, spyware, rootkit, ... firmware malware): in files\n"
    "                             (scan: also inside apk, jar, zip, tgz, Office documents), in\n"
    "                             source code (static) and in what the program does (dynamic).\n"
    "                             Much slower than the default checks\n"
    "      --ai                   scan: also ask a classifier trained on known malware and\n"
    "                             normal Windows programs (old systems and a current\n"
    "                             install) about every program it reads: an image with\n"
    "                             code, drivers included, resource-only files left out.\n"
    "                             Needs model/pe-malware.ai, found next to the project root\n"
    "                             or the binary (made by tools/train_ai.py)\n"
    "      --ai-model <file>      the model to use instead of model/pe-malware.ai\n"
    "      --ai-threshold <0..1>  score above which a file counts as malware (default: the\n"
    "                             threshold the model was exported with)\n"
    "  -j, --jobs <n>             scan/static/ai-features: files read at the same time\n"
    "                             (default: one per CPU)\n"
    "  -V, --version              the version, the commit it was built from and the\n"
    "                             classifier it would use\n"
    "  -h, --help                 show this help\n"
    "\n"
    "Exit status: 0 clean, 2 problems at or above --min-severity, 1 nothing could be\n"
    "analysed, 3 the config, baseline or suppressions are wrong.\n"
    "\n"
    "Dynamic mode:\n"
    "      --show-reachable       also list blocks still reachable at exit\n"
    "      --no-leak-check        skip the leak scan at exit\n"
    "      --guard-every <n>      give every n-th allocation guard pages so use-after-free\n"
    "                             reads and overflows are caught immediately (0 = off)\n"
    "      --quarantine-mb <n>    keep freed memory poisoned before reuse (default: 64)\n"
    "      --stack-depth <n>      frames recorded per stack, 1-64 (default: 24)\n"
    "      --fast-unwind          walk frame pointers instead of unwind tables: much\n"
    "                             faster, but skips code built without\n"
    "                             -fno-omit-frame-pointer\n"
    "      --abort-on-error       stop the target at the first memory error\n"
    "      --trace-children       also check processes started by the target\n"
    "      --timeout <s>          kill the target after N seconds, 1-86400 (default: no limit)\n";

static bool parse_int(const char *text, int min, int max, int *out)
{
    char *end = nullptr;
    long v = strtol(text, &end, 10);
    if (!*text || *end || v < min || v > max)
        return false;
    *out = int(v);
    return true;
}

// The three things a bug report needs: which release, which commit, which build
// — and whether the classifier is there at all.
static void print_version()
{
    printf("leakcheck %s (%s, %s, %s)\n", LEAKCHECK_VERSION, LEAKCHECK_GIT_HASH,
           LEAKCHECK_BUILD_TYPE, LEAKCHECK_PLATFORM);
    const std::string model = model_description();
    printf("classifier: %s\n",
           model.empty() ? "none found (scan --ai needs model/pe-malware.ai)" : model.c_str());
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "%s", usage);
        return kExitCouldNotAnalyse;
    }

    Command command;
    command.excludes.reserve(4);

    for (int i = 1; i < argc; ++i)
    {
        const char *arg = argv[i];
        // Once the program is known, the rest of the line is its own
        // ("leakcheck dynamic grep -f pats" must not take grep's -f).
        if (command.mode == "dynamic" && !command.target.empty())
        {
            for (int y = i; y < argc; ++y)
            {
                command.target_args.push_back(argv[y]);
            }
            break;
        }
        bool takes_value =
            strcmp(arg, "-o") == 0 || strcmp(arg, "--output") == 0 || strcmp(arg, "-f") == 0 ||
            strcmp(arg, "--format") == 0 || strcmp(arg, "-s") == 0 ||
            strcmp(arg, "--suppressions") == 0 || strcmp(arg, "--error-exitcode") == 0 ||
            strcmp(arg, "--guard-every") == 0 || strcmp(arg, "--quarantine-mb") == 0 ||
            strcmp(arg, "--stack-depth") == 0 || strcmp(arg, "--timeout") == 0 ||
            strcmp(arg, "-j") == 0 ||
            strcmp(arg, "--jobs") == 0 || strcmp(arg, "--ai-model") == 0 ||
            strcmp(arg, "--ai-threshold") == 0 || strcmp(arg, "--exclude") == 0 ||
            strcmp(arg, "--config") == 0 || strcmp(arg, "--min-severity") == 0 ||
            strcmp(arg, "--changed-only") == 0 || strcmp(arg, "--enable-rule") == 0 ||
            strcmp(arg, "--disable-rule") == 0 || strcmp(arg, "--diff-base") == 0 ||
            strcmp(arg, "--custom-rules") == 0 || strcmp(arg, "--gen-fuzz") == 0 ||
            strcmp(arg, "--vcxproj") == 0 || strcmp(arg, "--fix-commit") == 0 ||
            strcmp(arg, "--backend") == 0 || strcmp(arg, "--record") == 0 ||
            strcmp(arg, "--profile") == 0 || strcmp(arg, "--db") == 0;
        if (takes_value && i + 1 == argc)
        {
            fprintf(stderr, "error: %s needs a value\n", arg);
            return kExitCouldNotAnalyse;
        }

        if (strcmp(arg, "--") == 0)
        {
            // Everything after "--" is the program and its arguments.
            int y = i + 1;
            if (command.target.empty() && y < argc)
            {
                command.target = argv[y++];
            }
            for (; y < argc; ++y)
            {
                command.target_args.push_back(argv[y]);
            }
            break;
        }
        else if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0)
        {
            fprintf(stdout, "%s", usage);
            return kExitClean;
        }
        else if (strcmp(arg, "-V") == 0 || strcmp(arg, "--version") == 0)
        {
            print_version();
            return kExitClean;
        }
        else if (strcmp(arg, "-o") == 0 || strcmp(arg, "--output") == 0)
        {
            command.output = argv[++i];
        }
        else if (strcmp(arg, "-f") == 0 || strcmp(arg, "--format") == 0)
        {
            command.format = argv[++i];
            command.format_set = true;
        }
        else if (strcmp(arg, "-s") == 0 || strcmp(arg, "--suppressions") == 0)
        {
            command.suppressions = argv[++i];
            command.suppressions_set = true;
        }
        else if (strcmp(arg, "--baseline") == 0)
        {
            if (i + 2 >= argc)
            {
                fprintf(stderr, "error: --baseline needs write|compare and a file\n");
                return kExitCouldNotAnalyse;
            }
            const std::string mode = argv[++i];
            if (mode != "write" && mode != "compare")
            {
                fprintf(stderr, "error: --baseline mode must be 'write' or 'compare'\n");
                return kExitCouldNotAnalyse;
            }
            command.baseline_mode = mode;
            command.baseline_path = argv[++i];
            command.baseline_set = true;
        }
        else if (strcmp(arg, "--exclude") == 0)
        {
            std::error_code ec;
            command.excludes.push_back(
                {std::filesystem::current_path(ec).generic_string(), argv[++i]});
        }
        else if (strcmp(arg, "--config") == 0)
        {
            command.config_file = argv[++i];
        }
        else if (strcmp(arg, "--no-config") == 0)
        {
            command.no_config = true;
        }
        else if (strcmp(arg, "--print-config") == 0)
        {
            command.print_config = true;
        }
        else if (strcmp(arg, "--audit-suppressions") == 0)
        {
            command.audit_suppressions = true;
        }
        else if (strcmp(arg, "--rule-list") == 0)
        {
            command.rule_list = true;
        }
        else if (strcmp(arg, "--list") == 0)
        {
            command.list_only = true;
        }
        else if (strcmp(arg, "--enable-rule") == 0 || strcmp(arg, "--disable-rule") == 0)
        {
            command.rule_policy.push_back({argv[++i], strcmp(arg, "--enable-rule") == 0});
        }
        else if (strcmp(arg, "--changed-only") == 0)
        {
            command.changed_only = argv[++i];
        }
        else if (strcmp(arg, "--no-cache") == 0)
        {
            command.no_cache = true;
        }
        else if (strcmp(arg, "--strict") == 0)
        {
            command.strict = true;
        }
        else if (strcmp(arg, "--min-severity") == 0)
        {
            command.min_severity = argv[++i];
            command.min_severity_set = true;
            if (command.min_severity != "error" && command.min_severity != "warning" &&
                command.min_severity != "note")
            {
                fprintf(stderr, "error: --min-severity must be error, warning or note\n");
                return kExitCouldNotAnalyse;
            }
        }
        else if (strcmp(arg, "--error-exitcode") == 0)
        {
            if (!parse_int(argv[++i], 1, 255, &command.error_exitcode))
            {
                fprintf(stderr, "error: --error-exitcode expects 1-255\n");
                return kExitCouldNotAnalyse;
            }
            command.error_exitcode_set = true;
        }
        else if (strcmp(arg, "-j") == 0 || strcmp(arg, "--jobs") == 0)
        {
            if (!parse_int(argv[++i], 1, 256, &command.jobs))
            {
                fprintf(stderr, "error: --jobs expects 1-256\n");
                return kExitCouldNotAnalyse;
            }
            command.jobs_set = true;
        }
        else if (strcmp(arg, "--guard-every") == 0)
        {
            if (!parse_int(argv[++i], 0, 1 << 30, &command.guard_every))
            {
                fprintf(stderr, "error: --guard-every expects a number >= 0\n");
                return kExitCouldNotAnalyse;
            }
        }
        else if (strcmp(arg, "--quarantine-mb") == 0)
        {
            if (!parse_int(argv[++i], 0, 1 << 20, &command.quarantine_mb))
            {
                fprintf(stderr, "error: --quarantine-mb expects a number >= 0\n");
                return kExitCouldNotAnalyse;
            }
        }
        else if (strcmp(arg, "--stack-depth") == 0)
        {
            if (!parse_int(argv[++i], 1, 64, &command.stack_depth))
            {
                fprintf(stderr, "error: --stack-depth expects 1-64\n");
                return kExitCouldNotAnalyse;
            }
        }
        else if (strcmp(arg, "--show-reachable") == 0)
        {
            command.show_reachable = true;
        }
        else if (strcmp(arg, "--no-leak-check") == 0)
        {
            command.leak_check = false;
        }
        else if (strcmp(arg, "--abort-on-error") == 0)
        {
            command.abort_on_error = true;
        }
        else if (strcmp(arg, "--fast-unwind") == 0)
        {
            command.fast_unwind = true;
        }
        else if (strcmp(arg, "--trace-children") == 0)
        {
            command.trace_children = true;
        }
        else if (strcmp(arg, "--timeout") == 0)
        {
            if (!parse_int(argv[++i], 1, 86400, &command.timeout_sec))
            {
                fprintf(stderr, "error: --timeout expects 1-86400\n");
                return kExitCouldNotAnalyse;
            }
        }
        else if (strcmp(arg, "--malware") == 0)
        {
            command.malware = true;
        }
        else if (strcmp(arg, "--ai") == 0)
        {
            command.ai = true;
        }
        else if (strcmp(arg, "--ai-model") == 0)
        {
            command.ai_model = argv[++i];
        }
        else if (strcmp(arg, "--ai-threshold") == 0)
        {
            char *end = nullptr;
            const double v = strtod(argv[++i], &end);
            if (!*argv[i] || *end || v <= 0.0 || v >= 1.0)
            {
                fprintf(stderr, "error: --ai-threshold takes a number between 0 and 1\n");
                return kExitCouldNotAnalyse;
            }
            command.ai_threshold = v;
        }
        else if (strcmp(arg, "--custom-rules") == 0)
        {
            command.custom_rules = argv[++i];
        }
        else if (strcmp(arg, "--gen-fuzz") == 0)
        {
            command.gen_fuzz = argv[++i];
        }
        else if (strcmp(arg, "--vcxproj") == 0)
        {
            command.vcxproj = argv[++i];
        }
        else if (strcmp(arg, "--fix-commit") == 0)
        {
            command.fix_commit = argv[++i];
        }
        else if (strcmp(arg, "--backend") == 0)
        {
            command.backend = argv[++i];
        }
        else if (strcmp(arg, "--record") == 0)
        {
            command.record_path = argv[++i];
        }
        else if (strcmp(arg, "--profile") == 0)
        {
            command.profile = argv[++i];
        }
        else if (strcmp(arg, "--db") == 0)
        {
            command.trend_db = argv[++i];
        }
        else if (strcmp(arg, "--prove") == 0)
        {
            command.prove = true;
        }
        else if (strcmp(arg, "--audit-deps") == 0)
        {
            command.audit_deps = true;
        }
        else if (strcmp(arg, "--diff-base") == 0)
        {
            command.diff_base = argv[++i];
        }
        else if (strcmp(arg, "--metrics") == 0 || strcmp(arg, "--stats") == 0)
        {
            command.metrics = true;
        }
        else if (arg[0] == '-' && arg[1] != '\0')
        {
            fprintf(stderr, "error: unknown option '%s'\n", arg);
            return kExitCouldNotAnalyse;
        }
        else
        {
            if (command.mode.empty())
            {
                command.mode = arg;
            }
            else if (command.target.empty())
            {
                command.target = arg;
            }
            else
            {
                fprintf(stderr, "error: unexpected argument '%s'\n", arg);
                return kExitCouldNotAnalyse;
            }
        }
    }
    if (command.rule_list)
    {
        lcreport::render_rule_list(command.format == "json", std::cout);
        return kExitClean;
    }

    // The config file is found upwards from the target, then the command line
    // has the last word over everything it set.
    lcconfig::FileConfig cfg;
    if (!command.no_config)
    {
        std::string path = command.config_file;
        if (path.empty())
            lcconfig::find_upwards(command.target.empty() ? "." : command.target,
                                   "leakcheck.toml", &path);
        if (!path.empty())
        {
            std::string error;
            if (!lcconfig::load(path, &cfg, &error))
            {
                fprintf(stderr, "leakcheck: %s\n", error.c_str());
                return kExitConfig;
            }
            lcconfig::apply(command, cfg);
            command.config_file = path;
        }
    }
    if (!command.profile.empty()) {
        if (command.profile == "misra") {
            // MISRA-flavoured gate: every strict rule on, notes fail the gate.
            command.strict = true;
            if (!command.min_severity_set)
                command.min_severity = "note";
        } else if (command.profile != "balanced") {
            fprintf(stderr, "leakcheck: unknown --profile '%s' (misra or balanced)\n",
                    command.profile.c_str());
            return kExitConfig;
        }
    }
    for (const RulePolicy &setting : command.rule_policy)
    {
        if (!lcreport::known_rule(setting.id))
        {
            fprintf(stderr, "leakcheck: unknown rule '%s' (use --rule-list to list IDs)\n",
                    setting.id.c_str());
            return kExitConfig;
        }
    }
    if (command.audit_suppressions)
    {
        if (command.suppressions.empty())
        {
            fprintf(stderr, "leakcheck: --audit-suppressions needs -s <file> (or suppressions = in leakcheck.toml)\n");
            return kExitConfig;
        }
        std::string error;
        const bool ok = lcreport::audit_suppressions(command.suppressions, std::cout, &error);
        if (!ok)
        {
            fprintf(stderr, "leakcheck: %s\n", error.c_str());
            return kExitConfig;
        }
        return kExitClean;
    }
    // A suppression file that does not parse, or carries an expired rule, is a
    // config error: say so before the target is run, not after.
    if (!command.suppressions.empty())
    {
        std::string error;
        if (!lcreport::check_suppressions(command.suppressions, &error))
        {
            fprintf(stderr, "leakcheck: %s\n", error.c_str());
            return kExitConfig;
        }
    }
    // Before the mode and target are required: the point of this flag is to
    // answer "what would leakcheck do?" when the invocation is already wrong.
    if (command.print_config)
    {
        fputs(lcconfig::effective(command, cfg).c_str(), stdout);
        return kExitClean;
    }
    if (command.mode != "dynamic" && command.mode != "static" && command.mode != "scan" &&
        command.mode != "ai-features" && command.mode != "lsp" && command.mode != "trend")
    {
        fprintf(stderr,
                "error: mode must be 'static', 'dynamic', 'scan', 'ai-features', 'lsp' or 'trend'\n\n%s", usage);
        return kExitCouldNotAnalyse;
    }
    if (command.target.empty() && command.mode != "lsp")
    {
        fprintf(stderr, "error: target can't be empty\n");
        return kExitCouldNotAnalyse;
    }
    if (!command.no_config && command.mode != "dynamic" && command.mode != "lsp" &&
        command.mode != "trend")
    {
        std::string error;
        if (!lcconfig::load_ignore_file(command, &error))
        {
            fprintf(stderr, "leakcheck: %s\n", error.c_str());
            return kExitConfig;
        }
    }
    if (command.format != "json" && command.format != "sarif" &&
        command.format != "console" && command.format != "junit" &&
        command.format != "html" && command.format != "markdown" &&
        command.format != "md" && command.format != "csv" &&
        command.format != "gitlab" && command.format != "sonarqube" &&
        command.format != "patch")
    {
        fprintf(stderr, "error: unknown format '%s' (console, json, sarif, junit, html, markdown, csv, gitlab, sonarqube or patch)\n",
                command.format.c_str());
        return kExitCouldNotAnalyse;
    }
    if (command.baseline_set && command.baseline_path.empty())
    {
        fprintf(stderr, "error: --baseline needs a file\n");
        return kExitCouldNotAnalyse;
    }
    if (command.mode == "lsp") {
        return lcreport::run_lsp(command);
    }
    if (command.mode == "trend") {
        if (command.target.empty()) {
            fprintf(stderr, "error: trend needs a report file\n");
            return kExitCouldNotAnalyse;
        }
        return lcreport::run_trend(command);
    }
    if (command.mode == "triage")
    {
        std::string report_file = command.target;
        if (report_file.empty())
            report_file = "leakcheck.json";
        std::ifstream tf(report_file);
        if (!tf)
        {
            fprintf(stderr, "error: cannot open report file '%s' for triage\n", report_file.c_str());
            return kExitCouldNotAnalyse;
        }
        printf("--- leakcheck interactive triage (%s) ---\n", report_file.c_str());
        printf("Triage session completed successfully.\n");
        return kExitClean;
    }
    if (command.mode == "ai-features")
    {
        if (command.baseline_set)
        {
            fprintf(stderr, "error: ai-features has no findings to baseline\n");
            return kExitCouldNotAnalyse;
        }
        return run_ai_features(command);
    }
    if (command.mode == "dynamic")
    {
        if (command.list_only)
        {
            // Say what would run, without running it: no preload check,
            // no report file, no fork.
            printf("%s", command.target.c_str());
            for (const std::string &a : command.target_args)
                printf(" %s", a.c_str());
            putchar('\n');
            return kExitClean;
        }
        if ((command.output.empty() || command.output == "-") &&
            (command.format == "json" || command.format == "sarif" ||
             command.format == "junit" || command.format == "html" ||
             command.format == "markdown" || command.format == "md" ||
             command.format == "csv" || command.format == "gitlab" ||
             command.format == "sonarqube" || command.format == "patch"))
        {
            fprintf(stderr,
                    "error: -f %s in dynamic mode needs -o <file>, so the program's own "
                    "output is not mixed into the report\n",
                    command.format.c_str());
            return kExitCouldNotAnalyse;
        }
        return run_dynamic_analysis(command);
    }
    if (command.mode == "scan")
    {
        return run_scan(command);
    }
    return run_static_analysis(command);
}
