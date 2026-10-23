#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include "build_info.h"
#include "command.h"
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
    "                                             program (what tools/train_ai.py trains on)\n"
    "\n"
    "Options:\n"
    "  -o, --output <file>        write report to <file> instead of stdout\n"
    "  -f, --format <fmt>         console | json | sarif (default: console)\n"
    "  -s, --suppressions <file>  ignore findings matching <type>:<pattern> rules\n"
    "      --error-exitcode <n>   exit status when problems are found (default: 2)\n"
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
    "  -j, --jobs <n>             scan/static/ai-features: files read at the same time\n                             (default: one per CPU)\n"
    "  -V, --version              the version, the commit it was built from and the\n"
    "                             classifier it would use\n"
    "  -h, --help                 show this help\n"
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
    "      --trace-children       also check processes started by the target\n";

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
        return 1;
    }

    Command command;

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
            strcmp(arg, "--stack-depth") == 0 || strcmp(arg, "-j") == 0 ||
            strcmp(arg, "--jobs") == 0 || strcmp(arg, "--ai-model") == 0 ||
            strcmp(arg, "--ai-threshold") == 0;
        if (takes_value && i + 1 == argc)
        {
            fprintf(stderr, "error: %s needs a value\n", arg);
            return 1;
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
            return 0;
        }
        else if (strcmp(arg, "-V") == 0 || strcmp(arg, "--version") == 0)
        {
            print_version();
            return 0;
        }
        else if (strcmp(arg, "-o") == 0 || strcmp(arg, "--output") == 0)
        {
            command.output = argv[++i];
        }
        else if (strcmp(arg, "-f") == 0 || strcmp(arg, "--format") == 0)
        {
            command.format = argv[++i];
        }
        else if (strcmp(arg, "-s") == 0 || strcmp(arg, "--suppressions") == 0)
        {
            command.suppressions = argv[++i];
        }
        else if (strcmp(arg, "--error-exitcode") == 0)
        {
            if (!parse_int(argv[++i], 1, 255, &command.error_exitcode))
            {
                fprintf(stderr, "error: --error-exitcode expects 1-255\n");
                return 1;
            }
        }
        else if (strcmp(arg, "-j") == 0 || strcmp(arg, "--jobs") == 0)
        {
            if (!parse_int(argv[++i], 1, 256, &command.jobs))
            {
                fprintf(stderr, "error: --jobs expects 1-256\n");
                return 1;
            }
        }
        else if (strcmp(arg, "--guard-every") == 0)
        {
            if (!parse_int(argv[++i], 0, 1 << 30, &command.guard_every))
            {
                fprintf(stderr, "error: --guard-every expects a number >= 0\n");
                return 1;
            }
        }
        else if (strcmp(arg, "--quarantine-mb") == 0)
        {
            if (!parse_int(argv[++i], 0, 1 << 20, &command.quarantine_mb))
            {
                fprintf(stderr, "error: --quarantine-mb expects a number >= 0\n");
                return 1;
            }
        }
        else if (strcmp(arg, "--stack-depth") == 0)
        {
            if (!parse_int(argv[++i], 1, 64, &command.stack_depth))
            {
                fprintf(stderr, "error: --stack-depth expects 1-64\n");
                return 1;
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
                return 1;
            }
            command.ai_threshold = v;
        }
        else if (arg[0] == '-' && arg[1] != '\0')
        {
            fprintf(stderr, "error: unknown option '%s'\n", arg);
            return 1;
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
                return 1;
            }
        }
    }
    if (command.mode != "dynamic" && command.mode != "static" && command.mode != "scan" &&
        command.mode != "ai-features")
    {
        fprintf(stderr,
                "error: mode must be 'static', 'dynamic', 'scan' or 'ai-features'\n\n%s", usage);
        return 1;
    }
    if (command.mode == "ai-features")
    {
        return run_ai_features(command);
    }
    if (command.target.empty())
    {
        fprintf(stderr, "error: target can't be empty\n");
        return 1;
    }
    if (command.format != "json" && command.format != "sarif" && command.format != "console")
    {
        fprintf(stderr, "error: unknown format '%s' (console, json or sarif)\n",
                command.format.c_str());
        return 1;
    }
    if (command.mode == "dynamic")
    {
        if (command.output.empty() &&
            (command.format == "json" || command.format == "sarif"))
        {
            fprintf(stderr,
                    "error: -f %s in dynamic mode needs -o, so the program's own "
                    "output is not mixed into the report\n",
                    command.format.c_str());
            return 1;
        }
        return run_dynamic_analysis(command);
    }
    if (command.mode == "scan")
    {
        return run_scan(command);
    }
    return run_static_analysis(command);
}
