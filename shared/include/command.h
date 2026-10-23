#pragma once
#include <string>
#include <vector>

struct Command
{
    std::string mode;
    std::string target;
    std::string output;
    std::string format = "console";
    std::vector<std::string> target_args;

    std::string suppressions;
    int error_exitcode = 2;
    bool show_reachable = false;
    bool leak_check = true;
    int quarantine_mb = 64;
    int stack_depth = 24;
    int guard_every = 0;
    bool abort_on_error = false;
    bool fast_unwind = false;
    bool trace_children = false;
    bool malware = false; // --malware: the deep scan for the 100 malware families
    int jobs = 0;         // scan/static: files read and analysed at the same time (0: one per CPU)

    bool ai = false;              // --ai: also ask the trained PE classifier
    std::string ai_model;         // --ai-model <file> (default: model/pe-malware.ai)
    double ai_threshold = -1.0;   // --ai-threshold (default: the threshold the model was exported with)
};
