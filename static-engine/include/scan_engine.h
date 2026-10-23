#pragma once
#include "command.h"

#include <string>

namespace lcreport {
struct Report;
}

// leakcheck scan <file|dir>: look for malware in files without running them.
int run_scan(const Command &command);

// leakcheck ai-features <file|dir>: the classifier's input, one line per Windows
// program ("<path>\t<n1> <n2> ..."), for tools/train_ai.py.
int run_ai_features(const Command &command);

// One line about the classifier `scan --ai` would load on its own: its file,
// tree count and what it was trained on. Empty when there is none.
std::string model_description();

// What a scan says about one file (named by its absolute path), added to `report`.
// `malware` is --malware. The static analysis uses it for the sources it reads.
void scan_into_report(lcreport::Report *report, const std::string &abs, const std::string &bytes,
                      bool malware);
