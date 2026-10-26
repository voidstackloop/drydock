#pragma once
// leakcheck.toml and .leakcheckignore: the settings a team writes down once
// instead of repeating twenty flags, and the exclusion rules that keep a
// vendored tree out of the scan. A flag always wins over the file.
#include "command.h"

#include <string>
#include <vector>

namespace lcconfig {

// One mode's settings. An empty string or -1 means "not set here".
struct Settings
{
    std::string format;
    std::string suppressions;
    std::string baseline;
    std::string min_severity;
    int jobs = -1;
    int error_exitcode = -1;
    std::vector<std::string> exclude;
    std::vector<std::string> enable_rules;
    std::vector<std::string> disable_rules;
};

struct FileConfig
{
    bool found = false;
    std::string path;
    std::string root; // the directory of the file: what exclude patterns are relative to
    Settings all;
    Settings static_mode;
    Settings scan_mode;
    Settings dynamic_mode;
    Settings ai_features_mode;
    std::map<std::string, std::string> rule_severities;
};

// The nearest leakcheck.toml at or above `start`, climbing to the file-system
// root. False when there is none (not an error).
bool find_upwards(const std::string &start, const std::string &name, std::string *path);

// Parses a file. On failure *error says file:line and what was wrong.
bool load(const std::string &path, FileConfig *cfg, std::string *error);

// Fills what the command line did not set, from the top-level settings and
// then the section for the mode.
void apply(Command &command, const FileConfig &cfg);

// Loads the nearest .leakcheckignore above the target, if there is one, and
// adds its patterns. A malformed file is reported, not ignored.
bool load_ignore_file(Command &command, std::string *error);

// Whether `path` matches one of the rules; *which names the rule that hid it.
bool excluded(const std::string &path, const std::vector<ExcludeRule> &rules,
              std::string *which = nullptr);

// The effective settings as TOML, after config, environment defaults and flags.
// What --print-config prints, so a failing gate can be explained in one command.
std::string effective(const Command &command, const FileConfig &cfg);

} // namespace lcconfig
