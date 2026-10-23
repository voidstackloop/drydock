#pragma once
// The numbers a Windows program is turned into for --ai: what its PE headers say,
// how its sections are laid out and what its bytes look like. The same function
// feeds the trainer (leakcheck ai-features) and the scanner (scan --ai), so the
// model always sees what it was trained on.
#include <cstddef>
#include <string>
#include <vector>

namespace lcscan {

// Names in the order of the vector; the trainer reads them from
// "leakcheck ai-features" and checks the model's header against them.
extern const char *const kAiFeatureNames[];
extern const size_t kAiFeatureCount;

// Fills `out` (kAiFeatureCount values) from the bytes of a file. False when the
// file is not a PE header this can read (no MZ, no PE signature, truncated).
bool ai_pe_features(const std::string &bytes, std::vector<float> *out);

// Whether the image contains code at all: an executable section and an entry
// point. Resource-only images (.mui, "-RES.dll", .tlb) do not, and on a real
// Windows installation they were three quarters of the classifier's false
// alarms; it was trained on programs, so it does not guess at data files.
bool ai_has_code(const std::vector<float> &features);

// The feature vector of a file as one line of text: values separated by spaces,
// %.6g each. What the trainer reads.
std::string ai_features_line(const std::vector<float> &features);

} // namespace lcscan
