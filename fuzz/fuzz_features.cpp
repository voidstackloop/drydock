// ai-features walks the PE headers of every candidate program. A truncated or
// hostile image must produce "not a PE" rather than an out-of-bounds read.
#include "ai_features.h"

#include <cstdint>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string bytes(reinterpret_cast<const char *>(data), size);
    std::vector<float> features;
    if (lcscan::ai_pe_features(bytes, &features)) {
        volatile bool code = lcscan::ai_has_code(features);
        (void)code;
    }
    return 0;
}
