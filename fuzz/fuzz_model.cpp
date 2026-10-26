// The classifier file is data, and a build may be handed a corrupt or hostile
// one. Loading it must reject the file with an error, not walk out of bounds;
// a loaded model must score any vector safely.
#include "ai_model.h"
#include "temp_file.h"

#include <cstdint>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    lcscan::AiModel model;
    std::string error;
    if (model.load(fuzz_temp_file(data, size), &error)) {
        std::vector<float> features(model.features, 0.0f);
        volatile double score = model.score(features);
        (void)score;
    }
    return 0;
}
