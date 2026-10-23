#pragma once
// The --ai classifier: a gradient-boosted forest of small decision trees over the
// PE feature vector, as trained by tools/train_ai.py. The file is text (one line
// per node), so a model can be read, diffed and reviewed without a library.
#include <string>
#include <vector>

namespace lcscan {

struct AiModel {
    struct Node {
        int feature = -1; // -1: a leaf
        double threshold = 0;
        int left = 0, right = 0;
        double value = 0; // leaf weight
    };
    std::vector<std::vector<Node>> trees;
    size_t features = 0;
    double threshold = 0.5; // score above which a file is called malware
    // What the trainer measured: filled from the header, for the report's note.
    double accuracy = 0, precision = 0, recall = 0;
    std::string trained_on;

    bool load(const std::string &path, std::string *error);
    // Probability that the file is malicious, 0..1.
    double score(const std::vector<float> &x) const;
};

} // namespace lcscan
