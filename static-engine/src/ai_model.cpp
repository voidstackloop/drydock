#include "ai_model.h"

#include <cmath>
#include <fstream>
#include <sstream>

namespace lcscan {
namespace {

// A model is a text file a user can point at anything, so every count that
// sizes a vector is checked first. The limits are far above what the trainer
// writes (49 features, 231 trees, 35 nodes each) and far below a size that
// would throw or exhaust memory.
constexpr size_t kMaxFeatures = 4096;
constexpr size_t kMaxTrees = 1000000;
constexpr size_t kMaxNodes = 1000000;

} // namespace

bool AiModel::load(const std::string &path, std::string *error) {
    std::ifstream in(path);
    if (!in) {
        *error = "cannot open the model file " + path +
                 " (train one with tools/train_ai.py, or pass --ai-model)";
        return false;
    }
    std::string tag;
    if (!(in >> tag) || tag != "leakcheck-ai") {
        *error = path + " is not a leakcheck --ai model (it starts with \"leakcheck-ai\")";
        return false;
    }
    int version = 0;
    in >> version;
    if (version != 1) {
        *error = path + " is model format " + std::to_string(version) + ", this build reads 1";
        return false;
    }
    std::string key;
    while (in >> key) {
        if (key == "features") {
            in >> features;
            if (!in || features == 0 || features > kMaxFeatures) {
                *error = path + ": features must be between 1 and " + std::to_string(kMaxFeatures);
                return false;
            }
        } else if (key == "threshold") {
            in >> threshold;
        } else if (key == "accuracy") {
            in >> accuracy;
        } else if (key == "precision") {
            in >> precision;
        } else if (key == "recall") {
            in >> recall;
        } else if (key == "trained_on") {
            in >> std::ws;
            std::getline(in, trained_on);
        } else if (key == "trees") {
            size_t n = 0;
            in >> n;
            if (!in || n > kMaxTrees) {
                *error = path + ": trees must be at most " + std::to_string(kMaxTrees);
                return false;
            }
            trees.clear();
            trees.reserve(n);
            for (size_t t = 0; t < n; ++t) {
                std::string head;
                size_t count = 0;
                if (!(in >> head >> count) || head != "tree") {
                    *error = path + ": expected \"tree <nodes>\", found \"" + head + "\"";
                    return false;
                }
                if (count == 0 || count > kMaxNodes) {
                    *error = path + ": tree " + std::to_string(t) + " claims " +
                             std::to_string(count) + " nodes; a tree has 1 to " +
                             std::to_string(kMaxNodes);
                    return false;
                }
                std::vector<Node> nodes(count);
                for (size_t i = 0; i < count; ++i) {
                    Node &node = nodes[i];
                    int leaf = 0;
                    if (!(in >> node.feature >> node.threshold >> node.left >> node.right >> leaf >>
                          node.value)) {
                        *error = path + ": tree " + std::to_string(t) + " ends early";
                        return false;
                    }
                    if (leaf != 0 && leaf != 1) {
                        *error = path + ": tree " + std::to_string(t) + " node " +
                                 std::to_string(i) + " has leaf=" + std::to_string(leaf) +
                                 ", which is neither 0 nor 1";
                        return false;
                    }
                    node.feature = leaf ? -1 : node.feature;
                    if (node.feature < -1 || node.feature >= int(features)) {
                        *error = path + ": tree " + std::to_string(t) + " uses feature " +
                                 std::to_string(node.feature) + " but the model has " +
                                 std::to_string(features);
                        return false;
                    }
                    if (!leaf && (node.left < 0 || node.right < 0 ||
                                  size_t(node.left) >= count || size_t(node.right) >= count)) {
                        *error = path + ": tree " + std::to_string(t) + " node " +
                                 std::to_string(i) + " points at a node outside the tree";
                        return false;
                    }
                }
                trees.push_back(std::move(nodes));
            }
        } else if (key == "end") {
            break;
        } else { // "feature_names" and anything a later version adds: skipped
            std::getline(in, key);
        }
    }
    if (!features || trees.empty()) {
        *error = path + " has no trees";
        return false;
    }
    return true;
}

double AiModel::score(const std::vector<float> &x) const {
    double sum = 0.0;
    for (const std::vector<Node> &tree : trees) {
        size_t at = 0;
        for (size_t guard = 0; guard < tree.size(); ++guard) {
            const Node &node = tree[at];
            if (node.feature < 0) {
                sum += node.value;
                break;
            }
            const float value = size_t(node.feature) < x.size() ? x[size_t(node.feature)] : 0.0f;
            at = size_t(value <= node.threshold ? node.left : node.right);
            if (at >= tree.size())
                break;
        }
    }
    return 1.0 / (1.0 + std::exp(-sum));
}

} // namespace lcscan
