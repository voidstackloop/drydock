#include "ai_model.h"

#include <cmath>
#include <fstream>
#include <sstream>

namespace lcscan {

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
            trees.clear();
            trees.reserve(n);
            for (size_t t = 0; t < n; ++t) {
                std::string head;
                size_t count = 0;
                if (!(in >> head >> count) || head != "tree") {
                    *error = path + ": expected \"tree <nodes>\", found \"" + head + "\"";
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
                    node.feature = leaf ? -1 : node.feature;
                    if (node.feature >= int(features)) {
                        *error = path + ": tree " + std::to_string(t) + " uses feature " +
                                 std::to_string(node.feature) + " but the model has " +
                                 std::to_string(features);
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
