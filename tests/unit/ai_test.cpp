// Unit tests for the --ai classifier: the numbers read out of a Windows program,
// and the model file the scanner reads them with.
#include "check.h"

#include "ai_features.h"
#include "ai_model.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <vector>

using namespace lcscan;

namespace {

void put16(std::string &s, size_t at, uint16_t v) {
    s[at] = char(v & 0xff);
    s[at + 1] = char(v >> 8);
}

void put32(std::string &s, size_t at, uint32_t v) {
    put16(s, at, uint16_t(v & 0xffff));
    put16(s, at + 2, uint16_t(v >> 16));
}

// A 32-bit PE with one .text section, a two-function import table and two
// strings in it, so every feature that reads the headers has something to say.
std::string pe_with_imports() {
    std::string b(0x600, '\0');
    b[0] = 'M';
    b[1] = 'Z';
    put32(b, 0x3c, 0x80);
    b.replace(0x80, 4, std::string("PE\0\0", 4));
    put16(b, 0x80 + 4, 0x14c);  // i386
    put16(b, 0x80 + 6, 1);      // one section
    put16(b, 0x80 + 20, 0xe0);  // optional header size
    const size_t opt = 0x80 + 24;
    put16(b, opt, 0x10b);        // PE32
    put32(b, opt + 4, 0x200);    // SizeOfCode
    put32(b, opt + 16, 0x1000);  // AddressOfEntryPoint
    put32(b, opt + 32, 0x1000);  // SectionAlignment
    put32(b, opt + 36, 0x200);   // FileAlignment
    put32(b, opt + 56, 0x2000);  // SizeOfImage
    put32(b, opt + 60, 0x200);   // SizeOfHeaders
    put16(b, opt + 68, 2);       // GUI
    put32(b, opt + 92, 16);      // NumberOfRvaAndSizes
    put32(b, opt + 96 + 8, 0x1100);  // import directory RVA
    put32(b, opt + 96 + 12, 40);     // import directory size
    const size_t sec = opt + 0xe0;
    b.replace(sec, 8, std::string(".text\0\0\0", 8));
    put32(b, sec + 8, 0x400);   // VirtualSize
    put32(b, sec + 12, 0x1000); // VirtualAddress
    put32(b, sec + 16, 0x400);  // SizeOfRawData
    put32(b, sec + 20, 0x200);  // PointerToRawData
    put32(b, sec + 36, 0x60000020); // code | read | execute
    // .text maps 0x1000 -> 0x200
    const size_t imp = 0x200 + 0x100; // RVA 0x1100
    put32(b, imp + 12, 0x1130);       // DLL name
    put32(b, imp + 16, 0x1140);       // FirstThunk
    b.replace(0x200 + 0x130, 12, std::string("kernel32.dll", 12));
    put32(b, 0x200 + 0x140, 0x1160); // hint/name 1
    put32(b, 0x200 + 0x144, 0x1180); // hint/name 2
    b.replace(0x200 + 0x160, 14, std::string("\x00\x00LoadLibraryA", 14));
    b.replace(0x200 + 0x180, 16, std::string("\x00\x00GetProcAddress", 16));
    b.replace(0x200, 5, "hello");
    return b;
}

std::string temp_file(const std::string &content) {
    const char *dir = std::getenv("TEMP");
    std::string path = std::string(dir ? dir : "/tmp") + "/lc_ai_XXXXXX";
    const int fd = mkstemp(&path[0]);
    if (fd < 0)
        return {};
    const ssize_t written = write(fd, content.data(), content.size());
    (void)written;
    close(fd);
    return path;
}

size_t index_of(const char *name) {
    for (size_t i = 0; i < kAiFeatureCount; ++i)
        if (std::string(kAiFeatureNames[i]) == name)
            return i;
    std::abort();
}

float feature(const std::vector<float> &x, const char *name) { return x[index_of(name)]; }

} // namespace

TEST(ai_reads_a_windows_program) {
    std::vector<float> x;
    CHECK(ai_pe_features(pe_with_imports(), &x));
    CHECK_EQ(x.size(), kAiFeatureCount);
    CHECK_EQ(feature(x, "sections"), 1.0f);
    CHECK_EQ(feature(x, "pe32_plus"), 0.0f);
    CHECK_EQ(feature(x, "subsystem"), 2.0f);
    CHECK_EQ(feature(x, "entry_zero"), 0.0f);
    CHECK_EQ(feature(x, "sec_exec"), 1.0f);
    CHECK_EQ(feature(x, "sec_write"), 0.0f);
    CHECK_EQ(feature(x, "sec_names_dotted"), 1.0f);
    // one DLL, two imported functions, both of them ways of hiding a call
    CHECK_EQ(feature(x, "import_dlls_log"), 1.0f);
    CHECK(std::fabs(feature(x, "import_funcs_log") - float(std::log2(3.0))) < 1e-6);
    CHECK_EQ(feature(x, "import_suspicious"), 2.0f);
    CHECK_EQ(feature(x, "loadlib_getproc"), 1.0f);
    CHECK(std::fabs(feature(x, "size_log") - float(std::log2(0x601))) < 1e-6);
    // an executable section is not a file of random bytes
    CHECK(feature(x, "entropy") < 4.0f);
    CHECK_EQ(feature(x, "overlay_log"), 0.0f);
}

TEST(ai_reads_what_it_judges) {
    std::vector<float> x;
    CHECK(ai_pe_features(pe_with_imports(), &x));
    // the test image is a program with a .text section and an entry point
    CHECK(ai_has_code(x));
}

TEST(ai_leaves_alone_what_is_not_a_windows_program) {
    std::vector<float> x;
    CHECK(!ai_pe_features("\x7f" "ELF\x02\x01\x01", &x));
    CHECK(!ai_pe_features("MZ", &x));
    CHECK(!ai_pe_features(std::string(64, '\0'), &x));
    std::string truncated = pe_with_imports().substr(0, 0x90); // headers cut before the PE signature
    CHECK(!ai_pe_features(truncated, &x));
    std::string bad_magic = pe_with_imports();
    put16(bad_magic, 0x80 + 24, 0x999); // not a PE32 or PE32+ optional header
    CHECK(!ai_pe_features(bad_magic, &x));
}

TEST(ai_judges_only_images_with_code) {
    // the scanner reads these columns by number; a reordered list must fail here
    CHECK_EQ(std::string(kAiFeatureNames[9]), std::string("entry_zero"));
    CHECK_EQ(std::string(kAiFeatureNames[34]), std::string("sec_exec"));

    std::vector<float> x(kAiFeatureCount, 0.0f);
    auto set = [&x](const char *name, float value) { x[index_of(name)] = value; };
    set("sec_exec", 2);
    CHECK(ai_has_code(x)); // a section that can run, and an entry point
    set("entry_zero", 1);
    CHECK(!ai_has_code(x)); // no entry point
    set("entry_zero", 0);
    set("sec_exec", 0);
    CHECK(!ai_has_code(x)); // a resource-only image (.mui, .tlb)
    set("sec_exec", 2);
    CHECK(ai_has_code(x));
    x.resize(kAiFeatureCount - 1);
    CHECK(!ai_has_code(x)); // a vector that does not fit the list
}

TEST(ai_model_walks_its_trees) {
    // one stump: feature 0 <= 10 is normal, above it is malware
    const std::string path = temp_file(
        "leakcheck-ai 1\n"
        "features 49\n"
        "feature_names size_log entropy\n"
        "trained_on 2 samples\n"
        "threshold 0.75\n"
        "trees 1\n"
        "tree 3\n"
        "0 10 1 2 0 0\n"
        "-1 0 0 0 1 -2\n"
        "-1 0 0 0 1 2\n"
        "end\n");
    AiModel model;
    std::string error;
    CHECK(model.load(path, &error));
    CHECK_EQ(model.features, 49u);
    CHECK(std::fabs(model.threshold - 0.75) < 1e-9);
    CHECK_EQ(model.trained_on, std::string("2 samples"));
    std::vector<float> normal(49, 0.0f), hostile(49, 0.0f);
    normal[0] = 5.0f;
    hostile[0] = 20.0f;
    CHECK(model.score(normal) < 0.12);
    CHECK(model.score(hostile) > 0.88);
    // the threshold decides, not the score
    CHECK(model.score(normal) < model.threshold);
    CHECK(model.score(hostile) > model.threshold);
    unlink(path.c_str());
}

TEST(ai_model_refuses_what_it_cannot_read) {
    AiModel model;
    std::string error;
    const std::string missing = temp_file("");
    unlink(missing.c_str());
    CHECK(!model.load(missing, &error));
    CHECK(error.find("cannot open") != std::string::npos);

    const std::string not_model = temp_file("hello\n");
    CHECK(!model.load(not_model, &error));
    CHECK(error.find("not a leakcheck --ai model") != std::string::npos);
    unlink(not_model.c_str());

    const std::string wrong_version = temp_file("leakcheck-ai 7\nfeatures 2\ntrees 0\n");
    CHECK(!model.load(wrong_version, &error));
    CHECK(error.find("format 7") != std::string::npos);
    unlink(wrong_version.c_str());

    // a tree that reads a column the model does not have: a model and a build
    // that disagree about the features must not silently score anything
    const std::string bad_tree = temp_file(
        "leakcheck-ai 1\nfeatures 3\ntrees 1\ntree 3\n"
        "9 10 1 2 0 0\n-1 0 0 0 1 -2\n-1 0 0 0 1 2\nend\n");
    CHECK(!model.load(bad_tree, &error));
    CHECK(error.find("feature 9") != std::string::npos);
    unlink(bad_tree.c_str());

    const std::string no_trees = temp_file("leakcheck-ai 1\nfeatures 3\ntrees 0\nend\n");
    CHECK(!model.load(no_trees, &error));
    CHECK(error.find("no trees") != std::string::npos);
    unlink(no_trees.c_str());
}

TEST_MAIN()
