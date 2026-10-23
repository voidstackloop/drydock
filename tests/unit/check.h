#pragma once
// Minimal test harness: TEST(name) { CHECK(...); CHECK_EQ(a, b); }
// Run all tests, or only those whose name contains argv[1].
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace check {

struct Case {
    const char *name;
    void (*fn)();
};

inline std::vector<Case> &cases() {
    static std::vector<Case> c;
    return c;
}

inline int &failures() {
    static int f = 0;
    return f;
}

struct Register {
    Register(const char *name, void (*fn)()) { cases().push_back({name, fn}); }
};

template <class T> std::string show(const T &v) {
    std::ostringstream os;
    os << v;
    return os.str();
}

inline int run_all(int argc, char **argv) {
    const char *filter = argc > 1 ? argv[1] : "";
    int failed = 0, ran = 0;
    for (const Case &c : cases()) {
        if (!std::strstr(c.name, filter))
            continue;
        ++ran;
        const int before = failures();
        c.fn();
        const bool ok = failures() == before;
        failed += !ok;
        std::printf("%s %s\n", ok ? "PASS" : "FAIL", c.name);
    }
    std::printf("%d of %d failed\n", failed, ran);
    return failed ? 1 : 0;
}

} // namespace check

#define TEST(name)                                                             \
    static void name();                                                        \
    static check::Register register_##name(#name, name);                       \
    static void name()

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            ++check::failures();                                               \
            std::fprintf(stderr, "  %s:%d: CHECK(%s)\n", __FILE__, __LINE__,   \
                         #cond);                                               \
        }                                                                      \
    } while (0)

#define CHECK_EQ(a, b)                                                         \
    do {                                                                       \
        const auto &va_ = (a);                                                 \
        const auto &vb_ = (b);                                                 \
        if (!(va_ == vb_)) {                                                   \
            ++check::failures();                                               \
            std::fprintf(stderr,                                               \
                         "  %s:%d: %s == %s\n    got:  %s\n    want: %s\n",    \
                         __FILE__, __LINE__, #a, #b, check::show(va_).c_str(), \
                         check::show(vb_).c_str());                            \
        }                                                                      \
    } while (0)

#define TEST_MAIN()                                                            \
    int main(int argc, char **argv) { return check::run_all(argc, argv); }
