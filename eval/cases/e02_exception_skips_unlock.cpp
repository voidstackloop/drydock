// level: expert
// mode: dynamic
// expect: double-lock
// what: an exception thrown between lock() and unlock() leaves the mutex held; the next call hangs
#include <mutex>
#include <stdexcept>
#include <string>

static std::mutex g_mu;
static int g_total;

static int parse(const std::string &s) {
    if (s.empty())
        throw std::invalid_argument("empty");
    return int(s.size());
}

static void add(const std::string &s) {
    g_mu.lock();
    g_total += parse(s); // throws: unlock() below never runs
    g_mu.unlock();
}

int main() {
    for (const char *s : {"ab", "", "cde"}) {
        try {
            add(s);
        } catch (const std::exception &) {
            // logged and ignored
        }
    }
    return g_total;
}
