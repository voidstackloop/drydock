// Many threads allocating and freeing concurrently. "leak" makes each worker
// leak one block; "held" keeps a block alive only through a running thread's
// stack (must not be reported as lost).
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

static std::atomic<bool> g_stop{false};

__attribute__((noinline)) static void worker(int id, bool leak) {
    std::vector<std::string> keep;
    for (int i = 0; i < 20000; i++) {
        char *p = static_cast<char *>(std::malloc(16 + (i % 200)));
        std::memset(p, id, 16);
        if (i % 7 == 0)
            keep.emplace_back(p, 16);
        std::free(p);
        if (i % 1000 == 0)
            keep.clear();
    }
    if (leak)
        (void)std::malloc(64 + id);
}

__attribute__((noinline)) static void holder() {
    volatile char *held = static_cast<char *>(std::malloc(4096));
    held[0] = 1;
    while (!g_stop.load())
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    std::free(const_cast<char *>(held));
}

int main(int argc, char **argv) {
    bool leak = argc > 1 && std::string(argv[1]) == "leak";
    bool held = argc > 1 && std::string(argv[1]) == "held";
    std::vector<std::thread> ts;
    for (int i = 0; i < 8; i++)
        ts.emplace_back(worker, i, leak);
    for (auto &t : ts)
        t.join();
    if (held) {
        std::thread h(holder);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        h.detach(); // still running when main returns
        return 0;
    }
    std::puts("done");
    return 0;
}
