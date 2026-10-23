// std::mutex and friends on Windows (MinGW: pthread locks in libwinpthread).
// One case per argument; threads run one after the other.
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <thread>

static std::mutex a, b;
static std::recursive_mutex r;
static std::shared_mutex sa, sb;

static void both(std::mutex &x, std::mutex &y) {
    std::lock_guard<std::mutex> l1(x);
    std::lock_guard<std::mutex> l2(y);
}
static void both_shared(std::shared_mutex &x, std::shared_mutex &y) {
    std::unique_lock<std::shared_mutex> l1(x);
    std::unique_lock<std::shared_mutex> l2(y);
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        const char *c = argv[i];
        if (!strcmp(c, "inversion")) {
            std::thread([] { both(a, b); }).join();
            std::thread([] { both(b, a); }).join();
        } else if (!strcmp(c, "ordered")) {
            std::thread([] { both(a, b); }).join();
            std::thread([] { both(a, b); }).join();
        } else if (!strcmp(c, "relock")) {
            a.lock();
            a.lock(); // a normal mutex: waits for itself forever
        } else if (!strcmp(c, "recursive")) {
            r.lock();
            r.lock();
            r.unlock();
            r.unlock();
        } else if (!strcmp(c, "shared-inversion")) {
            std::thread([] { both_shared(sa, sb); }).join();
            std::thread([] { both_shared(sb, sa); }).join();
        } else if (!strcmp(c, "leak")) {
            std::thread([] { a.lock(); }).join(); // the thread ends with the mutex locked
        } else if (!strcmp(c, "condition")) {
            std::condition_variable cv;
            std::unique_lock<std::mutex> l(a);
            cv.wait_for(l, std::chrono::milliseconds(1));
        } else {
            std::fprintf(stderr, "unknown case %s\n", c);
            return 64;
        }
    }
    return 0;
}
