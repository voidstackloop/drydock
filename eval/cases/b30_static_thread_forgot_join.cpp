// level: basic
// mode: static
// expect: resource-leak
// what: a std::thread is started and the function ends without join or detach: the destructor calls std::terminate
#include <cstdio>
#include <thread>

static void worker(int id) { std::printf("worker %d\n", id); }

int main() {
    std::thread t(worker, 1);
    std::puts("started");
    return 0;
}
