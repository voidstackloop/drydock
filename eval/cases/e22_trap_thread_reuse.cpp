// level: expert
// mode: dynamic
// expect: none
// what: trap: thread handles reused by the C library across join, detach and self-detach
#include <pthread.h>
#include <thread>
#include <vector>

static void *self_detach(void *arg) {
    pthread_detach(pthread_self());
    return arg;
}

static void *work(void *arg) { return arg; }

int main() {
    for (int round = 0; round < 20; round++) {
        std::vector<std::thread> ts;
        for (int i = 0; i < 4; i++)
            ts.emplace_back([] {});
        for (auto &t : ts)
            t.join();
        std::thread([] {}).detach();
        pthread_t p;
        pthread_create(&p, nullptr, round % 2 ? work : self_detach, nullptr);
        if (round % 2)
            pthread_join(p, nullptr);
    }
    pthread_t last;
    pthread_create(&last, nullptr, work, nullptr);
    pthread_join(last, nullptr);
    return 0;
}
