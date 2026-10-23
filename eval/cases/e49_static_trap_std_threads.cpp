// level: expert
// mode: static
// expect: none
// what: trap: std::thread used correctly: joined or detached on every path, moved into a container or returned, tested with joinable(), lambdas that copy what changes, join in the same iteration
#include <atomic>
#include <thread>
#include <utility>
#include <vector>

void work(int);

void one_job() {
    std::thread t(work, 1);
    t.join();
}

int two_paths(bool fast) {
    std::thread t(work, 2);
    if (fast) {
        t.join();
        return 0;
    }
    t.detach();
    return 1;
}

std::thread start(int id) {
    std::thread t(work, id);
    return t;
}

void into_pool(std::vector<std::thread> &pool) {
    std::thread t(work, 3);
    pool.push_back(std::move(t));
}

void cleanup_guard() {
    std::thread t(work, 4);
    if (t.joinable())
        t.join();
}

void idle() {
    std::thread not_started;
    std::thread *heap = new std::thread(work, 5);
    heap->join();
    delete heap;
}

int copies_what_changes(int n) {
    std::atomic<int> total{0};
    std::vector<std::thread> pool;
    for (int i = 0; i < n; ++i)
        pool.emplace_back([i, &total] { total += i; });
    for (auto &t : pool)
        t.join();
    return total;
}

void default_copy(int n) {
    std::vector<std::thread> pool;
    for (int i = 0; i < n; ++i)
        pool.emplace_back([=] { work(i); });
    for (auto &t : pool)
        t.join();
}

void one_at_a_time(int n) {
    for (int i = 0; i < n; ++i) {
        std::thread t([&] { work(i); });
        t.join();
    }
}

void elements(std::vector<int> &items) {
    std::vector<std::thread> pool;
    for (auto &x : items)
        pool.emplace_back([&] { work(x); });
    for (auto &t : pool)
        t.join();
}

void detached_copy() {
    int budget = 3;
    std::thread t([budget] { work(budget); });
    t.detach();
}
