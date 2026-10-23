// level: expert
// mode: dynamic
// expect: none
// what: trap: a producer/consumer with std::condition_variable, wait_for, and notify outside the lock
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

int main() {
    std::mutex mu;
    std::condition_variable cv;
    std::deque<int> q;
    bool closed = false;
    long sum = 0;
    std::thread consumer([&] {
        std::unique_lock<std::mutex> lk(mu);
        for (;;) {
            cv.wait_for(lk, std::chrono::milliseconds(50),
                        [&] { return !q.empty() || closed; });
            while (!q.empty()) {
                sum += q.front();
                q.pop_front();
            }
            if (closed)
                break;
        }
    });
    for (int i = 0; i < 100; i++) {
        {
            std::lock_guard<std::mutex> g(mu);
            q.push_back(i);
        }
        cv.notify_one(); // outside the lock: allowed
    }
    {
        std::lock_guard<std::mutex> g(mu);
        closed = true;
    }
    cv.notify_all();
    consumer.join();
    return sum == 4950 ? 0 : 1;
}
