// level: expert
// mode: static
// expect: none
// what: trap: guards used correctly: one order everywhere, guards ended before the next lock, scoped_lock for two, deferred and early-released unique_locks, a recursive mutex, waits in loops
#include <condition_variable>
#include <mutex>
#include <queue>

static std::mutex a, b, c;
static std::recursive_mutex rm;
static std::condition_variable cv;
static std::queue<int> jobs;
static bool done;

void same_order_1() {
    std::lock_guard<std::mutex> x(a);
    std::lock_guard<std::mutex> y(b);
}

void same_order_2() {
    std::lock_guard<std::mutex> x(a);
    std::lock_guard<std::mutex> y(b);
    jobs.push(1);
}

void one_after_the_other() {
    {
        std::lock_guard<std::mutex> y(b);
        jobs.push(2);
    }
    std::lock_guard<std::mutex> x(a);
    jobs.push(3);
}

void both_at_once() {
    std::scoped_lock both(b, a);
    jobs.push(4);
}

void deferred_pair() {
    std::unique_lock<std::mutex> l1(b, std::defer_lock);
    std::unique_lock<std::mutex> l2(a, std::defer_lock);
    std::lock(l1, l2);
}

void recursive_ok() {
    std::lock_guard<std::recursive_mutex> x(rm);
    std::lock_guard<std::recursive_mutex> y(rm);
}

int pop_or(int dflt, bool quick) {
    std::lock_guard<std::mutex> g(c);
    if (quick)
        return dflt;
    if (jobs.empty())
        return dflt;
    int v = jobs.front();
    jobs.pop();
    return v;
}

void drain() {
    for (;;) {
        std::lock_guard<std::mutex> g(c);
        if (jobs.empty())
            break;
        jobs.pop();
    }
    std::lock_guard<std::mutex> again(c);
    jobs.push(5);
}

void work_outside_the_lock() {
    std::unique_lock<std::mutex> lk(c);
    int v = jobs.front();
    jobs.pop();
    lk.unlock();
    v *= 2;
    lk.lock();
    jobs.push(v);
}

int consumer() {
    std::unique_lock<std::mutex> lk(c);
    while (jobs.empty() && !done)
        cv.wait(lk);
    cv.wait(lk, [] { return !jobs.empty() || done; });
    if (jobs.empty())
        return -1;
    int v = jobs.front();
    jobs.pop();
    return v;
}
