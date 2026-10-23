// level: basic
// mode: static
// expect: spurious-wakeup
// what: a consumer waits on the condition variable once after seeing an empty queue and then pops without checking again
#include <condition_variable>
#include <mutex>
#include <queue>

static std::mutex mu;
static std::condition_variable not_empty;
static std::queue<int> items;

int take() {
    std::unique_lock<std::mutex> lk(mu);
    if (items.empty())
        not_empty.wait(lk);
    int v = items.front();
    items.pop();
    return v;
}

void put(int v) {
    {
        std::lock_guard<std::mutex> g(mu);
        items.push(v);
    }
    not_empty.notify_one();
}
