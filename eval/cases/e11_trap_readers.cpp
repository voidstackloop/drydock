// level: expert
// mode: dynamic
// expect: none
// what: trap: shared_mutex readers in both orders, recursive reads, scoped_lock for writers
#include <mutex>
#include <shared_mutex>
#include <thread>

static std::shared_mutex names, prices;
static std::mutex audit;
static int seen;

int main() {
    std::thread a([] {
        std::shared_lock<std::shared_mutex> n(names);
        std::shared_lock<std::shared_mutex> p(prices); // names -> prices, reading
        seen++;
    });
    a.join();
    std::thread b([] {
        std::shared_lock<std::shared_mutex> p(prices);
        std::shared_lock<std::shared_mutex> n(names); // prices -> names, reading
        seen++;
    });
    b.join();
    std::thread c([] {
        std::scoped_lock both(audit, names); // takes both without an order
        seen++;
    });
    c.join();
    return seen == 3 ? 0 : 1;
}
