// level: expert
// mode: static
// expect: lock-order-inversion
// what: register_item() holds the registry lock while a helper takes the stats lock; report() takes them the other way round, both with lock_guards
#include <map>
#include <mutex>
#include <string>

static std::mutex registry_mu;
static std::mutex stats_mu;
static std::map<std::string, int> registry;
static long total_registered;

static void bump_stats() {
    std::lock_guard<std::mutex> g(stats_mu);
    ++total_registered;
}

void register_item(const std::string &name) {
    std::lock_guard<std::mutex> g(registry_mu);
    registry[name] = 1;
    bump_stats();
}

long report(std::map<std::string, int> &copy) {
    std::lock_guard<std::mutex> s(stats_mu);
    std::lock_guard<std::mutex> r(registry_mu);
    copy = registry;
    return total_registered;
}
