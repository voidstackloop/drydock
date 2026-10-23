// level: expert
// mode: static
// expect: thread-stack-argument
// what: a worker pool starts one thread per shard with [&] while the loop variable and the per-shard job keep changing
#include <string>
#include <thread>
#include <vector>

struct Shard {
    std::string path;
    int first, last;
};

void scan(const Shard &s);

void scan_all(const std::vector<std::string> &paths, int per_shard) {
    std::vector<std::thread> pool;
    for (size_t i = 0; i < paths.size(); ++i) {
        Shard s{paths[i], int(i) * per_shard, int(i + 1) * per_shard};
        pool.emplace_back([&] { scan(s); });
    }
    for (auto &t : pool)
        t.join();
}
