// level: basic
// mode: static
// expect: double-lock
// what: a function holds a lock_guard on the cache mutex and takes a second guard on the same mutex in a nested block
#include <map>
#include <mutex>
#include <string>

static std::mutex cache_mutex;
static std::map<std::string, int> cache;

int lookup(const std::string &key) {
    std::lock_guard<std::mutex> hold(cache_mutex);
    auto it = cache.find(key);
    if (it != cache.end())
        return it->second;
    {
        std::lock_guard<std::mutex> again(cache_mutex);
        cache[key] = 0;
    }
    return 0;
}
