// level: hard
// mode: static
// expect: resource-leak
// what: the error path returns before the join, so the thread is destroyed while joinable
#include <string>
#include <thread>

bool prepare(const std::string &dir);
void crunch(const std::string &dir);

int run(const std::string &dir) {
    std::thread background(crunch, dir);
    if (!prepare(dir))
        return -1; // forgot: background.join()
    background.join();
    return 0;
}
