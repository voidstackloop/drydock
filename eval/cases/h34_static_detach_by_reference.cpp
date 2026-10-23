// level: hard
// mode: static
// expect: thread-stack-argument
// what: a detached watchdog thread uses the function's locals through a [&] lambda and the function returns
#include <atomic>
#include <chrono>
#include <thread>

void alarm();

void guard(int seconds) {
    std::atomic<bool> done{false};
    std::thread watchdog([&] {
        std::this_thread::sleep_for(std::chrono::seconds(seconds));
        if (!done)
            alarm();
    });
    watchdog.detach();
    // ... the work, then:
    done = true;
}
