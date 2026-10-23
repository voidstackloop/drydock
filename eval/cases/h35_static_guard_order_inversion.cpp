// level: hard
// mode: static
// expect: lock-order-inversion
// what: transfer() locks the source then the target account with lock_guards, refund() does the opposite; two threads running both deadlock
#include <mutex>

struct Account {
    std::mutex mu;
    long balance = 0;
};

static Account checking, savings;

void transfer(long amount) {
    std::lock_guard<std::mutex> from(checking.mu);
    std::lock_guard<std::mutex> to(savings.mu);
    checking.balance -= amount;
    savings.balance += amount;
}

void refund(long amount) {
    std::lock_guard<std::mutex> from(savings.mu);
    std::lock_guard<std::mutex> to(checking.mu);
    savings.balance -= amount;
    checking.balance += amount;
}
