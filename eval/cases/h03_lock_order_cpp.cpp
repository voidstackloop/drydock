// level: hard
// mode: dynamic
// expect: lock-order-inversion
// what: two classes, each with a mutex, locked in opposite orders by two code paths
#include <mutex>
#include <thread>
#include <vector>

class Ledger {
  public:
    void record(int amount) {
        std::lock_guard<std::mutex> g(mu_);
        entries_.push_back(amount);
    }
    template <class F> void for_each(F f) {
        std::lock_guard<std::mutex> g(mu_);
        for (int e : entries_)
            f(e);
    }

  private:
    std::mutex mu_;
    std::vector<int> entries_;
};

class Account {
  public:
    explicit Account(Ledger &l) : ledger_(l) {}
    void deposit(int amount) {
        std::lock_guard<std::mutex> g(mu_);
        balance_ += amount;
        ledger_.record(amount); // account, then ledger
    }
    int balance() {
        std::lock_guard<std::mutex> g(mu_);
        return balance_;
    }

  private:
    std::mutex mu_;
    Ledger &ledger_;
    int balance_ = 0;
};

int main() {
    Ledger ledger;
    Account account(ledger);
    std::thread payer([&] { account.deposit(10); });
    payer.join();
    std::thread auditor([&] {
        ledger.for_each([&](int) { account.balance(); }); // ledger, then account
    });
    auditor.join();
}
