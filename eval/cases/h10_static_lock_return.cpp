// level: hard
// mode: static
// expect: lock-leak
// what: a member function locks by hand and returns early on one path
#include <mutex>
#include <string>
#include <vector>

class Registry {
  public:
    bool add(const std::string &name) {
        mu_.lock();
        for (const auto &n : names_)
            if (n == name)
                return false; // still holding mu_
        names_.push_back(name);
        mu_.unlock();
        return true;
    }

  private:
    std::mutex mu_;
    std::vector<std::string> names_;
};
