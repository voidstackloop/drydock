// Each "expect:" comment names the finding the static engine must report on
// that line. Lines without one must stay silent.
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

struct Widget {
    int v = 0;
};

void leak_new(bool flag) {
    Widget *w = new Widget;
    if (flag)
        return; // expect: memory-leak
    delete w;
}

void wrong_delete() {
    int *a = new int[10];
    delete a; // expect: alloc-dealloc-mismatch
}

void wrong_free() {
    Widget *w = new Widget;
    free(w); // expect: alloc-dealloc-mismatch
}

void delete_twice() {
    auto *w = new Widget;
    delete w;
    delete w; // expect: double-free
}

int use_deleted() {
    Widget *w = new Widget;
    delete w;
    return w->v; // expect: heap-use-after-free
}

const char *dangling_array() {
    char buf[32] = "hi";
    return buf; // expect: dangling-pointer
}

class Holder {
  public:
    explicit Holder(int n) : data_(new int[n]) {}
    ~Holder() { delete[] data_; }
    void reset(int n) {
        delete[] data_;
        data_ = new int[n];
    }
    void bad_reset() {
        delete[] data_;
        data_[0] = 1; // expect: heap-use-after-free
    }

  private:
    int *data_;
};

// ---- idioms that must not be reported ----

std::unique_ptr<Widget> smart() {
    std::unique_ptr<Widget> p(new Widget);
    auto q = std::make_unique<Widget>();
    return p;
}

void into_container(std::vector<Widget *> &v) {
    Widget *w = new Widget;
    v.push_back(w);
}

Widget *factory() { return new Widget; }

void lambda_capture(std::vector<void (*)()> &) {
    int *p = new int(1);
    auto f = [p]() { delete p; };
    f();
}

void shared_owner() {
    Widget *raw = new Widget;
    std::shared_ptr<Widget> s(raw);
}

void range_loop(std::vector<std::string> &names) {
    for (const auto &n : names) {
        char *copy = strdup(n.c_str());
        free(copy);
    }
}

void switch_paths(int k) {
    char *p = static_cast<char *>(malloc(10));
    switch (k) {
    case 0:
        free(p);
        break;
    default:
        free(p);
        break;
    }
}

void try_catch() {
    int *p = new int(3);
    try {
        throw 1;
    } catch (...) {
    }
    delete p;
}

void use_after_move() {
    std::string s = "hello";
    std::string t = std::move(s);
    if (s.empty()) { // expect: use-after-move
    }
}

void move_then_reassign_ok() {
    std::string s = "hello";
    std::string t = std::move(s);
    s = "world";
    if (s.empty()) {
    }
}
