// C++ allocation API misuse, one case per argument.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

struct Base {
    int a = 0;
};
struct Derived : Base {
    char extra[40] = {};
};

__attribute__((noinline)) static void malloc_delete() {
    int *p = static_cast<int *>(std::malloc(sizeof(int)));
    delete p;
}

__attribute__((noinline)) static void new_free() {
    int *p = new int(3);
    std::free(p);
}

__attribute__((noinline)) static void array_scalar_delete() {
    int *p = new int[8];
    delete p;
}

__attribute__((noinline)) static void sized_delete_mismatch() {
    Base *b = new Derived;
    delete b; // Base has no virtual destructor
}

__attribute__((noinline)) static void leak_object() {
    auto *v = new std::vector<int>(1000, 7);
    (void)v;
}

__attribute__((noinline)) static void double_delete() {
    std::string *s = new std::string("a string long enough to live on the heap");
    delete s;
    delete s;
}

// Idiomatic code that must stay silent.
__attribute__((noinline)) static void clean_containers() {
    std::vector<std::string> v;
    for (int i = 0; i < 200; i++)
        v.push_back(std::string(50, char('a' + i % 26)));
    std::map<int, std::unique_ptr<int>> m;
    for (int i = 0; i < 200; i++)
        m[i] = std::make_unique<int>(i);
    auto sp = std::make_shared<std::vector<double>>(64, 1.0);
    try {
        throw std::runtime_error(std::string(100, 'e'));
    } catch (const std::exception &e) {
        std::printf("caught %zu\n", std::strlen(e.what()));
    }
    struct alignas(64) Wide {
        double d[8];
    };
    auto *w = new Wide;
    delete w;
    auto *wa = new Wide[3];
    delete[] wa;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        std::string c = argv[i];
        if (c == "malloc-delete") malloc_delete();
        else if (c == "new-free") new_free();
        else if (c == "array-scalar") array_scalar_delete();
        else if (c == "sized-delete") sized_delete_mismatch();
        else if (c == "leak") leak_object();
        else if (c == "double-delete") double_delete();
        else if (c == "clean") clean_containers();
        else {
            std::fprintf(stderr, "unknown case %s\n", c.c_str());
            return 64;
        }
    }
    return 0;
}
