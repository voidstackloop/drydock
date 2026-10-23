// level: expert
// mode: static
// expect: none
// what: trap: code that looks like a leak or a use after free but is not: a deferred cleanup macro, a lambda that deletes its own parameter, chained assignment, ObjectWrap::Wrap, smart pointers taking raw ones
#include <cstdlib>
#include <cstring>
#include <memory>

#define K_DEFER(name) auto name = Defer() + [&]()

struct Mem {
    char *stack = nullptr;
    int len = 0;
};

struct T {
    int x = 0;
};

struct Handle {
    int fd = -1;
};

Mem *make_mem(int n) {
    Mem *mem = new Mem();
    K_DEFER(guard) { delete mem; };
    mem->len = n;
    mem->stack = static_cast<char *>(std::malloc(size_t(n)));
    if (!mem->stack)
        return nullptr;
    guard.disable();
    return mem;
}

struct Poll {
    Handle *handle = nullptr;
    void start(Handle *);
    void stop(Handle *);
    void close() {
        auto release = [](Handle *ptr) {
            Handle *handle = ptr;
            delete handle;
        };
        start(handle);
        stop(handle);
        release(handle);
        handle = nullptr;
    }
};

int chained(int n) {
    char *buf, *ptr;
    buf = ptr = static_cast<char *>(std::malloc(size_t(n)));
    if (buf == nullptr)
        return -1;
    std::memset(ptr, 0, size_t(n));
    std::free(buf);
    return 0;
}

struct Wrapped {
    void Wrap(void *object);
};

void construct(void *self) {
    Wrapped *w = new Wrapped();
    w->Wrap(self); // the JavaScript object owns it from here
}

void owners(std::shared_ptr<T> *out, std::unique_ptr<T> &up) {
    T *p = new T();
    *out = std::shared_ptr<T>(p);
    T *q = new T();
    up = std::unique_ptr<T>(q);
}

void free_in_workers(char *a, char *b) {
    auto free_a = [=] { std::free(a); };
    auto free_b = [=] { std::free(b); };
    free_a();
    free_b();
}
