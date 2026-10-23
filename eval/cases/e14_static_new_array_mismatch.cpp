// level: expert
// mode: static
// expect: alloc-dealloc-mismatch
// what: a factory returns new[], and the caller releases it with delete (not delete[])
#include <cstddef>

struct Sample {
    double t, v;
};

static Sample *make_samples(std::size_t n) { return new Sample[n]; }

double first_value(std::size_t n) {
    Sample *s = make_samples(n);
    s[0].v = 1.0;
    double v = s[0].v;
    delete s; // must be delete[]
    return v;
}
