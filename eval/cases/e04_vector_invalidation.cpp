// level: expert
// mode: dynamic
// expect: heap-use-after-free
// what: a reference to a vector element written after push_back() reallocated the vector
#include <vector>

struct Point {
    int x, y;
};

int main() {
    std::vector<Point> pts;
    pts.push_back({1, 2});
    Point &origin = pts[0];
    for (int i = 0; i < 100; i++)
        pts.push_back({i, i}); // grows: the elements move
    origin.x = 0; // writes into the old, freed buffer
    return pts[0].x;
}
