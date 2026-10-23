#pragma once
// Call-stack capture and interning: identical stacks share one id.
#include "rt.h"

namespace lc::stacks {

inline constexpr uint32_t kMaxDepth = 64;

void init();                // locate our own code so it can be skipped
void set_ready();           // unwinder is warmed up; capture may run
#if defined(__APPLE__)
// One loaded Mach-O image. Writable segments are globals the leak scan roots.
struct ImageView {
    static constexpr int kW = 16;
    uintptr_t lo, hi, slide;
    const char *name;
    uintptr_t wlo[kW], whi[kW];
    int nw;
};
int for_each_image(int (*cb)(const ImageView &, void *), void *data);
#endif
bool in_self(uintptr_t pc); // pc belongs to this library

uint32_t capture(); // 0 if unavailable
uint32_t intern(const uintptr_t *frames, uint32_t n);
bool get(uint32_t id, const uintptr_t **frames, uint32_t *n);
uint32_t trim_self(uintptr_t *frames, uint32_t n); // drop our leading frames

void lock_all();
void unlock_all();
void reset_locks();

} // namespace lc::stacks
