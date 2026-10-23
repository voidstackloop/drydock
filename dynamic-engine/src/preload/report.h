#pragma once
// Writes findings to the report stream (see shared/include/protocol.h).
#include "rt.h"

namespace lc::report {

struct Finding {
    const char *type = nullptr;
    uintptr_t addr = 0;
    uint64_t size = 0;
    uint32_t tid = 0;
    const char *msg = "";
    uint32_t access_stack = 0;
    uint32_t alloc_stack = 0;
    uint32_t free_stack = 0;
    // Raw return addresses for the access stack (e.g. from a signal handler);
    // used instead of access_stack when set.
    const uintptr_t *access_frames = nullptr;
    uint32_t access_n = 0;
    // memory-leak only
    const char *category = nullptr;
    uint64_t blocks = 0;
    uint64_t bytes = 0;
    bool fatal = false; // honour --abort-on-error
    // Written even by an untraced child, as a lone record in the parent's
    // stream (the child is about to exec: there is no later report).
    bool untraced_too = false;
};

struct Stats {
    uint64_t allocs, frees, bytes, live_blocks, live_bytes, peak_bytes;
    bool scanned;
};

void open_stream();
void emit(const Finding &f);
void finish(const Stats &st);
void after_fork_child(); // traced child: start its own stream header
void lock();
void unlock();
void reset_lock();

} // namespace lc::report
