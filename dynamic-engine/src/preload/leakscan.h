#pragma once
#include "rt.h"

namespace lc::leakscan {

// Conservative reachability scan from globals, thread stacks, TLS and
// registers. Caller holds every block shard lock. Emits memory-leak findings.
// The calling thread's stack is scanned from stack_lo upwards: callers pass
// an address in the frame where the program handed control to the runtime,
// so the scanner's own frames (full of block addresses) are never roots.
void run_locked(uintptr_t stack_lo);

// Words that count as roots besides memory: the registers of the calling
// thread, when the caller saved them somewhere the scan does not read (Windows).
void set_extra_roots(const uintptr_t *words, size_t n);

} // namespace lc::leakscan
