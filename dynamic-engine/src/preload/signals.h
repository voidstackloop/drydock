#pragma once
// Signal handlers installed by the program run through a trampoline that
// records which signal this thread is handling, so calls that are not
// async-signal-safe (malloc, printf, exit, ...) made from one are reported:
// they deadlock or corrupt memory when the signal lands at the wrong moment.
// The sigaction/signal/longjmp wrappers live in signals.cpp.
#include "rt.h"

namespace lc::signals {

extern LC_TLS int tl_signal; // the signal this thread is handling, or 0

// `what` ("malloc()") was called; reports it if inside a handler.
void unsafe_call_slow(const char *what);
inline void unsafe_call(const char *what) {
    if (LC_UNLIKELY(tl_signal) && !tl_in_hook)
        unsafe_call_slow(what);
}

} // namespace lc::signals
