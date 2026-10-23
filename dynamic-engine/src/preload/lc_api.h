#pragma once

// On Linux the wrapper's name is the libc symbol (LD_PRELOAD). On Darwin the
// same function is lc_<name> and darwin_interpose.c points it at the real one.
#if defined(__APPLE__)
#define LC_FN(name) lc_##name
#else
#define LC_FN(name) name
#endif

#define LC_API extern "C" __attribute__((visibility("default")))
