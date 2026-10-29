// The exported allocator entry points. This file deliberately does not
// include <stdlib.h>/<malloc.h>: it defines those functions itself.
#include "heap.h"
#include "init.h"
#include "rt.h"
#include "signals.h"

#include <cerrno>
#if defined(__APPLE__)
#include <malloc/malloc.h>
#endif
#include <cstring>
#include <dlfcn.h>
#include <new>
#include <unistd.h>

#include "lc_api.h"

using namespace lc;

namespace {

void *c_alloc(Kind kind, size_t n, size_t align, bool zero) {
    if (LC_UNLIKELY(!tl_in_hook)) {
        static bool traced;
        if (!traced) {
            traced = true;
            trace_step("c_alloc: the program's first allocation");
        }
    }
    if (LC_UNLIKELY(tl_in_hook)) {
        void *p = ih::alloc(n, align);
        if (!p)
            errno = ENOMEM;
        else if (zero)
            memset(p, 0, n);
        return p;
    }
    ensure_init();
    if (LC_UNLIKELY(!g_cfg.active)) {
        if (align <= 16)
            return zero ? __libc_calloc(1, n) : __libc_malloc(n);
        void *p = __libc_memalign(align, n);
        if (p && zero)
            memset(p, 0, n);
        return p;
    }
    signals::unsafe_call(kind == Kind::New || kind == Kind::NewArray
                             ? "operator new"
                             : "malloc()");
    const int saved = errno;
    void *p;
    {
        HookGuard hg;
        p = heap_alloc(kind, n, align, zero);
    }
    errno = p ? saved : ENOMEM;
    return p;
}

void c_free(DeKind dk, void *p, size_t hint, bool sized) {
    if (!p)
        return;
    if (LC_UNLIKELY(!tl_in_hook)) {
        static bool traced;
        if (!traced) {
            traced = true;
            trace_step("c_free: the program's first free");
        }
    }
    if (ih::owns(p)) {
        ih::free(p);
        return;
    }
    const bool nested = tl_in_hook;
    if (!nested)
        ensure_init();
    if (LC_UNLIKELY(!g_cfg.active)) {
        __libc_free(p);
        return;
    }
    signals::unsafe_call(dk == DeKind::Free ? "free()" : "operator delete");
    const int saved = errno;
    {
        HookGuard hg;
        heap_free(dk, p, hint, sized, nested);
    }
    errno = saved;
}

void *c_realloc(void *p, size_t n) {
    if (!p)
        return c_alloc(Kind::Malloc, n, 16, false);
    if (ih::owns(p)) {
        const size_t old = ih::usable(p);
        void *np = c_alloc(Kind::Malloc, n ? n : 1, 16, false);
        if (np) {
            memcpy(np, p, old < n ? old : n);
            ih::free(p);
        }
        return np;
    }
    if (n == 0) {
        c_free(DeKind::Free, p, 0, false);
        return nullptr;
    }
    if (LC_UNLIKELY(tl_in_hook)) {
        if (!g_cfg.active)
            return __libc_realloc(p, n);
        const size_t old = heap_usable(p);
        if (!old)
            return __libc_realloc(p, n);
        void *np = ih::alloc(n, 16);
        if (np) {
            memcpy(np, p, old < n ? old : n);
            heap_free(DeKind::Free, p, 0, false, true);
        }
        return np;
    }
    ensure_init();
    if (LC_UNLIKELY(!g_cfg.active))
        return __libc_realloc(p, n);
    signals::unsafe_call("realloc()");
    const int saved = errno;
    void *np;
    {
        HookGuard hg;
        np = heap_realloc(p, n, false);
    }
    errno = np ? saved : ENOMEM;
    return np;
}

bool mul_overflows(size_t a, size_t b, size_t *out) {
    return __builtin_mul_overflow(a, b, out);
}

bool pow2(size_t a) { return a && !(a & (a - 1)); }

std::new_handler current_new_handler() {
    using Fn = std::new_handler (*)();
    static Fn fn;
    if (!fn) {
        HookGuard hg;
        fn =
            reinterpret_cast<Fn>(dlsym(RTLD_DEFAULT, "_ZSt15get_new_handlerv"));
    }
    return fn ? fn() : nullptr;
}

[[noreturn]] void throw_bad_alloc() {
    using Fn = void (*)();
    Fn fn;
    {
        HookGuard hg;
        fn = reinterpret_cast<Fn>(
            dlsym(RTLD_DEFAULT, "_ZSt17__throw_bad_allocv"));
    }
    if (fn)
        fn();
    static const char msg[] =
        "leakcheck: operator new failed and std::bad_alloc is unavailable\n";
    write_all(2, msg, sizeof msg - 1);
    __builtin_abort();
}

void *cxx_new(size_t n, size_t align, Kind kind, bool nothrow) {
    for (;;) {
        void *p = c_alloc(kind, n, align, false);
        if (LC_LIKELY(p))
            return p;
        std::new_handler h = current_new_handler();
        if (!h) {
            if (nothrow)
                return nullptr;
            throw_bad_alloc();
        }
        h();
    }
}

} // namespace

LC_API void *LC_FN(malloc)(size_t n) noexcept {
    return c_alloc(Kind::Malloc, n, 16, false);
}

LC_API void LC_FN(free)(void *p) noexcept { c_free(DeKind::Free, p, 0, false); }

LC_API void *LC_FN(calloc)(size_t a, size_t b) noexcept {
    size_t n;
    if (mul_overflows(a, b, &n)) {
        errno = ENOMEM;
        return nullptr;
    }
    return c_alloc(Kind::Malloc, n, 16, true);
}

LC_API void *LC_FN(realloc)(void *p, size_t n) noexcept { return c_realloc(p, n); }

LC_API void *LC_FN(reallocarray)(void *p, size_t a, size_t b) noexcept {
    size_t n;
    if (mul_overflows(a, b, &n)) {
        errno = ENOMEM;
        return nullptr;
    }
    return c_realloc(p, n);
}

LC_API void *LC_FN(memalign)(size_t align, size_t n) noexcept {
    size_t a = 16;
    while (a < align)
        a <<= 1;
    return c_alloc(Kind::Memalign, n, a, false);
}

LC_API void *LC_FN(aligned_alloc)(size_t align, size_t n) noexcept {
    if (!pow2(align)) {
        errno = EINVAL;
        return nullptr;
    }
    return c_alloc(Kind::Memalign, n, align, false);
}

LC_API int LC_FN(posix_memalign)(void **out, size_t align, size_t n) noexcept {
    if (!pow2(align) || align % sizeof(void *))
        return EINVAL;
    const int saved = errno;
    void *p = c_alloc(Kind::Memalign, n, align, false);
    errno = saved;
    if (!p)
        return ENOMEM;
    *out = p;
    return 0;
}

LC_API void *LC_FN(valloc)(size_t n) noexcept {
    return c_alloc(Kind::Memalign, n, page_size(), false);
}

LC_API void *LC_FN(pvalloc)(size_t n) noexcept {
    const size_t pg = page_size();
    return c_alloc(Kind::Memalign, n ? round_up(n, pg) : pg, pg, false);
}

#if defined(__APPLE__)
namespace {
size_t zone_size(const void *p) {
    malloc_zone_t *zone = malloc_default_zone();
    return zone->size(zone, p);
}
} // namespace
#endif

LC_API size_t LC_FN(malloc_usable_size)(void *p) noexcept {
    if (!p)
        return 0;
    if (ih::owns(p))
        return ih::usable(p);
    ensure_init();
#if defined(__APPLE__)
    // libSystem's own answer for a pointer it owns. Neither malloc_size() nor
    // dlsym() can give it here (the first is interposed by this dylib and would
    // come back to this function, the second finds the same thing), but the zone
    // carries its own size function, which nothing rewrites.
    if (!g_cfg.active)
        return zone_size(p);
    const size_t mine = heap_usable(p);
    return mine ? mine : zone_size(p);
#else
    if (!g_cfg.active) {
        using Fn = size_t (*)(void *);
        static Fn real;
        if (!real) {
            HookGuard hg;
            real = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "malloc_usable_size"));
        }
        return real ? real(p) : 0;
    }
    return heap_usable(p);
#endif
}

#if defined(__APPLE__)
LC_API size_t LC_FN(malloc_size)(const void *p) noexcept {
    return LC_FN(malloc_usable_size)(const_cast<void *>(p));
}
#endif

#define LC_CXX __attribute__((visibility("default")))

LC_CXX void *operator new(std::size_t n) {
    return cxx_new(n, 16, Kind::New, false);
}
LC_CXX void *operator new[](std::size_t n) {
    return cxx_new(n, 16, Kind::NewArray, false);
}
LC_CXX void *operator new(std::size_t n, const std::nothrow_t &) noexcept {
    return cxx_new(n, 16, Kind::New, true);
}
LC_CXX void *operator new[](std::size_t n, const std::nothrow_t &) noexcept {
    return cxx_new(n, 16, Kind::NewArray, true);
}
LC_CXX void *operator new(std::size_t n, std::align_val_t a) {
    return cxx_new(n, size_t(a), Kind::New, false);
}
LC_CXX void *operator new[](std::size_t n, std::align_val_t a) {
    return cxx_new(n, size_t(a), Kind::NewArray, false);
}
LC_CXX void *operator new(std::size_t n, std::align_val_t a,
                          const std::nothrow_t &) noexcept {
    return cxx_new(n, size_t(a), Kind::New, true);
}
LC_CXX void *operator new[](std::size_t n, std::align_val_t a,
                            const std::nothrow_t &) noexcept {
    return cxx_new(n, size_t(a), Kind::NewArray, true);
}

LC_CXX void operator delete(void *p) noexcept {
    c_free(DeKind::Delete, p, 0, false);
}
LC_CXX void operator delete[](void *p) noexcept {
    c_free(DeKind::DeleteArray, p, 0, false);
}
LC_CXX void operator delete(void *p, std::size_t n) noexcept {
    c_free(DeKind::Delete, p, n, true);
}
LC_CXX void operator delete[](void *p, std::size_t n) noexcept {
    c_free(DeKind::DeleteArray, p, n, true);
}
LC_CXX void operator delete(void *p, std::align_val_t) noexcept {
    c_free(DeKind::Delete, p, 0, false);
}
LC_CXX void operator delete[](void *p, std::align_val_t) noexcept {
    c_free(DeKind::DeleteArray, p, 0, false);
}
LC_CXX void operator delete(void *p, std::size_t n, std::align_val_t) noexcept {
    c_free(DeKind::Delete, p, n, true);
}
LC_CXX void operator delete[](void *p, std::size_t n,
                              std::align_val_t) noexcept {
    c_free(DeKind::DeleteArray, p, n, true);
}
LC_CXX void operator delete(void *p, const std::nothrow_t &) noexcept {
    c_free(DeKind::Delete, p, 0, false);
}
LC_CXX void operator delete[](void *p, const std::nothrow_t &) noexcept {
    c_free(DeKind::DeleteArray, p, 0, false);
}
LC_CXX void operator delete(void *p, std::align_val_t,
                            const std::nothrow_t &) noexcept {
    c_free(DeKind::Delete, p, 0, false);
}
LC_CXX void operator delete[](void *p, std::align_val_t,
                              const std::nothrow_t &) noexcept {
    c_free(DeKind::DeleteArray, p, 0, false);
}
