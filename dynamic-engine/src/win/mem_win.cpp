// Memory on Windows. Every allocation the program makes ends in the process
// heap: malloc, new, strdup, fopen's buffers (the C runtime calls HeapAlloc).
// Watching HeapAlloc/HeapFree/HeapReAlloc/HeapSize therefore sees them all, in
// the program, in the C++ runtime and in the C runtime alike, with the C and
// C++ entry points (free, operator new/delete) only saying which family the
// memory belongs to.
#include "win_heap.h"
#include "win_hooks.h"

#include "blocks.h"
#include "heap.h"
#include "init.h"

#include <cstring>

namespace lc::win {

LPVOID(WINAPI *real_HeapAlloc)(HANDLE, DWORD, SIZE_T);
BOOL(WINAPI *real_HeapFree)(HANDLE, DWORD, LPVOID);
LPVOID(WINAPI *real_HeapReAlloc)(HANDLE, DWORD, LPVOID, SIZE_T);
SIZE_T(WINAPI *real_HeapSize)(HANDLE, DWORD, LPCVOID);
BOOL(WINAPI *real_HeapValidate)(HANDLE, DWORD, LPCVOID);

namespace {

HANDLE g_heap;
bool g_on; // tracking has started

// The family the next allocation or release belongs to, set by the entry
// point that is about to reach the heap: lc::Kind (0 = a plain allocation),
// and lc::DeKind + 1 (0 = none said).
#define tl_alloc_kind (ts().alloc_kind)
#define tl_free_kind (ts().free_kind)

bool ours(HANDLE h) { return g_on && h == g_heap && !tl_in_hook; }

LPVOID WINAPI hk_HeapAlloc(HANDLE h, DWORD flags, SIZE_T n) {
    if (LC_UNLIKELY(!ours(h)))
        return real_HeapAlloc(h, flags, n);
    const Kind kind = tl_alloc_kind ? Kind(tl_alloc_kind) : Kind::Malloc;
    tl_alloc_kind = 0;
    void *p;
    {
        HookGuard hg;
        ErrnoSaver es;
        p = heap_alloc(kind, n, 16, (flags & HEAP_ZERO_MEMORY) != 0);
    }
    if (!p) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        if (flags & HEAP_GENERATE_EXCEPTIONS)
            RaiseException(STATUS_NO_MEMORY, 0, 0, nullptr);
    }
    return p;
}

BOOL WINAPI hk_HeapFree(HANDLE h, DWORD flags, LPVOID p) {
    if (LC_UNLIKELY(!ours(h)) || !p)
        return real_HeapFree(h, flags, p);
    const DeKind dk = tl_free_kind ? DeKind(tl_free_kind - 1) : DeKind::Any;
    const bool sized = ts().free_sized;
    const size_t hint = size_t(ts().free_size);
    HookGuard hg;
    ErrnoSaver es;
    heap_free(dk, p, hint, sized, false);
    return TRUE;
}

// Resizing always moves the block (the redzones sit on both sides of it), so
// a caller that insists on the same place is told it cannot be done.
LPVOID WINAPI hk_HeapReAlloc(HANDLE h, DWORD flags, LPVOID p, SIZE_T n) {
    if (LC_UNLIKELY(!ours(h)) || !p)
        return real_HeapReAlloc(h, flags, p, n);
    const size_t old = heap_usable(p);
    if (flags & HEAP_REALLOC_IN_PLACE_ONLY) {
        if (old && n <= old)
            return p;
        if (old) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return nullptr;
        }
        return real_HeapReAlloc(h, flags, p, n);
    }
    void *np;
    {
        HookGuard hg;
        ErrnoSaver es;
        np = heap_realloc(p, n, false);
    }
    if (!np) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return nullptr;
    }
    if ((flags & HEAP_ZERO_MEMORY) && old && n > old)
        memset(static_cast<char *>(np) + old, 0, n - old);
    return np;
}

SIZE_T WINAPI hk_HeapSize(HANDLE h, DWORD flags, LPCVOID p) {
    if (ours(h) && p) {
        const size_t n = heap_usable(p);
        if (n)
            return n;
    }
    return real_HeapSize(h, flags, p);
}

// A pointer we hand out is not where the heap's own block starts.
BOOL WINAPI hk_HeapValidate(HANDLE h, DWORD flags, LPCVOID p) {
    if (ours(h) && p && heap_usable(p))
        return TRUE;
    return real_HeapValidate(h, flags, p);
}

// ---- which family: the C and C++ entry points -----------------------------------------

void (*real_free)(void *);
void *(*real_new)(size_t);
void *(*real_new_array)(size_t);
void *(*real_new_nt)(size_t, const void *);
void *(*real_new_array_nt)(size_t, const void *);
void (*real_delete)(void *);
void (*real_delete_array)(void *);
void (*real_delete_sized)(void *, size_t);
void (*real_delete_array_sized)(void *, size_t);
void (*real_delete_nt)(void *, const void *);
void (*real_delete_array_nt)(void *, const void *);

void *with_kind(Kind k, void *(*f)(size_t), size_t n) {
    tl_alloc_kind = uint8_t(k);
    void *p = f(n);
    tl_alloc_kind = 0;
    return p;
}

// operator delete reaches free(); only the outermost entry point names the family.
template <class F> void release_as(DeKind k, F f) {
    const uint8_t outer = tl_free_kind;
    if (!outer)
        tl_free_kind = uint8_t(unsigned(k) + 1);
    f();
    tl_free_kind = outer;
}

void hk_free(void *p) { release_as(DeKind::Free, [&] { real_free(p); }); }

void *hk_new(size_t n) { return with_kind(Kind::New, real_new, n); }
void *hk_new_array(size_t n) { return with_kind(Kind::NewArray, real_new_array, n); }
void *hk_new_nt(size_t n, const void *t) {
    tl_alloc_kind = uint8_t(Kind::New);
    void *p = real_new_nt(n, t);
    tl_alloc_kind = 0;
    return p;
}
void *hk_new_array_nt(size_t n, const void *t) {
    tl_alloc_kind = uint8_t(Kind::NewArray);
    void *p = real_new_array_nt(n, t);
    tl_alloc_kind = 0;
    return p;
}
void hk_delete(void *p) { release_as(DeKind::Delete, [&] { real_delete(p); }); }
void hk_delete_array(void *p) { release_as(DeKind::DeleteArray, [&] { real_delete_array(p); }); }
// The size a sized operator delete is told rides along to the heap call.
template <class F> void release_sized(DeKind k, size_t n, F f) {
    ThreadState &t = ts();
    const bool outer = t.free_kind != 0;
    if (!outer) {
        t.free_sized = 1;
        t.free_size = n;
    }
    release_as(k, f);
    if (!outer)
        ts().free_sized = 0;
}
void hk_delete_sized(void *p, size_t n) {
    release_sized(DeKind::Delete, n, [&] { real_delete_sized(p, n); });
}
void hk_delete_array_sized(void *p, size_t n) {
    release_sized(DeKind::DeleteArray, n, [&] { real_delete_array_sized(p, n); });
}
void hk_delete_nt(void *p, const void *t) {
    release_as(DeKind::Delete, [&] { real_delete_nt(p, t); });
}
void hk_delete_array_nt(void *p, const void *t) {
    release_as(DeKind::DeleteArray, [&] { real_delete_array_nt(p, t); });
}

#define H(name, fn, orig, crt) {name, reinterpret_cast<void *>(fn), (void **)(orig), crt}
const Hook g_hooks[] = {
    // The heap itself, under the C runtime too (kernel32 and ntdll spell it two ways).
    H("HeapAlloc", hk_HeapAlloc, nullptr, true),
    H("RtlAllocateHeap", hk_HeapAlloc, nullptr, true),
    H("HeapFree", hk_HeapFree, nullptr, true),
    H("RtlFreeHeap", hk_HeapFree, nullptr, true),
    H("HeapReAlloc", hk_HeapReAlloc, nullptr, true),
    H("RtlReAllocateHeap", hk_HeapReAlloc, nullptr, true),
    H("HeapSize", hk_HeapSize, nullptr, true),
    H("RtlSizeHeap", hk_HeapSize, nullptr, true),
    H("HeapValidate", hk_HeapValidate, nullptr, true),
    H("RtlValidateHeap", hk_HeapValidate, nullptr, true),
    // Which family a block belongs to.
    H("free", hk_free, &real_free, false),
    H("_Znwy", hk_new, &real_new, false),
    H("_Znay", hk_new_array, &real_new_array, false),
    H("_ZnwyRKSt9nothrow_t", hk_new_nt, &real_new_nt, false),
    H("_ZnayRKSt9nothrow_t", hk_new_array_nt, &real_new_array_nt, false),
    H("_ZdlPv", hk_delete, &real_delete, false),
    H("_ZdaPv", hk_delete_array, &real_delete_array, false),
    H("_ZdlPvy", hk_delete_sized, &real_delete_sized, false),
    H("_ZdaPvy", hk_delete_array_sized, &real_delete_array_sized, false),
    H("_ZdlPvRKSt9nothrow_t", hk_delete_nt, &real_delete_nt, false),
    H("_ZdaPvRKSt9nothrow_t", hk_delete_array_nt, &real_delete_array_nt, false),
};
#undef H

} // namespace

HANDLE process_heap() { return g_heap; }

bool untracked_heap_block(const void *p) { return real_HeapValidate(g_heap, 0, p) != 0; }

const Hook *memory_hooks(size_t *n) {
    *n = sizeof g_hooks / sizeof g_hooks[0];
    return g_hooks;
}

void memory_start() {
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    real_HeapAlloc = proc_address<decltype(real_HeapAlloc)>(k32, "HeapAlloc");
    real_HeapFree = proc_address<decltype(real_HeapFree)>(k32, "HeapFree");
    real_HeapReAlloc = proc_address<decltype(real_HeapReAlloc)>(k32, "HeapReAlloc");
    real_HeapSize = proc_address<decltype(real_HeapSize)>(k32, "HeapSize");
    real_HeapValidate = proc_address<decltype(real_HeapValidate)>(k32, "HeapValidate");
    g_heap = GetProcessHeap();
}

void memory_on() { g_on = true; }

} // namespace lc::win
