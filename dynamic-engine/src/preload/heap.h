#pragma once
// Tracked allocation/deallocation: redzones, quarantine, error detection.
#include "blocks.h"
#include "report.h"

namespace lc {

enum class DeKind : uint8_t { Free, Delete, DeleteArray, Any };

inline constexpr size_t kRedzone = 32;
inline constexpr uint8_t kLeftBase = 0xa0;
inline constexpr uint8_t kRightBase = 0xb0;
inline constexpr uint8_t kPoison = 0xdd;
inline constexpr size_t kPoisonMax = size_t(1) << 20;

// libc's own allocator, reachable without dlsym.
extern "C" {
void *__libc_malloc(size_t);
void *__libc_calloc(size_t, size_t);
void *__libc_realloc(void *, size_t);
void *__libc_memalign(size_t, size_t);
void __libc_free(void *);
}

void *heap_alloc(Kind kind, size_t size, size_t align, bool zero);
void heap_free(DeKind dk, void *p, size_t hint, bool sized, bool nested);
void *heap_realloc(void *p, size_t n, bool nested);
size_t heap_usable(const void *p);

// Exit-time checks; caller holds every block shard lock.
void heap_verify_all_locked();

report::Stats heap_stats();
void stats_on_alloc(uint64_t size);

void quarantine_lock();
void quarantine_unlock();
void quarantine_reset_lock();

inline uint8_t rz_byte(size_t i, uint8_t base) {
    return uint8_t(base + (i & 15));
}
void fill_rz(byte *p, size_t n, uint8_t base);

const char *kind_name(Kind k);

} // namespace lc
