#pragma once
// Guard-page allocations: each sampled block gets its own mapping with
// inaccessible pages around it, so overflows and use-after-free fault
// immediately instead of being found later.
#include "blocks.h"

namespace lc::guard {

void init(); // installs the SIGSEGV handler when guarding is enabled
bool want(size_t size, size_t align);
bool alloc(size_t size, size_t align, uintptr_t *base, uint64_t *total,
           uintptr_t *user);
void on_free(const Block &b); // make the data pages inaccessible
void release(const Block &b); // unmap

} // namespace lc::guard
