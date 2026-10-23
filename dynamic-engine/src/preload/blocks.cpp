#include "blocks.h"

#include <cstring>

namespace lc::blocks {
namespace {

struct alignas(64) Shard {
    SpinLock lock;
    Block *slots;
    size_t cap;
    size_t count;
};

Shard g_shards[kShards];

inline uint64_t mix(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

inline Shard &shard_for(uintptr_t user, uint64_t *h) {
    *h = mix(user);
    return g_shards[*h >> (64 - kShardBits)];
}

Block *probe(Shard &s, uintptr_t user, uint64_t h) {
    if (!s.cap)
        return nullptr;
    const size_t mask = s.cap - 1;
    for (size_t i = h & mask;; i = (i + 1) & mask) {
        if (s.slots[i].user == user)
            return &s.slots[i];
        if (!s.slots[i].user)
            return nullptr;
    }
}

void place(Block *slots, size_t cap, const Block &b) {
    const size_t mask = cap - 1;
    size_t i = mix(b.user) & mask;
    while (slots[i].user)
        i = (i + 1) & mask;
    slots[i] = b;
}

void grow(Shard &s) {
    size_t ncap = s.cap ? s.cap * 2 : 256;
    auto *ns = static_cast<Block *>(map_pages(ncap * sizeof(Block)));
    if (!ns)
        die("out of memory for allocation metadata");
    for (size_t i = 0; i < s.cap; ++i)
        if (s.slots[i].user)
            place(ns, ncap, s.slots[i]);
    unmap_pages(s.slots, s.cap * sizeof(Block));
    s.slots = ns;
    s.cap = ncap;
}

} // namespace

Handle lookup(uintptr_t user) {
    uint64_t h;
    Shard &s = shard_for(user, &h);
    s.lock.lock();
    return Handle(&s.lock, probe(s, user, h));
}

void insert(const Block &b) {
    uint64_t h;
    Shard &s = shard_for(b.user, &h);
    LockGuard g(s.lock);
    if (Block *e = probe(s, b.user, h)) {
        *e = b;
        return;
    }
    if ((s.count + 1) * 2 > s.cap)
        grow(s);
    place(s.slots, s.cap, b);
    ++s.count;
}

bool remove(uintptr_t user, Block *old, uint64_t seq) {
    uint64_t h;
    Shard &s = shard_for(user, &h);
    LockGuard g(s.lock);
    Block *e = probe(s, user, h);
    if (!e || (seq && e->seq != seq))
        return false;
    if (old)
        *old = *e;
    const size_t mask = s.cap - 1;
    size_t i = size_t(e - s.slots);
    // Backward-shift deletion keeps probe chains intact without tombstones.
    for (size_t j = (i + 1) & mask; s.slots[j].user; j = (j + 1) & mask) {
        size_t k = mix(s.slots[j].user) & mask;
        bool stays = (i <= j) ? (i < k && k <= j) : (i < k || k <= j);
        if (!stays) {
            s.slots[i] = s.slots[j];
            i = j;
        }
    }
    s.slots[i].user = 0;
    --s.count;
    return true;
}

size_t count() {
    size_t n = 0;
    for (auto &s : g_shards)
        n += __atomic_load_n(&s.count, __ATOMIC_RELAXED);
    return n;
}

void lock_all() {
    for (auto &s : g_shards)
        s.lock.lock();
}

void unlock_all() {
    for (auto &s : g_shards)
        s.lock.unlock();
}

void reset_locks() {
    for (auto &s : g_shards)
        s.lock.reset();
}

Block *shard_slots(size_t shard, size_t *cap) {
    *cap = g_shards[shard].cap;
    return g_shards[shard].slots;
}

} // namespace lc::blocks
