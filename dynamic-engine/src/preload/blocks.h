#pragma once
// Sharded open-addressing table: user pointer -> allocation record.
// Storage comes from mmap, never from the heap being tracked.
#include "rt.h"

namespace lc {

enum class Kind : uint8_t { None = 0, Malloc, Memalign, New, NewArray };
enum class State : uint8_t { None = 0, Live, Freed };

inline constexpr uint8_t kFlagGuarded =
    1; // lives in its own guard-page mapping
inline constexpr uint8_t kFlagReleased = 2; // freed; memory already returned
inline constexpr uint8_t kFlagSystem = 4;   // made by Windows' own code: its state, not the program's

struct Block {
    uintptr_t user;
    uintptr_t base; // what the underlying allocator returned
    uint64_t size;  // bytes the program asked for
    uint64_t total; // bytes obtained from the underlying allocator
    uint64_t seq;
    uint32_t alloc_stack;
    uint32_t free_stack;
    uint32_t alloc_tid;
    uint32_t free_tid;
    Kind kind;
    State state;
    uint8_t flags;
    uint8_t align_log2;
    uint32_t spare;
};
static_assert(sizeof(Block) == 64, "Block layout");

namespace blocks {

inline constexpr unsigned kShardBits = 6;
inline constexpr size_t kShards = size_t(1) << kShardBits;

// Holds the shard lock for as long as it lives.
class Handle {
  public:
    Handle() = default;
    Handle(SpinLock *l, Block *b) : lock_(l), b_(b) {}
    Handle(Handle &&o) noexcept : lock_(o.lock_), b_(o.b_) {
        o.lock_ = nullptr;
        o.b_ = nullptr;
    }
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    ~Handle() { release(); }
    Block *get() const { return b_; }
    void release() {
        if (lock_) {
            lock_->unlock();
            lock_ = nullptr;
            b_ = nullptr;
        }
    }

  private:
    SpinLock *lock_ = nullptr;
    Block *b_ = nullptr;
};

Handle lookup(uintptr_t user);
void insert(const Block &b);
// seq != 0: only remove if the record still belongs to that allocation.
bool remove(uintptr_t user, Block *old, uint64_t seq = 0);
size_t count();

void lock_all();
void unlock_all();
void reset_locks();
// Only while every shard is locked.
Block *shard_slots(size_t shard, size_t *cap);

} // namespace blocks
} // namespace lc
