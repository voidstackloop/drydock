#pragma once

namespace lc {

// Loads the configuration on the first allocator call, which can happen
// before this library's constructor has run.
void ensure_init();

// The program cannot go on (it would hang forever): close the report,
// print `why` and abort.
[[noreturn]] void stop_program(const char *why);

} // namespace lc
