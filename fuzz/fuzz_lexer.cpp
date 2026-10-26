// The lexer reads bytes that are not always C: generated files, editor
// leftovers, an attacker's attachment. Nothing it sees may crash the scanner.
#include "lexer.h"

#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string input(reinterpret_cast<const char *>(data), size);
    const auto tokens = lcstatic::lex(input);
    // Touch the result so the optimiser cannot drop the call.
    volatile size_t n = tokens.size();
    (void)n;
    return 0;
}
