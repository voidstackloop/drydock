#pragma once
// Tokenizer for C and C++ sources. Comments and preprocessor lines are
// dropped; macros are not expanded.
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

namespace lcstatic {

enum class Tok { Ident, Number, String, Char, Punct };

struct Token {
    Tok kind;
    std::string text;
    int line;
    int col;
    // Comparing a token against a literal is the inner loop of every check in
    // this engine, so it takes the literal's length from the type and compares
    // bytes directly. `text == s` strlen's the literal and then goes through
    // std::string::compare, whose npos bookkeeping costs more than the compare.
    template <std::size_t N> bool is(const char (&s)[N]) const {
        constexpr std::size_t n = N - 1; // never the terminating NUL
        if (text.size() != n)
            return false;
        if (kind == Tok::String || kind == Tok::Char)
            return false;
        return n == 0 || std::memcmp(text.data(), s, n) == 0;
    }
    // For a length that is only known at run time. It is not called `is`:
    // with both overloads taking a literal, the non-template one won overload
    // resolution (the array-to-pointer decay is an exact match) and every
    // check paid a strlen again.
    bool is_text(const char *s) const {
        if (kind == Tok::String || kind == Tok::Char)
            return false;
        const std::size_t n = std::strlen(s);
        return text.size() == n &&
               (n == 0 || std::memcmp(text.data(), s, n) == 0);
    }
};

std::vector<Token> lex(const std::string &src);

} // namespace lcstatic
