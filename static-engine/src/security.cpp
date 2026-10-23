#include "analyzer.h"
#include "rules.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <string_view>

// Source-level security checks: the classic ways C code is made to do what its
// author never meant. Each rule is a pattern in the token stream, and the ones
// about input follow it through assignments inside one function (a "taint":
// the names that hold text from outside, see Taint below). Findings are
// warnings like the rest of static mode: a pattern is not proof.
namespace lcstatic {
namespace {

using Toks = std::vector<Token>;

struct Range {
    size_t b, e; // tokens [b, e)
};

size_t match_scan(const Toks &t, size_t i) {
    const Token &open = t[i];
    if (open.kind == Tok::Punct && open.text.size() == 1) {
        const char oc = open.text[0];
        const char cc = oc == '(' ? ')' : oc == '[' ? ']' : '}';
        int depth = 0;
        for (size_t k = i; k < t.size(); ++k) {
            if (t[k].kind != Tok::Punct || t[k].text.size() != 1)
                continue;
            const char c = t[k].text[0];
            if (c == oc)
                ++depth;
            else if (c == cc && --depth == 0)
                return k;
        }
        return t.size();
    }
    // Not a bracket: the old generic scan, kept so an odd caller sees no change.
    const char *close = open.is("(") ? ")" : open.is("[") ? "]" : "}";
    int depth = 0;
    for (size_t k = i; k < t.size(); ++k) {
        if (t[k].kind != Tok::Punct)
            continue;
        if (t[k].text == open.text)
            ++depth;
        else if (t[k].text == close && --depth == 0)
            return k;
    }
    return t.size();
}

constexpr size_t kNotAnOpener = static_cast<size_t>(-1);

// The closing bracket of every opening one in a token stream, in one pass.
// Each check used to scan forward from the call it was looking at to find the
// end of its arguments, so a function was walked once per call in it: that
// made the whole pass quadratic in the size of a function. The scan pairs an
// opener with a close of its own kind by counting, which a stack per bracket
// kind reproduces exactly.
struct BracketTable {
    const Token *key = nullptr;
    size_t n = 0;
    std::vector<size_t> close; // opener index -> its close, or n if unbalanced

    void reset() {
        key = nullptr;
        n = 0;
        close.clear();
    }
    bool current(const Toks &t) const { return key == t.data() && n == t.size(); }
    void build(const Toks &t) {
        key = t.data();
        n = t.size();
        close.assign(n, kNotAnOpener);
        std::vector<size_t> stack[3];
        for (size_t k = 0; k < n; ++k) {
            const Token &tk = t[k];
            if (tk.kind != Tok::Punct || tk.text.size() != 1)
                continue;
            const char c = tk.text[0];
            const int opens = c == '(' ? 0 : c == '[' ? 1 : c == '{' ? 2 : -1;
            if (opens >= 0) {
                stack[opens].push_back(k);
                continue;
            }
            const int closes = c == ')' ? 0 : c == ']' ? 1 : c == '}' ? 2 : -1;
            if (closes >= 0 && !stack[closes].empty()) {
                close[stack[closes].back()] = k;
                stack[closes].pop_back();
            }
        }
        for (const std::vector<size_t> &open : stack)
            for (size_t k : open)
                close[k] = n; // never closed
    }
};

// One table per thread: the static engine analyses one file at a time per
// thread, and security_issues() clears it when it starts on new tokens.
thread_local BracketTable g_brackets;

// The index of the bracket that closes the one at `i` (t.size() when it is
// never closed).
size_t match(const Toks &t, size_t i) {
    if (!g_brackets.current(t))
        g_brackets.build(t);
    if (i < g_brackets.close.size() && g_brackets.close[i] != kNotAnOpener)
        return g_brackets.close[i];
    return match_scan(t, i);
}

// The arguments of the call whose '(' is at `open`.
std::vector<Range> args_of(const Toks &t, size_t open, size_t close) {
    std::vector<Range> out;
    if (close <= open + 1)
        return out;
    size_t b = open + 1;
    int depth = 0;
    for (size_t k = open + 1; k < close; ++k) {
        if (t[k].is("(") || t[k].is("[") || t[k].is("{"))
            ++depth;
        else if (t[k].is(")") || t[k].is("]") || t[k].is("}"))
            --depth;
        else if (depth == 0 && t[k].is(",")) {
            out.push_back({b, k});
            b = k + 1;
        }
    }
    out.push_back({b, close});
    return out;
}

bool member(const Toks &t, size_t i) {
    return i > 0 && (t[i - 1].is(".") || t[i - 1].is("->") || t[i - 1].is("::"));
}

bool is_call(const Toks &t, size_t i) {
    return i + 1 < t.size() && t[i].kind == Tok::Ident && t[i + 1].is("(") &&
           !member(t, i);
}

bool has_string(const Toks &t, Range r) {
    for (size_t k = r.b; k < r.e; ++k)
        if (t[k].kind == Tok::String)
            return true;
    return false;
}

bool slash_in(const Toks &t, Range r) {
    for (size_t k = r.b; k < r.e; ++k)
        if (t[k].kind == Tok::String && t[k].text.find('/') != std::string::npos)
            return true;
    return false;
}

// ponytail: ".." counts only as an argument of strstr/find/contains/rfind
// earlier in the function. A hand-rolled scan of the two dots is still reported.
bool dotdot_rejected(const Toks &t, size_t b, size_t e) {
    for (size_t k = b; k < e; ++k) {
        if (t[k].kind != Tok::String || t[k].text.find("..") == std::string::npos)
            continue;
        for (size_t j = k; j-- > b && k - j < 12;)
            if (t[j].is("strstr") || t[j].is("find") || t[j].is("rfind") ||
                t[j].is("contains"))
                return true;
    }
    return false;
}

// The contents of the string literals in r joined ("a" "b" is "ab"); false if
// r holds anything else.
bool literal(const Toks &t, Range r, std::string *out) {
    if (r.b >= r.e)
        return false;
    std::string s;
    for (size_t k = r.b; k < r.e; ++k) {
        if (t[k].kind != Tok::String || t[k].text.size() < 2)
            return false;
        const std::string &x = t[k].text;
        const size_t q = x.find('"');
        if (q == std::string::npos || x.back() != '"')
            return false;
        s += x.substr(q + 1, x.size() - q - 2);
    }
    *out = s;
    return true;
}

// Bytes a C string literal holds (an escape is one byte).
size_t literal_bytes(const std::string &s) {
    size_t n = 0;
    for (size_t k = 0; k < s.size(); ++k, ++n)
        if (s[k] == '\\' && k + 1 < s.size())
            ++k;
    return n;
}

std::string show(const Toks &t, Range r) {
    std::string s;
    for (size_t k = r.b; k < r.e && s.size() < 40; ++k)
        s += t[k].text;
    return s.size() >= 40 ? s.substr(0, 37) + "..." : s;
}

bool all_caps(const std::string &s) {
    bool letter = false;
    for (char c : s) {
        if (std::islower(static_cast<unsigned char>(c)))
            return false;
        letter |= std::isupper(static_cast<unsigned char>(c)) != 0;
    }
    return letter;
}

// A format written with macros and literals only (HOME CLEAR, "x" PRIu64).
bool macro_text(const Toks &t, Range r) {
    for (size_t k = r.b; k < r.e; ++k)
        if (!(t[k].kind == Tok::String || (t[k].kind == Tok::Ident && all_caps(t[k].text))))
            return false;
    return r.e > r.b;
}

// ASCII lower case. std::tolower is a call into the C library for every byte,
// and this runs over millions of bytes of every file scanned; the C locale
// (which is never changed here) maps only 'A'-'Z'.
inline char ascii_lower(char c) { return c >= 'A' && c <= 'Z' ? char(c + 32) : c; }

std::string lower(std::string_view s) {
    std::string out(s);
    for (char &c : out)
        c = ascii_lower(c);
    return out;
}

// Is `w` this word? The literal's length is known here, so this needs no
// strlen and no std::string::compare: a compare against a literal costs more
// in setup than in comparing. These tests are the inner loop of the rules.
template <std::size_t N>
bool word_is(const std::string &w, const char (&lit)[N]) {
    return w.size() == N - 1 && std::memcmp(w.data(), lit, N - 1) == 0;
}

// Prefix and suffix tests against a literal, with the length from the type.
// The `const char *` versions below are for a length only known at run time
// and are not called `starts`/`ends` for the same reason as Token::is_text:
// overload resolution prefers a non-template over a template.
template <std::size_t N>
bool starts(const std::string &s, const char (&lit)[N]) {
    return s.size() >= N - 1 && std::memcmp(s.data(), lit, N - 1) == 0;
}

template <std::size_t N> bool ends(const std::string &s, const char (&lit)[N]) {
    return s.size() >= N - 1 &&
           std::memcmp(s.data() + s.size() - (N - 1), lit, N - 1) == 0;
}

bool starts_text(const std::string &s, const char *p) {
    const size_t n = std::strlen(p);
    return s.size() >= n && std::memcmp(s.data(), p, n) == 0;
}

bool ends_text(const std::string &s, const char *p) {
    const size_t n = std::strlen(p);
    return s.size() >= n && std::memcmp(s.data() + s.size() - n, p, n) == 0;
}

// ---- what holds text from outside -------------------------------------------

// Calls whose result is text from outside.
const std::set<std::string> kSources = {"getenv", "secure_getenv", "readline",
                                        "getpass", "gets_s"};
// Calls that fill a buffer given as this argument with text from outside.
const std::map<std::string, size_t> kFills = {
    {"fgets", 0}, {"gets", 0}, {"fread", 0},   {"read", 1},   {"pread", 1},
    {"recv", 1},  {"recvfrom", 1}, {"getline", 0}, {"getdelim", 0}};
// A call that turns text into something that cannot carry an attack.
const std::set<std::string> kSafe = {
    "atoi",   "atol",    "atoll",  "atof",   "strtol", "strtoul", "strtoll",
    "strtoull", "strtod", "strlen", "strcmp", "strncmp", "strcasecmp",
    "strncasecmp", "sizeof", "isalpha", "isdigit", "isalnum", "memcmp"};

std::string call_name(const Toks &t, size_t i); // below

// Functions whose result is (part of) their text argument.
bool passes_text(const std::string &n) {
    return starts(n, "str") || starts(n, "mem") || starts(n, "skip_") ||
           n.find("strdup") != std::string::npos || n.find("basename") != std::string::npos ||
           n.find("dirname") != std::string::npos || n == "realpath" || n == "trim" ||
           n == "stpcpy" || n == "concat_path_file";
}

bool is_tainted_name(const std::set<std::string> &taint, const Toks &t, size_t k) {
    return t[k].kind == Tok::Ident && !member(t, k) && taint.count(t[k].text);
}

// Does r hold text from outside: a tainted name, or a call that reads it,
// outside the arguments of a call that makes it harmless?
bool tainted(const Toks &t, Range r, const std::set<std::string> &taint) {
    for (size_t k = r.b; k < r.e; ++k) {
        if (t[k].is("[")) { // months[n]: the index is not the value
            k = std::min(match(t, k), r.e);
            continue;
        }
        if (is_call(t, k)) {
            const std::string n = call_name(t, k);
            if (kSources.count(n))
                return true;
            // What an unknown function returns is not its argument; only the
            // ones that hand text on (strdup, strchr, strtok, ...) carry it.
            if (kSafe.count(n) || !passes_text(n)) {
                k = std::min(match(t, k + 1), r.e);
                continue;
            }
        }
        if (is_tainted_name(taint, t, k))
            return true;
    }
    return false;
}

// A size taken from outside text: a tainted name, a name already known to hold
// such a size, or getenv() and the other readers. Looks inside atoi/strlen,
// which tainted() skips because they do not hand the text itself on.
bool size_from_outside(const Toks &t, Range r, const std::set<std::string> &taint,
                       const std::set<std::string> &sizes) {
    for (size_t k = r.b; k < r.e; ++k) {
        if (is_call(t, k) && kSources.count(call_name(t, k)))
            return true;
        if (t[k].kind == Tok::Ident && !member(t, k) &&
            (taint.count(t[k].text) || sizes.count(t[k].text)))
            return true;
    }
    return false;
}

// The variable an expression names or points into: "buf", "&buf[0]", "buf + n".
std::string base_name(const Toks &t, Range r) {
    size_t k = r.b;
    // (past "&", "*" and a cast such as "(char *)")
    while (k < r.e && (t[k].is("&") || t[k].is("*") || t[k].is("(") || t[k].is(")") ||
                       t[k].is("char") || t[k].is("unsigned") || t[k].is("signed") ||
                       t[k].is("void") || t[k].is("const") || t[k].is("struct")))
        ++k;
    if (k >= r.e || t[k].kind != Tok::Ident || member(t, k))
        return {};
    if (k + 1 < r.e && (t[k + 1].is(".") || t[k + 1].is("->")))
        return {}; // a field: not a plain variable
    return t[k].text;
}

// ---- a function's local arrays ------------------------------------------------

constexpr long kUnknownSize = -1;

// Bytes of one element of a scalar type name; 0 for anything else.
long element_size(const std::string &w) {
    // Called once per token in every function body. Filtering on the length
    // first turns the 17 comparisons into one size test plus, for the few
    // words of that length, one compare.
    switch (w.size()) {
    case 3:
        return word_is(w, "int") ? 4 : 0;
    case 4:
        if (word_is(w, "char") || word_is(w, "bool"))
            return 1;
        return word_is(w, "long") ? 8 : 0;
    case 5:
        if (word_is(w, "short"))
            return 2;
        return word_is(w, "float") ? 4 : 0;
    case 6:
        if (word_is(w, "int8_t"))
            return 1;
        if (word_is(w, "size_t"))
            return 8;
        return word_is(w, "double") ? 8 : 0;
    case 7:
        if (word_is(w, "uint8_t"))
            return 1;
        if (word_is(w, "int32_t") || word_is(w, "wchar_t"))
            return 4;
        return word_is(w, "int64_t") ? 8 : 0;
    case 8:
        if (word_is(w, "uint16_t"))
            return 2;
        if (word_is(w, "uint32_t"))
            return 4;
        return word_is(w, "uint64_t") ? 8 : 0;
    default:
        return 0; // not a scalar type name
    }
}

bool const_expr_value(const Toks &t, Range r, long *out); // below

// char name[N]: N, or kUnknownSize for a size written with macros. A size that
// uses a variable (a VLA) is left out.
std::map<std::string, long> local_arrays(const Toks &t, Range body,
                                         std::map<std::string, std::string> *texts) {
    std::map<std::string, long> out;
    for (size_t k = body.b; k + 3 < body.e; ++k) {
        const long elem = element_size(t[k].text);
        if (!elem)
            continue;
        size_t n = k + 1;
        if (t[n].is("const"))
            ++n;
        // (a "*" here makes it an array of pointers, not of characters)
        if (n + 2 >= body.e || t[n].kind != Tok::Ident || !t[n + 1].is("["))
            continue;
        // char a[N];  and  char a[N], b[M];
        for (size_t at = n; at + 1 < body.e && t[at].kind == Tok::Ident && t[at + 1].is("[");) {
            const size_t close = match(t, at + 1);
            if (close >= body.e)
                break;
            bool vla = false;
            for (size_t j = at + 2; j < close; ++j)
                if (t[j].kind == Tok::Ident && !all_caps(t[j].text) && !t[j].is("sizeof"))
                    vla = true;
            if (!vla) {
                long size = kUnknownSize;
                if (long n = 0; const_expr_value(t, {at + 2, close}, &n) && n > 0)
                    size = n * elem;
                std::string text; // how the size is written, to tell two equal sizes
                for (size_t j = at + 2; j < close; ++j)
                    text += t[j].text + " ";
                auto [it, fresh] = out.emplace(t[at].text, size);
                if (!fresh && (it->second != size || (*texts)[t[at].text] != text)) {
                    it->second = kUnknownSize; // two arrays of one name in different scopes
                    (*texts)[t[at].text] = "?" + t[at].text;
                } else if (fresh) {
                    (*texts)[t[at].text] = text;
                }
            }
            // the next declarator of the same declaration
            size_t next = close + 1;
            for (int depth = 0; next < body.e; ++next) {
                if (t[next].is("(") || t[next].is("[") || t[next].is("{"))
                    ++depth;
                else if (t[next].is(")") || t[next].is("]") || t[next].is("}"))
                    --depth;
                else if (depth == 0 && (t[next].is(";") || t[next].is(",")))
                    break;
            }
            at = next < body.e && t[next].is(",") ? next + 1 : body.e;
        }
    }
    return out;
}

// ---- format strings ------------------------------------------------------------

// The same with a va_list after the format: the format of a wrapper is its
// caller's business, so only text from outside is reported.
const std::map<std::string, size_t> kVPrintf = {
    {"vprintf", 0}, {"vfprintf", 1}, {"vsprintf", 1}, {"vsnprintf", 2}, {"vdprintf", 1},
    {"vsyslog", 1}, {"verr", 1}, {"verrx", 1}, {"vwarn", 0}, {"vwarnx", 0},
    {"vwprintf", 0}, {"vfwprintf", 1}, {"vswprintf", 2}, {"vasprintf", 1}};

const std::map<std::string, size_t> kPrintf = {
    {"printf", 0}, {"fprintf", 1}, {"dprintf", 1}, {"sprintf", 1},
    {"snprintf", 2}, {"syslog", 1}, {"asprintf", 1}, {"err", 1}, {"errx", 1},
    {"warn", 0}, {"warnx", 0}, {"wprintf", 0}, {"fwprintf", 1}, {"swprintf", 2}};

// Names that are only ever given a string literal: a format held in one is as
// safe as the literal.
std::set<std::string> literal_names(const Toks &t) {
    std::map<std::string, std::pair<int, int>> seen; // name -> literal, other
    for (size_t k = 1; k + 1 < t.size(); ++k) {
        if (!t[k].is("=") || member(t, k))
            continue;
        size_t n = k - 1;
        if (t[n].is("]")) { // name[] = ...
            while (n > 0 && !t[n].is("["))
                --n;
            if (n == 0)
                continue;
            --n;
        }
        if (t[n].kind != Tok::Ident || member(t, n))
            continue;
        (t[k + 1].kind == Tok::String ? seen[t[n].text].first : seen[t[n].text].second)++;
    }
    std::set<std::string> out;
    for (const auto &[name, c] : seen)
        if (c.first && !c.second)
            out.insert(name);
    return out;
}

// ---- scanf formats ---------------------------------------------------------------

// Does a scanf format have %s or %[ with no width (the reader overflows its
// buffer on a long word)?
bool scanf_without_width(const std::string &f) {
    for (size_t k = 0; k < f.size(); ++k) {
        if (f[k] != '%')
            continue;
        ++k;
        if (k < f.size() && f[k] == '%')
            continue;
        if (k < f.size() && f[k] == '*') // read and discarded
            continue;
        bool width = false;
        while (k < f.size() && std::isdigit(static_cast<unsigned char>(f[k])))
            width = true, ++k;
        while (k < f.size() && strchr("hlLqjzt", f[k]))
            ++k;
        if (k < f.size() && (f[k] == 's' || f[k] == '[') && !width)
            return true;
    }
    return false;
}

// The arguments a scanf format stores into, in order: true for %s and %[ with
// no width (they write a word of any length).
std::vector<bool> scan_stores(const std::string &f) {
    std::vector<bool> out;
    for (size_t k = 0; k < f.size(); ++k) {
        if (f[k] != '%')
            continue;
        ++k;
        if (k < f.size() && f[k] == '%')
            continue;
        const bool discarded = k < f.size() && f[k] == '*';
        if (discarded)
            ++k;
        bool width = false;
        while (k < f.size() && std::isdigit(static_cast<unsigned char>(f[k])))
            width = true, ++k;
        while (k < f.size() && strchr("hlLqjzt", f[k]))
            ++k;
        if (k >= f.size())
            break;
        const char conv = f[k];
        if (f[k] == '[') { // skip the set
            ++k;
            if (k < f.size() && f[k] == '^')
                ++k;
            if (k < f.size() && f[k] == ']')
                ++k;
            while (k < f.size() && f[k] != ']')
                ++k;
        }
        if (!discarded)
            out.push_back((conv == 's' || conv == '[') && !width);
    }
    return out;
}

// What each argument of a printf format can write: the most characters it adds
// (numbers up to 24, a %.5s five), or -1 for a %s with no precision, which has
// no limit of its own. A '*' takes an argument of its own, which writes nothing.
std::vector<long> print_args(const std::string &f) {
    std::vector<long> out;
    for (size_t k = 0; k < f.size(); ++k) {
        if (f[k] != '%')
            continue;
        ++k;
        if (k < f.size() && f[k] == '%')
            continue;
        long width = 0, precision = -1;
        bool in_precision = false;
        while (k < f.size() && !std::isalpha(static_cast<unsigned char>(f[k]))) {
            if (f[k] == '.') {
                in_precision = true;
                precision = 0;
            } else if (f[k] == '*') {
                out.push_back(0);
            } else if (std::isdigit(static_cast<unsigned char>(f[k]))) {
                (in_precision ? precision : width) =
                    (in_precision ? precision : width) * 10 + (f[k] - '0');
            }
            ++k;
        }
        while (k < f.size() && strchr("hlLqjzt", f[k]) && k + 1 < f.size() &&
               std::isalpha(static_cast<unsigned char>(f[k + 1])))
            ++k;
        if (k >= f.size())
            break;
        const char conv = f[k];
        if (conv == 's')
            out.push_back(precision >= 0 ? std::max(width, precision) : -1);
        else if (conv == 'c')
            out.push_back(std::max(width, 1L));
        else if (strchr("fFeEgGaA", conv))
            out.push_back(std::max(width, 330L));
        else
            out.push_back(std::max(width, 24L));
    }
    return out;
}

// Literal characters of a printf format outside its conversions, and whether a
// %s (with no precision) is among them.
struct FormatInfo {
    size_t fixed = 0;
    bool unbounded_s = false;
};

FormatInfo scan_format(const std::string &f) {
    FormatInfo info;
    for (size_t k = 0; k < f.size(); ++k) {
        if (f[k] == '\\' && k + 1 < f.size()) {
            ++info.fixed;
            ++k;
            continue;
        }
        if (f[k] != '%') {
            ++info.fixed;
            continue;
        }
        ++k;
        if (k < f.size() && f[k] == '%') {
            ++info.fixed;
            continue;
        }
        bool precision = false;
        while (k < f.size() && !std::isalpha(static_cast<unsigned char>(f[k]))) {
            precision |= f[k] == '.';
            ++k;
        }
        while (k < f.size() && strchr("hlLqjzt", f[k]))
            ++k;
        if (k < f.size() && f[k] == 's' && !precision)
            info.unbounded_s = true;
    }
    return info;
}

// ---- the rules -----------------------------------------------------------------------

const std::set<std::string> kWeakCrypto = {
    "MD5", "MD5_Init", "MD5_Update", "MD5_Final", "MD4", "MD4_Init", "MD4_Update",
    "MD4_Final", "MD2", "MD2_Init", "MD2_Update", "MD2_Final", "SHA1", "SHA1_Init",
    "SHA1_Update", "SHA1_Final", "DES_ecb_encrypt", "DES_set_key",
    "DES_set_key_unchecked", "DES_ncbc_encrypt", "DES_cbc_encrypt",
    "DES_ede3_cbc_encrypt", "RC4",
    "RC4_set_key", "RC2_set_key", "RC2_ecb_encrypt", "RC2_cbc_encrypt",
    "crypt", "crypt_r", "EVP_md4", "EVP_md5", "EVP_sha1", "CC_MD5", "CC_SHA1",
    "EVP_des_cbc", "EVP_des_ecb", "EVP_des_ede3_cbc", "EVP_rc2_cbc",
    "PKCS5_PBKDF2_HMAC_SHA1",
    "EVP_rc4", "EVP_aes_128_ecb", "EVP_aes_192_ecb", "EVP_aes_256_ecb"};

// A mode written as a number or as S_I* names: can everyone write it?
bool world_writable(const Toks &t, Range r) {
    // a constant only: `mode & 07777` keeps the caller's bits, it sets none
    for (size_t k = r.b; k < r.e; ++k)
        if (!(t[k].kind == Tok::Number || t[k].is("|") || t[k].is("(") || t[k].is(")") ||
              (t[k].kind == Tok::Ident &&
               (starts(t[k].text, "S_I") || t[k].text == "ACCESSPERMS" ||
                t[k].text == "DEFFILEMODE"))))
            return false;
    for (size_t k = r.b; k < r.e; ++k) {
        if (t[k].is("S_IWOTH") || t[k].is("S_IRWXO") || t[k].is("ACCESSPERMS") ||
            t[k].is("DEFFILEMODE"))
            return true;
        if (t[k].kind == Tok::Number && t[k].text.size() > 1 && t[k].text[0] == '0' &&
            std::isdigit(static_cast<unsigned char>(t[k].text[1]))) {
            const long mode = strtol(t[k].text.c_str(), nullptr, 8);
            if (mode & 0002)
                return true;
        }
    }
    return false;
}

// 04755 and S_ISUID. A variable mode is not a bit we can see, but `mode | 04755` is.
bool setid_mode(const Toks &t, Range r) {
    for (size_t k = r.b; k < r.e; ++k) {
        if (t[k].is("S_ISUID") || t[k].is("S_ISGID"))
            return true;
        if (t[k].kind == Tok::Number && t[k].text.size() > 1 && t[k].text[0] == '0' &&
            std::isdigit(static_cast<unsigned char>(t[k].text[1])))
            if (strtol(t[k].text.c_str(), nullptr, 8) & 06000)
                return true;
    }
    return false;
}

// msgget/semget/shmget write IPC_CREAT | 0666. IPC_* is not a permission bit.
bool ipc_world_writable(const Toks &t, Range r) {
    bool write = false;
    for (size_t k = r.b; k < r.e; ++k) {
        if (t[k].is("|") || t[k].is("(") || t[k].is(")"))
            continue;
        if (t[k].kind == Tok::Ident && starts(t[k].text, "IPC_"))
            continue;
        if (t[k].kind == Tok::Ident && starts(t[k].text, "S_I")) {
            if (t[k].is("S_IWOTH") || t[k].is("S_IRWXO"))
                write = true;
            continue;
        }
        if (t[k].kind == Tok::Number && t[k].text.size() > 1 && t[k].text[0] == '0' &&
            std::isdigit(static_cast<unsigned char>(t[k].text[1]))) {
            if (strtol(t[k].text.c_str(), nullptr, 8) & 0002)
                write = true;
            continue;
        }
        return false;
    }
    return write;
}

// EVP_get_digestbyname("MD5") and EVP_MD_fetch(ctx, "SHA-1") name the algorithm
// in a string. Empty when it is not one of the weak families already listed.
std::string weak_alg_key(std::string s) {
    for (char &c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    auto family = [&](const char *prefix, const char *key) -> const char * {
        const size_t n = std::strlen(prefix);
        if (s.size() >= n && s.compare(0, n, prefix) == 0 &&
            (s.size() == n || !std::isdigit(static_cast<unsigned char>(s[n]))))
            return key;
        return nullptr;
    };
    if (const char *k = family("md2", "MD2"))
        return k;
    if (const char *k = family("md4", "MD4"))
        return k;
    if (const char *k = family("md5", "MD5"))
        return k;
    if (s.size() >= 5 && s.compare(0, 5, "sha-1") == 0 &&
        (s.size() == 5 || !std::isdigit(static_cast<unsigned char>(s[5]))))
        return "SHA1";
    if (const char *k = family("sha1", "SHA1"))
        return k;
    if (const char *k = family("des", "DES"))
        return k;
    if (const char *k = family("rc2", "RC2"))
        return k;
    if (const char *k = family("rc4", "RC4"))
        return k;
    return {};
}

// 0: not a secret's name; 1: it is; 2: a bare "token", which is a parser's word
// as often as a credential: only a value that looks random makes it one.
int secret_name(const std::string &raw) {
    const std::string n = lower(raw);
    static const char *const kWords[] = {"passwd", "password", "passphrase",
                                         "secret", "apikey", "api_key",
                                         "private_key", "privkey", "auth_key",
                                         "access_key", "secret_key", "credential"};
    static const char *const kNotValues[] = {"_prompt", "_label", "_name", "_file",
                                             "_path", "_env", "_var", "_len",
                                             "_size", "_type", "_field", "_param",
                                             "_arg", "_opt", "_flag", "_header",
                                             "_url", "_msg", "_message", "_text",
                                             "_fmt", "_format", "_hash", "_algo",
                                             "_id", "_kind", "_mode", "_option",
                                             "_help", "_usage", "_error", "_err"};
    for (const char *s : kNotValues)
        if (ends_text(n, s))
            return false;
    for (const char *p : {"no_", "has_", "is_", "max_", "min_", "num_", "n_"})
        if (starts_text(n, p))
            return false;
    if (n.find("tokeniz") != std::string::npos || n.find("tokens") != std::string::npos)
        return 0;
    for (const char *w : kWords)
        if (n == w || starts_text(n, (std::string(w) + "_").c_str()) ||
            ends_text(n, (std::string("_") + w).c_str()) ||
            n.find(std::string("_") + w + "_") != std::string::npos ||
            (w[0] == 'p' && w[1] == 'a' && n.find(w) != std::string::npos))
            return 1;
    for (const char *q : {"api", "auth", "access", "bearer", "secret", "session", "refresh",
                          "oauth", "github", "slack", "bot"})
        if (n.find(std::string(q) + "_token") != std::string::npos ||
            n.find(std::string(q) + "token") != std::string::npos)
            return 1;
    return n == "token" ? 2 : 0;
}

bool sensitive_prng_name(const std::string &raw) {
    if (secret_name(raw) != 0)
        return true;
    const std::string n = lower(raw);
    for (const char *w : {"nonce", "salt", "session_id", "sessionid", "session_key",
                          "iv", "seed", "challenge", "auth", "token"}) {
        if (n == w || starts_text(n, (std::string(w) + "_").c_str()) ||
            ends_text(n, (std::string("_") + w).c_str()) ||
            n.find(std::string("_") + w + "_") != std::string::npos)
            return true;
    }
    return false;
}

// A key, password, token, iv or nonce in the variable or the function name.
// "keyboard" and "filename" do not match: the word has to stand on its own.
bool weak_material(const std::string &raw) {
    const std::string n = lower(raw);
    for (const char *w : {"key", "password", "passwd", "token", "iv", "nonce"}) {
        const std::string s = w;
        if (n == s || starts_text(n, (s + "_").c_str()) ||
            ends_text(n, ("_" + s).c_str()) ||
            n.find("_" + s + "_") != std::string::npos)
            return true;
    }
    return false;
}

bool has_html_tag(const std::string &s) {
    std::string l = lower(s);
    return l.find("<html") != std::string::npos ||
           l.find("<body") != std::string::npos ||
           l.find("<script") != std::string::npos ||
           l.find("<div") != std::string::npos ||
           l.find("<p>") != std::string::npos ||
           l.find("<span>") != std::string::npos ||
           l.find("<h1") != std::string::npos ||
           l.find("<table") != std::string::npos ||
           l.find("<b>") != std::string::npos ||
           l.find("<a ") != std::string::npos ||
           l.find("content-type: text/html") != std::string::npos;
}

// Mixed character classes and long enough to be generated, not typed.
bool random_looking(const std::string &v) {
    bool lo = false, up = false, dig = false, sym = false;
    for (char c : v) {
        lo |= std::islower(static_cast<unsigned char>(c)) != 0;
        up |= std::isupper(static_cast<unsigned char>(c)) != 0;
        dig |= std::isdigit(static_cast<unsigned char>(c)) != 0;
        sym |= !std::isalnum(static_cast<unsigned char>(c));
    }
    return v.size() >= 16 && int(lo) + int(up) + int(dig) + int(sym) >= 2;
}

// A value that looks like a credential and not like a message.
bool credential_value(const std::string &v) {
    if (v.size() < 4 || v.find(' ') != std::string::npos ||
        v.find(':') != std::string::npos || v.find('%') != std::string::npos ||
        v.find('/') != std::string::npos || v.find('\\') != std::string::npos ||
        v.find('$') != std::string::npos || v.find('{') != std::string::npos)
        return false;
    return true;
}

// Strings that are secrets by their shape, wherever they appear.
const char *known_secret(const std::string &v) {
    auto run = [&](size_t at, size_t n, bool (*ok)(char)) {
        if (v.size() < at + n)
            return false;
        for (size_t k = at; k < at + n; ++k)
            if (!ok(v[k]))
                return false;
        return true;
    };
    auto upper_digit = [](char c) { return std::isupper(static_cast<unsigned char>(c)) || std::isdigit(static_cast<unsigned char>(c)); };
    auto alnum = [](char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0; };
    if (v.find("PRIVATE KEY-----") != std::string::npos && v.find("-----BEGIN") != std::string::npos)
        return "a private key";
    if (starts(v, "AKIA") && v.size() == 20 && run(4, 16, upper_digit))
        return "an AWS access key id";
    if (starts(v, "ghp_") && run(4, 36, alnum))
        return "a GitHub token";
    if (starts(v, "glpat-"))
        return "a GitLab token";
    if (starts(v, "npm_"))
        return "an npm token";
    if (starts(v, "sk-") && v.size() >= 20)
        return "an OpenAI key";
    if (starts(v, "github_pat_"))
        return "a GitHub token";
    if (starts(v, "xoxb-") || starts(v, "xoxp-") || starts(v, "xoxa-"))
        return "a Slack token";
    if (starts(v, "sk_live_") || starts(v, "rk_live_"))
        return "a Stripe key";
    if (starts(v, "AIza") && v.size() == 39)
        return "a Google API key";
    return nullptr;
}

// ---- names of calls ------------------------------------------------------------

// Code often calls a function through a macro named like it in capitals (OPEN,
// SYSTEM, SNPRINTF: one name for the platforms' different spellings). Macros
// are not expanded, so the capitals stand for the function when it is one this
// file knows.
const std::set<std::string> &known_calls() {
    static const std::set<std::string> known = [] {
        std::set<std::string> k = {
            "system", "popen", "execl", "execlp", "execle", "execv", "execvp",
            "execve", "execvpe", "strcpy", "strcat", "stpcpy", "strncpy", "strncat",
            "memcpy", "memmove", "memset", "sprintf", "vsprintf", "gets", "getwd",
            "mktemp", "tmpnam", "tempnam", "scanf", "fscanf", "sscanf", "access",
            "stat", "lstat", "open", "fopen", "creat", "unlink", "chmod", "fchmod",
            "fchmodat", "umask", "chown", "rename", "truncate", "remove", "rmdir",
            "readlink", "symlink", "getenv", "alloca", "malloc", "strncat"};
        for (const auto &p : kPrintf)
            k.insert(p.first);
        for (const auto &p : kFills)
            k.insert(p.first);
        return k;
    }();
    return known;
}

// A value written in a size: numbers, + - * /, parentheses, sizeof of a type or
// of a local array. Nothing else (a variable, a macro) is a constant here.
class ConstExpr {
  public:
    // fill: the length of the text a local array was filled with (memset)
    ConstExpr(const Toks &t, Range r, const std::map<std::string, long> &arrays,
              const std::map<std::string, std::string> &alias,
              const std::map<std::string, long> &fill)
        : t_(t), i_(r.b), e_(r.e), arrays_(arrays), alias_(alias), fill_(fill) {}

    bool value(long *out) {
        bool ok = true;
        const long v = sum(&ok);
        if (!ok || i_ != e_)
            return false;
        *out = v;
        return true;
    }

  private:
    long sum(bool *ok) {
        long v = product(ok);
        while (*ok && i_ < e_ && (t_[i_].is("+") || t_[i_].is("-"))) {
            const bool plus = t_[i_++].is("+");
            const long r = product(ok);
            v = plus ? v + r : v - r;
        }
        return v;
    }
    long product(bool *ok) {
        long v = atom(ok);
        while (*ok && i_ < e_ && (t_[i_].is("*") || t_[i_].is("/"))) {
            const bool times = t_[i_++].is("*");
            const long r = atom(ok);
            if (!times && r == 0)
                *ok = false;
            else
                v = times ? v * r : v / r;
        }
        return v;
    }
    long atom(bool *ok) {
        if (i_ >= e_) {
            *ok = false;
            return 0;
        }
        const Token &x = t_[i_];
        if (x.kind == Tok::Number) {
            ++i_;
            if (x.text.find_first_of(".eE") != std::string::npos && !starts(x.text, "0x")) {
                *ok = false;
                return 0;
            }
            return strtol(x.text.c_str(), nullptr, 0);
        }
        if (x.is("(")) {
            ++i_;
            const long v = sum(ok);
            if (i_ < e_ && t_[i_].is(")"))
                ++i_;
            else
                *ok = false;
            return v;
        }
        if (x.is("strlen") && i_ + 3 < e_ && t_[i_ + 1].is("(") && t_[i_ + 3].is(")") &&
            t_[i_ + 2].kind == Tok::Ident) {
            std::string n = t_[i_ + 2].text;
            for (int hop = 0; hop < 4 && alias_.count(n) && !alias_.at(n).empty(); ++hop)
                n = alias_.at(n);
            i_ += 4;
            if (auto f = fill_.find(n); f != fill_.end())
                return f->second;
            *ok = false;
            return 0;
        }
        if (x.is("sizeof")) {
            ++i_;
            const bool paren = i_ < e_ && t_[i_].is("(");
            const size_t close = paren ? match(t_, i_) : i_;
            if (paren && close >= e_) {
                *ok = false;
                return 0;
            }
            const size_t b = paren ? i_ + 1 : i_, end = paren ? close : i_ + 1;
            i_ = paren ? close + 1 : i_ + 1;
            return size_of(b, end, ok);
        }
        *ok = false;
        return 0;
    }
    long size_of(size_t b, size_t e, bool *ok) {
        if (e == b + 1 && t_[b].kind == Tok::Ident) {
            std::string n = t_[b].text;
            for (int hop = 0; hop < 4 && alias_.count(n) && !alias_.at(n).empty(); ++hop)
                n = alias_.at(n);
            if (auto a = arrays_.find(n); a != arrays_.end() && a->second != kUnknownSize)
                return a->second;
        }
        bool star = false;
        long size = 0;
        for (size_t k = b; k < e; ++k) {
            const std::string &w = t_[k].text;
            if (w == "*")
                star = true;
            else if (w == "char" || w == "uint8_t" || w == "int8_t" || w == "bool")
                size = std::max(size, 1L);
            else if (w == "short" || w == "uint16_t" || w == "int16_t")
                size = std::max(size, 2L);
            else if (w == "int" || w == "float" || w == "uint32_t" || w == "int32_t" ||
                     w == "wchar_t")
                size = std::max(size, 4L);
            else if (w == "long" || w == "double" || w == "size_t" || w == "uint64_t" ||
                     w == "int64_t")
                size = std::max(size, 8L);
            else if (w != "unsigned" && w != "signed" && w != "const") {
                *ok = false;
                return 0;
            }
        }
        if (star)
            return 8;
        if (!size)
            *ok = false;
        return size;
    }

    const Toks &t_;
    size_t i_, e_;
    const std::map<std::string, long> &arrays_;
    const std::map<std::string, std::string> &alias_;
    const std::map<std::string, long> &fill_;
};

bool const_expr_value(const Toks &t, Range r, long *out) {
    static const std::map<std::string, long> none;
    static const std::map<std::string, std::string> no_alias;
    return ConstExpr(t, r, none, no_alias, none).value(out);
}

std::string call_name(const Toks &t, size_t i) {
    const std::string &n = t[i].text;
    // (not the ones whose capitals are usually a logging macro of the program's own,
    // or that take their format elsewhere: DPRINTF, ERR, WARN)
    static const std::set<std::string> kNoAlias = {
        "dprintf", "err", "errx", "warn", "warnx", "syslog", "asprintf", "read", "remove",
        "link", "rename", "truncate", "symlink", "readlink", "chown", "umask"};
    if (all_caps(n))
        if (std::string l = lower(n); known_calls().count(l) && !kNoAlias.count(l))
            return l;
    return n;
}

// Calls that write n bytes (the size argument) into the buffer argument.
struct Writer {
    const char *name;
    size_t dest, size;
    long extra; // bytes written besides the count (strncat's terminator)
};
constexpr Writer kWriters[] = {{"memcpy", 0, 2, 0}, {"memmove", 0, 2, 0}, {"memset", 0, 2, 0},
                               {"mempcpy", 0, 2, 0}, {"memccpy", 0, 3, 0}, {"bcopy", 1, 2, 0},
                               {"bzero", 0, 1, 0},
                               {"explicit_bzero", 0, 1, 0},
                               {"strncpy", 0, 2, 0}, {"strncat", 0, 2, 1}, {"fgets", 0, 1, 0},
                               {"read", 1, 2, 0}, {"pread", 1, 2, 0}, {"recv", 1, 2, 0},
                               {"recvfrom", 1, 2, 0}, {"getcwd", 0, 1, 0},
                               {"gethostname", 0, 1, 0}, {"getlogin_r", 0, 1, 0},
                               {"ttyname_r", 1, 2, 0},
                               {"readlink", 1, 2, 0}, {"readlinkat", 2, 3, 0},
                               {"strlcpy", 0, 2, 0}, {"strlcat", 0, 2, 0},
                               {"snprintf", 0, 1, 0}, {"vsnprintf", 0, 1, 0},
                               {"gets_s", 0, 1, 0}, {"memcpy_s", 0, 1, 0},
                               {"strcpy_s", 0, 1, 0}, {"strcat_s", 0, 1, 0},
                               {"fgets_unlocked", 0, 1, 0},
                               {"getdomainname", 0, 1, 0}, {"ptsname_r", 1, 2, 0},
                               {"confstr", 1, 2, 0}, {"inet_ntop", 2, 3, 0},
                               {"strxfrm", 0, 2, 0}, {"stpncpy", 0, 2, 0},
                               {"getrandom", 0, 1, 0}, {"getentropy", 0, 1, 0},
                               {"arc4random_buf", 0, 1, 0}, {"strftime", 0, 1, 0}};

// Calls that only read their arguments: a buffer given to one stays as it was.
const std::set<std::string> kReaders = {"strlen", "strcmp", "strncmp", "memcmp", "strchr",
                                        "strrchr", "strstr", "puts", "fputs", "atoi",
                                        "atol", "strcasecmp", "strncasecmp", "access",
                                        "stat", "lstat", "open", "fopen", "unlink",
                                        "system", "popen", "chmod", "free"};

struct Context {
    std::map<std::string, long> arrays;           // local char arrays: size or kUnknownSize
    std::map<std::string, std::string> alias;     // "p = buf": p stands for buf
    std::set<std::string> constant;               // hold only string literals
    std::set<std::string> taint;                  // hold text from outside
    std::set<std::string> outside_size;          // hold a size taken from that text
    std::set<std::string> slash;                 // hold a path that contains '/'
    std::set<std::string> joined;                // that path with outside text appended
    std::map<std::string, long> fill;             // array -> length of the text memset put in
    std::set<std::string> params;                 // the function's own parameters
    std::map<std::string, size_t> param_index;    // parameter name -> position
    // For each name that holds text from outside: where that text entered the
    // program (the report shows it as the route, see route below).
    std::map<std::string, FlowStep> origin;
    std::map<std::string, std::string> size_text; // array -> its size as written
    std::set<std::string> crypto_seen;            // algorithms already reported in this function
    std::set<std::string> format_seen;            // formats already reported in this function
    std::set<std::string> sql_seen;
    std::set<std::string> prng_seen;
    std::set<std::string> ssrf_seen;
    std::set<std::string> xss_seen;
    std::set<std::string> off_by_one_seen;
    std::set<std::string> int_overflow_seen;
    std::map<std::string, size_t> null_ptrs; // pointer name -> assignment token index
    std::set<std::string> null_reported;
    std::set<std::string> pointers;

    // Can `src`, a string held in a local array, not overflow the local array `dest`:
    // both sizes are known and dest is the bigger, or both are written the same way?
    bool fits(const std::string &dest, const std::string &src) const {
        auto d = arrays.find(dest), s = arrays.find(src);
        if (d == arrays.end() || s == arrays.end())
            return false;
        if (d->second != kUnknownSize && s->second != kUnknownSize)
            return d->second >= s->second;
        auto dt = size_text.find(dest), st = size_text.find(src);
        return dt != size_text.end() && st != size_text.end() && dt->second == st->second &&
               dt->second.rfind("?", 0) != 0;
    }
    struct Check {
        size_t at;
        std::string fn;
        bool weak; // stat(): a read-only use afterwards is ordinary
        bool reported = false;
    };
    std::map<std::string, Check> checked;         // path -> the access()/stat() that looked at it

    std::string root(std::string n) const {
        for (int hop = 0; hop < 4; ++hop) {
            auto it = alias.find(n);
            if (it == alias.end() || it->second.empty())
                break;
            n = it->second;
        }
        return n;
    }
};

// Does the open() flags / fopen() mode argument ask to write?
// /proc/<digits>/mem, not /proc/self. `tail` includes the slash.
bool proc_pid(const std::string &p, const char *tail) {
    if (!starts(p, "/proc/"))
        return false;
    size_t i = 6;
    if (i >= p.size() || !std::isdigit(static_cast<unsigned char>(p[i])))
        return false;
    while (i < p.size() && std::isdigit(static_cast<unsigned char>(p[i])))
        ++i;
    return p.compare(i, std::string::npos, tail) == 0;
}

// Runtime kSecrets entries that are not already rows in the command table.
bool stored_secret(const std::string &p) {
    if (p == "/etc/gshadow")
        return true;
    static const char *tails[] = {"/.docker/config.json", "/.git-credentials", "/.kube/config",
                                  "/logins.json", "/key4.db", "/cookies.sqlite", "/Login Data",
                                  "/wallet.dat"};
    for (const char *t : tails)
        if (ends_text(p, t))
            return true;
    return p.find("/.gnupg/") != std::string::npos || p.find("/.config/gcloud/") != std::string::npos ||
           p.find("/.azure/") != std::string::npos || p.find("/.electrum/") != std::string::npos;
}

// Runtime kStartup entries. ld.so.preload and /etc/shadow are already command rows.
bool startup_file(const std::string &p) {
    if (p == "/etc/crontab" || p == "/etc/rc.local" || p == "/etc/profile" ||
        p == "/etc/ld.so.conf" || p == "/etc/passwd")
        return true;
    if (starts(p, "/etc/sudoers") || starts(p, "/etc/cron.") || starts(p, "/etc/init.d/") ||
        starts(p, "/etc/systemd/system/") || starts(p, "/var/spool/cron/") ||
        starts(p, "/etc/pam.d/") || starts(p, "/etc/xdg/autostart/"))
        return true;
    return ends(p, "/.bashrc") || ends(p, "/.profile") || ends(p, "/.zshrc") ||
           ends(p, "/.ssh/authorized_keys");
}

// A mount target the dynamic check treats as a system program or directory.
bool system_mount_target(const std::string &p) {
    if (starts(p, "/usr/local/") || starts(p, "/usr/share/") || starts(p, "/usr/include/") ||
        starts(p, "/usr/src/") || starts(p, "/opt/") || starts(p, "/snap/") ||
        starts(p, "/nix/"))
        return false;
    return starts(p, "/bin/") || starts(p, "/sbin/") || starts(p, "/usr/") ||
           starts(p, "/lib/") || starts(p, "/lib32/") || starts(p, "/lib64/") ||
           starts(p, "/boot/");
}

bool opens_for_writing(const Toks &t, const std::string &name, Range flags) {
    if (name == "creat" || name == "creat64")
        return true;
    if (name == "fopen" || name == "fopen64" || name == "freopen" || name == "freopen64") {
        std::string mode;
        return literal(t, flags, &mode) && (mode.find_first_of("wa+") != std::string::npos);
    }
    for (size_t k = flags.b; k < flags.e; ++k)
        if (t[k].is("O_WRONLY") || t[k].is("O_RDWR") || t[k].is("O_CREAT") ||
            t[k].is("O_TRUNC") || t[k].is("O_APPEND"))
            return true;
    return false;
}

class Checker {
  public:
    Checker(const Toks &t, const std::vector<Function> &fns, TaintDb *db)
        : t_(t), fns_(fns), db_(db) {}

    std::vector<Issue> run() {
        index_lines();
        const std::set<std::string> literals = literal_names(t_);
        globals_ = file_scope_names(t_);
        for (const Function &f : fns_) {
            names_.insert(f.name);
            if (is_static(f))
                static_.insert(f.name);
        }
        compute_modifies();
        // What the calls of the file pass to each function, and what is put in
        // file-scope variables, decides how the next pass reads those functions'
        // parameters and variables. Only the last pass reports.
        for (int pass = 0; pass < 3; ++pass) {
            emit_ = pass == 2;
            next_.clear();
            for (const Function &f : fns_)
                function(f, literals);
            params_ = std::move(next_);
        }
        // One more read for the other files: what each parameter of each
        // function reaches here, treating every parameter as text from outside
        // (in another file the caller is what decides). Nothing is reported
        // from this pass; it only fills the facts resolve_taint() uses.
        if (db_) {
            export_pass_ = true;
            emit_ = false;
            params_.clear();
            next_.clear();
            // Only a function another file can call needs this: what a static
            // one is given is decided by its calls in this file, which the
            // reporting pass already follows.
            for (const Function &f : fns_)
                if (!f.params.empty() && !static_.count(f.name) && calls_a_sink(f))
                    function(f, literals);
            export_pass_ = false;
            emit_ = true;
        }
        secrets();
        std::stable_sort(out_.begin(), out_.end(), [](const Issue &a, const Issue &b) {
            return a.line < b.line;
        });
        return std::move(out_);
    }

  private:
    // What the calls in this file pass for one parameter.
    struct Param {
        bool tainted = false; // some call passes text from outside
        bool unknown = false; // some call passes something else than a literal
        int calls = 0;
    };

    // First token on or after each line. Walking from token 0 per function
    // was most of a static run.
    void index_lines() {
        int maxl = 1;
        for (const Token &tok : t_)
            if (tok.line > maxl)
                maxl = tok.line;
        line_tok_.assign(size_t(maxl) + 2, t_.size());
        for (size_t i = 0; i < t_.size(); ++i) {
            size_t &slot = line_tok_[size_t(t_[i].line)];
            if (slot == t_.size())
                slot = i;
        }
        for (size_t L = line_tok_.size() - 1; L-- > 0;)
            if (line_tok_[L] == t_.size())
                line_tok_[L] = line_tok_[L + 1];
    }

    size_t at_line(int line) const {
        return line > 0 && size_t(line) < line_tok_.size() ? line_tok_[size_t(line)]
                                                           : t_.size();
    }

    // Cheap gate for the pass that reads for other files: a function that
    // never calls anything on this list cannot have a parameter that reaches a
    // dangerous call, so re-reading it would only cost time.
    bool calls_a_sink(const Function &f) const {
        static const std::set<std::string> kSinkCalls = {
            "system", "popen", "_popen", "wordexp", "WinExec", "CreateProcess",
            "CreateProcessA", "CreateProcessW", "ShellExecute", "ShellExecuteA",
            "ShellExecuteW", "posix_spawn", "posix_spawnp", "dlopen", "dlmopen",
            "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA",
            "LoadLibraryExW", "open", "open64", "openat", "openat64", "fopen",
            "fopen64", "freopen", "freopen64", "creat", "realpath",
            "canonicalize_file_name", "alloca", "__builtin_alloca", "mysql_query",
            "sqlite3_exec", "PQexec", "PQexecParams", "strcpy", "strcat",
            "strncpy", "strncat", "stpcpy", "memcpy", "memmove", "sprintf",
            "snprintf", "asprintf", "vasprintf", "printf", "fprintf", "vprintf",
            "vfprintf", "syslog", "vsyslog", "setenv", "putenv"};
        const Range body = body_of(f);
        for (size_t i = body.b; i < body.e; ++i)
            if (t_[i].kind == Tok::Ident &&
                (kSinkCalls.count(t_[i].text) || t_[i].text.rfind("exec", 0) == 0))
                return true;
        return false;
    }

    bool is_static(const Function &f) const {
        const size_t end = at_line(f.line + 1);
        for (size_t i = at_line(f.line); i < end && i + 1 < t_.size(); ++i)
            if (t_[i].text == f.name && t_[i + 1].is("(")) {
                for (size_t k = i; k-- > 0 && !t_[k].is(";") && !t_[k].is("}") &&
                                   !t_[k].is("{");)
                    if (t_[k].is("static"))
                        return true;
                return false;
            }
        return false;
    }

    // Parameter names, in order ("char *data, int n" -> data, n).
    static std::vector<std::string> param_names(const Function &f) {
        std::vector<std::string> out;
        std::string last;
        int depth = 0;
        bool value = false;
        for (const Token &p : f.params) {
            if (p.is("(") || p.is("[") || p.is("<"))
                ++depth;
            else if (p.is(")") || p.is("]") || p.is(">"))
                --depth;
            else if (depth == 0 && p.is(",")) {
                out.push_back(last);
                last.clear();
                value = false;
            } else if (depth == 0 && p.is("="))
                value = true;
            else if (depth == 0 && !value && p.kind == Tok::Ident)
                last = p.text;
        }
        out.push_back(last);
        return out;
    }

    // Index of the buffer a call fills or copies into; -1 if it does not.
    static int written_arg(const std::string &name, size_t nargs) {
        static const std::set<std::string> kFirst = {
            "strcpy", "strncpy", "strcat", "strncat", "stpcpy", "memcpy", "memmove",
            "memset", "sprintf", "snprintf", "vsprintf", "fgets", "gets", "fread",
            "getline", "getdelim"};
        if (kFirst.count(name))
            return 0;
        if (name == "read" || name == "pread" || name == "recv" || name == "recvfrom")
            return nargs > 1 ? 1 : -1;
        return -1;
    }

    // Which parameters of the functions of this file are written through
    // (strcpy(p, ...), fgets(p, ...), p[i] = ..., or handed to a function that
    // does). A buffer given to a function that never writes through its
    // parameter is still what it was.
    void compute_modifies() {
        for (int round = 0; round < 3; ++round)
            for (const Function &f : fns_) {
                const std::vector<std::string> names = param_names(f);
                const Range body = body_of(f);
                auto note = [&](const std::string &base) {
                    for (size_t j = 0; j < names.size(); ++j)
                        if (!base.empty() && base == names[j])
                            modifies_[f.name].insert(j);
                };
                for (size_t i = body.b; i < body.e; ++i) {
                    if (t_[i].is("=") && !member(t_, i) && i > body.b) {
                        const size_t n = assigned(i, body);
                        if (n != t_.size() && (t_[i - 1].is("]") || (n > 0 && t_[n - 1].is("*"))))
                            note(t_[n].text); // p[i] = x;  *p = x;
                        continue;
                    }
                    if (!is_call(t_, i))
                        continue;
                    const size_t close = match(t_, i + 1);
                    if (close >= body.e)
                        continue;
                    const std::string name = call_name(t_, i);
                    const std::vector<Range> a = args_of(t_, i + 1, close);
                    if (const int w = written_arg(name, a.size()); w >= 0 && size_t(w) < a.size())
                        note(base_name(t_, a[size_t(w)]));
                    if (name == "scanf" || name == "fscanf" || name == "sscanf")
                        for (size_t k = name == "scanf" ? 1 : 2; k < a.size(); ++k)
                            note(base_name(t_, a[k]));
                    if (auto m = modifies_.find(name); m != modifies_.end() && name != f.name)
                        for (size_t k : m->second)
                            if (k < a.size())
                                note(base_name(t_, a[k]));
                }
            }
    }

    bool callee_writes(const std::string &name, size_t k) const {
        auto m = modifies_.find(name);
        return m != modifies_.end() && m->second.count(k);
    }

    // Where the text in `r` entered the program, if it is known: a name that
    // was already tainted (its origin is remembered), argv, or a call that
    // reads text from outside.
    FlowStep source_of(const Context &c, Range r) const {
        for (size_t k = r.b; k < r.e; ++k) {
            if (is_call(t_, k)) {
                const std::string n = call_name(t_, k);
                if (kSources.count(n))
                    return FlowStep{n + "()", cur_fn_, t_[k].line, t_[k].col};
                if (kSafe.count(n) || !passes_text(n)) {
                    // What it returns is not its argument: skip its own.
                    k = std::min(match(t_, k + 1), r.e);
                    continue;
                }
                continue; // strdup(), strchr(), ...: look inside
            }
            if (t_[k].kind != Tok::Ident || member(t_, k))
                continue;
            // A parameter is a place text from outside can come from: the
            // caller decides. (For an edge, wherever it is used here.)
            if (auto it = c.param_index.find(t_[k].text); it != c.param_index.end())
                return FlowStep{t_[k].text, cur_fn_, t_[k].line, t_[k].col,
                                int(it->second)};
            if (t_[k].is("argv"))
                return FlowStep{"argv", cur_fn_, t_[k].line, t_[k].col};
            if (auto it = c.origin.find(t_[k].text); it != c.origin.end())
                return it->second;
        }
        return {};
    }

    // The route from where `r`'s text entered the program to the call `call`
    // at `at`: two steps, or none when the source is not known.
    std::vector<FlowStep> route(const Context &c, Range r, size_t at,
                                const std::string &call) const {
        std::vector<FlowStep> out;
        FlowStep from = source_of(c, r);
        if (from.what.empty())
            return out;
        out.push_back(std::move(from));
        out.push_back(FlowStep{call + "()", cur_fn_, t_[at].line, t_[at].col});
        return out;
    }

    // `name` holds text from outside; if it is a variable of the whole file,
    // so it does in every function.
    void taint_name(Context *c, const std::string &name, FlowStep from = {}) {
        c->taint.insert(name);
        if (!from.what.empty())
            c->origin.emplace(name, std::move(from));
        if (globals_.count(name) && !c->arrays.count(name) && !c->params.count(name))
            global_taint_.insert(name);
    }

    // `name` is a directory path (`append` is += / strcat; otherwise the whole
    // value is replaced). Outside text joined onto a '/' makes it dangerous.
    void note_join(Context *c, const std::string &name, Range r, bool append) {
        if (name.empty())
            return;
        const std::string n = c->root(name);
        const bool lit = slash_in(t_, r);
        const bool out = tainted(t_, r, c->taint);
        const bool onto = lit || (append && (c->slash.count(n) || c->joined.count(n)));
        if (!append) {
            c->joined.erase(n);
            c->slash.erase(n);
        }
        if (out && onto)
            c->joined.insert(n);
        else if (!out && lit)
            c->slash.insert(n);
    }

    std::string path_name(Range r) const {
        if (std::string b = base_name(t_, r); !b.empty())
            return b;
        if (r.b < r.e && t_[r.b].kind == Tok::Ident && !member(t_, r.b))
            return t_[r.b].text; // path.c_str()
        return {};
    }

    // A parameter of a function of this file reaching a dangerous call: the
    // fact another file needs to report the call that feeds it.
    void note_export(const std::vector<FlowStep> &flow, const char *rule) {
        if (!db_ || flow.size() < 2 || flow.front().param < 0 ||
            !is_taint_rule(rule))
            return;
        const FlowStep &from = flow.front();
        std::string call = flow.back().what;
        if (call.size() > 2 && call.compare(call.size() - 2, 2, "()") == 0)
            call.resize(call.size() - 2);
        db_->sinks.push_back(TaintSink{from.function, size_t(from.param), rule, call,
                                       cur_fn_, std::string(), flow.back().line});
    }

    // Rules that are about text from outside: for those, the route the text
    // took is part of the finding.
    static bool is_taint_rule(const std::string &rule) {
        return rule == "command-injection" || rule == "path-traversal" ||
               rule == "sql-injection" || rule == "format-string" ||
               rule == "unbounded-copy" || rule == "unbounded-alloca" ||
               rule == "process-injection";
    }

    void issue(const char *rule, std::string message, const std::string &fn,
               size_t at, int related = 0,
               std::vector<FlowStep> flow = {}) {
        // A rule about outside text, reported at the call its route ends at:
        // the route is the one call() worked out for this call's arguments.
        if (flow.empty() && at == call_at_ && is_taint_rule(rule))
            flow = call_flow_;
        if (export_pass_) {
            note_export(flow, rule);
            return;
        }
        if (!emit_)
            return;
        Issue is;
        is.rule = rule;
        is.message = std::move(message);
        is.function = fn;
        is.line = t_[at].line;
        is.col = t_[at].col;
        is.alloc_line = related;
        note_export(flow, rule);
        is.flow = std::move(flow);
        out_.push_back(std::move(is));
    }

    Range body_of(const Function &f) const {
        size_t b = at_line(f.line);
        size_t e = at_line(f.end_line + 1);
        // (from the opening brace: the name and the parameters are not calls)
        while (b < e && !t_[b].is("{"))
            ++b;
        return {b, e};
    }

    std::string function_at(int line) const {
        for (const Function &f : fns_)
            if (line >= f.line && line <= f.end_line)
                return f.name;
        return {};
    }

    // The name on the left of the '=' at `eq` ("p", "buf[0]" -> "buf").
    size_t assigned(size_t eq, Range body) const {
        if (eq <= body.b)
            return t_.size();
        size_t n = eq - 1;
        if (t_[n].is("]")) {
            while (n > body.b && !t_[n].is("["))
                --n;
            if (n == body.b)
                return t_.size();
            --n;
        }
        return t_[n].kind == Tok::Ident && !member(t_, n) ? n : t_.size();
    }

    // The right side of the assignment at `eq`: up to ; or , outside brackets.
    Range right_of(size_t eq, Range body) const {
        size_t e = eq + 1;
        for (int depth = 0; e < body.e; ++e) {
            if (t_[e].is("(") || t_[e].is("[") || t_[e].is("{"))
                ++depth;
            else if (t_[e].is(")") || t_[e].is("]") || t_[e].is("}")) {
                if (--depth < 0)
                    break;
            } else if (depth == 0 && (t_[e].is(";") || t_[e].is(",")))
                break;
        }
        return {eq + 1, e};
    }

    // Which names stand for a local array, and which hold only literals.
    void prepare(Range body, const std::set<std::string> &file_literals, Context *c) {
        c->arrays = local_arrays(t_, body, &c->size_text);
        // p = alloca(50);  p = malloc(50);  are buffers of that size too
        for (size_t i = body.b; i < body.e; ++i) {
            if (!t_[i].is("=") || member(t_, i))
                continue;
            const size_t n = assigned(i, body);
            if (n == t_.size())
                continue;
            const Range r = right_of(i, body);
            for (size_t k = r.b; k < r.e; ++k) {
                if (!is_call(t_, k))
                    continue;
                const std::string fn = call_name(t_, k);
                if (fn != "alloca" && fn != "malloc")
                    break;
                const size_t close = match(t_, k + 1);
                long bytes = 0;
                if (close <= r.e &&
                    ConstExpr(t_, {k + 2, close}, c->arrays, c->alias, c->fill).value(&bytes)) {
                    auto [it, fresh] = c->arrays.emplace(t_[n].text, bytes);
                    if (!fresh && it->second != bytes)
                        it->second = kUnknownSize; // two sizes: not known
                }
                break;
            }
        }
        // p = buf; char *p = buf;
        for (size_t i = body.b; i < body.e; ++i) {
            if (!t_[i].is("=") || member(t_, i))
                continue;
            const size_t n = assigned(i, body);
            if (n == t_.size())
                continue;
            const Range r = right_of(i, body);
            size_t k = r.b;
            if (k < r.e && t_[k].is("&"))
                ++k;
            if (k < r.e && t_[k].kind == Tok::Ident &&
                (c->arrays.count(t_[k].text) ||
                 (c->alias.count(t_[k].text) && !c->alias.at(t_[k].text).empty())) &&
                (k + 1 == r.e || (t_[k + 1].is("[") && t_[k + 2].is("0")))) {
                auto [it, fresh] = c->alias.emplace(t_[n].text, t_[k].text);
                if (!fresh && it->second != t_[k].text)
                    it->second.clear(); // two different buffers: not known
            }
        }
        // memset(buf, 'A', 99): the array holds a string of that length
        for (size_t i = body.b; i < body.e; ++i)
            if (is_call(t_, i) && call_name(t_, i) == "memset") {
                const size_t close = match(t_, i + 1);
                const std::vector<Range> a = args_of(t_, i + 1, close);
                long n = 0;
                if (close < body.e && a.size() == 3 &&
                    ConstExpr(t_, a[2], c->arrays, c->alias, c->fill).value(&n)) {
                    const std::string d = c->root(base_name(t_, a[0]));
                    if (c->arrays.count(d))
                        c->fill.emplace(d, n);
                }
            }
        // literal or something else, per name (through aliases)
        std::map<std::string, std::pair<int, int>> use; // name -> literal, other
        auto mark = [&](const std::string &name, bool lit) {
            (lit ? use[c->root(name)].first : use[c->root(name)].second)++;
        };
        for (size_t i = body.b; i < body.e; ++i) {
            if (t_[i].is("=") && !member(t_, i)) {
                const size_t n = assigned(i, body);
                if (n == t_.size())
                    continue;
                const Range r = right_of(i, body);
                std::string ignored;
                if (c->alias.count(t_[n].text) && r.e == r.b + 1 + (t_[r.b].is("&") ? 1 : 0) &&
                    (c->arrays.count(t_[r.e - 1].text) || c->alias.count(t_[r.e - 1].text)))
                    continue; // p = buf
                mark(t_[n].text, literal(t_, r, &ignored) || t_[r.b].is("{"));
                continue;
            }
            if (!is_call(t_, i))
                continue;
            const size_t close = match(t_, i + 1);
            if (close >= body.e)
                continue;
            const std::string name = call_name(t_, i);
            const std::vector<Range> a = args_of(t_, i + 1, close);
            std::string ignored;
            for (size_t k = 0; k < a.size(); ++k) {
                const std::string b = base_name(t_, a[k]);
                if (b.empty())
                    continue;
                bool lit = false;
                if (k == 0 && (name == "strcpy" || name == "strncpy" || name == "strcat" ||
                               name == "strncat" || name == "stpcpy") && a.size() >= 2)
                    lit = literal(t_, a[1], &ignored);
                else if (k == 0 && name == "memset")
                    lit = true;
                else if (k == 0 && name == "sprintf" && a.size() == 2)
                    lit = literal(t_, a[1], &ignored);
                else if (k == 0 && name == "snprintf" && a.size() == 3)
                    lit = literal(t_, a[2], &ignored);
                else if (kPrintf.count(name) || kReaders.count(name) ||
                         (names_.count(name) && !callee_writes(name, k)))
                    continue; // only reads it
                mark(b, lit);
            }
        }
        for (const auto &[name, n] : use)
            if (n.first && !n.second)
                c->constant.insert(name);
        for (size_t k = body.b; k + 1 < body.e; ++k)
            if (t_[k].is("*") && k + 1 < body.e && t_[k + 1].kind == Tok::Ident && !member(t_, k))
                c->pointers.insert(t_[k + 1].text);
        (void)file_literals;
    }

    void function(const Function &f, const std::set<std::string> &literals) {
        const Range body = body_of(f);
        Context c;
        cur_fn_ = f.name;
        prepare(body, literals, &c);
        for (const Token &p : f.params) {
            if (p.is("argv")) {
                c.taint.insert("argv");
                c.origin.emplace("argv",
                                 FlowStep{"argv", f.name, p.line, p.col});
            }
            if (p.kind == Tok::Ident)
                c.pointers.insert(p.text);
        }
        c.taint.insert(global_taint_.begin(), global_taint_.end());
        const std::vector<std::string> names = param_names(f);
        for (size_t k = 0; k < names.size(); ++k) {
            if (names[k].empty())
                continue;
            c.params.insert(names[k]);
            c.param_index[names[k]] = k;
            auto it = params_.find(f.name);
            if (it == params_.end() || k >= it->second.size())
                continue;
            const Param &p = it->second[k];
            if (p.tainted) {
                c.taint.insert(names[k]);
                // The route starts at the caller: the crossing into this
                // function is the step, and note_export() reports it onward.
                c.origin.emplace(names[k],
                                 FlowStep{names[k], f.name, f.line, 0, int(k)});
            } else if (p.calls > 0 && !p.unknown && static_.count(f.name))
                c.constant.insert(names[k]); // every call passes a literal
        }
        if (export_pass_)
            for (size_t k = 0; k < names.size(); ++k) {
                if (names[k].empty())
                    continue;
                c.params.insert(names[k]);
                c.taint.insert(names[k]);
                c.origin[names[k]] =
                    FlowStep{names[k], f.name, f.line, 0, int(k)};
            }
        bool sized_stream = false; // setw() or width() was called on the stream
        std::set<std::string> hosts; // look-alike hosts already reported in this function
        std::set<const char *> cmds; // command-line rules already reported here
        for (size_t i = body.b; i < body.e; ++i) {
            sized_stream |= t_[i].is("setw") || t_[i].is("width");
            // A string written in the source. The file scanner sees the same
            // bytes only after the program is compiled.
            if (t_[i].kind == Tok::String) {
                std::string lit;
                if (literal(t_, {i, i + 1}, &lit)) {
                    auto report = [&](const std::string &host) {
                        if (const char *t = lcrules::imitates(host.c_str()))
                            if (hosts.insert(host).second)
                                issue("masquerade",
                                      "the host name \"" + host + "\" is made to look like " +
                                          t + ": malware names its servers after the sites you trust",
                                      f.name, i);
                    };
                    bool url = false;
                    for (size_t at = 0; (at = lit.find("://", at)) != std::string::npos; at += 3) {
                        url = true;
                        const size_t b = at + 3;
                        size_t e = b;
                        while (e < lit.size() && lit[e] != '/' && lit[e] != '?' && lit[e] != '#' &&
                               lit[e] != ' ')
                            ++e;
                        std::string host = lit.substr(b, e - b);
                        if (const size_t amp = host.rfind('@'); amp != std::string::npos)
                            host = host.substr(amp + 1);
                        report(host);
                    }
                    if (!url && lit.find(' ') == std::string::npos &&
                        lit.find('.') != std::string::npos && lit.find('/') == std::string::npos)
                        report(lit);
                    // "Authorization: Basic <token>" written into the program.
                    {
                        std::string low = lit;
                        for (char &c : low)
                            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                        for (const char *mark : {"authorization: basic ", "authorization: bearer "}) {
                            const size_t at = low.find(mark);
                            if (at != std::string::npos &&
                                low.size() > at + std::strlen(mark) + 3 &&
                                hosts.insert(std::string("auth|") + mark).second) {
                                issue("hardcoded-secret",
                                      "an Authorization header contains a credential: it is "
                                      "known to everyone who has the binary; read it from "
                                      "the environment",
                                      f.name, i);
                                break;
                            }
                        }
                    }
                    // scheme://user:password@host. The password is not a separate argument.
                    if (const size_t scheme = lit.find("://"); scheme != std::string::npos) {
                        const size_t colon = lit.find(':', scheme + 3);
                        const size_t amp = lit.find('@', scheme + 3);
                        if (colon != std::string::npos && amp != std::string::npos && colon < amp &&
                            amp - colon > 1 && hosts.insert("pw|" + lit).second)
                            issue("hardcoded-secret",
                                  "a URL contains a password: a credential written into the "
                                  "program is known to everyone who has the binary; read it "
                                  "from the environment",
                                  f.name, i);
                    }
                    // The same command rows the file scanner matches in a binary.
                    if (lit.find_first_of(" /|;") != std::string::npos) {
                        char norm[1024];
                        lcrules::normalize(lit.c_str(), norm, sizeof norm);
                        for (const lcrules::Cmd &cmd : lcrules::kCmds)
                            if (lcrules::has_all(norm, cmd) && cmds.insert(cmd.what).second)
                                issue(cmd.type,
                                      std::string("a command line ") + cmd.what,
                                      f.name, i);
                        // Windows commands are case-blind, as in the file scanner.
                        char low[sizeof norm];
                        size_t li = 0;
                        for (; norm[li]; ++li)
                            low[li] = norm[li] >= 'A' && norm[li] <= 'Z' ? char(norm[li] | 0x20)
                                                                        : norm[li];
                        low[li] = 0;
                        for (const lcrules::Cmd &cmd : lcrules::kWinCmds)
                            if (lcrules::has_all(low, cmd) && cmds.insert(cmd.what).second)
                                issue(cmd.type,
                                      std::string("a command line ") + cmd.what,
                                      f.name, i);
                        if (lcrules::downloads_into_interpreter(norm) &&
                            cmds.insert("download").second)
                            issue("dropper",
                                  "a command line downloads or decodes code and runs it at once",
                                  f.name, i);
                    }
                }
            }
            // std::cin >> word;  reads a word of any length into a char array
            if (t_[i].is(">>") && i > body.b && t_[i - 1].is("cin") && i + 1 < body.e &&
                t_[i + 1].kind == Tok::Ident && !sized_stream &&
                c.arrays.count(c.root(t_[i + 1].text)))
                issue("unsafe-function",
                      "cin >> " + t_[i + 1].text + " reads a word of any length into the "
                      "array, which holds " + std::to_string(c.arrays.at(c.root(t_[i + 1].text))) +
                      " bytes: set a width first with cin.width(n) or setw(n), or read "
                      "into a std::string",
                      f.name, i);
            if (t_[i].is("=") && !member(t_, i))
                assignment(f, i, body, &c);
            if (t_[i].is("+=") && !member(t_, i)) {
                const size_t n = assigned(i, body);
                if (n != t_.size())
                    note_join(&c, t_[n].text, right_of(i, body), true);
            }

            // -- null-dereference: dereferencing a pointer known to be NULL
            if (t_[i].is("*") && i + 1 < body.e && t_[i + 1].kind == Tok::Ident && !member(t_, i)) {
                const bool is_decl = i > body.b && (t_[i - 1].is("char") || t_[i - 1].is("int") ||
                                                   t_[i - 1].is("void") || t_[i - 1].is("struct") ||
                                                   t_[i - 1].is("const") || t_[i - 1].is("unsigned") ||
                                                   t_[i - 1].is("signed") || t_[i - 1].is("long") ||
                                                   t_[i - 1].is("auto") || t_[i - 1].is(","));
                if (!is_decl) {
                    const std::string &pname = t_[i + 1].text;
                    if (c.null_ptrs.count(pname) && c.null_reported.insert(pname).second) {
                        issue("null-dereference",
                              "'" + pname + "' is dereferenced at line " + std::to_string(t_[i].line) +
                                  " after being set to NULL at line " +
                                  std::to_string(t_[c.null_ptrs.at(pname)].line) +
                                  ": dereferencing a NULL pointer leads to an immediate crash (SIGSEGV)",
                              f.name, i);
                    }
                }
            }
            if (t_[i].kind == Tok::Ident && i + 1 < body.e && t_[i + 1].is("->")) {
                const std::string &pname = t_[i].text;
                if (c.null_ptrs.count(pname) && c.null_reported.insert(pname).second) {
                    issue("null-dereference",
                          "'" + pname + "' is dereferenced at line " + std::to_string(t_[i].line) +
                              " via -> after being set to NULL at line " +
                              std::to_string(t_[c.null_ptrs.at(pname)].line) +
                              ": dereferencing a NULL pointer leads to an immediate crash (SIGSEGV)",
                          f.name, i);
                }
            }
            if (t_[i].kind == Tok::Ident && i + 1 < body.e && t_[i + 1].is("[")) {
                const std::string &pname = t_[i].text;
                if (c.null_ptrs.count(pname) && c.null_reported.insert(pname).second) {
                    issue("null-dereference",
                          "'" + pname + "' is indexed at line " + std::to_string(t_[i].line) +
                              " after being set to NULL at line " +
                              std::to_string(t_[c.null_ptrs.at(pname)].line) +
                              ": dereferencing a NULL pointer leads to an immediate crash (SIGSEGV)",
                          f.name, i);
                }
            }
            if (t_[i].is("if") && i + 1 < body.e && t_[i + 1].is("(")) {
                const size_t cond_close = match(t_, i + 1);
                if (cond_close < body.e) {
                    std::string null_pname;
                    if (cond_close == i + 4 && t_[i + 2].is("!") && t_[i + 3].kind == Tok::Ident) {
                        null_pname = t_[i + 3].text;
                    } else if (cond_close == i + 5 && t_[i + 2].kind == Tok::Ident && t_[i + 3].is("==") &&
                               (t_[i + 4].is("NULL") || t_[i + 4].is("nullptr") || t_[i + 4].is("0"))) {
                        null_pname = t_[i + 2].text;
                    }
                    if (!null_pname.empty() && cond_close + 1 < body.e && t_[cond_close + 1].is("{")) {
                        const size_t block_close = match(t_, cond_close + 1);
                        if (block_close <= body.e) {
                            for (size_t k = cond_close + 2; k < block_close; ++k) {
                                bool deref = false;
                                if (t_[k].is("*") && k + 1 < block_close && t_[k + 1].text == null_pname &&
                                    !member(t_, k))
                                    deref = true;
                                if (t_[k].text == null_pname && k + 1 < block_close &&
                                    (t_[k + 1].is("->") || t_[k + 1].is("[")))
                                    deref = true;
                                if (deref && c.null_reported.insert(null_pname + "_" + std::to_string(t_[k].line)).second) {
                                    issue("null-dereference",
                                          "'" + null_pname + "' is dereferenced inside a branch that verified it is NULL at line " +
                                              std::to_string(t_[i].line) + ": dereferencing a NULL pointer leads to an immediate crash",
                                          f.name, k);
                                    break;
                                }
                            }
                        }
                    }
                    for (size_t k = i + 2; k + 1 < cond_close; ++k) {
                        if (t_[k].is("+")) {
                            const bool bad_l = t_[k - 1].kind == Tok::Ident &&
                                               (c.taint.count(t_[k - 1].text) || c.outside_size.count(t_[k - 1].text));
                            const bool bad_r = t_[k + 1].kind == Tok::Ident &&
                                               (c.taint.count(t_[k + 1].text) || c.outside_size.count(t_[k + 1].text));
                            if (bad_l || bad_r) {
                                for (size_t cmp = k + 2; cmp < cond_close; ++cmp) {
                                    if (t_[cmp].is(">") || t_[cmp].is(">=") || t_[cmp].is("<") || t_[cmp].is("<=")) {
                                        if (c.int_overflow_seen.insert(std::to_string(t_[k].line) + "_add").second) {
                                            issue("integer-overflow",
                                                  "condition '" + show(t_, {i + 2, cond_close}) +
                                                      "' adds untrusted values: the sum can overflow and wrap around, "
                                                      "bypassing bounds checks; verify bounds before addition (e.g. 'a > max - b')",
                                                  f.name, k);
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // -- off-by-one: array indexed at capacity or sizeof
            if (t_[i].kind == Tok::Ident && i + 1 < body.e && t_[i + 1].is("[")) {
                bool is_array_decl = false;
                size_t stmt_start = i;
                while (stmt_start > body.b && !t_[stmt_start - 1].is(";") &&
                       !t_[stmt_start - 1].is("{") && !t_[stmt_start - 1].is("}"))
                    --stmt_start;
                bool has_eq = false;
                for (size_t s = stmt_start; s < i; ++s)
                    if (t_[s].is("="))
                        has_eq = true;
                if (!has_eq) {
                    for (size_t s = stmt_start; s < i; ++s) {
                        if (element_size(t_[s].text) > 0 || t_[s].is("struct") || t_[s].is("const") ||
                            t_[s].is("unsigned") || t_[s].is("signed") || t_[s].is("static") ||
                            t_[s].is("auto") || t_[s].is("typedef") || t_[s].is("extern")) {
                            is_array_decl = true;
                            break;
                        }
                    }
                }
                const size_t close = match(t_, i + 1);
                if (!is_array_decl && close < body.e) {
                    const std::string arr = c.root(t_[i].text);
                    if (c.arrays.count(arr)) {
                        const long cap = c.arrays.at(arr);
                        if (cap > 0) {
                            const Range idx = {i + 2, close};
                            bool is_sizeof = false;
                            if (t_[i + 2].is("sizeof")) {
                                size_t at = i + 3;
                                if (at < close && t_[at].is("(")) ++at;
                                if (at < close && t_[at].text == t_[i].text) {
                                    size_t aft = at + 1;
                                    if (aft < close && t_[aft].is(")")) ++aft;
                                    if (aft == close)
                                        is_sizeof = true;
                                }
                            }
                            long val = -1;
                            if (is_sizeof) {
                                if (c.off_by_one_seen.insert(arr + "_" + std::to_string(t_[i].line)).second) {
                                    issue("off-by-one",
                                          "'" + t_[i].text + "' has size " + std::to_string(cap) +
                                              " bytes but is indexed at sizeof(" + t_[i].text +
                                              "): index " + std::to_string(cap) + " is one byte past the buffer end "
                                              "(valid indices are 0 to " + std::to_string(cap - 1) + ")",
                                          f.name, i);
                                }
                            } else if (ConstExpr(t_, idx, c.arrays, c.alias, c.fill).value(&val) && val == cap) {
                                if (c.off_by_one_seen.insert(arr + "_" + std::to_string(t_[i].line)).second) {
                                    issue("off-by-one",
                                          "'" + t_[i].text + "' has capacity " + std::to_string(cap) +
                                              " elements but is indexed at " + std::to_string(val) +
                                              ": index " + std::to_string(val) + " is one element past the buffer end "
                                              "(valid indices are 0 to " + std::to_string(cap - 1) + ")",
                                          f.name, i);
                                }
                            }
                        }
                    }
                }
            }

            if (!is_call(t_, i))
                continue;
            const size_t close = match(t_, i + 1);
            if (close >= body.e)
                continue;
            const std::vector<Range> a = args_of(t_, i + 1, close);
            call(f, i, a, literals, &c);
        }
    }

    // `name = text`: the name holds text from outside if the right side does.
    void assignment(const Function &f, size_t eq, Range body, Context *c) {
        const size_t n = assigned(eq, body);
        if (n == t_.size())
            return;
        const Range rhs = right_of(eq, body);
        note_join(c, t_[n].text, rhs, false);
        if (tainted(t_, rhs, c->taint))
            taint_name(c, t_[n].text, source_of(*c, rhs));
        // n = strtoul(argv[1]): the number is from outside, the name is not
        // text, so the other rules leave it alone.
        if (size_from_outside(t_, rhs, c->taint, c->outside_size))
            c->outside_size.insert(t_[n].text);
        else
            c->outside_size.erase(t_[n].text);

        // -- null-dereference: track pointer assignment to NULL / nullptr / 0
        if (t_[n].kind == Tok::Ident) {
            if (rhs.e == rhs.b + 1 &&
                (t_[rhs.b].is("NULL") || t_[rhs.b].is("nullptr") ||
                 (t_[rhs.b].is("0") && c->pointers.count(t_[n].text)))) {
                c->null_ptrs[t_[n].text] = eq;
            } else {
                c->null_ptrs.erase(t_[n].text);
            }
        }

        // -- insecure-prng: sensitive variable assigned from rand()/random()
        if (sensitive_prng_name(t_[n].text)) {
            for (size_t k = rhs.b; k < rhs.e; ++k) {
                if (is_call(t_, k)) {
                    const std::string fn = call_name(t_, k);
                    if (fn == "rand" || fn == "random" || fn == "rand_r" || fn == "drand48" ||
                        fn == "lrand48" || fn == "mrand48" || fn == "jrand48" ||
                        fn == "nrand48" || fn == "erand48") {
                        if (c->prng_seen.insert(t_[n].text).second) {
                            issue("insecure-prng",
                                  "'" + t_[n].text + "' is generated with " + fn +
                                      "(): standard PRNGs are predictable and cryptographically weak; "
                                      "use getrandom(), /dev/urandom, or OpenSSL RAND_bytes() for security-sensitive values",
                                  f.name, k);
                        }
                        break;
                    }
                }
            }
        } else if (weak_material(t_[n].text) || weak_material(f.name)) {
            // rand() into a name insecure-prng already covers stays that finding.
            for (size_t k = rhs.b; k < rhs.e; ++k) {
                if (!is_call(t_, k))
                    continue;
                const std::string fn = call_name(t_, k);
                if (fn != "rand" && fn != "srand" && fn != "random" && fn != "rand_r" &&
                    fn != "drand48" && fn != "lrand48" && fn != "mrand48" &&
                    fn != "jrand48" && fn != "nrand48" && fn != "erand48")
                    continue;
                if (c->prng_seen.insert("w|" + f.name).second)
                    issue("weak-crypto",
                          (weak_material(t_[n].text) ? "'" + t_[n].text + "'"
                                                     : "function '" + f.name + "'") +
                              " takes " + fn +
                              "(): a predictable generator must not make a key, password, "
                              "token, iv or nonce; use getrandom() or RAND_bytes()",
                          f.name, k);
                break;
            }
        }

        // -- integer-overflow: multiplication of outside size outside allocators
        for (size_t k = rhs.b + 1; k + 1 < rhs.e; ++k) {
            if (t_[k].is("*")) {
                bool in_alloc = false;
                for (size_t j = rhs.b; j < k; ++j) {
                    if (is_call(t_, j)) {
                        std::string cn = call_name(t_, j);
                        if (cn == "malloc" || cn == "realloc" || cn == "aligned_alloc" ||
                            cn == "memalign" || cn == "posix_memalign" || cn == "calloc" ||
                            cn == "alloca")
                            in_alloc = true;
                    }
                }
                if (!in_alloc) {
                    const bool bad_left = t_[k - 1].kind == Tok::Ident && !member(t_, k - 1) &&
                                          (c->taint.count(t_[k - 1].text) || c->outside_size.count(t_[k - 1].text));
                    const bool bad_right = t_[k + 1].kind == Tok::Ident && !member(t_, k + 1) &&
                                           (c->taint.count(t_[k + 1].text) || c->outside_size.count(t_[k + 1].text));
                    if ((bad_left || bad_right) && c->int_overflow_seen.insert(t_[n].text).second) {
                        issue("integer-overflow",
                              "calculation of '" + t_[n].text + "' involves multiplication with untrusted input '" +
                                  show(t_, rhs) + "': integer multiplication can wrap around without check; "
                                  "validate bounds before multiplying",
                              f.name, k);
                    }
                }
            }
        }
    }

    void call(const Function &f, size_t i, const std::vector<Range> &a,
              const std::set<std::string> &literals, Context *c) {
        const std::string name = call_name(t_, i);
        std::set<std::string> *taint = &c->taint;

        // The route to this call, if any of its arguments holds text from
        // outside: issue() attaches it to the rules about outside text.
        call_at_ = i;
        call_flow_.clear();        for (const Range &arg : a)
            if (tainted(t_, arg, *taint)) {
                call_flow_ = route(*c, arg, i, name);
                break;
            }

        // -- what this call hands to a function another file defines, and what
        // it passes on from its own parameters (resolve_taint() walks these).
        if (db_)
            for (size_t k = 0; k < a.size(); ++k) {
                const bool carries = tainted(t_, a[k], *taint);
                const FlowStep from = source_of(*c, a[k]);
                // One parameter handed to another's: resolve_taint() follows
                // these through any number of files, tainted here or not (the
                // caller of this function decides what it holds).
                if (from.param >= 0 && name != cur_fn_)
                    db_->edges.push_back(
                        TaintEdge{cur_fn_, size_t(from.param), name, k, t_[i].line,
                                  std::string()});
                if (carries && !names_.count(name) && name != cur_fn_ &&
                    !from.what.empty())
                    db_->callers.push_back(TaintCaller{std::string(), cur_fn_, name, k,
                                                       t_[i].line, t_[i].col, from});
                if (from.param >= 0 || carries)
                    break; // the first argument that carries the text is enough
            }

        // Out-parameters: passing &p to any function fills or modifies p
        for (const Range &arg : a) {
            for (size_t k = arg.b; k < arg.e; ++k) {
                if (t_[k].is("&") && k + 1 < arg.e && t_[k + 1].kind == Tok::Ident) {
                    c->null_ptrs.erase(t_[k + 1].text);
                }
            }
        }

        // -- a function of this file: what it is given
        if (names_.count(name) && name != f.name) {
            std::vector<Param> &ps = next_[name];
            if (ps.size() < a.size())
                ps.resize(a.size());
            for (size_t k = 0; k < a.size(); ++k) {
                std::string ignored;
                const std::string b = base_name(t_, a[k]);
                const bool constant = literal(t_, a[k], &ignored) ||
                                      (!b.empty() && a[k].e == a[k].b + 1 &&
                                       c->constant.count(c->root(b)));
                Param &p = ps[k];
                ++p.calls;
                if (tainted(t_, a[k], *taint))
                    p.tainted = true;
                else if (!constant)
                    p.unknown = true;
            }
        }

        // -- text from outside lands in a buffer
        const FlowStep read_by{name + "()", cur_fn_, t_[i].line, t_[i].col};
        if (auto it = kFills.find(name); it != kFills.end() && it->second < a.size())
            if (std::string b = base_name(t_, a[it->second]); !b.empty())
                taint_name(c, b, read_by);
        if (word_is(name, "scanf") || word_is(name, "fscanf") || word_is(name, "sscanf")) {
            // only a word of any length is text to be careful with: numbers and
            // a field with a width are not
            const size_t fmt = word_is(name, "scanf") ? 0 : 1;
            const bool from_text = word_is(name, "sscanf");
            std::string text;
            if (fmt < a.size() && literal(t_, a[fmt], &text) &&
                (!from_text || (a.size() > 0 && tainted(t_, a[0], *taint)))) {
                const std::vector<bool> stores = scan_stores(text);
                for (size_t k = 0; k < stores.size() && fmt + 1 + k < a.size(); ++k)
                    if (stores[k])
                        if (std::string b = base_name(t_, a[fmt + 1 + k]); !b.empty())
                            taint_name(c, b, read_by);
            }
        }
        // copies carry the taint along
        if ((word_is(name, "strcpy") || word_is(name, "strncpy") || word_is(name, "strcat") ||
             word_is(name, "strncat") || word_is(name, "stpcpy") || word_is(name, "memcpy") ||
             word_is(name, "memmove")) && a.size() >= 2 && tainted(t_, a[1], *taint))
            if (std::string b = base_name(t_, a[0]); !b.empty())
                taint_name(c, b, source_of(*c, a[1]));
        // asprintf() and vasprintf() do not call sprintf(). The buffer is &cmd.
        if ((word_is(name, "sprintf") || word_is(name, "snprintf") || word_is(name, "asprintf") ||
             word_is(name, "vasprintf")) &&
            a.size() >= 2) {
            bool any = false;
            FlowStep from;
            for (size_t k = word_is(name, "snprintf") ? 2 : 1; k < a.size(); ++k)
                if (tainted(t_, a[k], *taint)) {
                    any = true;
                    if (from.what.empty())
                        from = source_of(*c, a[k]);
                }
            if (any)
                if (std::string b = base_name(t_, a[0]); !b.empty())
                    taint_name(c, b, from);
            if (std::string b = c->root(base_name(t_, a[0])); !b.empty()) {
                c->joined.erase(b);
                const size_t fa = word_is(name, "snprintf") ? 2 : 1;
                std::string fmt;
                if (fa < a.size() && literal(t_, a[fa], &fmt) &&
                    fmt.find('/') != std::string::npos)
                    for (size_t k = fa + 1; k < a.size(); ++k)
                        if (tainted(t_, a[k], *taint)) {
                            c->joined.insert(b);
                            break;
                        }
            }
        }
        if ((word_is(name, "strcat") || word_is(name, "strncat")) && a.size() >= 2)
            note_join(c, base_name(t_, a[0]), a[1], true);

        // -- alloca() of a size that comes from outside. A constant
        // (alloca(64), alloca(sizeof buf)) is a fixed stack slot.
        if ((word_is(name, "alloca") || word_is(name, "__builtin_alloca")) && !a.empty()) {
            long bytes = 0;
            if (!ConstExpr(t_, a[0], c->arrays, c->alias, c->fill).value(&bytes) &&
                size_from_outside(t_, a[0], *taint, c->outside_size))
                issue("unbounded-alloca",
                      "alloca() takes its size from '" + show(t_, a[0]) +
                          "', which comes from outside the program: a long enough "
                          "value smashes the stack; use malloc() and check the size",
                      f.name, i);
        }

        // -- functions that cannot be used safely
        if (word_is(name, "gets"))
            issue("unsafe-function",
                  "gets() reads a line with no limit on its length (it was removed "
                  "from C11): any long input overflows the buffer; use fgets()",
                  f.name, i);
        else if (word_is(name, "getwd"))
            issue("unsafe-function",
                  "getwd() writes a path of any length into the buffer; use "
                  "getcwd(buf, size)",
                  f.name, i);
        else if (word_is(name, "mktemp") || word_is(name, "tmpnam") || word_is(name, "tmpnam_r") ||
                 word_is(name, "tempnam"))
            issue("unsafe-function",
                  name + "() returns a name that is only chosen, not created: "
                  "someone else can create a file or a symlink of that name "
                  "first and the program then writes through it; use mkstemp()",
                  f.name, i);
        else if ((word_is(name, "scanf") || word_is(name, "vscanf") || word_is(name, "wscanf") ||
                  word_is(name, "vwscanf") || word_is(name, "fscanf") || word_is(name, "vfscanf") ||
                  word_is(name, "fwscanf") || word_is(name, "vfwscanf")) &&
                 a.size() > (word_is(name, "scanf") || word_is(name, "vscanf") || word_is(name, "wscanf") ||
                                     word_is(name, "vwscanf")
                                 ? 0u
                                 : 1u)) {
            // a stream has no limit. The v and wide forms do not call scanf().
            std::string fmt;
            const bool direct = word_is(name, "scanf") || word_is(name, "vscanf") || word_is(name, "wscanf") ||
                                word_is(name, "vwscanf");
            if (literal(t_, a[direct ? 0 : 1], &fmt) && scanf_without_width(fmt))
                issue("unsafe-function",
                      name + "() with %s (or %[) and no width copies a word of any "
                      "length into the buffer: write the size, as in %63s",
                      f.name, i);
        } else if ((word_is(name, "sscanf") || word_is(name, "swscanf")) && a.size() >= 3) {
            // a string of known size cannot give a word longer than itself: only an
            // array it may not fit in is a problem
            std::string fmt;
            if (literal(t_, a[1], &fmt)) {
                const std::vector<bool> stores = scan_stores(fmt);
                const std::string src = c->root(base_name(t_, a[0]));
                for (size_t k = 0; k < stores.size() && 2 + k < a.size(); ++k) {
                    const std::string d = c->root(base_name(t_, a[2 + k]));
                    if (!stores[k] || d.empty() || !c->arrays.count(d) ||
                        (!src.empty() && c->arrays.count(src) && c->fits(d, src)))
                        continue;
                    issue("unsafe-function",
                          name + "() with %s (or %[) and no width copies a word of any length "
                          "into the array '" + d + "': write the size, as in %63s",
                          f.name, i);
                    break;
                }
            }
        }
        // vsscanf() hides the destination in a va_list, so a width cannot be checked.
        if ((word_is(name, "vsscanf") || word_is(name, "vswscanf")) && a.size() >= 3) {
            std::string fmt;
            if (literal(t_, a[1], &fmt) && scanf_without_width(fmt))
                issue("unsafe-function",
                      name + "() with %s (or %[) and no width copies a word of any "
                      "length into the buffer: write the size, as in %63s",
                      f.name, i);
        }
        // mkstemp of a template the program wrote is the safe call. One it was given
        // from outside lets the caller choose the directory. mkostemp/mkstemps/
        // mkostemps take the same template and do not call mkstemp().
        if ((word_is(name, "mkstemp") || word_is(name, "mkostemp") || word_is(name, "mkstemps") ||
             word_is(name, "mkostemps") || word_is(name, "mkdtemp")) &&
            !a.empty() && tainted(t_, a[0], *taint))
            issue("unsafe-function",
                  name + "() is given '" + show(t_, a[0]) +
                      "', a template the program does not control: the caller chooses "
                      "where the file is created; pass a template the program itself writes",
                  f.name, i);

        // -- a format that is not a literal
        // (with arguments after it the format is only a problem when it comes
        // from outside: the caller chose them to match a format of its own)
        if (auto it = kPrintf.find(name);
            it != kPrintf.end() && a.size() > it->second &&
            (a.size() == it->second + 1 || tainted(t_, a[it->second], *taint))) {
            const Range fmt = a[it->second];
            const bool alone = a.size() == it->second + 1;
            if (!has_string(t_, fmt) && fmt.e > fmt.b) {
                const std::string base = c->root(base_name(t_, fmt));
                const bool macro = macro_text(t_, fmt);
                // A local array is judged by what this function does to it; any
                // other name by every assignment to it in the file.
                const bool fixed = fmt.e == fmt.b + 1 &&
                                   (c->constant.count(base) > 0 ||
                                    (!c->arrays.count(base) && !c->params.count(base) &&
                                     literals.count(base) > 0));
                // (once per function and format: a function that prints one format
                // in six ways is one finding)
                if (!macro && !fixed && c->format_seen.insert(name + "|" + show(t_, fmt)).second) {
                    const bool from_input = tainted(t_, fmt, *taint);
                    issue("format-string",
                          name + "() is given '" + show(t_, fmt) +
                              (alone ? "' as its format with no arguments after it"
                                     : "' as its format") +
                              (from_input ? ", and that text comes from outside the program" : "") +
                              ": any % in it makes " + name +
                              "() read arguments that were never passed, and %n "
                              "writes to memory; print it with " + name +
                              "(\"%s\", ...)",
                          f.name, i);
                }
            }
        }

        if (auto it = kVPrintf.find(name); it != kVPrintf.end() && a.size() == it->second + 2 &&
                                          tainted(t_, a[it->second], *taint))
            issue("format-string",
                  name + "() is given '" + show(t_, a[it->second]) +
                      "' as its format, and that text comes from outside the program: "
                      "any % in it makes " + name + "() read arguments that were never "
                      "passed, and %n writes to memory; use a literal format",
                  f.name, i);

        // -- a command line built from outside text
        // wordexp() runs a shell to expand the words; it does not call system().
        if ((word_is(name, "system") || word_is(name, "popen") || word_is(name, "_popen") || word_is(name, "wordexp")) &&
            !a.empty() && tainted(t_, a[0], *taint))
            issue("command-injection",
                  name + "() runs '" + show(t_, a[0]) + "', a command line made from "
                  "text that comes from outside the program: a ; or | or $( ) in it "
                  "runs something else with this program's rights; pass the "
                  "arguments to execv() instead of through a shell",
                  f.name, i);
        // WinExec(cmd), CreateProcess(app, cmd), ShellExecute(hwnd, op, file, parms).
        {
            int cmd_i = -1;
            if (word_is(name, "WinExec") && !a.empty() && tainted(t_, a[0], *taint))
                cmd_i = 0;
            else if ((word_is(name, "CreateProcess") || word_is(name, "CreateProcessA") ||
                      word_is(name, "CreateProcessW")) &&
                     a.size() >= 2)
                cmd_i = tainted(t_, a[1], *taint) ? 1 : tainted(t_, a[0], *taint) ? 0 : -1;
            else if ((word_is(name, "ShellExecute") || word_is(name, "ShellExecuteA") ||
                      word_is(name, "ShellExecuteW")) &&
                     a.size() >= 3)
                cmd_i = tainted(t_, a[2], *taint)                           ? 2
                        : a.size() >= 4 && tainted(t_, a[3], *taint) ? 3
                                                                     : -1;
            if (cmd_i >= 0)
                issue("command-injection",
                      name + "() runs '" + show(t_, a[size_t(cmd_i)]) +
                          "', a command line made from text that comes from outside the "
                          "program: a ; or | or $( ) in it runs something else with this "
                          "program's rights; pass the arguments without a shell",
                      f.name, i);
        }
        if (name.rfind("exec", 0) == 0)
            for (size_t k = 0; k + 1 < a.size(); ++k) {
                std::string flag;
                if (literal(t_, a[k], &flag) && flag == "-c" && tainted(t_, a[k + 1], *taint))
                    issue("command-injection",
                          name + "() hands '" + show(t_, a[k + 1]) + "' to a shell with -c: "
                          "text from outside the program in a command line runs "
                          "whatever it says; pass the arguments separately",
                          f.name, i);
            }
        // syslog(pri, "%s", password), and err()/warn() which print it too.
        // The value can be the format or an argument after it.
        if (word_is(name, "syslog") || word_is(name, "vsyslog") || word_is(name, "err") || word_is(name, "errx") ||
            word_is(name, "warn") || word_is(name, "warnx")) {
            const size_t from = word_is(name, "warn") || word_is(name, "warnx") ? 0 : 1;
            for (size_t k = from; k < a.size(); ++k) {
                const std::string pw = base_name(t_, a[k]);
                if (pw.empty() || secret_name(pw) != 1)
                    continue;
                issue("credential-access",
                      name + "() writes '" + pw +
                          "' where a log or a terminal keeps it: a password or a key "
                          "there is readable by anyone who can read that stream",
                      f.name, i);
                break;
            }
        }
        // execve() takes the argument vector as one value, not as execl() does.
        if ((word_is(name, "execve") || word_is(name, "execv") || word_is(name, "execvp") || word_is(name, "execvpe") ||
             word_is(name, "fexecve")) &&
            a.size() >= 2 && tainted(t_, a[1], *taint)) {
            bool dashc = false;
            for (size_t k = a[1].b; k < a[1].e; ++k) {
                std::string flag;
                if (literal(t_, {k, k + 1}, &flag) && flag == "-c")
                    dashc = true;
            }
            if (dashc)
                issue("command-injection",
                      name + "() hands a command from outside the program to a shell with -c: "
                      "text from outside the program in a command line runs whatever it says; "
                      "pass the arguments separately",
                      f.name, i);
        }
        // posix_spawn() takes the argument vector as one value, not as execl() does.
        if ((word_is(name, "posix_spawn") || word_is(name, "posix_spawnp")) && a.size() >= 5 &&
            tainted(t_, a[4], *taint)) {
            bool dashc = false;
            for (size_t k = a[4].b; k < a[4].e; ++k) {
                std::string flag;
                if (literal(t_, {k, k + 1}, &flag) && flag == "-c")
                    dashc = true;
            }
            if (dashc)
                issue("command-injection",
                      name + "() hands a command from outside the program to a shell with -c: "
                      "text from outside the program in a command line runs whatever it says; "
                      "pass the arguments separately",
                      f.name, i);
        }

        // -- a copy that can overflow a local array
        if ((word_is(name, "strcpy") || word_is(name, "strcat") || word_is(name, "stpcpy") ||
             word_is(name, "wcscpy") || word_is(name, "wcscat") || word_is(name, "wcpcpy")) &&
            a.size() == 2)
            copy_into_array(f, i, name, a[0], a[1], *c);
        // fread(buf, size, n, f) writes size * n bytes. fread_unlocked does not call fread().
        if ((word_is(name, "fread") || word_is(name, "fread_unlocked")) && a.size() >= 3) {
            long have = 0, sz = 0, n = 0;
            const std::string d = array_of(a[0], *c, &have);
            if (!d.empty() && have != kUnknownSize && have > 0 &&
                ConstExpr(t_, a[1], c->arrays, c->alias, c->fill).value(&sz) &&
                ConstExpr(t_, a[2], c->arrays, c->alias, c->fill).value(&n) &&
                sz > 0 && n > 0 && sz > have / n)
                issue("unbounded-copy",
                      name + "() is told to read " + std::to_string(n) + " groups of " +
                          std::to_string(sz) + " bytes into '" + d + "', which holds " +
                          std::to_string(have) + ": the read runs past the end of the array",
                      f.name, i);
        }
        if ((word_is(name, "sprintf") || word_is(name, "vsprintf")) && a.size() >= 2)
            format_into_array(f, i, name, a, *c);
        for (const Writer &w : kWriters)
            if (name == w.name && a.size() > std::max(w.dest, w.size))
                write_too_much(f, i, name, a, w.dest, w.size, w.extra, *c);
        // Two buffers. A Writer has one destination.
        if (word_is(name, "getnameinfo") && a.size() >= 6) {
            write_too_much(f, i, name, a, 2, 3, 0, *c);
            write_too_much(f, i, name, a, 4, 5, 0, *c);
        }
        // The count is wide characters, not bytes. wchar_t is 4, as in element_size.
        // swprintf's count is argument 1; wmemcpy's is argument 2.
        if ((word_is(name, "swprintf") || word_is(name, "vswprintf") || word_is(name, "wcsftime")) &&
            a.size() >= 2) {
            long have = 0, n = 0;
            const std::string d = array_of(a[0], *c, &have);
            if (!d.empty() && have != kUnknownSize &&
                ConstExpr(t_, a[1], c->arrays, c->alias, c->fill).value(&n) && n > 0 &&
                n > have / 4)
                issue("unbounded-copy",
                      name + "() is told to write " + std::to_string(n) +
                          " wide characters into '" + d + "', which holds " +
                          std::to_string(have / 4) +
                          ": the write runs past the end of the array",
                      f.name, i);
        }
        if ((word_is(name, "wmemcpy") || word_is(name, "wmemmove") || word_is(name, "wmemset") ||
             word_is(name, "wcsncpy")) &&
            a.size() >= 3) {
            long have = 0, n = 0;
            const std::string d = array_of(a[0], *c, &have);
            if (!d.empty() && have != kUnknownSize &&
                ConstExpr(t_, a[2], c->arrays, c->alias, c->fill).value(&n) && n > 0 &&
                n > have / 4)
                issue("unbounded-copy",
                      name + "() is told to write " + std::to_string(n) +
                          " wide characters into '" + d + "', which holds " +
                          std::to_string(have / 4) +
                          ": the write runs past the end of the array",
                      f.name, i);
        }
        // ponytail: only strlen(src) as the whole size; a length kept in a variable is not seen
        if ((word_is(name, "memcpy") || word_is(name, "memmove")) && a.size() == 3 &&
            tainted(t_, a[1], *taint)) {
            long have = 0;
            const std::string d = array_of(a[0], *c, &have);
            const Range sz = a[2];
            const size_t close = sz.e > sz.b + 3 && t_[sz.b].is("strlen") && t_[sz.b + 1].is("(")
                                     ? match(t_, sz.b + 1)
                                     : t_.size();
            if (!d.empty() && have != kUnknownSize && close + 1 == sz.e) {
                const std::string sb = c->root(base_name(t_, a[1]));
                const std::string ib = c->root(base_name(t_, {sz.b + 2, close}));
                if (!sb.empty() && sb == ib && !c->fits(d, sb)) {
                    long from = 0;
                    const std::string s = array_of(a[1], *c, &from);
                    if (s.empty() || (from != kUnknownSize && from > have + 1))
                        issue("unbounded-copy",
                              name + "() copies '" + show(t_, a[1]) +
                                  "', text from outside the program, into '" + d + "' with " +
                                  show(t_, sz) + ", that text's length, which can pass the " +
                                  std::to_string(have) + " bytes '" + d + "' holds",
                              f.name, i);
                }
            }
        }
        // asctime_r(tm, buf) and ctime_r(t, buf) write at least 26 bytes and take no length.
        if ((word_is(name, "asctime_r") || word_is(name, "ctime_r")) && a.size() >= 2) {
            long have = 0;
            const std::string d = array_of(a[1], *c, &have);
            if (!d.empty() && have != kUnknownSize && have < 26)
                issue("unbounded-copy",
                      name + "() writes 26 bytes into '" + d + "', which holds " +
                          std::to_string(have) +
                          ": the time can run past the end of the array",
                      f.name, i);
        }

        // cuserid(buf) writes L_cuserid (9) bytes and takes no length.
        if (word_is(name, "cuserid") && !a.empty() && a[0].e > a[0].b &&
            !(t_[a[0].e - 1].is("NULL") || t_[a[0].e - 1].is("nullptr") ||
              t_[a[0].e - 1].is("0"))) {
            long have = 0;
            const std::string d = array_of(a[0], *c, &have);
            if (!d.empty() && have != kUnknownSize && have < 9)
                issue("unbounded-copy",
                      "cuserid() writes 9 bytes into '" + d + "', which holds " +
                          std::to_string(have) +
                          ": the name can run past the end of the array; use getlogin_r()",
                      f.name, i);
        }

        // realpath(path, buf) has no length and writes PATH_MAX bytes. NULL allocates.
        // ponytail: 4096 is Linux PATH_MAX; a pathconf() size is not seen
        if (word_is(name, "realpath") && a.size() >= 2 && a[1].e > a[1].b &&
            !(t_[a[1].e - 1].is("NULL") || t_[a[1].e - 1].is("nullptr") ||
              t_[a[1].e - 1].is("0"))) {
            long have = 0;
            const std::string d = array_of(a[1], *c, &have);
            if (!d.empty() && have != kUnknownSize && have < 4096)
                issue("unbounded-copy",
                      "realpath() writes a path of up to PATH_MAX bytes into '" + d +
                          "', which holds " + std::to_string(have) +
                          ": the path can run past the end of the array; pass NULL and free "
                          "the result, or a buffer of PATH_MAX bytes",
                      f.name, i);
        }

        // -- check, then use
        if ((word_is(name, "access") || word_is(name, "euidaccess") || word_is(name, "eaccess") || word_is(name, "stat") ||
             word_is(name, "lstat")) &&
            !a.empty()) {
            const bool weak = !word_is(name, "access") && !word_is(name, "euidaccess") && !word_is(name, "eaccess");
            c->checked[show(t_, a[0])] = {i, name, weak, false};
        } else if ((word_is(name, "faccessat") || word_is(name, "fstatat") || word_is(name, "statx")) && a.size() >= 2) {
            // These do not call access()/stat(); the path is the second argument.
            const bool weak = !word_is(name, "faccessat");
            c->checked[show(t_, a[1])] = {i, name, weak, false};
        } else if (!a.empty()) {
            // *at calls do not call the unadorned function; the path is argument 1.
            const bool at_path = word_is(name, "openat") || word_is(name, "unlinkat") || word_is(name, "fchmodat") ||
                                 word_is(name, "fchownat") || word_is(name, "execveat") || word_is(name, "renameat") ||
                                 word_is(name, "renameat2") || word_is(name, "linkat");
            const bool openat_ = word_is(name, "openat");
            // The *64 names and freopen() do not call open()/fopen()/truncate().
            const bool uses = word_is(name, "open") || word_is(name, "fopen") || word_is(name, "creat") ||
                              word_is(name, "open64") || word_is(name, "fopen64") || word_is(name, "freopen") ||
                              word_is(name, "freopen64") || word_is(name, "creat64") || word_is(name, "truncate64") ||
                              word_is(name, "unlink") || word_is(name, "chmod") || word_is(name, "chown") ||
                              word_is(name, "rename") || word_is(name, "truncate") || word_is(name, "execve") ||
                              word_is(name, "execv") || word_is(name, "remove") || word_is(name, "rmdir") ||
                              word_is(name, "readlink") || word_is(name, "symlink") || word_is(name, "symlinkat") ||
                              word_is(name, "link") || word_is(name, "lchown") || at_path;
            const size_t path_i = at_path ? 1 : 0;
            if (uses && path_i < a.size())
                if (auto ch = c->checked.find(show(t_, a[path_i])); ch != c->checked.end() &&
                                                                   ch->second.at < i) {
                    const size_t flag_i = openat_ ? 2 : 1;
                    const bool open_like = word_is(name, "open") || word_is(name, "open64") ||
                                           word_is(name, "fopen") || word_is(name, "fopen64") ||
                                           word_is(name, "freopen") || word_is(name, "freopen64") ||
                                           word_is(name, "creat") || word_is(name, "creat64") || openat_;
                    const bool writes = open_like ? a.size() > flag_i &&
                                                        opens_for_writing(t_, openat_ ? "open" : name,
                                                                          a[flag_i])
                                                  : !word_is(name, "readlink");
                    // O_EXCL and O_NOFOLLOW make the open itself the check; unlink,
                    // rmdir and remove do not follow a link, and a program often
                    // looks (stat) before it runs a file
                    bool safe = false;
                    if ((word_is(name, "open") || word_is(name, "open64") || openat_) && a.size() > flag_i)
                        for (size_t k = a[flag_i].b; k < a[flag_i].e; ++k)
                            safe |= t_[k].is("O_EXCL") || t_[k].is("O_NOFOLLOW");
                    if (ch->second.weak && (word_is(name, "unlink") || word_is(name, "unlinkat") ||
                                            word_is(name, "rmdir") || word_is(name, "remove") ||
                                            word_is(name, "execve") || word_is(name, "execveat") ||
                                            word_is(name, "execv")))
                        safe = true;
                    if (!ch->second.reported && !safe && (writes || !ch->second.weak) &&
                        (ch->second.reported = true)) // (once per check)
                        issue("toctou-race",
                              ch->second.fn + "(" + ch->first + ") checks the file at line " +
                                  std::to_string(t_[ch->second.at].line) + " and " + name +
                                  "() uses it here: in between, the file can be replaced "
                                  "(by a symlink to a file the caller may not touch, say), "
                                  "so the check proves nothing; call " + name +
                                  "() directly and look at errno",
                              f.name, i, t_[ch->second.at].line);
                }
        }

        // -- permissions anyone can write
        const char *what = nullptr;
        if (word_is(name, "chmod") && a.size() == 2 && world_writable(t_, a[1]))
            what = "chmod() makes the file writable by every user";
        else if (word_is(name, "fchmod") && a.size() == 2 && world_writable(t_, a[1]))
            what = "fchmod() makes the file writable by every user";
        else if (word_is(name, "fchmodat") && a.size() >= 3 && world_writable(t_, a[2]))
            what = "fchmodat() makes the file writable by every user";
        else if ((word_is(name, "creat") || word_is(name, "creat64")) && a.size() >= 2 &&
                 world_writable(t_, a[1]))
            what = word_is(name, "creat") ? "creat() creates the file writable by every user"
                                   : "creat64() creates the file writable by every user";
        else if (word_is(name, "mkdir") && a.size() >= 2 && world_writable(t_, a[1]))
            what = "mkdir() creates the directory writable by every user";
        else if (word_is(name, "mkdirat") && a.size() >= 3 && world_writable(t_, a[2]))
            what = "mkdirat() creates the directory writable by every user";
        else if (word_is(name, "mkfifo") && a.size() >= 2 && world_writable(t_, a[1]))
            what = "mkfifo() creates the pipe writable by every user";
        else if (word_is(name, "mkfifoat") && a.size() >= 3 && world_writable(t_, a[2]))
            what = "mkfifoat() creates the pipe writable by every user";
        else if (word_is(name, "mknod") && a.size() >= 2 && world_writable(t_, a[1]))
            what = "mknod() creates the node writable by every user";
        else if (word_is(name, "mknodat") && a.size() >= 3 && world_writable(t_, a[2]))
            what = "mknodat() creates the node writable by every user";
        else if ((word_is(name, "open") || word_is(name, "open64") || word_is(name, "openat") ||
                  word_is(name, "openat64")) &&
                 a.size() >= (word_is(name, "open") || word_is(name, "open64") ? 3u : 4u) &&
                 world_writable(t_, a[word_is(name, "open") || word_is(name, "open64") ? 2 : 3])) {
            // ponytail: O_CREAT must be written in the call; a flags variable is not seen
            const size_t flags = word_is(name, "open") || word_is(name, "open64") ? 1 : 2;
            for (size_t k = a[flags].b; k < a[flags].e; ++k)
                if (t_[k].is("O_CREAT") || t_[k].is("O_TMPFILE")) {
                    what = word_is(name, "open")      ? "open() creates the file writable by every user"
                           : word_is(name, "open64")  ? "open64() creates the file writable by every user"
                           : word_is(name, "openat")  ? "openat() creates the file writable by every user"
                                               : "openat64() creates the file writable by every user";
                    break;
                }
        } else if ((word_is(name, "msgget") || word_is(name, "semget") || word_is(name, "shmget")) &&
                   a.size() >= 2 && ipc_world_writable(t_, a.back()))
            what = word_is(name, "msgget") ? "msgget() creates the queue writable by every user"
                   : word_is(name, "semget")
                       ? "semget() creates the set writable by every user"
                       : "shmget() creates the segment writable by every user";
        else if ((word_is(name, "shm_open") || word_is(name, "sem_open") || word_is(name, "mq_open")) &&
                 a.size() >= 3 && world_writable(t_, a[2])) {
            for (size_t k = a[1].b; k < a[1].e; ++k)
                if (t_[k].is("O_CREAT")) {
                    what = word_is(name, "shm_open") ? "shm_open() creates the shared memory writable by every user"
                           : word_is(name, "sem_open")
                               ? "sem_open() creates the semaphore writable by every user"
                               : "mq_open() creates the queue writable by every user";
                    break;
                }
        } else if (word_is(name, "umask") && a.size() == 1 && a[0].e == a[0].b + 1 &&
                   t_[a[0].b].kind == Tok::Number &&
                   strtol(t_[a[0].b].text.c_str(), nullptr, 0) == 0)
            what = "umask(0) lets every user write files this program creates";
        if (what)
            issue("insecure-permissions",
                  std::string(what) + ": another user can change what the program "
                  "reads later; give the owner (and a group) the write bit only",
                  f.name, i);
        // chmod(path, 04755) is not world-writable. open() with O_CREAT is the same bit.
        {
            int mode_i = -1;
            if ((word_is(name, "chmod") || word_is(name, "fchmod") || word_is(name, "creat") || word_is(name, "creat64")) &&
                a.size() >= 2)
                mode_i = 1;
            else if (word_is(name, "fchmodat") && a.size() >= 3)
                mode_i = 2;
            else if ((word_is(name, "open") || word_is(name, "open64")) && a.size() >= 3)
                mode_i = 2;
            else if ((word_is(name, "openat") || word_is(name, "openat64")) && a.size() >= 4)
                mode_i = 3;
            bool creating = !word_is(name, "open") && !word_is(name, "open64") && !word_is(name, "openat") &&
                            !word_is(name, "openat64");
            if (!creating && mode_i > 0) {
                const size_t flags = word_is(name, "openat") || word_is(name, "openat64") ? 2 : 1;
                for (size_t k = a[flags].b; k < a[flags].e; ++k)
                    if (t_[k].is("O_CREAT") || t_[k].is("O_TMPFILE"))
                        creating = true;
            }
            if (creating && mode_i >= 0 && setid_mode(t_, a[size_t(mode_i)]))
                issue("privilege-escalation",
                      name + "() sets the setuid or setgid bit: whoever runs that file "
                      "runs it with the owner's rights, a way to keep root access",
                      f.name, i);
        }

        // setuid(0) and the calls that do not go through it. A literal 0 only:
        // setuid(getuid()) drops privileges.
        {
            auto id_zero = [&](Range r) {
                return r.e == r.b + 1 && t_[r.b].is("0");
            };
            const bool one = word_is(name, "setuid") || word_is(name, "seteuid") || word_is(name, "setfsuid") ||
                             word_is(name, "setgid") || word_is(name, "setegid") || word_is(name, "setfsgid");
            const bool two = word_is(name, "setreuid") || word_is(name, "setregid");
            const bool three = word_is(name, "setresuid") || word_is(name, "setresgid");
            if ((one && a.size() >= 1 && id_zero(a[0])) ||
                (two && a.size() >= 2 && (id_zero(a[0]) || id_zero(a[1]))) ||
                (three && a.size() >= 3 &&
                 (id_zero(a[0]) || id_zero(a[1]) || id_zero(a[2]))))
                issue("privilege-escalation",
                      name + "() asks to become user or group 0: a program that is not "
                      "root and can do this was given a way to keep root; drop to the "
                      "caller's id",
                      f.name, i);
        }
        // ADDR_NO_RANDOMIZE is 0x40000. personality() does not go through prctl().
        if (word_is(name, "personality") && a.size() == 1) {
            bool off = false;
            for (size_t k = a[0].b; k < a[0].e; ++k) {
                if (t_[k].is("ADDR_NO_RANDOMIZE"))
                    off = true;
                else if (t_[k].kind == Tok::Number &&
                         (strtol(t_[k].text.c_str(), nullptr, 0) & 0x40000))
                    off = true;
            }
            if (off)
                issue("anti-analysis",
                      "personality() turns off address randomization: the next program "
                      "starts at a fixed address, which is how a later exploit is aimed",
                      f.name, i);
        }
        // open("/proc/<pid>/mem") does not go through process_vm_writev().
        {
            int path_i = -1, flag_i = -1;
            if (word_is(name, "open") || word_is(name, "open64") || word_is(name, "fopen") || word_is(name, "fopen64") ||
                word_is(name, "freopen") || word_is(name, "freopen64")) {
                path_i = 0;
                flag_i = 1;
            } else if (word_is(name, "openat") || word_is(name, "openat64")) {
                path_i = 1;
                flag_i = 2;
            }
            std::string path;
            if (path_i >= 0 && size_t(path_i) < a.size() &&
                literal(t_, a[size_t(path_i)], &path)) {
                const bool stream = word_is(name, "fopen") || word_is(name, "fopen64") || word_is(name, "freopen") ||
                                    word_is(name, "freopen64");
                bool writing = false, wipes = false;
                if (flag_i >= 0 && size_t(flag_i) < a.size()) {
                    if (stream) {
                        std::string mode;
                        if (literal(t_, a[size_t(flag_i)], &mode)) {
                            writing = mode.find_first_of("wa+") != std::string::npos;
                            wipes = mode.find('w') != std::string::npos;
                        }
                    } else {
                        writing = opens_for_writing(t_, "open", a[size_t(flag_i)]);
                        for (size_t k = a[size_t(flag_i)].b; k < a[size_t(flag_i)].e; ++k)
                            wipes |= t_[k].is("O_TRUNC");
                    }
                }
                if (starts(path, "/proc/") && ends(path, "/maps"))
                    issue("anti-analysis",
                          name + "() opens '" + path +
                              "': a process memory map, which shows what is loaded where",
                          f.name, i);
                else if (proc_pid(path, "/mem") && writing)
                    issue("process-injection",
                          name + "() opens '" + path +
                              "' for writing: it changes the code of another running program",
                          f.name, i);
                else if (proc_pid(path, "/mem") || proc_pid(path, "/environ"))
                    issue("credential-access",
                          name + "() opens '" + path +
                              "': the memory or environment of another program",
                          f.name, i);
                else if (path == "/dev/mem" || path == "/dev/kmem" || path == "/dev/port" ||
                         path == "/proc/kcore")
                    issue("credential-access",
                          name + "() opens '" + path +
                              "': the kernel's or the machine's memory",
                          f.name, i);
                else if (starts(path, "/dev/input/") || path == "/dev/uinput")
                    issue("credential-access",
                          name + "() opens '" + path +
                              "': keystrokes or pointer input",
                          f.name, i);
                else if (stored_secret(path))
                    issue("credential-access",
                          name + "() opens '" + path +
                              "': a stored password, key, or wallet",
                          f.name, i);
                else if (wipes && (starts(path, "/var/log/") || ends(path, "/.bash_history") ||
                                   ends(path, "/.zsh_history") || ends(path, "/.sh_history")))
                    issue("log-tampering",
                          name + "() empties '" + path +
                              "': a log or a shell history, so what happened can be denied",
                          f.name, i);
                else if (writing && (path == "/etc/hosts" || path == "/etc/resolv.conf"))
                    issue("system-tampering",
                          name + "() opens '" + path +
                              "' for writing: it changes where the machine's connections go",
                          f.name, i);
                else if (writing && startup_file(path))
                    issue("persistence",
                          name + "() opens '" + path +
                              "' for writing: that file decides what runs later or who may "
                              "become root",
                          f.name, i);
                else if (writing && system_mount_target(path))
                    issue("system-tampering",
                          name + "() opens '" + path +
                              "' for writing: this changes a program or library the "
                              "whole system trusts",
                          f.name, i);
            }
        }
        // utime() of a log does not go through open().
        {
            int tp = -1;
            if ((word_is(name, "utime") || word_is(name, "utimes") || word_is(name, "lutimes")) && !a.empty())
                tp = 0;
            else if (word_is(name, "utimensat") && a.size() >= 2)
                tp = 1;
            std::string tpath;
            if (tp >= 0 && literal(t_, a[size_t(tp)], &tpath) &&
                (starts(tpath, "/var/log/") || ends(tpath, "/.bash_history") ||
                 ends(tpath, "/.zsh_history") || ends(tpath, "/.sh_history")))
                issue("log-tampering",
                      name + "() changes the time on '" + tpath +
                          "': a log or a shell history can be made to look older than it is",
                      f.name, i);
        }
        // unlink() of a system program does not go through open().
        {
            int sp = -1;
            if ((word_is(name, "unlink") || word_is(name, "remove") || word_is(name, "rmdir") || word_is(name, "truncate") ||
                 word_is(name, "truncate64") || word_is(name, "rename") || word_is(name, "chmod") ||
                 word_is(name, "chown") || word_is(name, "lchown") || word_is(name, "mkdir")) &&
                !a.empty())
                sp = (word_is(name, "rename") && a.size() >= 2) ? 1 : 0;
            else if ((word_is(name, "unlinkat") || word_is(name, "fchmodat") || word_is(name, "fchownat") ||
                      word_is(name, "link") || word_is(name, "symlink") || word_is(name, "mkdirat")) &&
                     a.size() >= 2)
                sp = 1;
            else if ((word_is(name, "linkat") || word_is(name, "renameat") || word_is(name, "renameat2")) &&
                     a.size() >= 4)
                sp = 3;
            else if (word_is(name, "symlinkat") && a.size() >= 3)
                sp = 2;
            std::string spath;
            if (sp >= 0 && size_t(sp) < a.size() && literal(t_, a[size_t(sp)], &spath)) {
                const bool log = starts(spath, "/var/log/") || ends(spath, "/.bash_history") ||
                                 ends(spath, "/.zsh_history") || ends(spath, "/.sh_history");
                const bool removes = word_is(name, "unlink") || word_is(name, "unlinkat") || word_is(name, "remove") ||
                                     word_is(name, "truncate") || word_is(name, "truncate64") || word_is(name, "rename");
                if (startup_file(spath))
                    issue("persistence",
                          name + "() changes '" + spath +
                              "': that file decides what runs later or who may become root",
                          f.name, i);
                else if (log && removes)
                    issue("log-tampering",
                          name + "() removes '" + spath +
                              "': a log or a shell history, so what happened can be denied",
                          f.name, i);
                else if (system_mount_target(spath))
                    issue("system-tampering",
                          name + "() changes '" + spath +
                              "', a program or library the whole system trusts",
                          f.name, i);
            }
        }
        if ((word_is(name, "mount") && a.size() >= 2) ||
            ((word_is(name, "umount") || word_is(name, "umount2")) && !a.empty())) {
            const size_t path_i = word_is(name, "mount") ? 1 : 0;
            std::string path;
            if (path_i < a.size() && literal(t_, a[path_i], &path) && system_mount_target(path))
                issue("system-tampering",
                      name + "() changes where '" + path +
                          "' is mounted: a program or directory the whole system trusts",
                      f.name, i);
        }
        // A trusted name on a memfd or a thread. Neither is the program's own argv[0].
        if (word_is(name, "memfd_create") && !a.empty()) {
            std::string n;
            if (literal(t_, a[0], &n) && lcrules::trusted_name(n.c_str()))
                issue("masquerade",
                      "memfd_create() names a file \"" + n +
                          "\", the name of something the system runs",
                      f.name, i);
        }
        if (word_is(name, "pthread_setname_np")) {
            for (const Range &r : a) {
                std::string n;
                if (literal(t_, r, &n) && lcrules::trusted_name(n.c_str())) {
                    issue("masquerade",
                          "the process renames itself \"" + n +
                              "\", the name of something the system runs",
                          f.name, i);
                    break;
                }
            }
        }
        if (word_is(name, "prctl") && a.size() >= 2) {
            bool set = false;
            for (size_t k = a[0].b; k < a[0].e; ++k)
                if (t_[k].is("PR_SET_NAME") ||
                    (t_[k].kind == Tok::Number && strtol(t_[k].text.c_str(), nullptr, 0) == 15))
                    set = true;
            std::string n;
            if (set && literal(t_, a[1], &n) && lcrules::trusted_name(n.c_str()))
                issue("masquerade",
                      "the process renames itself \"" + n +
                          "\", the name of something the system runs",
                      f.name, i);
        }
        // ptrace() and process_vm_*() do not go through open("/proc/<pid>/mem").
        if (word_is(name, "ptrace") && !a.empty()) {
            bool poke = false, attach = false, traceme = false, peek = false;
            for (size_t k = a[0].b; k < a[0].e; ++k) {
                if (t_[k].is("PTRACE_POKETEXT") || t_[k].is("PTRACE_POKEDATA") ||
                    t_[k].is("PTRACE_POKEUSER") || t_[k].is("PTRACE_SETREGS") ||
                    t_[k].is("PTRACE_SETREGSET") || t_[k].is("PT_WRITE_I") ||
                    t_[k].is("PT_WRITE_D") || t_[k].is("PT_WRITE_U"))
                    poke = true;
                else if (t_[k].is("PTRACE_PEEKTEXT") || t_[k].is("PTRACE_PEEKDATA") ||
                         t_[k].is("PTRACE_PEEKUSER") || t_[k].is("PTRACE_GETREGSET") ||
                         t_[k].is("PT_READ_I") || t_[k].is("PT_READ_D") || t_[k].is("PT_READ_U"))
                    peek = true;
                else if (t_[k].is("PTRACE_ATTACH") || t_[k].is("PTRACE_SEIZE") ||
                         t_[k].is("PT_ATTACH"))
                    attach = true;
                else if (t_[k].is("PTRACE_TRACEME") || t_[k].is("PT_TRACE_ME") ||
                         t_[k].is("PT_DENY_ATTACH"))
                    traceme = true;
                else if (t_[k].kind == Tok::Number) {
                    const long v = strtol(t_[k].text.c_str(), nullptr, 0);
                    if (v == 4 || v == 5 || v == 6 || v == 13 || v == 0x4205)
                        poke = true;
                    else if (v == 1 || v == 2 || v == 3 || v == 0x4204)
                        peek = true;
                    else if (v == 16 || v == 0x4206)
                        attach = true;
                    else if (v == 0)
                        traceme = true;
                }
            }
            if (poke || attach)
                issue("process-injection",
                      name + "() writes into or attaches to another running program",
                      f.name, i);
            else if (peek)
                issue("credential-access",
                      "ptrace() reads the memory of another running program",
                      f.name, i);
            else if (traceme)
                issue("anti-analysis",
                      "ptrace(PTRACE_TRACEME) keeps a debugger from attaching afterwards",
                      f.name, i);
        }
        if (word_is(name, "pcap_open_live") || word_is(name, "pcap_create"))
            issue("credential-access",
                  name + "() captures packets on the network: it can read traffic that is not this program's",
                  f.name, i);
        if (word_is(name, "socket") && a.size() >= 2) {
            bool raw = false;
            for (size_t k = a[0].b; k < a[0].e; ++k)
                raw |= t_[k].is("AF_PACKET");
            for (size_t k = a[1].b; k < a[1].e; ++k)
                raw |= t_[k].is("SOCK_RAW");
            if (raw)
                issue("credential-access",
                      "socket() opens a raw socket: it can read or forge packets on the network",
                      f.name, i);
        }
        if (word_is(name, "pidfd_getfd"))
            issue("credential-access",
                  "pidfd_getfd() takes a file another process has open",
                  f.name, i);
        if (word_is(name, "process_vm_writev"))
            issue("process-injection",
                  "process_vm_writev() writes into the memory of another running program",
                  f.name, i);
        else if (word_is(name, "process_vm_readv"))
            issue("credential-access",
                  "process_vm_readv() reads the memory of another running program",
                  f.name, i);
        if (word_is(name, "capset"))
            issue("privilege-escalation",
                  "capset() changes the process's capabilities: a capability is a root "
                  "privilege kept after the user id is dropped",
                  f.name, i);
        if (word_is(name, "prctl")) {
            bool exe = false;
            for (const Range &r : a)
                for (size_t k = r.b; k < r.e && !exe; ++k)
                    exe = t_[k].is("PR_SET_MM_EXE_FILE");
            if (exe)
                issue("masquerade",
                      "prctl(PR_SET_MM_EXE_FILE) changes the program the process claims to be",
                      f.name, i);
        }
        if (word_is(name, "prctl")) {
            bool raise = false;
            for (const Range &r : a)
                for (size_t k = r.b; k < r.e && !raise; ++k)
                    raise = t_[k].is("PR_CAP_AMBIENT_RAISE");
            if (raise)
                issue("privilege-escalation",
                      "prctl(PR_CAP_AMBIENT_RAISE) changes the process's capabilities: "
                      "a capability is a root privilege kept after the user id is dropped",
                      f.name, i);
        }
        // iopl(3) and ioperm(..., 1) ask for hardware ports. A literal 0 turns that off.
        if (word_is(name, "iopl") || word_is(name, "ioperm")) {
            const bool off = word_is(name, "iopl") ? a.size() == 1 && a[0].e == a[0].b + 1 &&
                                                  t_[a[0].b].is("0")
                                            : a.size() >= 3 && a[2].e == a[2].b + 1 &&
                                                  t_[a[2].b].is("0");
            if (!off)
                issue("privilege-escalation",
                      name + "() asks for direct access to hardware ports: that reaches "
                      "the machine past the operating system",
                      f.name, i);
        }
        // init_module() does not go through open() of a system file.
        if (word_is(name, "init_module") || word_is(name, "finit_module") || word_is(name, "delete_module") ||
            word_is(name, "kexec_load") || word_is(name, "kexec_file_load") || word_is(name, "bpf"))
            issue("system-tampering",
                  name + "() changes the running kernel: a module or a new kernel "
                  "runs with every program's rights",
                  f.name, i);

        // -- sizeof(a pointer): touches only the pointer itself, not the buffer.
        // The size argument written as sizeof(p), where p is a pointer: a name of
        // a malloc'ed block (an alias of one, too: the pointer is what sizeof
        // sees), or a parameter. A real array's sizeof is its whole size, so
        // names local_arrays() knows are fine.
        int size_at = -1;
        if ((word_is(name, "memset") || word_is(name, "memcpy") || word_is(name, "memmove") || word_is(name, "mempcpy") ||
             word_is(name, "strncpy") || word_is(name, "strncat") || word_is(name, "strlcpy") || word_is(name, "strlcat") ||
             word_is(name, "read") || word_is(name, "pread") || word_is(name, "recv") || word_is(name, "recvfrom") ||
             word_is(name, "wcsncpy") || word_is(name, "wmemcpy") || word_is(name, "wmemmove")) &&
            a.size() >= 3)
            size_at = 2;
        else if ((word_is(name, "snprintf") || word_is(name, "vsnprintf") || word_is(name, "bzero") ||
                  word_is(name, "explicit_bzero") || word_is(name, "fgets") || word_is(name, "fgets_unlocked")) &&
                 a.size() >= 2)
            size_at = 1;
        if (size_at >= 0) {
            const Range sz = a[size_t(size_at)];
            if (sz.e - sz.b >= 2 && t_[sz.b].is("sizeof")) {
                size_t k = sz.b + 1; // after "sizeof"
                if (k < sz.e && t_[k].is("("))
                    ++k;
                if (k < sz.e && t_[k].kind == Tok::Ident &&
                    (k + 1 == sz.e || (t_[k + 1].is(")") && k + 2 == sz.e))) {
                    const std::string &n = t_[k].text;
                    const bool pointer = (c->arrays.count(n) && !c->size_text.count(n)) ||
                                         (c->alias.count(n) && !c->alias.at(n).empty()) ||
                                         c->params.count(n);
                    if (pointer)
                        issue("sizeof-pointer",
                              name + "() is given sizeof(" + n + "), and " + n +
                                  " is a pointer: only the pointer's own bytes are "
                                  "touched, not the buffer it points to; use sizeof(*" + n +
                                  ") or the buffer size",
                              f.name, i);
                }
            }
        }

        // -- an allocation sized by a multiplication of outside text: the product
        // can wrap around and the buffer come out smaller than asked. calloc()
        // checks the product itself; malloc(), realloc() and aligned_alloc() do not.
        if ((word_is(name, "malloc") || word_is(name, "realloc") || word_is(name, "aligned_alloc") ||
             word_is(name, "memalign") || word_is(name, "posix_memalign")) &&
            !a.empty()) {
            const Range sz = a.back();
            for (size_t k = sz.b + 1; k + 1 < sz.e; ++k) {
                if (!t_[k].is("*"))
                    continue;
                const bool bad_left = t_[k - 1].kind == Tok::Ident && !member(t_, k - 1) &&
                                      (taint->count(t_[k - 1].text) ||
                                       c->outside_size.count(t_[k - 1].text));
                const bool bad_right = t_[k + 1].kind == Tok::Ident && !member(t_, k + 1) &&
                                       (taint->count(t_[k + 1].text) ||
                                        c->outside_size.count(t_[k + 1].text));
                if (bad_left || bad_right) {
                    issue("alloc-size-overflow",
                          name + "() is given '" + show(t_, sz) +
                              "' as its size, and a factor comes from outside the program: "
                              "the multiplication can wrap around and the buffer be smaller "
                              "than the product; check the factor first, or use calloc()",
                          f.name, i);
                    break;
                }
            }
        }

        // GnuTLS priority strings. NORMAL alone is the library's current default.
        // '+' turns a feature on, '-' turns it off: "-VERS-TLS1.0" disables the old
        // protocol (secure) and must not match the same as "+VERS-TLS1.0" (asks for it).
        if (word_is(name, "gnutls_priority_set_direct") && a.size() >= 2) {
            std::string pri;
            if (literal(t_, a[1], &pri)) {
                for (char &c : pri)
                    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                auto enables = [&](const char *feature) {
                    for (size_t at = pri.find(feature); at != std::string::npos;
                         at = pri.find(feature, at + 1))
                        if (at > 0 && pri[at - 1] == '+')
                            return true;
                    return false;
                };
                if (enables("VERS-SSL3") || enables("VERS-TLS1.0") || enables("ARCFOUR") ||
                    pri.find("+3DES") != std::string::npos)
                    issue("weak-crypto",
                          "gnutls_priority_set_direct() asks for SSL 3, TLS 1.0, RC4, or 3DES: "
                          "those are broken; use NORMAL or a TLS 1.2 profile",
                          f.name, i);
            }
        }
        // Legacy renegotiation lets an attacker splice data into a session.
        if (word_is(name, "SSL_CTX_set_options") || word_is(name, "SSL_set_options")) {
            bool unsafe = false;
            for (const Range &r : a)
                for (size_t k = r.b; k < r.e && !unsafe; ++k)
                    unsafe = t_[k].is("SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION");
            if (unsafe)
                issue("weak-crypto",
                      name + "() allows unsafe legacy renegotiation: an attacker "
                      "can splice data into the session; leave that option off",
                      f.name, i);
        }
        // Level 0 accepts algorithms OpenSSL otherwise refuses.
        if ((word_is(name, "SSL_CTX_set_security_level") || word_is(name, "SSL_set_security_level")) &&
            a.size() >= 2 && a[1].e == a[1].b + 1 && t_[a[1].b].is("0"))
            issue("weak-crypto",
                  name + "() sets the security level to 0: weak ciphers and short keys "
                  "are accepted; leave the level at 1 or higher",
                  f.name, i);
        // A ceiling of TLS 1.0 or SSL 3, or a floor of SSL 3. TLS 1.2 as the floor is fine.
        if ((word_is(name, "SSL_CTX_set_max_proto_version") || word_is(name, "SSL_set_max_proto_version") ||
             word_is(name, "SSL_CTX_set_min_proto_version") || word_is(name, "SSL_set_min_proto_version")) &&
            a.size() >= 2) {
            const bool ceiling = name.find("set_max_") != std::string::npos;
            bool weak = false;
            for (size_t k = a[1].b; k < a[1].e; ++k)
                weak |= t_[k].is("SSL3_VERSION") ||
                        (ceiling && (t_[k].is("TLS1_VERSION") || t_[k].is("TLS1_1_VERSION")));
            if (weak)
                issue("weak-crypto",
                      name + "() allows SSL 3 or TLS 1.0: those protocols are broken; "
                      "require TLS 1.2 or newer",
                      f.name, i);
        }
        // A cipher list that names RC4, DES, 3DES, an export cipher, or MD5.
        // "!aNULL" is not one of those: it turns anonymous suites off.
        if ((word_is(name, "SSL_CTX_set_cipher_list") || word_is(name, "SSL_set_cipher_list")) &&
            a.size() >= 2) {
            std::string list;
            if (literal(t_, a[1], &list)) {
                for (char &c : list)
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (list.find("rc4") != std::string::npos || list.find("rc2") != std::string::npos ||
                    list.find("3des") != std::string::npos || list.find("des-cbc") != std::string::npos ||
                    list.find("exp-") != std::string::npos || list.find("md5") != std::string::npos ||
                    list.find("null-") != std::string::npos || list.find("enull") != std::string::npos)
                    issue("weak-crypto",
                          name + "() asks for a cipher list that includes a broken algorithm: "
                          "RC4, DES, 3DES, an export cipher, or MD5; use a list of AES-GCM "
                          "or ChaCha20",
                          f.name, i);
            }
        }
        if (word_is(name, "curl_easy_setopt") && a.size() >= 3) {
            bool pair = false, alone = false;
            for (size_t k = a[1].b; k < a[1].e; ++k) {
                pair |= t_[k].is("CURLOPT_USERPWD") || t_[k].is("CURLOPT_PROXYUSERPWD");
                alone |= t_[k].is("CURLOPT_PASSWORD") || t_[k].is("CURLOPT_PROXYPASSWORD");
            }
            std::string val;
            if (literal(t_, a[2], &val) &&
                ((pair && val.find(':') != std::string::npos &&
                  val.find(':') + 1 < val.size()) ||
                 (alone && credential_value(val))))
                issue("hardcoded-secret",
                      "curl_easy_setopt() is given the password \"" + val +
                          "\": a credential written into the program is known to everyone "
                          "who has the binary; read it from the environment",
                      f.name, i);
        }
        // The password argument of these connectors is not an assignment, so the
        // name-equals-literal rule does not see it.
        if (word_is(name, "PQsetdbLogin") && a.size() >= 7) {
            std::string pw;
            if (literal(t_, a[6], &pw) && credential_value(pw))
                issue("hardcoded-secret",
                      "PQsetdbLogin() is given the password \"" + pw +
                          "\": a credential written into the program is known to everyone "
                          "who has the binary; read it from the environment",
                      f.name, i);
        }
        if (word_is(name, "SSL_CTX_set_default_passwd_cb_userdata") && a.size() >= 2) {
            std::string pw;
            if (literal(t_, a[1], &pw) && credential_value(pw))
                issue("hardcoded-secret",
                      "SSL_CTX_set_default_passwd_cb_userdata() is given the password \"" +
                          pw + "\": a credential written into the program is known to everyone "
                          "who has the binary; read it from the environment",
                      f.name, i);
        }
        if ((word_is(name, "PEM_read_bio_PrivateKey") || word_is(name, "PEM_read_PrivateKey") ||
             word_is(name, "PEM_read_bio_RSAPrivateKey") || word_is(name, "PEM_read_RSAPrivateKey")) &&
            a.size() >= 4) {
            std::string pw;
            if (literal(t_, a[3], &pw) && credential_value(pw))
                issue("hardcoded-secret",
                      name + "() is given the password \"" + pw +
                          "\": a credential written into the program is known to everyone "
                          "who has the binary; read it from the environment",
                      f.name, i);
        }
        if (word_is(name, "mysql_real_connect") && a.size() >= 4) {
            std::string pw;
            if (literal(t_, a[3], &pw) && credential_value(pw))
                issue("hardcoded-secret",
                      "mysql_real_connect() is given the password \"" + pw +
                          "\": a credential written into the program is known to everyone "
                          "who has the binary; read it from the environment",
                      f.name, i);
        }
        // mysql_options(c, MYSQL_OPT_SSL_MODE, SSL_MODE_DISABLED) does not call
        // SSL_set_verify(). A literal 0 next to the verify option is the same.
        if (word_is(name, "mysql_options") || word_is(name, "mysql_optionsv")) {
            bool opt = false, zero = false, disabled = false;
            for (const Range &r : a)
                for (size_t k = r.b; k < r.e; ++k) {
                    opt |= t_[k].is("MYSQL_OPT_SSL_VERIFY_SERVER_CERT");
                    disabled |= t_[k].is("SSL_MODE_DISABLED");
                    zero |= t_[k].is("0");
                }
            if (disabled || (opt && zero))
                issue("tls-no-verify",
                      name + "() turns off certificate checks: anyone who intercepts the "
                      "connection impersonates the server; leave SSL verification on",
                      f.name, i);
        }
        // -- TLS verification switched off: anyone in the middle is the server.
        if ((word_is(name, "SSL_CTX_set_verify") || word_is(name, "SSL_set_verify") ||
             word_is(name, "wolfSSL_CTX_set_verify") || word_is(name, "wolfSSL_set_verify") ||
             word_is(name, "mbedtls_ssl_conf_authmode") ||
             word_is(name, "gnutls_certificate_set_verify_flags")) &&
            a.size() >= 2)
            for (size_t k = a[1].b; k < a[1].e; ++k)
                if (t_[k].is("SSL_VERIFY_NONE") || t_[k].is("MBEDTLS_SSL_VERIFY_NONE") ||
                    t_[k].is("GNUTLS_VERIFY_DISABLE_CA_SIGN")) {
                    issue("tls-no-verify",
                          name + "() is called with " + t_[k].text + ": the peer's "
                          "certificate is not checked, so anyone who intercepts the "
                          "connection impersonates the server; use SSL_VERIFY_PEER with "
                          "a certificate the program trusts",
                          f.name, i);
                    break;
                }
        if (word_is(name, "curl_easy_setopt") && a.size() >= 3) {
            bool peer = false, host = false;
            for (size_t k = a[1].b; k < a[1].e; ++k) {
                peer |= t_[k].is("CURLOPT_SSL_VERIFYPEER");
                host |= t_[k].is("CURLOPT_SSL_VERIFYHOST");
            }
            const bool off = a[2].e == a[2].b + 1 && t_[a[2].b].is("0");
            if (peer && off)
                issue("tls-no-verify",
                      "curl_easy_setopt() is given CURLOPT_SSL_VERIFYPEER, 0: the "
                      "server's certificate is not checked, so anyone who intercepts "
                      "the connection impersonates the server; leave the check on "
                      "(it is the default)",
                      f.name, i);
            // 2 checks the name (the default). 0 does not. VERIFYHOST does not
            // go through SSL_set_verify.
            if (host && off)
                issue("tls-no-verify",
                      "curl_easy_setopt() is given CURLOPT_SSL_VERIFYHOST, 0: the "
                      "server's name is not checked, so anyone who intercepts the "
                      "connection impersonates the server; leave the check on "
                      "(2 is the default)",
                      f.name, i);
        }
        // A literal the program itself writes. getenv("LD_PRELOAD") only reads it.
        if (word_is(name, "putenv") && !a.empty()) {
            std::string lit;
            if (literal(t_, a[0], &lit) &&
                ((starts(lit, "LD_PRELOAD=") && lit.size() > strlen("LD_PRELOAD=")) ||
                 (starts(lit, "DYLD_INSERT_LIBRARIES=") &&
                  lit.size() > strlen("DYLD_INSERT_LIBRARIES="))))
                issue("process-injection",
                      "putenv() assigns " + lit.substr(0, lit.find('=')) +
                          ": a library named here is loaded into programs this one starts",
                      f.name, i);
        } else if (word_is(name, "setenv") && a.size() >= 2) {
            std::string key, val;
            if (literal(t_, a[0], &key) && literal(t_, a[1], &val) && !val.empty() &&
                (key == "LD_PRELOAD" || key == "DYLD_INSERT_LIBRARIES"))
                issue("process-injection",
                      "setenv() assigns " + key +
                          ": a library named here is loaded into programs this one starts",
                      f.name, i);
        }
        // setenv("PATH", "/tmp") makes the next bare command run a program anyone can write.
        if (word_is(name, "setenv") && a.size() >= 2) {
            std::string key, val;
            const bool path = literal(t_, a[0], &key) && key == "PATH";
            const bool loose = literal(t_, a[1], &val) &&
                               (val.empty() || val[0] == '.' || starts(val, "/tmp") ||
                                starts(val, "/var/tmp") || starts(val, "/dev/shm"));
            const bool lib = literal(t_, a[0], &key) &&
                             (key == "LD_LIBRARY_PATH" || key == "DYLD_LIBRARY_PATH");
            if (path && (loose || tainted(t_, a[1], *taint)))
                issue("command-injection",
                      "setenv() sets PATH to '" + show(t_, a[1]) +
                          "': a later command that is named, not given as a full path, "
                          "starts a program anyone can write there",
                      f.name, i);
            if (lib && (loose || tainted(t_, a[1], *taint)))
                issue("process-injection",
                      "setenv() sets " + key + " to '" + show(t_, a[1]) +
                          "': the next library is loaded from a directory anyone can write",
                      f.name, i);
            std::string hist;
            if (literal(t_, a[0], &key) && literal(t_, a[1], &hist) &&
                ((key == "HISTFILE" && (hist == "/dev/null" || hist.empty())) ||
                 (key == "HISTSIZE" && hist == "0")))
                issue("log-tampering",
                      "setenv() sets " + key + " so the shell keeps no history: what was "
                      "typed can be denied",
                      f.name, i);
        } else if (word_is(name, "unsetenv") && a.size() == 1) {
            std::string key;
            if (literal(t_, a[0], &key) && key == "PATH")
                issue("command-injection",
                      "unsetenv() clears PATH: a later command that is named, not given as "
                      "a full path, starts from the current directory",
                      f.name, i);
            if (literal(t_, a[0], &key) && key == "HISTFILE")
                issue("log-tampering",
                      "unsetenv() clears HISTFILE so the shell keeps no history: what was "
                      "typed can be denied",
                      f.name, i);
        } else if (word_is(name, "putenv") && !a.empty()) {
            std::string lit;
            if (literal(t_, a[0], &lit) && starts(lit, "PATH=")) {
                const std::string val = lit.substr(5);
                if (val.empty() || val[0] == '.' || starts(val, "/tmp") ||
                    starts(val, "/var/tmp") || starts(val, "/dev/shm"))
                    issue("command-injection",
                          "putenv() sets PATH to '" + val +
                              "': a later command that is named, not given as a full path, "
                              "starts a program anyone can write there",
                          f.name, i);
            }
        }
        // dlopen() of a path the caller chose. dlmopen()'s path is the second argument.
        if (((word_is(name, "dlopen") || word_is(name, "LoadLibrary") || word_is(name, "LoadLibraryA") ||
              word_is(name, "LoadLibraryW") || word_is(name, "LoadLibraryExA") ||
              word_is(name, "LoadLibraryExW")) &&
             !a.empty() && tainted(t_, a[0], *taint)) ||
            (word_is(name, "dlmopen") && a.size() >= 2 && tainted(t_, a[1], *taint)))
            issue("process-injection",
                  name + "() loads '" + show(t_, word_is(name, "dlmopen") ? a[1] : a[0]) +
                      "', a library named by text from outside the program: that code "
                      "runs in this process; load a library the program itself names",
                  f.name, i);
        // openat's path is the second argument. creat/open64/fopen64 do not call open().
        int path_at = -1;
        if ((word_is(name, "open") || word_is(name, "fopen") || word_is(name, "freopen") || word_is(name, "creat") ||
             word_is(name, "open64") || word_is(name, "fopen64") || word_is(name, "freopen64") ||
             word_is(name, "canonicalize_file_name") || word_is(name, "realpath")) &&
            !a.empty())
            path_at = 0;
        else if ((word_is(name, "openat") || word_is(name, "openat64")) && a.size() >= 2)
            path_at = 1;
        if (path_at >= 0) {
            const std::string p = c->root(path_name(a[size_t(path_at)]));
            const Range body = body_of(f);
            if (!p.empty() && c->joined.count(p) && !dotdot_rejected(t_, body.b, i))
                issue("path-traversal",
                      name + "() opens '" + show(t_, a[size_t(path_at)]) +
                          "', a path built by joining "
                          "a directory with text from outside the program, and nothing "
                          "rejects \"..\": a value such as ../etc/passwd leaves the directory; "
                          "reject \"..\" first, or open the directory and use openat()",
                      f.name, i);
        }

        // A DH or DSA parameter shorter than 2048 bits.
        if ((word_is(name, "DH_generate_parameters_ex") || word_is(name, "DSA_generate_parameters_ex") ||
             word_is(name, "EVP_PKEY_CTX_set_dsa_paramgen_bits")) &&
            a.size() >= 2 && a[1].e == a[1].b + 1 && t_[a[1].b].kind == Tok::Number) {
            const long n = strtol(t_[a[1].b].text.c_str(), nullptr, 0);
            if (n > 0 && n < 2048)
                issue("weak-crypto",
                      name + "() asks for a " + std::to_string(n) +
                          "-bit parameter: that is small enough to attack; use 2048 bits or more",
                      f.name, i);
        }
        // Curves too small to be safe. P-256 and X25519 are not in this list.
        if ((word_is(name, "EC_KEY_new_by_curve_name") && !a.empty()) ||
            (word_is(name, "EVP_PKEY_CTX_set_ec_paramgen_curve_nid") && a.size() >= 2)) {
            const Range r = a[word_is(name, "EC_KEY_new_by_curve_name") ? 0 : 1];
            for (size_t k = r.b; k < r.e; ++k)
                if (t_[k].is("NID_secp112r1") || t_[k].is("NID_secp112r2") ||
                    t_[k].is("NID_secp128r1") || t_[k].is("NID_secp160k1") ||
                    t_[k].is("NID_secp160r1") || t_[k].is("NID_secp160r2") ||
                    t_[k].is("NID_sect163k1") || t_[k].is("NID_sect163r1") ||
                    t_[k].is("NID_sect163r2")) {
                    issue("weak-crypto",
                          name + "() asks for " + t_[k].text +
                              ", a curve that is too small; use P-256 or X25519",
                          f.name, i);
                    break;
                }
        }
        // 512- and 1024-bit RSA. 2048 and above are left alone.
        if ((word_is(name, "RSA_generate_key") && !a.empty()) ||
            ((word_is(name, "RSA_generate_key_ex") || word_is(name, "EVP_PKEY_CTX_set_rsa_keygen_bits")) &&
             a.size() >= 2)) {
            const Range bits = a[word_is(name, "RSA_generate_key") ? 0 : 1];
            if (bits.e == bits.b + 1 && t_[bits.b].kind == Tok::Number) {
                const long n = strtol(t_[bits.b].text.c_str(), nullptr, 0);
                if (n > 0 && n < 2048)
                    issue("weak-crypto",
                          name + "() asks for a " + std::to_string(n) +
                              "-bit RSA key: that is small enough to factor; use 2048 bits or more",
                          f.name, i);
            }
        }
        // RAND_pseudo_bytes() is the call OpenSSL marked as not unpredictable.
        // It does not go through rand().
        // EVP_BytesToKey() is the old password KDF. The digest it is given does not
        // make it a modern one.
        if (word_is(name, "EVP_BytesToKey"))
            issue("weak-crypto",
                  "EVP_BytesToKey() turns a password into a key with a weak function: "
                  "use a password hash such as PBKDF2 with SHA-256, or argon2",
                  f.name, i);
        if (word_is(name, "RAND_pseudo_bytes") || word_is(name, "BN_pseudo_rand") ||
            word_is(name, "BN_pseudo_rand_range"))
            issue("weak-crypto",
                  name + "() is a predictable generator: it must not make a key, "
                  "password, token, iv or nonce; use RAND_bytes() or BN_rand()",
                  f.name, i);

        if (word_is(name, "srand") && weak_material(f.name) &&
            c->prng_seen.insert("w|" + f.name).second)
            issue("weak-crypto",
                  "function '" + f.name +
                      "' seeds the generator with srand(): a predictable generator must not "
                      "make a key, password, token, iv or nonce; use getrandom() or RAND_bytes()",
                  f.name, i);

        // -- weak algorithms (not inside the implementation of the algorithm itself:
        // SHA1_Final() calling SHA1_Update())
        if (kWeakCrypto.count(name) &&
            f.name.rfind(name.substr(0, name.find('_')) + "_", 0) != 0 &&
            c->crypto_seen.insert(name.substr(0, name.find('_'))).second) // once per algorithm
            issue("weak-crypto",
                  name + "() is a broken or weak algorithm: fine for a checksum "
                  "nobody attacks, not for passwords, signatures or secrecy; use "
                  "SHA-256 or better, AES-GCM, or a password hash such as argon2",
                  f.name, i);

        // These take the algorithm as a string and do not call MD5_Init().
        if ((word_is(name, "EVP_get_digestbyname") || word_is(name, "EVP_get_cipherbyname") ||
             word_is(name, "EVP_MD_fetch") || word_is(name, "EVP_CIPHER_fetch")) &&
            !a.empty()) {
            const size_t arg = name.find("fetch") != std::string::npos ? 1 : 0;
            std::string alg;
            if (arg < a.size() && literal(t_, a[arg], &alg)) {
                const std::string key = weak_alg_key(alg);
                if (!key.empty() && c->crypto_seen.insert(key).second)
                    issue("weak-crypto",
                          name + "() asks for " + alg +
                              ", a broken or weak algorithm: fine for a checksum "
                              "nobody attacks, not for passwords, signatures or secrecy; use "
                              "SHA-256 or better, AES-GCM, or a password hash such as argon2",
                          f.name, i);
            }
        }

        // -- SQL query executed with outside/tainted text (CWE-89)
        const bool is_sql_exec = word_is(name, "sqlite3_exec") || word_is(name, "sqlite3_prepare") ||
                                 word_is(name, "sqlite3_prepare_v2") || word_is(name, "sqlite3_prepare_v3") ||
                                 word_is(name, "sqlite3_prepare16") || word_is(name, "sqlite3_prepare16_v2") ||
                                 word_is(name, "sqlite3_prepare16_v3") ||
                                 word_is(name, "mysql_query") ||
                                 word_is(name, "mysql_real_query") || word_is(name, "mysql_stmt_prepare") ||
                                 word_is(name, "PQexec") ||
                                 word_is(name, "PQexecParams") || word_is(name, "PQsendQuery") ||
                                 word_is(name, "PQsendQueryParams") || word_is(name, "SQLExecDirect") ||
                                 word_is(name, "SQLExecDirectA") || word_is(name, "SQLExecDirectW") ||
                                 word_is(name, "SQLPrepare") || word_is(name, "SQLPrepareA") ||
                                 word_is(name, "SQLPrepareW");
        if (is_sql_exec && a.size() > 1 && tainted(t_, a[1], *taint)) {
            if (c->sql_seen.insert(std::to_string(t_[i].line) + "_" + name).second) {
                issue("sql-injection",
                      name + "() runs '" + show(t_, a[1]) +
                          "', a SQL query constructed from text that comes from outside the program: "
                          "an attacker can inject SQL syntax to read or alter database records; "
                          "use parameterized prepared statements with bind parameters instead",
                      f.name, i);
            }
        }
        if ((word_is(name, "sprintf") || word_is(name, "snprintf") || word_is(name, "asprintf") || word_is(name, "vasprintf")) &&
            a.size() >= 2) {
            const size_t fa = word_is(name, "sprintf") ? 1 : (word_is(name, "snprintf") ? 2 : 1);
            std::string fmt;
            if (fa < a.size() && literal(t_, a[fa], &fmt)) {
                std::string lfmt = lower(fmt);
                if (lfmt.find("select ") != std::string::npos ||
                    lfmt.find("insert into ") != std::string::npos ||
                    lfmt.find("update ") != std::string::npos ||
                    lfmt.find("delete from ") != std::string::npos ||
                    lfmt.find("drop table ") != std::string::npos) {
                    for (size_t k = fa + 1; k < a.size(); ++k) {
                        if (tainted(t_, a[k], *taint)) {
                            std::string b = c->root(base_name(t_, a[0]));
                            if (b.empty() || c->sql_seen.insert(std::to_string(t_[i].line) + "_" + b).second) {
                                issue("sql-injection",
                                      name + "() builds a SQL query with '" + show(t_, a[k]) +
                                          "', text that comes from outside the program: "
                                          "an attacker can alter SQL query syntax; "
                                          "use parameterized queries with bound parameters",
                                      f.name, i);
                            }
                            break;
                        }
                    }
                }
            }
        }

        // -- SSRF (CWE-918)
        // curl_url_set() and soup_message_new() do not call curl_easy_setopt().
        if (word_is(name, "curl_url_set") && a.size() >= 3) {
            bool part = false;
            for (size_t k = a[1].b; k < a[1].e; ++k)
                part |= t_[k].is("CURLUPART_URL") || t_[k].is("CURLUPART_HOST");
            if (part && tainted(t_, a[2], *taint) &&
                c->ssrf_seen.insert(show(t_, a[2])).second)
                issue("ssrf",
                      "curl_url_set() is given '" + show(t_, a[2]) +
                          "', a URL that comes from outside the program: an attacker can target "
                          "internal network services or cloud metadata endpoints (SSRF); "
                          "validate and restrict destination URLs against an allowlist",
                      f.name, i);
        }
        if (word_is(name, "soup_message_new") && a.size() >= 2 &&
            tainted(t_, a[1], *taint) && c->ssrf_seen.insert(show(t_, a[1])).second)
            issue("ssrf",
                  name + "() is given '" + show(t_, a[1]) +
                      "', a URL that comes from outside the program: an attacker can target "
                      "internal network services or cloud metadata endpoints (SSRF); "
                      "validate and restrict destination URLs against an allowlist",
                  f.name, i);
        if (word_is(name, "curl_easy_setopt") && a.size() >= 3) {
            bool is_url = false;
            for (size_t k = a[1].b; k < a[1].e; ++k)
                is_url |= t_[k].is("CURLOPT_URL");
            if (is_url && tainted(t_, a[2], *taint)) {
                if (c->ssrf_seen.insert(show(t_, a[2])).second) {
                    issue("ssrf",
                          "curl_easy_setopt() is given CURLOPT_URL with '" + show(t_, a[2]) +
                              "', a URL that comes from outside the program: an attacker can target "
                              "internal network services or cloud metadata endpoints (SSRF); "
                              "validate and restrict destination URLs against an allowlist",
                          f.name, i);
                }
            }
        }

        // -- XSS (CWE-79)
        if (auto it = kPrintf.find(name); it != kPrintf.end() && a.size() > it->second) {
            std::string fmt;
            if (literal(t_, a[it->second], &fmt) && has_html_tag(fmt)) {
                for (size_t k = it->second + 1; k < a.size(); ++k) {
                    if (tainted(t_, a[k], *taint)) {
                        if (c->xss_seen.insert(show(t_, a[k])).second) {
                            issue("xss",
                                  name + "() outputs unescaped text '" + show(t_, a[k]) +
                                      "' from outside the program into an HTML response: an attacker can inject "
                                      "malicious scripts (Cross-Site Scripting); encode HTML characters before output",
                                  f.name, i);
                        }
                        break;
                    }
                }
            }
        }
    }

    // The array a destination expression is, with its size (kUnknownSize if
    // unknown); empty if it is not a local array.
    std::string array_of(Range r, const Context &c, long *size) const {
        const std::string d = c.root(base_name(t_, r));
        auto it = c.arrays.find(d);
        if (d.empty() || it == c.arrays.end())
            return {};
        *size = it->second;
        return d;
    }

    void write_too_much(const Function &f, size_t i, const std::string &name,
                        const std::vector<Range> &a, size_t dest_at, size_t size_at,
                        long extra, const Context &c) {
        const Range dst = a[dest_at], size = a[size_at];
        long have = 0, want = 0;
        const std::string d = array_of(dst, c, &have);
        if (d.empty() || have == kUnknownSize)
            return;
        if (!ConstExpr(t_, size, c.arrays, c.alias, c.fill).value(&want))
            return;
        // strncat stops at the end of its source: a source known to be shorter
        // than the count is what gets copied
        if (name == "strncat" && a.size() == 3) {
            std::string lit;
            long len = -1;
            if (literal(t_, a[1], &lit))
                len = long(literal_bytes(lit));
            else if (auto f = c.fill.find(c.root(base_name(t_, a[1]))); f != c.fill.end())
                len = f->second;
            if (len >= 0)
                want = std::min(want, len);
        }
        want += extra;
        if (want <= have)
            return;
        issue("unbounded-copy",
              name + "() is told to write " + std::to_string(want) + " bytes into '" + d +
                  "', which holds " + std::to_string(have) +
                  ": the write runs past the end of the array",
              f.name, i);
    }

    void copy_into_array(const Function &f, size_t i, const std::string &name,
                         Range dst, Range src, const Context &c) {
        long have = 0;
        const std::string d = array_of(dst, c, &have);
        if (d.empty())
            return;
        std::string lit;
        if (literal(t_, src, &lit)) {
            // wcscpy copies wide characters. wchar_t is 4 bytes, matching element_size.
            const bool wide = name == "wcscpy" || name == "wcscat" || name == "wcpcpy";
            const size_t need = (literal_bytes(lit) + 1) * (wide ? 4 : 1);
            if (have != kUnknownSize && long(need) > have)
                issue("unbounded-copy",
                      name + "() copies a string of " + std::to_string(need) +
                          " bytes (with its terminator) into '" + d + "', which holds " +
                          std::to_string(have) + ": the write runs past the end of the array",
                      f.name, i);
            return;
        }
        if (tainted(t_, src, c.taint)) {
            // a string held in an array cannot be longer than the array
            if (const std::string sa = c.root(base_name(t_, src)); !sa.empty() && c.fits(d, sa))
                return;
            issue("unbounded-copy",
                  name + "() copies '" + show(t_, src) + "', text that comes from "
                  "outside the program, into the buffer '" + d +
                      "' with no length check: a long enough value overwrites the "
                      "stack; use snprintf() or check the length first",
                  f.name, i);
            return;
        }
        // an array a memset filled holds a string of that length
        long from = 0;
        const std::string s = array_of(src, c, &from);
        if (const auto filled = c.fill.find(s);
            !s.empty() && s != d && filled != c.fill.end() && have != kUnknownSize &&
            filled->second + 1 > have)
            issue("unbounded-copy",
                  name + "() copies the " + std::to_string(filled->second) +
                      " characters that were put into '" + s + "' (and a terminator) into '" +
                      d + "', which holds " + std::to_string(have) +
                      ": the write runs past the end of the array",
                  f.name, i);
    }

    void format_into_array(const Function &f, size_t i, const std::string &name,
                           const std::vector<Range> &a, const Context &c) {
        long have = 0;
        const std::string d = array_of(a[0], c, &have);
        std::string fmt;
        if (d.empty() || !literal(t_, a[1], &fmt))
            return;
        const FormatInfo info = scan_format(fmt);
        if (have != kUnknownSize && long(info.fixed) + 1 > have) {
            issue("unbounded-copy",
                  name + "() writes at least " + std::to_string(info.fixed + 1) +
                      " bytes into '" + d + "', which holds " + std::to_string(have) +
                      ": the write runs past the end of the array",
                  f.name, i);
            return;
        }
        if (!info.unbounded_s)
            return;
        // The most the call can write, when every %s argument is a string of known
        // size (a literal, or an array: it holds at most size - 1 characters).
        const std::vector<long> conv = print_args(fmt);
        long upper = long(info.fixed) + 1;
        bool bounded = true;
        size_t from_outside = conv.size();
        for (size_t k = 0; k < conv.size(); ++k) {
            const bool arg = 2 + k < a.size();
            if (conv[k] >= 0) {
                upper += conv[k];
                continue;
            }
            std::string lit;
            long size = 0;
            if (arg && literal(t_, a[2 + k], &lit))
                upper += long(literal_bytes(lit));
            else if (arg && !array_of(a[2 + k], c, &size).empty() && size != kUnknownSize)
                upper += size - 1;
            else
                bounded = false;
            if (arg && from_outside == conv.size() && tainted(t_, a[2 + k], c.taint))
                from_outside = k;
        }
        if (from_outside == conv.size() || (bounded && have != kUnknownSize && upper <= have))
            return;
        issue("unbounded-copy",
              name + "() puts '" + show(t_, a[2 + from_outside]) + "', text that comes from "
              "outside the program, into the buffer '" + d + "' with %s "
              "and no precision: a long enough value overwrites the stack; "
              "use snprintf(), or %.Ns",
              f.name, i);
    }

    // Credentials written into the program: a value for a variable named like
    // one, a string compared with one, a key that is recognisable by its shape.
    void secrets() {
        for (size_t i = 0; i < t_.size(); ++i) {
            std::string value;
            if (literal(t_, {i, i + 1}, &value))
                if (const char *what = known_secret(value)) {
                    issue("hardcoded-secret",
                          std::string("the program contains ") + what +
                              " as a string: anyone who has the binary or the source has it; "
                              "read it from the environment or a file the user controls",
                          function_at(t_[i].line), i);
                    continue;
                }
            size_t name_at = t_.size();
            if (i > 1 && t_[i].is("=") && i + 1 < t_.size() &&
                t_[i + 1].kind == Tok::String) {
                size_t n = i - 1;
                if (t_[n].is("]") && n > 1) {
                    while (n > 0 && !t_[n].is("["))
                        --n;
                    --n;
                }
                // (a field counts: cfg.password = "...", .password = "...")
                if (t_[n].kind == Tok::Ident && secret_name(t_[n].text) &&
                    literal(t_, {i + 1, i + 2}, &value) && credential_value(value) &&
                    (secret_name(t_[n].text) == 1 || random_looking(value)))
                    name_at = n;
            }
            if (t_[i].kind == Tok::Ident &&
                (t_[i].is("strcmp") || t_[i].is("strncmp") || t_[i].is("strcasecmp") ||
                 t_[i].is("strncasecmp") || t_[i].is("memcmp")) && is_call(t_, i)) {
                const size_t close = match(t_, i + 1);
                const std::vector<Range> a = args_of(t_, i + 1, close);
                for (size_t k = 0; k < 2 && a.size() >= 2; ++k) {
                    const std::string other = base_name(t_, a[k]);
                    if (!other.empty() && secret_name(other) == 1 &&
                        literal(t_, a[1 - k], &value) && credential_value(value)) {
                        issue("hardcoded-secret",
                              "'" + other + "' is compared with the literal \"" + value +
                                  "\": a password or key that is written into the program "
                                  "lets in anyone who reads it (a backdoor, when it is not "
                                  "the real one)",
                              function_at(t_[i].line), i);
                        break;
                    }
                }
                // A literal is hardcoded-secret, above. Two names still leak one byte at a time.
                if ((t_[i].is("strcmp") || t_[i].is("memcmp") || t_[i].is("strncmp") ||
                     t_[i].is("strcasecmp") || t_[i].is("strncasecmp")) &&
                    a.size() >= 2) {
                    std::string lit;
                    if (!literal(t_, a[0], &lit) && !literal(t_, a[1], &lit))
                        for (size_t k = 0; k < 2; ++k) {
                            const std::string pw = base_name(t_, a[k]);
                            if (pw.empty() || secret_name(pw) != 1)
                                continue;
                            issue("weak-crypto",
                                  "'" + pw + "' is compared with " + t_[i].text +
                                      "(): it stops at the first byte that differs, so the "
                                      "time leaks the secret; use a constant-time compare",
                                  function_at(t_[i].line), i);
                            break;
                        }
                }
            }
            if (name_at != t_.size())
                issue("hardcoded-secret",
                      "'" + t_[name_at].text + "' is set to the literal \"" + value +
                          "\": a credential written into the program is known to "
                          "everyone who has the binary or the source; read it from the "
                          "environment or a file the user controls",
                      function_at(t_[i].line), name_at);
        }
    }

    const Toks &t_;
    const std::vector<Function> &fns_;
    std::vector<size_t> line_tok_; // line -> first token on or after it
    std::vector<Issue> out_;
    bool emit_ = true;
    std::set<std::string> globals_, global_taint_;
    std::set<std::string> names_, static_; // functions defined here; the static ones
    std::map<std::string, std::vector<Param>> params_, next_;
    std::map<std::string, std::set<size_t>> modifies_; // function -> parameters written through
    TaintDb *db_ = nullptr;      // what other files need to know (see analyzer.h)
    std::string cur_fn_;         // the function being read
    size_t call_at_ = size_t(-1);    // the call being read, and the route
    std::vector<FlowStep> call_flow_; // its arguments' text took to reach it
    bool export_pass_ = false;        // reading for other files, not reporting
};

} // namespace

std::vector<Issue> security_issues(const std::vector<Token> &tokens,
                                   const std::vector<Function> &fns, TaintDb *taint) {
    g_brackets.reset(); // the table belongs to the tokens it was built from
    return Checker(tokens, fns, taint).run();
}

namespace {

std::string file_name(const std::string &p) {
    const size_t s = p.rfind('/');
    return s == std::string::npos ? p : p.substr(s + 1);
}

} // namespace

std::vector<std::pair<std::string, Issue>> resolve_taint(const TaintDb &db) {
    std::vector<std::pair<std::string, Issue>> out;
    if (db.callers.empty() || db.sinks.empty())
        return out;

    std::map<std::string, std::vector<const TaintSink *>> sinks_of;
    for (const TaintSink &s : db.sinks)
        sinks_of[s.function].push_back(&s);
    std::map<std::string, std::vector<const TaintEdge *>> edges_of;
    for (const TaintEdge &e : db.edges)
        edges_of[e.function].push_back(&e);

    // One finding per dangerous call, shown from the furthest place the text
    // is known to have come from: the same call reached from two callers is one
    // vulnerability, and the longest route names the entry point.
    struct Best {
        std::string file;
        Issue issue;
    };
    std::map<std::string, Best> best;

    for (const TaintCaller &c : db.callers) {
        // From the callee's parameter, follow the parameters it is passed on to
        // (through however many files) until one reaches a dangerous call.
        std::vector<const TaintEdge *> path, best_path;
        std::set<std::pair<std::string, size_t>> on_path;
        const TaintSink *best_found = nullptr;
        size_t best_len = 0; // the longest chain seen so far wins
        // Depth-first with backtracking, so the chosen route is a real chain.
        std::function<bool(const std::string &, size_t)> walk =
            [&](const std::string &fn, size_t param) -> bool {
                if (path.size() > 8 || !on_path.insert({fn, param}).second)
                    return false;
                for (const TaintSink *s : sinks_of[fn])
                    if (s->param == param) {
                        if (path.size() >= best_len) {
                            best_len = path.size();
                            best_path = path;
                            best_found = s;
                        }
                        on_path.erase({fn, param});
                        return true;
                    }
                for (const TaintEdge *e : edges_of[fn])
                    if (e->param == param) {
                        path.push_back(e);
                        walk(e->callee, e->callee_param);
                        path.pop_back();
                    }
                on_path.erase({fn, param});
                return false;
            };
        walk(c.callee, c.param);
        if (!best_found)
            continue;
        // best_found/best_path hold the longest chain found from this caller.
        FlowStep sink_step{best_found->call + "()", best_found->sink_function,
                           best_found->sink_line, 0};
        // The last step is in the file the dangerous call is in, which is not
        // the file the finding is written in.
        sink_step.file = best_found->file;
        Issue is;
        is.rule = best_found->rule;
        is.function = c.function;
        is.line = c.line;
        is.col = c.col;
        is.message = "text from outside is passed to " + c.callee + "(), which " +
                     (best_path.empty() ? "reaches " : "hands it on until it reaches ") +
                     best_found->call + "() in " + best_found->sink_function +
                     "() (" + file_name(best_found->file) + ":" +
                     std::to_string(best_found->sink_line) +
                     "): what that call does with this text is chosen by whoever "
                     "controls it";
        is.flow.push_back(c.origin);
        is.flow.push_back(FlowStep{c.callee + "()", c.function, c.line, c.col});
        for (const TaintEdge *e : best_path) {
            FlowStep hop{e->callee + "()", e->function, e->line, 0};
            hop.file = e->file;
            is.flow.push_back(std::move(hop));
        }
        is.flow.push_back(std::move(sink_step));

        const std::string key = best_found->file + "|" + best_found->sink_function +
                                "|" + std::to_string(best_found->sink_line) + "|" +
                                best_found->rule;
        auto it = best.find(key);
        if (it == best.end() || it->second.issue.flow.size() < is.flow.size())
            best[key] = Best{c.file, std::move(is)};
    }
    for (auto &[key, b] : best)
        out.emplace_back(b.file, std::move(b.issue));
    return out;
}
} // namespace lcstatic
