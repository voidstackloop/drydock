#include "lexer.h"

#include <cctype>
#include <cstring>
#include <string_view>

namespace lcstatic {
namespace {

class Lexer {
  public:
    explicit Lexer(const std::string &s) : s_(s) {}

    std::vector<Token> run() {
        bool line_start = true;
        while (i_ < s_.size()) {
            char c = s_[i_];
            if (c == '\n') {
                advance();
                line_start = true;
                continue;
            }
            if (!active()) {
                // Inside a preprocessor branch we do not take: only look for
                // the directives that end it.
                if (c == '#' && line_start) {
                    skip_directive();
                    continue;
                }
                if (c == '/' && peek(1) == '*') {
                    skip_block_comment();
                    continue;
                }
                if (!std::isspace(static_cast<unsigned char>(c)))
                    line_start = false;
                advance();
                continue;
            }
            if (std::isspace(static_cast<unsigned char>(c))) {
                advance();
                continue;
            }
            if (c == '\\' && peek(1) == '\n') {
                advance();
                advance();
                continue;
            }
            if (c == '/' && peek(1) == '/') {
                skip_line_comment();
                continue;
            }
            if (c == '/' && peek(1) == '*') {
                skip_block_comment();
                continue;
            }
            if (c == '#' && line_start) {
                skip_directive();
                continue;
            }
            line_start = false;
            const int line = line_, col = col_;
            if (std::isalpha(static_cast<unsigned char>(c)) || c == '_' ||
                c == '$') {
                std::string id = ident();
                if (!s_.compare(i_, 1, "\"") && is_raw_prefix(id)) {
                    out_.push_back({Tok::String, raw_string(), line, col});
                } else if ((c == 'L' || c == 'u' || c == 'U') &&
                           i_ < s_.size() &&
                           (s_[i_] == '"' || s_[i_] == '\'') &&
                           (id == "L" || id == "u" || id == "U" ||
                            id == "u8")) {
                    char q = s_[i_];
                    out_.push_back({q == '"' ? Tok::String : Tok::Char,
                                    quoted(q), line, col});
                } else {
                    out_.push_back({Tok::Ident, id, line, col});
                }
                continue;
            }
            if (std::isdigit(static_cast<unsigned char>(c)) ||
                (c == '.' &&
                 std::isdigit(static_cast<unsigned char>(peek(1))))) {
                out_.push_back({Tok::Number, number(), line, col});
                continue;
            }
            if (c == '"') {
                out_.push_back({Tok::String, quoted('"'), line, col});
                continue;
            }
            if (c == '\'') {
                out_.push_back({Tok::Char, quoted('\''), line, col});
                continue;
            }
            out_.push_back({Tok::Punct, punct(), line, col});
        }
        return std::move(out_);
    }

  private:
    char peek(size_t k) const { return i_ + k < s_.size() ? s_[i_ + k] : '\0'; }

    void advance() {
        if (s_[i_] == '\n') {
            ++line_;
            col_ = 1;
        } else {
            ++col_;
        }
        ++i_;
    }

    void skip_line_comment() {
        while (i_ < s_.size() && s_[i_] != '\n') {
            if (s_[i_] == '\\' && peek(1) == '\n')
                advance();
            advance();
        }
    }

    void skip_block_comment() {
        advance();
        advance();
        while (i_ < s_.size() && !(s_[i_] == '*' && peek(1) == '/'))
            advance();
        if (i_ < s_.size()) {
            advance();
            advance();
        }
    }

    // Without macro definitions we cannot evaluate #if, so like ctags we take
    // the first branch of every conditional (except literal "#if 0"). Taking
    // both branches would duplicate braces and break function boundaries.
    struct Cond {
        bool parent_active;
        bool taken;
        bool active;
    };

    bool active() const { return conds_.empty() || conds_.back().active; }

    void skip_directive() {
        advance(); // '#'
        std::string text;
        while (i_ < s_.size() && s_[i_] != '\n') {
            if (s_[i_] == '\r') { // a CRLF file: "#endif\r" is "#endif"
                advance();
                continue;
            }
            if (s_[i_] == '\\' && (peek(1) == '\n' || (peek(1) == '\r' && peek(2) == '\n'))) {
                while (s_[i_] != '\n')
                    advance();
                advance();
                text += ' ';
                continue;
            }
            if (s_[i_] == '/' && peek(1) == '*') {
                skip_block_comment();
                text += ' ';
                continue;
            }
            if (s_[i_] == '/' && peek(1) == '/') {
                skip_line_comment();
                break;
            }
            text += s_[i_];
            advance();
        }
        size_t b = text.find_first_not_of(" \t");
        if (b == std::string::npos)
            return;
        size_t e = text.find_first_of(" \t(", b);
        const std::string name =
            text.substr(b, e == std::string::npos ? std::string::npos : e - b);
        std::string expr =
            e == std::string::npos ? std::string() : text.substr(e);
        size_t xb = expr.find_first_not_of(" \t"),
               xe = expr.find_last_not_of(" \t\r");
        expr = xb == std::string::npos ? std::string()
                                       : expr.substr(xb, xe - xb + 1);
        const bool literal_false = expr == "0" || expr == "(0)";
        if (name == "if" || name == "ifdef" || name == "ifndef") {
            const bool parent = active();
            const bool value = !(name == "if" && literal_false);
            conds_.push_back(Cond{parent, value, parent && value});
        } else if ((name == "elif" || name == "elifdef" ||
                    name == "elifndef") &&
                   !conds_.empty()) {
            Cond &c = conds_.back();
            const bool value = !(name == "elif" && literal_false);
            c.active = c.parent_active && !c.taken && value;
            c.taken = c.taken || value;
        } else if (name == "else" && !conds_.empty()) {
            Cond &c = conds_.back();
            c.active = c.parent_active && !c.taken;
            c.taken = true;
        } else if (name == "endif" && !conds_.empty()) {
            conds_.pop_back();
        }
    }

    std::string ident() {
        size_t b = i_;
        while (i_ < s_.size() &&
               (std::isalnum(static_cast<unsigned char>(s_[i_])) ||
                s_[i_] == '_' || s_[i_] == '$'))
            advance();
        return s_.substr(b, i_ - b);
    }

    static bool is_raw_prefix(const std::string &id) {
        return id == "R" || id == "LR" || id == "uR" || id == "UR" ||
               id == "u8R";
    }

    std::string raw_string() {
        size_t b = i_;
        advance(); // "
        std::string delim;
        while (i_ < s_.size() && s_[i_] != '(')
            delim += s_[i_], advance();
        const std::string end = ")" + delim + "\"";
        while (i_ < s_.size() && s_.compare(i_, end.size(), end) != 0)
            advance();
        for (size_t k = 0; k < end.size() && i_ < s_.size(); ++k)
            advance();
        return s_.substr(b, i_ - b);
    }

    std::string quoted(char q) {
        size_t b = i_;
        advance();
        while (i_ < s_.size() && s_[i_] != q && s_[i_] != '\n') {
            if (s_[i_] == '\\' && i_ + 1 < s_.size())
                advance();
            advance();
        }
        if (i_ < s_.size() && s_[i_] == q)
            advance();
        return s_.substr(b, i_ - b);
    }

    std::string number() {
        size_t b = i_;
        while (i_ < s_.size()) {
            char c = s_[i_];
            if (std::isalnum(static_cast<unsigned char>(c)) || c == '.' ||
                c == '_' ||
                (c == '\'' &&
                 std::isxdigit(static_cast<unsigned char>(peek(1))))) {
                char p = c;
                advance();
                if ((p == 'e' || p == 'E' || p == 'p' || p == 'P') &&
                    i_ < s_.size() && (s_[i_] == '+' || s_[i_] == '-'))
                    advance();
            } else {
                break;
            }
        }
        return s_.substr(b, i_ - b);
    }

    std::string punct() {
        // Every punctuation character in the source walks this table, so the
        // lengths are part of the type: a `const char *` table strlen'd each
        // entry, which was most of what the lexer spent on punctuation.
        static const std::string_view ops[] = {
            "<<=", ">>=", "->*", "...", "<=>", "::", "->", "++", "--",
            "<<",  ">>",  "<=",  ">=",  "==",  "!=", "&&", "||", "+=",
            "-=",  "*=",  "/=",  "%=",  "&=",  "|=", "^=", ".*", "##"};
        for (std::string_view op : ops) {
            const size_t n = op.size();
            if (s_.compare(i_, n, op.data(), n) == 0) {
                for (size_t k = 0; k < n; ++k)
                    advance();
                return std::string(op);
            }
        }
        std::string one(1, s_[i_]);
        advance();
        return one;
    }

    const std::string &s_;
    size_t i_ = 0;
    int line_ = 1, col_ = 1;
    std::vector<Token> out_;
    std::vector<Cond> conds_;
};

} // namespace

std::vector<Token> lex(const std::string &src) { return Lexer(src).run(); }

} // namespace lcstatic
