#include "parser.h"

#include <set>

namespace lcstatic {
namespace {

const std::set<std::string> kNotFunctions = {"if",
                                             "while",
                                             "for",
                                             "switch",
                                             "catch",
                                             "return",
                                             "sizeof",
                                             "alignof",
                                             "decltype",
                                             "typeid",
                                             "static_assert",
                                             "alignas",
                                             "__attribute__",
                                             "__declspec",
                                             "noexcept",
                                             "throw",
                                             "defined",
                                             "requires",
                                             "new",
                                             "delete"};

const std::set<std::string> kQualifiers = {
    "const", "volatile", "override", "final",     "noexcept",      "throw",
    "&",     "&&",       "mutable",  "constexpr", "__attribute__", "requires"};

class Parser {
  public:
    explicit Parser(const std::vector<Token> &t) : t_(t) {}

    std::vector<Function> run() {
        scope(0, t_.size());
        return std::move(out_);
    }

  private:
    template <std::size_t N> bool is(size_t i, const char (&s)[N]) const {
        return i < t_.size() && t_[i].is(s);
    }

    size_t match(size_t open) const {
        const Token &o = t_[open];
        if (o.kind == Tok::Punct && o.text.size() == 1) {
            const char oc = o.text[0];
            const char cc = oc == '(' ? ')' : oc == '[' ? ']' : '}';
            int depth = 0;
            for (size_t i = open; i < t_.size(); ++i) {
                if (t_[i].kind != Tok::Punct || t_[i].text.size() != 1)
                    continue;
                const char c = t_[i].text[0];
                if (c == oc)
                    ++depth;
                else if (c == cc && --depth == 0)
                    return i;
            }
            return t_.size();
        }
        const std::string &os = o.text;
        const std::string c = os == "(" ? ")" : os == "[" ? "]" : "}";
        int depth = 0;
        for (size_t i = open; i < t_.size(); ++i) {
            if (t_[i].kind != Tok::Punct)
                continue;
            if (t_[i].text == os)
                ++depth;
            else if (t_[i].text == c && --depth == 0)
                return i;
        }
        return t_.size();
    }

    // Skips a balanced <...> starting at i (t_[i] == "<"); returns index after
    // it.
    size_t skip_angles(size_t i, size_t e) const {
        int depth = 0;
        for (; i < e; ++i) {
            const std::string &x = t_[i].text;
            if (t_[i].kind != Tok::Punct)
                continue;
            if (x == "<")
                ++depth;
            else if (x == ">")
                --depth;
            else if (x == ">>")
                depth -= 2;
            else if (x == "(" || x == "[" || x == "{")
                i = match(i);
            else if (x == ";")
                return i;
            if (depth <= 0)
                return i + 1;
        }
        return e;
    }

    size_t skip_to_semicolon(size_t i, size_t e) const {
        for (; i < e; ++i) {
            if (is(i, ";"))
                return i + 1;
            if (is(i, "(") || is(i, "[") || is(i, "{"))
                i = match(i);
        }
        return e;
    }

    std::string function_name(size_t paren, size_t *start = nullptr) const {
        if (paren == 0)
            return {};
        size_t k = paren - 1;
        if (start)
            *start = k;
        const Token &last = t_[k];
        if (last.kind != Tok::Ident && last.kind != Tok::Punct)
            return {};
        // operator overloads: "operator" followed by symbol tokens
        for (size_t back = 0; back < 4 && back <= k; ++back) {
            if (t_[k - back].is("operator")) {
                std::string n;
                for (size_t j = k - back; j < paren; ++j)
                    n += t_[j].text;
                return n;
            }
        }
        if (last.kind != Tok::Ident || kNotFunctions.count(last.text))
            return {};
        std::string n = last.text;
        while (k >= 2 && (t_[k - 1].is("::") || t_[k - 1].is("~"))) {
            if (t_[k - 1].is("~")) {
                n = "~" + n;
                --k;
                if (k >= 2 && t_[k - 1].is("::") &&
                    t_[k - 2].kind == Tok::Ident) {
                    n = t_[k - 2].text + "::" + n;
                    k -= 2;
                    continue;
                }
                break;
            }
            if (t_[k - 2].kind != Tok::Ident)
                break;
            n = t_[k - 2].text + "::" + n;
            k -= 2;
        }
        if (start)
            *start = k;
        return n;
    }

    // From just after ')' of a parameter list, finds the body '{' if this is a
    // function definition (qualifiers, trailing return, ctor initializers).
    size_t body_start(size_t k, size_t e) const {
        while (k < e) {
            if (is(k, "{"))
                return k;
            if (t_[k].kind == Tok::Ident && kQualifiers.count(t_[k].text)) {
                ++k;
                if (is(k, "("))
                    k = match(k) + 1;
                continue;
            }
            if (is(k, "&") || is(k, "&&")) {
                ++k;
                continue;
            }
            if (is(k, "->")) { // trailing return type
                ++k;
                while (k < e && !is(k, "{") && !is(k, ";") && !is(k, "=")) {
                    if (is(k, "<"))
                        k = skip_angles(k, e);
                    else if (is(k, "("))
                        k = match(k) + 1;
                    else
                        ++k;
                }
                continue;
            }
            if (is(k, ":")) { // constructor member initializers
                ++k;
                while (k < e) {
                    while (k < e && !is(k, "(") && !is(k, "{") && !is(k, ";"))
                        k = is(k, "<") ? skip_angles(k, e) : k + 1;
                    if (k >= e || is(k, ";"))
                        return e;
                    k = match(k) + 1;
                    if (is(k, ",")) {
                        ++k;
                        continue;
                    }
                    break;
                }
                continue;
            }
            return e;
        }
        return e;
    }

    void scope(size_t b, size_t e) {
        size_t i = b;
        while (i < e) {
            const Token &tk = t_[i];
            if (tk.is("namespace")) {
                size_t k = i + 1;
                while (k < e && !is(k, "{") && !is(k, ";") && !is(k, "="))
                    ++k;
                if (is(k, "{")) {
                    size_t j = match(k);
                    scope(k + 1, j);
                    i = j + 1;
                } else {
                    i = skip_to_semicolon(k, e);
                }
                continue;
            }
            if (tk.is("extern") && i + 2 < e && t_[i + 1].kind == Tok::String &&
                is(i + 2, "{")) {
                size_t j = match(i + 2);
                scope(i + 3, j);
                i = j + 1;
                continue;
            }
            if (tk.is("class") || tk.is("struct") || tk.is("union")) {
                size_t k = i + 1;
                while (k < e && !is(k, "{") && !is(k, ";") && !is(k, "(") &&
                       !is(k, "=") && !is(k, ")") && !is(k, ","))
                    k = is(k, "<") ? skip_angles(k, e) : k + 1;
                if (is(k, "{")) {
                    size_t j = match(k);
                    scope(k + 1, j);
                    i = j + 1;
                    continue;
                }
                ++i;
                continue;
            }
            if (tk.is("enum")) {
                size_t k = i + 1;
                while (k < e && !is(k, "{") && !is(k, ";"))
                    ++k;
                i = is(k, "{") ? match(k) + 1 : k;
                continue;
            }
            if (tk.is("template") && is(i + 1, "<")) {
                i = skip_angles(i + 1, e);
                continue;
            }
            if (tk.is("=")) {
                i = skip_to_semicolon(i, e);
                continue;
            }
            if (tk.is("(")) {
                size_t j = match(i);
                if (j >= e) {
                    ++i;
                    continue;
                }
                size_t name_start = i;
                std::string name = function_name(i, &name_start);
                size_t k = body_start(j + 1, e);
                if (!name.empty() && k < e && is(k, "{")) {
                    size_t end = match(k);
                    Function f;
                    f.name = name;
                    f.returns_pointer =
                        name_start > 0 && is(name_start - 1, "*");
                    f.params.assign(t_.begin() + long(i) + 1,
                                    t_.begin() + long(j));
                    f.line = t_[i].line;
                    size_t pos = k;
                    f.body = stmt(pos, end + 1);
                    f.end_line = end < t_.size() ? t_[end].line : f.line;
                    out_.push_back(std::move(f));
                    i = end + 1;
                    continue;
                }
                i = j + 1;
                continue;
            }
            if (tk.is("{")) {
                i = match(i) + 1;
                continue;
            }
            ++i;
        }
    }

    // Tokens of an expression ending at ';' (consumed) or at a closing '}'.
    std::vector<Token> until_semicolon(size_t &i, size_t e) {
        size_t b = i;
        while (i < e && !is(i, ";") && !is(i, "}")) {
            if (is(i, "(") || is(i, "[") || is(i, "{"))
                i = match(i);
            ++i;
        }
        std::vector<Token> out(t_.begin() + long(b),
                               t_.begin() + long(std::min(i, e)));
        if (is(i, ";"))
            ++i;
        return out;
    }

    std::vector<Token> paren_contents(size_t &i, size_t e) {
        if (!is(i, "("))
            return {};
        size_t j = match(i);
        if (j >= e)
            j = e;
        std::vector<Token> out(t_.begin() + long(i) + 1, t_.begin() + long(j));
        i = j + 1;
        return out;
    }

    std::unique_ptr<Stmt> make(Stmt::Kind k, size_t at) {
        auto s = std::make_unique<Stmt>();
        s->kind = k;
        if (at < t_.size()) {
            s->line = t_[at].line;
            s->col = t_[at].col;
        }
        return s;
    }

    std::unique_ptr<Stmt> stmt(size_t &i, size_t e) {
        if (i >= e)
            return make(Stmt::Empty, i);
        const Token &tk = t_[i];
        const size_t at = i;
        if (tk.is("{")) {
            auto s = make(Stmt::Block, at);
            size_t j = std::min(match(i), e);
            s->end_line = j < t_.size() ? t_[j].line : s->line;
            size_t p = i + 1;
            while (p < j)
                s->kids.push_back(stmt(p, j));
            i = j + 1;
            return s;
        }
        if (tk.is("if")) {
            ++i;
            if (is(i, "constexpr"))
                ++i;
            auto s = make(Stmt::If, at);
            std::vector<Token> cond = paren_contents(i, e);
            // if (init; cond): run init as its own statement first
            std::unique_ptr<Stmt> init;
            for (size_t k = 0, depth = 0; k < cond.size(); ++k) {
                if (cond[k].is("(") || cond[k].is("[") || cond[k].is("{"))
                    ++depth;
                else if (cond[k].is(")") || cond[k].is("]") || cond[k].is("}"))
                    --depth;
                else if (depth == 0 && cond[k].is(";")) {
                    init = make(Stmt::Simple, at);
                    init->a.assign(cond.begin(), cond.begin() + long(k));
                    cond.erase(cond.begin(), cond.begin() + long(k) + 1);
                    break;
                }
            }
            s->a = std::move(cond);
            s->s1 = stmt(i, e);
            if (is(i, "else")) {
                ++i;
                s->s2 = stmt(i, e);
            }
            if (!init)
                return s;
            auto blk = make(Stmt::Block, at);
            blk->kids.push_back(std::move(init));
            blk->kids.push_back(std::move(s));
            return blk;
        }
        if (tk.is("while")) {
            ++i;
            auto s = make(Stmt::While, at);
            s->a = paren_contents(i, e);
            s->s1 = stmt(i, e);
            return s;
        }
        if (tk.is("do")) {
            ++i;
            auto s = make(Stmt::DoWhile, at);
            s->s1 = stmt(i, e);
            if (is(i, "while")) {
                ++i;
                s->a = paren_contents(i, e);
            }
            if (is(i, ";"))
                ++i;
            return s;
        }
        if (tk.is("for")) {
            ++i;
            auto s = make(Stmt::For, at);
            std::vector<Token> head = paren_contents(i, e);
            std::vector<std::vector<Token>> parts(1);
            size_t depth = 0;
            for (const Token &x : head) {
                if (x.is("(") || x.is("[") || x.is("{"))
                    ++depth;
                else if (x.is(")") || x.is("]") || x.is("}"))
                    --depth;
                if (depth == 0 && x.is(";")) {
                    parts.emplace_back();
                    continue;
                }
                parts.back().push_back(x);
            }
            if (parts.size() >= 3) {
                s->a = std::move(parts[0]);
                s->b = std::move(parts[1]);
                s->c = std::move(parts[2]);
            } else {
                s->range_for = true;
                // split "decl : range" at the top-level ':'
                std::vector<Token> &h = parts[0];
                size_t d = 0, colon = h.size();
                for (size_t k = 0; k < h.size(); ++k) {
                    if (h[k].is("(") || h[k].is("[") || h[k].is("{"))
                        ++d;
                    else if (h[k].is(")") || h[k].is("]") || h[k].is("}"))
                        --d;
                    else if (d == 0 && h[k].is(":")) {
                        colon = k;
                        break;
                    }
                }
                s->a.assign(h.begin(), h.begin() + long(colon));
                if (colon < h.size())
                    s->b.assign(h.begin() + long(colon) + 1, h.end());
            }
            s->s1 = stmt(i, e);
            return s;
        }
        if (tk.is("switch")) {
            ++i;
            auto s = make(Stmt::Switch, at);
            s->a = paren_contents(i, e);
            s->s1 = stmt(i, e);
            return s;
        }
        if (tk.is("case") || (tk.is("default") && is(i + 1, ":"))) {
            auto s = make(Stmt::Case, at);
            s->label = tk.text;
            while (i < e && !is(i, ":"))
                ++i;
            ++i;
            return s;
        }
        if (tk.is("return") || tk.is("co_return")) {
            ++i;
            auto s = make(Stmt::Return, at);
            s->a = until_semicolon(i, e);
            return s;
        }
        if (tk.is("break") || tk.is("continue")) {
            auto s = make(tk.is("break") ? Stmt::Break : Stmt::Continue, at);
            ++i;
            if (is(i, ";"))
                ++i;
            return s;
        }
        if (tk.is("goto")) {
            auto s = make(Stmt::Goto, at);
            ++i;
            if (i < e && t_[i].kind == Tok::Ident)
                s->label = t_[i++].text;
            if (is(i, ";"))
                ++i;
            return s;
        }
        if (tk.is("try")) {
            ++i;
            auto s = make(Stmt::Try, at);
            s->s1 = stmt(i, e);
            while (is(i, "catch")) {
                ++i;
                paren_contents(i, e);
                s->kids.push_back(stmt(i, e));
            }
            return s;
        }
        if (tk.kind == Tok::Ident && is(i + 1, ":") && !tk.is("default") &&
            !tk.is("public") && !tk.is("private") && !tk.is("protected")) {
            auto s = make(Stmt::Label, at);
            s->label = tk.text;
            i += 2;
            return s;
        }
        if (tk.is(";")) {
            ++i;
            return make(Stmt::Empty, at);
        }
        if (tk.is("}")) { // stray closer: skip
            ++i;
            return make(Stmt::Empty, at);
        }
        auto s = make(Stmt::Simple, at);
        s->a = until_semicolon(i, e);
        if (s->a.empty() && i < e && !is(i, "}"))
            ++i; // never stall
        return s;
    }

    const std::vector<Token> &t_;
    std::vector<Function> out_;
};

} // namespace

std::vector<Function> parse_functions(const std::vector<Token> &toks) {
    return Parser(toks).run();
}

} // namespace lcstatic
