// Unit tests for the reporter: runtime stream parsing, suppressions,
// severities, the JSON writer and the three renderers.
#include "check.h"

#include "internal.h"
#include "protocol.h"
#include "report.h"
#include "vulnerability.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <set>
#include <sstream>
#include <unistd.h>
#ifndef _WIN32
#include <fnmatch.h>
#endif

using namespace lcreport;

namespace {

std::string temp_file(const std::string &content) {
    const char *dir = std::getenv("TEMP"); // Windows; /tmp elsewhere
    std::string path = std::string(dir ? dir : "/tmp") + "/lc_reporter_XXXXXX";
    int fd = mkstemp(&path[0]);
    if (fd >= 0) {
        if (write(fd, content.data(), content.size()) < 0)
            std::perror("write");
        close(fd);
    }
    return path;
}

// Recursive-descent JSON validator: is s exactly one JSON value?
class JsonCheck {
  public:
    explicit JsonCheck(const std::string &s) : s_(s) {}
    bool valid() {
        bool ok = value();
        ws();
        return ok && i_ == s_.size();
    }

  private:
    void ws() {
        while (i_ < s_.size() &&
               std::isspace(static_cast<unsigned char>(s_[i_])))
            ++i_;
    }
    bool lit(const char *w) {
        size_t n = std::strlen(w);
        if (s_.compare(i_, n, w) != 0)
            return false;
        i_ += n;
        return true;
    }
    bool string() {
        if (s_[i_] != '"')
            return false;
        for (++i_; i_ < s_.size(); ++i_) {
            unsigned char c = static_cast<unsigned char>(s_[i_]);
            if (c < 0x20)
                return false;
            if (c == '\\') {
                ++i_;
                if (i_ >= s_.size() || !std::strchr("\"\\/bfnrtu", s_[i_]))
                    return false;
                if (s_[i_] == 'u') {
                    for (int k = 0; k < 4; ++k)
                        if (++i_ >= s_.size() ||
                            !std::isxdigit(static_cast<unsigned char>(s_[i_])))
                            return false;
                }
            } else if (c == '"') {
                ++i_;
                return true;
            }
        }
        return false;
    }
    bool number() {
        size_t b = i_;
        if (s_[i_] == '-')
            ++i_;
        while (i_ < s_.size() &&
               (std::isdigit(static_cast<unsigned char>(s_[i_])) ||
                std::strchr(".eE+-", s_[i_])))
            ++i_;
        return i_ > b && std::isdigit(static_cast<unsigned char>(s_[i_ - 1]));
    }
    bool value() {
        ws();
        if (i_ >= s_.size())
            return false;
        char c = s_[i_];
        if (c == '{' || c == '[') {
            const char close = c == '{' ? '}' : ']';
            ++i_;
            ws();
            if (i_ < s_.size() && s_[i_] == close) {
                ++i_;
                return true;
            }
            for (;;) {
                if (c == '{') {
                    ws();
                    if (!string())
                        return false;
                    ws();
                    if (i_ >= s_.size() || s_[i_++] != ':')
                        return false;
                }
                if (!value())
                    return false;
                ws();
                if (i_ < s_.size() && s_[i_] == ',') {
                    ++i_;
                    continue;
                }
                if (i_ < s_.size() && s_[i_] == close) {
                    ++i_;
                    return true;
                }
                return false;
            }
        }
        if (c == '"')
            return string();
        if (lit("true") || lit("false") || lit("null"))
            return true;
        return number();
    }
    const std::string &s_;
    size_t i_ = 0;
};

Frame frame(const std::string &fn, const std::string &file, int line,
            const std::string &module = "") {
    Frame f;
    f.function = fn;
    f.file = file;
    f.line = line;
    f.module = module;
    f.offset = 0x1234;
    return f;
}

Finding finding(const std::string &type, const std::string &category = "") {
    Finding f;
    f.type = type;
    f.category = category;
    f.message = "message for " + type;
    return f;
}

Report sample_dynamic() {
    Report r;
    r.mode = "dynamic";
    r.command = {"./prog", "arg with space"};
    r.ran = true;
    Finding df = finding(lcproto::kDoubleFree);
    df.address = 0x1000;
    df.size = 16;
    df.tid = 7;
    df.pid = 7;
    df.occurrences = 3;
    df.key = "k1";
    df.access = {frame("second", "/work/src/a.c", 10)};
    df.freed = {frame("first", "/work/src/a.c", 9)};
    df.alloc = {frame("make", "/work/src/a.c", 5),
                frame("main", "/work/src/a.c", 20)};
    Finding lk = finding(lcproto::kLeak, lcproto::kCatDefinite);
    lk.blocks = 2;
    lk.bytes = 64;
    lk.alloc = {frame("", "", 0, "/usr/lib/libz.so")};
    r.findings = {df, lk};
    Process p;
    p.pid = 7;
    p.exe = "/work/prog";
    p.complete = true;
    p.scanned = true;
    p.stats.allocs = 10;
    r.processes = {p};
    r.notes = {"a note with \"quotes\""};
    return r;
}

} // namespace

// ---------------------------------------------------------- stream parse

TEST(stream_parse_all_record_kinds) {
    const std::string path =
        temp_file("H v=1 pid=10 exe=/bin/prog with space\n"
                  "M 10 1 /bin/prog with space\n"
                  "M 10 2 /lib/libc.so.6\n"
                  "B type=double-free pid=10 addr=7f00 size=16 tid=10 key=abc "
                  "msg=free() on a 16-byte block = bad\n"
                  "S a 1:10 2:20\n"
                  "S l 1:30\n"
                  "S f 1:40 0:7fff\n"
                  "X\n"
                  "B type=memory-leak pid=10 addr=1000 size=8 tid=11 key=def "
                  "cat=definite blocks=3 "
                  "bytes=24 msg=24 byte(s) in 3 block(s) are definitely lost\n"
                  "S l 2:50\n"
                  "X\n"
                  "D key=abc count=3\n"
                  "T pid=10 allocs=5 frees=4 bytes=100 live_blocks=1 "
                  "live_bytes=8 peak_bytes=64 "
                  "dropped=2 scanned=1\n"
                  "Z pid=10\n"
                  "B type=invalid-free pid=11 addr=0 size=0 tid=11 key=ghi "
                  "msg=from a forked child\n"
                  "S a 1:60\n"
                  "X\n"
                  "H v=1 pid=11 exe=/bin/prog with space\n");
    Report r;
    CHECK(parse_runtime_stream(path, r));
    unlink(path.c_str());

    CHECK_EQ(r.processes.size(), size_t(2));
    CHECK_EQ(r.findings.size(), size_t(3));
    if (r.processes.size() != 2 || r.findings.size() != 3)
        return;
    const Process &p10 = r.processes[0];
    CHECK_EQ(p10.pid, 10u);
    CHECK_EQ(p10.exe, std::string("/bin/prog with space"));
    CHECK(p10.complete && p10.scanned);
    CHECK_EQ(p10.stats.allocs, uint64_t(5));
    CHECK_EQ(p10.stats.peak_bytes, uint64_t(64));
    CHECK_EQ(p10.stats.dropped, uint64_t(2));
    CHECK(!r.processes[1].complete);

    const Finding &df = r.findings[0];
    CHECK_EQ(df.type, std::string("double-free"));
    CHECK_EQ(df.address, uint64_t(0x7f00));
    CHECK_EQ(df.size, uint64_t(16));
    CHECK_EQ(df.message, std::string("free() on a 16-byte block = bad"));
    CHECK_EQ(df.occurrences, uint64_t(4));
    CHECK_EQ(df.access.size(), size_t(2));
    CHECK_EQ(df.access[0].module, std::string("/bin/prog with space"));
    CHECK_EQ(df.access[0].offset, uint64_t(0x10));
    CHECK_EQ(df.access[1].module, std::string("/lib/libc.so.6"));
    CHECK_EQ(df.freed.size(), size_t(2));
    CHECK_EQ(df.freed[1].module, std::string(""));
    CHECK_EQ(df.freed[1].offset, uint64_t(0x7fff));

    const Finding &lk = r.findings[1];
    CHECK_EQ(lk.category, std::string("definite"));
    CHECK_EQ(lk.blocks, uint64_t(3));
    CHECK_EQ(lk.bytes, uint64_t(24));
    CHECK_EQ(lk.tid, 11u);
    CHECK_EQ(lk.occurrences, uint64_t(1));

    // A forked child reuses its parent's module ids without new M records.
    CHECK_EQ(r.findings[2].pid, 11u);
    CHECK_EQ(r.findings[2].access[0].module,
             std::string("/bin/prog with space"));
}

TEST(stream_parse_missing_file) {
    Report r;
    CHECK(!parse_runtime_stream("/nonexistent/stream", r));
}

TEST(stream_parse_tolerates_junk) {
    const std::string path =
        temp_file("garbage\nS a 1:2\nX\nB\nB type=x\nS q 1:1\n\nT\nZ\n");
    Report r;
    CHECK(parse_runtime_stream(path, r));
    unlink(path.c_str());
    CHECK_EQ(r.findings.size(), size_t(2));
}

// ------------------------------------------------------------ severities

TEST(severity_and_problem_classification) {
    CHECK_EQ(severity_of(finding(lcproto::kLeak, lcproto::kCatDefinite)),
             std::string("error"));
    CHECK_EQ(severity_of(finding(lcproto::kLeak, lcproto::kCatPossible)),
             std::string("warning"));
    CHECK_EQ(severity_of(finding(lcproto::kLeak, lcproto::kCatIndirect)),
             std::string("note"));
    CHECK_EQ(severity_of(finding(lcproto::kLeak, lcproto::kCatReachable)),
             std::string("note"));
    CHECK_EQ(severity_of(finding(lcproto::kDoubleFree)), std::string("error"));
    CHECK_EQ(severity_of(finding(lcproto::kDoubleFree, "static")),
             std::string("warning"));
    CHECK(is_problem(finding(lcproto::kLeak, lcproto::kCatPossible)));
    CHECK(!is_problem(finding(lcproto::kLeak, lcproto::kCatReachable)));
    CHECK(!is_problem(finding(lcproto::kLeak, lcproto::kCatIndirect)));
    // Open at exit is certain but often deliberate; closing twice is a bug.
    CHECK_EQ(severity_of(finding(lcproto::kResourceLeak, lcproto::kCatFd)),
             std::string("warning"));
    CHECK(is_problem(finding(lcproto::kResourceLeak, lcproto::kCatThread)));
    CHECK_EQ(severity_of(finding(lcproto::kInheritedFd, lcproto::kCatFd)),
             std::string("warning"));
    CHECK_EQ(severity_of(finding(lcproto::kDoubleClose, lcproto::kCatStream)),
             std::string("error"));
    CHECK(is_resource(finding(lcproto::kMismatch, lcproto::kCatDir)));
    CHECK(is_resource(finding(lcproto::kResourceLeak, lcproto::kCatProcess)));
    CHECK(!is_resource(finding(lcproto::kLeak, lcproto::kCatDefinite)));
}

TEST(primary_frame_prefers_user_code) {
    Finding f = finding(lcproto::kLeak, lcproto::kCatDefinite);
    f.alloc = {
        frame("", "", 0, "/lib/libc.so.6"),
        frame("std::vector::push", "/usr/include/c++/16/bits/vector.tcc", 99),
        frame("load", "/home/me/app/load.cpp", 12)};
    const Frame *p = primary_frame(f);
    CHECK(p && p->function == "load");

    // glibc's debug info: relative source paths, told apart by the module
    Finding g = finding(lcproto::kSignalUnsafe, lcproto::kCatSignal);
    g.access = {
        frame("_IO_file_doallocate", "./libio/filedoalloc.c", 101,
              "/lib/x86_64-linux-gnu/libc.so.6"),
        frame("on_int", "/home/me/app/sig.c", 34, "/home/me/app/a.out")};
    p = primary_frame(g);
    CHECK(p && p->function == "on_int");

    Finding s = finding(lcproto::kLeak, "static");
    s.access = {frame("f", "/src/x.c", 14)};
    s.alloc = {frame("f", "/src/x.c", 10)};
    p = primary_frame(s);
    CHECK(p && p->line == 14); // static: where it leaks, not where allocated

    Finding raw = finding(lcproto::kDoubleFree);
    raw.access = {frame("", "", 0, "/lib/libfoo.so")};
    p = primary_frame(raw);
    CHECK(p && p->module == "/lib/libfoo.so");

    CHECK(primary_frame(finding(lcproto::kDoubleFree)) == nullptr);
}

// ---------------------------------------------------------- suppressions

TEST(suppressions_match_type_and_frames) {
    Report r;
    Finding leak = finding(lcproto::kLeak, lcproto::kCatDefinite);
    leak.alloc = {frame("lose_buffer", "/src/leaks.c", 16)};
    Finding df = finding(lcproto::kDoubleFree);
    df.access = {frame("main", "/src/heap_errors.c", 3)};
    Finding inv = finding(lcproto::kInvalidFree);
    inv.access = {frame("lose_other", "/src/x.c", 1)};
    Finding mod = finding(lcproto::kMismatch);
    mod.access = {frame("", "", 0, "/usr/lib/libfoo.so.1")};
    r.findings = {leak, df, inv, mod};

    const std::string path =
        temp_file("# comment\n\n  leak : lose_*  \n"
                  "double-free:*heap_errors.c\n*:*/libfoo.so*\n");
    std::string error;
    CHECK(apply_suppressions(path, r, &error));
    unlink(path.c_str());
    CHECK_EQ(r.findings.size(), size_t(1));
    if (!r.findings.empty())
        CHECK_EQ(r.findings[0].type, std::string(lcproto::kInvalidFree));
    CHECK(!r.notes.empty() &&
          r.notes.back().find("3 finding(s) suppressed") != std::string::npos);
}

TEST(suppressions_near_looks_at_the_innermost_frames_only) {
    // an interpreter's own allocation vs the program's, made through it
    Report r;
    Finding inside = finding(lcproto::kLeak, lcproto::kCatDefinite);
    inside.alloc = {frame("PyMem_RawMalloc", "", 0, "/usr/bin/python3"),
                    frame("PyUnicode_New", "", 0, "/usr/bin/python3"),
                    frame("main", "", 0, "/usr/bin/python3")};
    Finding mine = finding(lcproto::kLeak, lcproto::kCatDefinite);
    mine.alloc = {frame("ffi_call", "", 0, "/lib/libffi.so.8"),
                  frame("_ctypes_call", "", 0, "/usr/lib/_ctypes.so"),
                  frame("helper", "/src/ext.c", 9, "/usr/lib/_ext.so"),
                  frame("PyEval", "", 0, "/usr/bin/python3")};
    r.findings = {inside, mine};
    const std::string path = temp_file("leak:near:*/usr/bin/python3\n");
    std::string error;
    CHECK(apply_suppressions(path, r, &error));
    unlink(path.c_str());
    CHECK_EQ(r.findings.size(), size_t(1));
    if (!r.findings.empty())
        CHECK_EQ(r.findings[0].alloc[0].function, std::string("ffi_call"));
    // without near: the interpreter frame further up hides it too
    Report r2;
    r2.findings = {mine};
    const std::string path2 = temp_file("leak:*/usr/bin/python3\n");
    CHECK(apply_suppressions(path2, r2, &error));
    unlink(path2.c_str());
    CHECK(r2.findings.empty());
}

TEST(suppressions_top_matches_only_the_innermost_frame) {
    Report r;
    Finding inside = finding(lcproto::kLeak, lcproto::kCatDefinite);
    inside.alloc = {frame("PyMem_RawMalloc", "", 0, "/usr/bin/python3"),
                    frame("main", "", 0, "/usr/bin/python3")};
    Finding mine = finding(lcproto::kLeak, lcproto::kCatDefinite);
    mine.alloc = {frame("ffi_call", "", 0, "/lib/libffi.so"),
                  frame("PyMem_RawMalloc", "", 0, "/usr/bin/python3")};
    r.findings = {inside, mine};
    const std::string path = temp_file("leak:top:PyMem_*\n");
    std::string error;
    CHECK(apply_suppressions(path, r, &error));
    unlink(path.c_str());
    CHECK_EQ(r.findings.size(), size_t(1));
    if (!r.findings.empty())
        CHECK_EQ(r.findings[0].alloc[0].function, std::string("ffi_call"));
}

TEST(suppressions_star_matches_a_finding_with_no_stacks) {
    Report r;
    r.findings = {finding(lcproto::kLeak, lcproto::kCatDefinite)};
    const std::string path = temp_file("*:*\n");
    std::string error;
    CHECK(apply_suppressions(path, r, &error));
    unlink(path.c_str());
    CHECK(r.findings.empty());
    // A pattern that is not * still needs a frame.
    Report r2;
    r2.findings = {finding(lcproto::kLeak, lcproto::kCatDefinite)};
    const std::string path2 = temp_file("leak:main\n");
    CHECK(apply_suppressions(path2, r2, &error));
    unlink(path2.c_str());
    CHECK_EQ(r2.findings.size(), size_t(1));
}

TEST(suppressions_reject_bad_files) {
    Report r;
    std::string error;
    std::string path = temp_file("leak:ok\nno colon here\n");
    CHECK(!apply_suppressions(path, r, &error));
    CHECK(error.find(":2: expected <type>:<pattern>") != std::string::npos);
    unlink(path.c_str());
    path = temp_file(":pattern\n");
    CHECK(!apply_suppressions(path, r, &error));
    unlink(path.c_str());
    path = temp_file("type:\n");
    CHECK(!apply_suppressions(path, r, &error));
    unlink(path.c_str());
    CHECK(!apply_suppressions("/nonexistent/supp", r, &error));
    CHECK(error.find("cannot read") != std::string::npos);
}

TEST(default_suppressions_drop_loader_leaks_only) {
    Report r;
    Finding loader = finding(lcproto::kLeak, lcproto::kCatPossible);
    loader.alloc = {frame("malloc", "rtld-malloc.h", 56,
                          "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
                    frame("main", "/src/a.c", 3)};
    Finding user = finding(lcproto::kLeak, lcproto::kCatDefinite);
    user.alloc = {frame("main", "/src/a.c", 4)};
    Finding not_leak = finding(lcproto::kDoubleFree);
    not_leak.alloc = loader.alloc;
    r.findings = {loader, user, not_leak};
    apply_default_suppressions(r);
    CHECK_EQ(r.findings.size(), size_t(2));
    CHECK(!r.notes.empty());
}

TEST(memory_of_a_leaked_handle_is_reported_with_it) {
    const std::string libc = "/usr/lib/x86_64-linux-gnu/libc.so.6";
    Finding dir = finding(lcproto::kResourceLeak, lcproto::kCatDir);
    dir.alloc = {frame("leak_dir", "/work/r.c", 50, "/work/prog"),
                 frame("main", "/work/r.c", 90, "/work/prog")};
    // libc's buffer for that DIR: the same stack under two libc frames
    Finding buffer = finding(lcproto::kLeak, lcproto::kCatDefinite);
    buffer.alloc = {frame("__alloc_dir", "", 0, libc),
                    frame("opendir", "", 0, libc), dir.alloc[0], dir.alloc[1]};
    // Allocated by the program itself next to the open call: its own leak.
    Finding own = buffer;
    own.alloc[1] = frame("helper", "/work/r.c", 40, "/work/prog");
    // Same frames, but the handle is not leaked: nothing to fold into.
    Finding unrelated = buffer;
    unrelated.alloc[2] = frame("other", "/work/r.c", 60, "/work/prog");
    Report r;
    r.findings = {buffer, dir, own, unrelated};
    apply_default_suppressions(r);
    CHECK_EQ(r.findings.size(), size_t(3));
    for (const Finding &f : r.findings) // libc's buffer is the one gone
        CHECK(!(f.alloc.size() > 2 && f.alloc[1].function == "opendir" &&
                f.alloc[2].function == "leak_dir"));
    CHECK(!r.notes.empty() &&
          r.notes.back().find("1 memory leak report(s) belong to a leaked") !=
              std::string::npos);
}

// ------------------------------------------------------------------ json

TEST(json_writer_layout_and_escaping) {
    std::ostringstream os;
    Json j(os);
    j.begin_object();
    j.kv("s", "a\"b\\c\n\t\x01");
    j.kv("n", uint64_t(7));
    j.kv("i", -3);
    j.kv("b", true);
    j.key("z").null();
    j.key("arr").begin_array();
    j.value(uint64_t(1));
    j.begin_object().kv("k", "v").end_object();
    j.end_array();
    j.key("empty").begin_object().end_object();
    j.key("none").begin_array().end_array();
    j.end_object();
    const std::string want = "{\n"
                             "  \"s\": \"a\\\"b\\\\c\\n\\t\\u0001\",\n"
                             "  \"n\": 7,\n"
                             "  \"i\": -3,\n"
                             "  \"b\": true,\n"
                             "  \"z\": null,\n"
                             "  \"arr\": [\n"
                             "    1,\n"
                             "    {\n"
                             "      \"k\": \"v\"\n"
                             "    }\n"
                             "  ],\n"
                             "  \"empty\": {},\n"
                             "  \"none\": []\n"
                             "}\n";
    CHECK_EQ(os.str(), want);
    CHECK(JsonCheck(os.str()).valid());
}

TEST(json_writer_escapes_bytes_at_or_above_7f) {
    std::ostringstream os;
    Json j(os);
    std::string v = "a";
    v.push_back(char(0xff));
    v.push_back(char(0x7f));
    j.begin_object().kv("p", v).end_object();
    const std::string s = os.str();
    CHECK(s.find("\"p\": \"a\\u00ff\\u007f\"") != std::string::npos);
    CHECK(s.find('\xff') == std::string::npos);
    CHECK(JsonCheck(s).valid());
}

TEST(json_writer_writes_utf8_as_the_characters_it_is) {
    std::ostringstream os;
    Json j(os);
    // e-acute, dotless i, a four-byte emoji, and a truncated sequence at the end
    j.begin_object().kv("p", std::string("\xC3\xA9 \xC4\xB1 \xF0\x9F\x98\x80 \xC3")).end_object();
    const std::string s = os.str();
    CHECK(s.find("\"p\": \"\\u00e9 \\u0131 \\ud83d\\ude00 \\u00c3\"") != std::string::npos);
    CHECK(JsonCheck(s).valid());
    // not UTF-8: an overlong sequence, a surrogate, a lone continuation byte
    std::ostringstream os2;
    Json j2(os2);
    j2.begin_object().kv("p", std::string("\xC0\xAF\xED\xA0\x80\x80")).end_object();
    CHECK(os2.str().find("\\u00c0\\u00af\\u00ed\\u00a0\\u0080\\u0080") != std::string::npos);
    CHECK(JsonCheck(os2.str()).valid());
}

TEST(json_validator_self_check) {
    CHECK(JsonCheck("{\"a\": [1, -2.5e3, true, null, \"x\\u00e9\"]}").valid());
    CHECK(!JsonCheck("{\"a\": [1,]}").valid());
    CHECK(!JsonCheck("{\"a\" 1}").valid());
    CHECK(!JsonCheck("\"raw\nnewline\"").valid());
}

// ------------------------------------------------------------- renderers

TEST(render_json_is_valid_and_complete) {
    std::ostringstream os;
    render_json(sample_dynamic(), os);
    const std::string s = os.str();
    CHECK(JsonCheck(s).valid());
    CHECK(s.find("\"problems\": 2") != std::string::npos);
    CHECK(s.find("\"occurrences\": 3") != std::string::npos);
    CHECK(s.find("\"definite\": {") != std::string::npos);
    CHECK(s.find("\"arg with space\"") != std::string::npos);
    CHECK(s.find("a note with \\\"quotes\\\"") != std::string::npos);
}

TEST(render_sarif_is_valid) {
    std::ostringstream os;
    render_sarif(sample_dynamic(), os);
    const std::string s = os.str();
    CHECK(JsonCheck(s).valid());
    CHECK(s.find("\"version\": \"2.1.0\"") != std::string::npos);
    CHECK(s.find("\"ruleId\": \"double-free\"") != std::string::npos);
    CHECK(s.find("\"leakcheck/v1\": \"k1\"") != std::string::npos);
    CHECK(s.find("\"startLine\": 10") != std::string::npos);
    CHECK(s.find("file:///work/src/a.c") != std::string::npos);
}

TEST(render_sarif_relative_uris_under_cwd) {
    char cwd[4096];
    CHECK(getcwd(cwd, sizeof cwd) != nullptr);
    std::string here(cwd);
    std::replace(here.begin(), here.end(), '\\', '/'); // Windows: findings use '/'
    Report r;
    r.mode = "static";
    Finding f = finding(lcproto::kLeak, "static");
    f.access = {frame("fn", here + "/dir with space/a.c", 3)};
    r.findings = {f};
    std::ostringstream os;
    render_sarif(r, os);
    CHECK(JsonCheck(os.str()).valid());
    CHECK(os.str().find("\"uri\": \"dir%20with%20space/a.c\"") !=
          std::string::npos);
    CHECK(os.str().find("\"uriBaseId\": \"SRCROOT\"") != std::string::npos);
}

TEST(render_console_sections) {
    std::ostringstream os;
    render_console(sample_dynamic(), os);
    const std::string s = os.str();
    CHECK(s.find("[1] ERROR double-free: message for double-free") !=
          std::string::npos);
    CHECK(s.find("second release here:") != std::string::npos);
    CHECK(s.find("first released here:") != std::string::npos);
    CHECK(s.find("#1 main at /work/src/a.c:20") != std::string::npos);
    CHECK(s.find("(seen 3 times") != std::string::npos);
    CHECK(s.find("(libz.so+0x1234)") != std::string::npos);
    CHECK(s.find("definitely lost: 64 bytes in 2 blocks") != std::string::npos);
    CHECK(s.find("target:   exited with status 0") != std::string::npos);

    Report st;
    st.mode = "static";
    st.files_analyzed = 3;
    std::ostringstream os2;
    render_console(st, os2);
    CHECK(os2.str().find("files analyzed: 3") != std::string::npos);
    CHECK(os2.str().find("problems: 0") != std::string::npos);
}

TEST(render_console_resources) {
    Report r;
    r.mode = "dynamic";
    Finding leak = finding(lcproto::kResourceLeak, lcproto::kCatFd);
    leak.address = 5;
    leak.tid = 9;
    leak.alloc = {frame("serve", "/work/s.c", 12)};
    Finding twice = finding(lcproto::kDoubleClose, lcproto::kCatStream);
    twice.access = {frame("done", "/work/s.c", 30)};
    twice.freed = {frame("done", "/work/s.c", 29)};
    Finding thread = finding(lcproto::kResourceLeak, lcproto::kCatThread);
    thread.alloc = {frame("spawn", "/work/s.c", 40)};
    Finding child = finding(lcproto::kResourceLeak, lcproto::kCatProcess);
    child.alloc = {frame("run", "/work/s.c", 50)};
    r.findings = {leak, twice, thread, child};
    std::ostringstream os;
    render_console(r, os);
    const std::string s = os.str();
    CHECK(s.find("WARNING resource-leak (file descriptor): ") !=
          std::string::npos);
    CHECK(s.find("address") == std::string::npos); // the number is the handle
    CHECK(s.find("    thread 9\n") != std::string::npos);
    CHECK(s.find("opened here:\n      #0 serve at /work/s.c:12") !=
          std::string::npos);
    CHECK(s.find("second close here:") != std::string::npos);
    CHECK(s.find("first closed here:") != std::string::npos);
    CHECK(s.find("created here:\n      #0 spawn") != std::string::npos);
    CHECK(s.find("WARNING resource-leak (child process): ") !=
          std::string::npos);
    CHECK(s.find("created here:\n      #0 run") != std::string::npos);
    CHECK(s.find("problems: 4") != std::string::npos);
}

TEST(render_console_locks) {
    Report r;
    r.mode = "dynamic";
    Finding order = finding(lcproto::kLockOrder, lcproto::kCatLock);
    order.access = {frame("b_then_a", "/work/l.c", 22)};
    order.freed = {frame("b_then_a", "/work/l.c", 21)};
    order.alloc = {frame("a_then_b", "/work/l.c", 14)};
    Finding held = finding(lcproto::kLockLeak, lcproto::kCatLock);
    held.access = {frame("keep", "/work/l.c", 60)};
    held.alloc = {frame("spawn", "/work/l.c", 70)};
    Finding again = finding(lcproto::kDoubleLock, lcproto::kCatLock);
    again.access = {frame("relock", "/work/l.c", 81)};
    again.alloc = {frame("relock", "/work/l.c", 80)};
    Finding stat = finding(lcproto::kLockLeak, "static");
    stat.access = {frame("take", "/work/l.c", 90)};
    stat.alloc = {frame("take", "/work/l.c", 88)};
    Finding sig = finding(lcproto::kSignalUnsafe, lcproto::kCatSignal);
    sig.address = 2; // the signal: named in the message, not an address
    sig.access = {frame("on_int", "/work/l.c", 100)};
    sig.alloc = {frame("setup", "/work/l.c", 110)};
    r.findings = {order, held, again, stat, sig};
    std::ostringstream os;
    render_console(r, os);
    const std::string s = os.str();
    for (const char *want :
         {"locked here, while holding the other mutex:\n      #0 b_then_a",
          "the other mutex was locked here:\n      #0 b_then_a at /work/l.c:21",
          "locked in the opposite order here:\n      #0 a_then_b",
          "locked here:\n      #0 keep", "thread created here:\n      #0 spawn",
          "locked again here:\n      #0 relock at /work/l.c:81",
          "first locked here:\n      #0 relock at /work/l.c:80",
          "locked here:\n      #0 take at /work/l.c:88",
          "called here, inside the handler:\n      #0 on_int",
          "handler installed here:\n      #0 setup"})
        CHECK(s.find(want) != std::string::npos);
    CHECK(s.find("address 0x2") == std::string::npos);
    CHECK_EQ(severity_of(order), std::string("error"));
}

TEST(write_report_to_file_and_errors) {
    std::string error;
    CHECK(!write_report(sample_dynamic(), "json", "/nonexistent-dir/out.json",
                        &error));
    CHECK(error.find("cannot write report") != std::string::npos);
    const std::string path = temp_file("");
    CHECK(write_report(sample_dynamic(), "sarif", path, &error));
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    unlink(path.c_str());
    CHECK(JsonCheck(ss.str()).valid());
}

TEST(rule_table_is_consistent) {
    std::set<std::string> ids;
    for (const Rule &r : rules()) {
        CHECK(ids.insert(r.id).second);
        CHECK(*r.name && *r.summary && *r.help);
    }
    for (const char *t : {lcproto::kDoubleFree,     lcproto::kInvalidFree,
                          lcproto::kUseAfterFree,   lcproto::kOverflow,
                          lcproto::kUnderflow,      lcproto::kMismatch,
                          lcproto::kSizeMismatch,   lcproto::kLeak,
                          "dangling-pointer",       lcproto::kResourceLeak,
                          lcproto::kDoubleClose,    lcproto::kUseAfterClose,
                          lcproto::kLockLeak,       lcproto::kDoubleLock,
                          lcproto::kLockOrder,      lcproto::kSignalUnsafe,
                          lcproto::kInheritedFd,    lcproto::kUnlockedWait,
                          lcproto::kForeignUnlock,  lcproto::kDoubleJoin,
                          lcproto::kDestroyLocked,  lcproto::kUseAfterDestroy,
                          lcproto::kUncheckedStream, lcproto::kThreadStackArg,
                          lcproto::kSpuriousWakeup, lcproto::kOrphanedLock,
                          lcproto::kThreadUnsafe,   lcproto::kSigpipe,
                          lcproto::kEofSpin,        lcproto::kEagain,
                          lcproto::kBindReuse,
                          lcproto::kFdLimit,        lcproto::kSelectOverflow,
                          lcproto::kReverseShell,
                          lcproto::kDropper,        lcproto::kFileless,
                          lcproto::kPersistence,    lcproto::kCredAccess,
                          lcproto::kInjection,      lcproto::kAntiAnalysis,
                          lcproto::kPrivEsc,        lcproto::kLogTamper,
                          lcproto::kDestructive,    lcproto::kMiner,
                          lcproto::kFormatString,   lcproto::kCmdInjection,
                          lcproto::kUnboundedCopy,  lcproto::kUnboundedAlloca,
                          lcproto::kUnsafeFunction,
                          lcproto::kHardcodedSecret, lcproto::kToctou,
                          lcproto::kBadPermissions, lcproto::kWeakCrypto,
                          lcproto::kPathTraversal,
                          lcproto::kSizeofPointer,  lcproto::kAllocSizeOverflow,
                          lcproto::kTlsNoVerify,
                          lcproto::kSqlInjection,   lcproto::kNullDeref,
                          lcproto::kInsecurePrng,   lcproto::kSsrf,
                          lcproto::kXss,            lcproto::kOffByOne,
                          lcproto::kIntegerOverflow,
                          lcproto::kMasquerade,     lcproto::kSystemTamper,
                          lcproto::kMalware,        lcproto::kDisguised,
                          lcproto::kSuspiciousBin,
                          lcproto::kObfuscated,     lcproto::kRansom,
                          lcproto::kNetScan})
        CHECK(find_rule(t) != nullptr);
    CHECK(find_rule("nope") == nullptr);
}

TEST(vulnerability_metadata_rendered) {
    Report r;
    r.mode = "static";
    r.command = {"leakcheck", "static", "test.c"};
    Finding f = finding(lcproto::kSqlInjection, "static");
    f.message = "sqlite3_exec() runs SQL constructed from outside text";
    f.access = {frame("main", "/work/src/main.c", 42)};
    r.findings = {f};

    // 1. JSON renderer
    {
        std::ostringstream os;
        render_json(r, os);
        const std::string s = os.str();
        CHECK(JsonCheck(s).valid());
        CHECK(s.find("\"cwe\": 89") != std::string::npos);
        CHECK(s.find("\"vulnerability\": \"SQL Injection\"") != std::string::npos);
        CHECK(s.find("\"vuln_severity\": \"critical\"") != std::string::npos);
    }

    // 2. SARIF renderer
    {
        std::ostringstream os;
        render_sarif(r, os);
        const std::string s = os.str();
        CHECK(JsonCheck(s).valid());
        CHECK(s.find("\"external/cwe/cwe-89\"") != std::string::npos);
        CHECK(s.find("\"cwe\": 89") != std::string::npos);
        CHECK(s.find("\"security-severity\": \"9.0\"") != std::string::npos);
        CHECK(s.find("\"vulnerability\": \"SQL Injection\"") != std::string::npos);
    }

    // 3. Console renderer
    {
        std::ostringstream os;
        render_console(r, os);
        const std::string s = os.str();
        CHECK(s.find("vulnerability: CWE-89 (SQL Injection) [critical]") != std::string::npos);
    }
}

// Windows has no fnmatch, so suppress.cpp brings its own; on Linux it must agree.
TEST(glob_match_is_fnmatch) {
    struct Row {
        const char *pattern, *text;
        bool match;
    };
    const Row rows[] = {
        {"*", "", true},          {"*", "abc", true},         {"a*", "abc", true},
        {"a*c", "abc", true},     {"a*c", "abd", false},      {"?x", "ax", true},
        {"?x", "x", false},       {"[abc]x", "bx", true},     {"[abc]x", "dx", false},
        {"[!a]x", "bx", true},    {"[!a]x", "ax", false},     {"[a-c]x", "cx", true},
        {"[a-c]x", "dx", false},  {"*libc*", "/usr/lib/libc.so.6", true},
        {"a\\*", "a*", true},     {"a\\*", "ab", false},      {"[]a]", "]", true},
        {"", "", true},           {"", "a", false},           {"a?c*d", "abcxxd", true},
        {"**a", "bba", true},     {"*.c", "dir/a.c", true},   {"*.c", "a.cc", false},
    };
    for (const Row &r : rows) {
        CHECK_EQ(glob_match(r.pattern, r.text), r.match);
#ifndef _WIN32
        CHECK_EQ(fnmatch(r.pattern, r.text, 0) == 0, r.match);
#endif
    }
}

TEST_MAIN()
