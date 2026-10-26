#include "cache.h"

#include <cstdio>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace lcstatic {
namespace {

constexpr char kMagic[8] = {'L', 'K', 'C', 'A', 'C', 'H', 'E', '1'};

class Out {
  public:
    void u8(uint8_t v) { data_.push_back(char(v)); }
    void u32(uint32_t v) {
        for (int i = 0; i < 4; ++i)
            data_.push_back(char((v >> (8 * i)) & 0xff));
    }
    void u64(uint64_t v) {
        for (int i = 0; i < 8; ++i)
            data_.push_back(char((v >> (8 * i)) & 0xff));
    }
    void i32(int v) { u32(uint32_t(v)); }
    void str(const std::string &s) {
        u32(uint32_t(s.size()));
        data_ += s;
    }
    const std::string &data() const { return data_; }

  private:
    std::string data_;
};

class In {
  public:
    explicit In(std::string data) : data_(std::move(data)) {}
    bool u8(uint8_t *v) {
        if (at_ + 1 > data_.size())
            return false;
        *v = uint8_t(data_[at_++]);
        return true;
    }
    bool u32(uint32_t *v) {
        if (at_ + 4 > data_.size())
            return false;
        uint32_t x = 0;
        for (int i = 0; i < 4; ++i)
            x |= uint32_t(uint8_t(data_[at_++])) << (8 * i);
        *v = x;
        return true;
    }
    bool u64(uint64_t *v) {
        if (at_ + 8 > data_.size())
            return false;
        uint64_t x = 0;
        for (int i = 0; i < 8; ++i)
            x |= uint64_t(uint8_t(data_[at_++])) << (8 * i);
        *v = x;
        return true;
    }
    bool i32(int *v) {
        uint32_t x = 0;
        if (!u32(&x))
            return false;
        *v = int(x);
        return true;
    }
    bool str(std::string *s) {
        uint32_t n = 0;
        if (!u32(&n) || at_ + n > data_.size())
            return false;
        s->assign(data_, at_, n);
        at_ += n;
        return true;
    }

  private:
    std::string data_;
    size_t at_ = 0;
};

void frame(Out &o, const lcreport::Frame &f) {
    o.str(f.module);
    o.u64(f.offset);
    o.str(f.function);
    o.str(f.file);
    o.i32(f.line);
    o.i32(f.column);
    o.u8(f.inlined ? 1 : 0);
    o.str(f.what);
}

bool frame(In &i, lcreport::Frame *f) {
    uint8_t b = 0;
    if (!i.str(&f->module) || !i.u64(&f->offset) || !i.str(&f->function) ||
        !i.str(&f->file) || !i.i32(&f->line) || !i.i32(&f->column) || !i.u8(&b) ||
        !i.str(&f->what))
        return false;
    f->inlined = b != 0;
    return true;
}

void frames(Out &o, const std::vector<lcreport::Frame> &list) {
    o.u32(uint32_t(list.size()));
    for (const lcreport::Frame &f : list)
        frame(o, f);
}

bool frames(In &i, std::vector<lcreport::Frame> *list) {
    uint32_t n = 0;
    if (!i.u32(&n) || n > (1u << 24))
        return false;
    list->resize(n);
    for (lcreport::Frame &f : *list)
        if (!frame(i, &f))
            return false;
    return true;
}

void order(Out &o, const LockOrder &x) {
    o.str(x.held);
    o.str(x.taken);
    o.str(x.function);
    o.i32(x.line);
    o.i32(x.held_line);
    o.str(x.file);
    o.str(x.via);
}

bool order(In &i, LockOrder *x) {
    return i.str(&x->held) && i.str(&x->taken) && i.str(&x->function) &&
           i.i32(&x->line) && i.i32(&x->held_line) && i.str(&x->file) && i.str(&x->via);
}

void step(Out &o, const FlowStep &s) {
    o.str(s.what);
    o.str(s.function);
    o.i32(s.line);
    o.i32(s.col);
    o.i32(s.param);
    o.str(s.file);
}

bool step(In &i, FlowStep *s) {
    return i.str(&s->what) && i.str(&s->function) && i.i32(&s->line) && i.i32(&s->col) &&
           i.i32(&s->param) && i.str(&s->file);
}

void finding(Out &o, const lcreport::Finding &f) {
    o.str(f.type);
    o.str(f.category);
    o.str(f.message);
    o.str(f.key);
    o.u64(f.address);
    o.u64(f.size);
    o.u64(f.blocks);
    o.u64(f.bytes);
    o.u64(f.occurrences);
    o.u32(f.pid);
    o.u32(f.tid);
    frames(o, f.access);
    frames(o, f.flow);
    frames(o, f.alloc);
    frames(o, f.freed);
}

bool finding(In &i, lcreport::Finding *f) {
    return i.str(&f->type) && i.str(&f->category) && i.str(&f->message) && i.str(&f->key) &&
           i.u64(&f->address) && i.u64(&f->size) && i.u64(&f->blocks) &&
           i.u64(&f->bytes) && i.u64(&f->occurrences) && i.u32(&f->pid) &&
           i.u32(&f->tid) && frames(i, &f->access) && frames(i, &f->flow) &&
           frames(i, &f->alloc) && frames(i, &f->freed);
}

uint32_t count(size_t n) {
    return uint32_t(n);
}

void strings(Out &o, const std::set<std::string> &list) {
    o.u32(count(list.size()));
    for (const std::string &s : list)
        o.str(s);
}

bool strings(In &i, std::set<std::string> *list) {
    uint32_t n = 0;
    if (!i.u32(&n) || n > (1u << 24))
        return false;
    for (uint32_t k = 0; k < n; ++k) {
        std::string s;
        if (!i.str(&s))
            return false;
        list->insert(std::move(s));
    }
    return true;
}

void notes(Out &o, const std::vector<std::string> &list) {
    o.u32(count(list.size()));
    for (const std::string &s : list)
        o.str(s);
}

bool notes(In &i, std::vector<std::string> *list) {
    uint32_t n = 0;
    if (!i.u32(&n) || n > (1u << 24))
        return false;
    list->resize(n);
    for (std::string &s : *list)
        if (!i.str(&s))
            return false;
    return true;
}

} // namespace

uint64_t cache_key(const std::string &absolute_path, const std::string &content,
                   bool malware) {
    uint64_t h = 1469598103934665603ull;
    auto eat = [&](const std::string &s) {
        for (unsigned char c : s) {
            h ^= c;
            h *= 1099511628211ull;
        }
    };
    eat("leakcheck-static-cache");
    eat(std::to_string(kCacheParserVersion));
    eat(malware ? "malware" : "default");
    eat(absolute_path);
    eat("\x1f");
    eat(content);
    return h;
}

std::string cache_file(const std::string &directory, uint64_t key) {
    char name[64];
    std::snprintf(name, sizeof name, "%016llx.bin", static_cast<unsigned long long>(key));
    return (fs::path(directory) / name).generic_string();
}

bool save_cache(const std::string &path, const CachedFile &file) {
    Out o;
    o.u32(kCacheParserVersion);
    o.u8(file.analyzed ? 1 : 0);
    o.u32(count(file.findings.size()));
    for (const lcreport::Finding &f : file.findings)
        finding(o, f);
    notes(o, file.notes);
    o.u32(count(file.orders.size()));
    for (const LockOrder &x : file.orders)
        order(o, x);
    strings(o, file.shared_names);

    o.u32(count(file.taint.sinks.size()));
    for (const TaintSink &s : file.taint.sinks) {
        o.str(s.function);
        o.u32(uint32_t(s.param));
        o.str(s.rule);
        o.str(s.call);
        o.str(s.sink_function);
        o.str(s.file);
        o.i32(s.sink_line);
    }
    o.u32(count(file.taint.edges.size()));
    for (const TaintEdge &e : file.taint.edges) {
        o.str(e.function);
        o.u32(uint32_t(e.param));
        o.str(e.callee);
        o.u32(uint32_t(e.callee_param));
        o.i32(e.line);
        o.str(e.file);
    }
    o.u32(count(file.taint.callers.size()));
    for (const TaintCaller &c : file.taint.callers) {
        o.str(c.file);
        o.str(c.function);
        o.str(c.callee);
        o.u32(uint32_t(c.param));
        o.i32(c.line);
        o.i32(c.col);
        step(o, c.origin);
    }

    std::error_code ec;
    fs::create_directories(fs::path(path).parent_path(), ec);
    // A crash mid-write must not leave a half file that parses: write beside it
    // and rename, which replaces atomically.
    const std::string temp = path + ".new";
    {
        std::ofstream out(temp, std::ios::binary | std::ios::trunc);
        if (!out)
            return false;
        out.write(kMagic, sizeof kMagic);
        out.write(o.data().data(), std::streamsize(o.data().size()));
        if (!out)
            return false;
    }
    // Windows rename does not replace an existing file.
    fs::remove(path, ec);
    fs::rename(temp, path, ec);
    if (ec) {
        fs::remove(temp, ec);
        return false;
    }
    return true;
}

bool load_cache(const std::string &path, CachedFile *out) {
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return false;
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (data.size() < sizeof kMagic + 4 || data.compare(0, sizeof kMagic, kMagic, sizeof kMagic) != 0)
        return false;
    // Read after the magic; the length is part of the header, not a guess.
    In body(data.substr(sizeof kMagic));
    uint32_t version = 0;
    uint8_t analyzed = 0;
    if (!body.u32(&version) || version != kCacheParserVersion || !body.u8(&analyzed))
        return false;
    out->analyzed = analyzed != 0;
    uint32_t n = 0;
    if (!body.u32(&n) || n > (1u << 24))
        return false;
    out->findings.resize(n);
    for (lcreport::Finding &f : out->findings)
        if (!finding(body, &f))
            return false;
    if (!notes(body, &out->notes))
        return false;
    if (!body.u32(&n) || n > (1u << 24))
        return false;
    out->orders.resize(n);
    for (LockOrder &x : out->orders)
        if (!order(body, &x))
            return false;
    if (!strings(body, &out->shared_names))
        return false;
    if (!body.u32(&n) || n > (1u << 24))
        return false;
    out->taint.sinks.resize(n);
    for (TaintSink &s : out->taint.sinks) {
        uint32_t param = 0;
        if (!body.str(&s.function) || !body.u32(&param) || !body.str(&s.rule) ||
            !body.str(&s.call) || !body.str(&s.sink_function) || !body.str(&s.file) ||
            !body.i32(&s.sink_line))
            return false;
        s.param = param;
    }
    if (!body.u32(&n) || n > (1u << 24))
        return false;
    out->taint.edges.resize(n);
    for (TaintEdge &e : out->taint.edges) {
        uint32_t param = 0, callee_param = 0;
        if (!body.str(&e.function) || !body.u32(&param) || !body.str(&e.callee) ||
            !body.u32(&callee_param) || !body.i32(&e.line) || !body.str(&e.file))
            return false;
        e.param = param;
        e.callee_param = callee_param;
    }
    if (!body.u32(&n) || n > (1u << 24))
        return false;
    out->taint.callers.resize(n);
    for (TaintCaller &c : out->taint.callers) {
        uint32_t param = 0;
        if (!body.str(&c.file) || !body.str(&c.function) || !body.str(&c.callee) ||
            !body.u32(&param) || !body.i32(&c.line) || !body.i32(&c.col) ||
            !step(body, &c.origin))
            return false;
        c.param = param;
    }
    return true;
}

} // namespace lcstatic
