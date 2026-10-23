#pragma once
#include "report.h"

#include <ostream>
#include <string>
#include <vector>

namespace lcreport {

struct Rule {
    const char *id;
    const char *name;
    const char *summary;
    const char *help;
};
const std::vector<Rule> &rules();
const Rule *find_rule(const std::string &id);

// About a descriptor, stream, directory or thread rather than memory.
bool is_resource(const Finding &f);

// Human label for each stack of a finding.
const char *access_label(const Finding &f);
const char *alloc_label(const Finding &f);
const char *freed_label(const Finding &f);

std::string hex(uint64_t v);

// Shell-style pattern match (`*`, `?`, `[..]`), the same as fnmatch(p, t, 0).
bool glob_match(const char *pattern, const char *text);

// Minimal streaming JSON writer.
class Json {
  public:
    explicit Json(std::ostream &os) : os_(os) {}
    Json &begin_object();
    Json &end_object();
    Json &begin_array();
    Json &end_array();
    Json &key(const std::string &k);
    Json &value(const std::string &v);
    Json &value(const char *v) { return value(std::string(v)); }
    Json &value(uint64_t v);
    Json &value(int64_t v);
    Json &value(int v) { return value(int64_t(v)); }
    Json &value(bool v);
    Json &null();
    Json &kv(const std::string &k, const std::string &v) {
        return key(k).value(v);
    }
    Json &kv(const std::string &k, const char *v) { return key(k).value(v); }
    Json &kv(const std::string &k, uint64_t v) { return key(k).value(v); }
    Json &kv(const std::string &k, int v) { return key(k).value(v); }
    Json &kv(const std::string &k, bool v) { return key(k).value(v); }

  private:
    void comma();
    void indent();
    void str(const std::string &s);
    std::ostream &os_;
    std::vector<bool> first_; // per open container: next element is the first
    bool after_key_ = false;
};

} // namespace lcreport
