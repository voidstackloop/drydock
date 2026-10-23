#include "ai_features.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace lcscan {
namespace {

using Bytes = std::string;

uint16_t u16(const Bytes &b, size_t o) {
    return o + 2 <= b.size() ? uint16_t(uint8_t(b[o]) | (uint8_t(b[o + 1]) << 8)) : 0;
}

uint32_t u32(const Bytes &b, size_t o) {
    if (o + 4 > b.size())
        return 0;
    return uint32_t(uint8_t(b[o])) | (uint32_t(uint8_t(b[o + 1])) << 8) |
           (uint32_t(uint8_t(b[o + 2])) << 16) | (uint32_t(uint8_t(b[o + 3])) << 24);
}

uint64_t u64(const Bytes &b, size_t o) {
    return uint64_t(u32(b, o)) | (uint64_t(u32(b, o + 4)) << 32);
}

// log2(1+n): the features that grow with size are used as logs, so that a
// 100 KB stub and a 100 MB installer are not two different worlds to the model.
float lg(uint64_t n) { return float(std::log2(double(n) + 1.0)); }

float ratio(size_t part, size_t whole) {
    return whole ? float(double(part) / double(whole)) : 0.0f;
}

double entropy_of(const Bytes &b, size_t from, size_t len) {
    if (from >= b.size())
        return 0.0;
    len = std::min(len, b.size() - from);
    if (!len)
        return 0.0;
    size_t hist[256] = {};
    for (size_t i = 0; i < len; ++i)
        ++hist[uint8_t(b[from + i])];
    double e = 0.0;
    for (size_t h : hist) {
        if (!h)
            continue;
        const double p = double(h) / double(len);
        e -= p * std::log2(p);
    }
    return e;
}

size_t find_text(const Bytes &b, const char *needle, size_t limit) {
    const size_t n = std::strlen(needle);
    const size_t end = std::min(b.size(), limit);
    if (end < n)
        return 0;
    return b.find(needle, 0) < end ? 1 : 0;
}

size_t count_text(const Bytes &b, const char *needle, size_t limit) {
    const size_t n = std::strlen(needle);
    const size_t end = std::min(b.size(), limit);
    size_t count = 0;
    for (size_t at = b.find(needle); at != Bytes::npos && at < end;
         at = b.find(needle, at + n))
        ++count;
    return count;
}

bool contains_ci(const Bytes &b, size_t from, size_t to, const char *needle) {
    const size_t n = std::strlen(needle);
    if (n == 0 || to <= from || to - from < n || to > b.size())
        return false;
    for (size_t i = from; i + n <= to; ++i) {
        size_t k = 0;
        while (k < n && std::tolower(uint8_t(b[i + k])) == std::tolower(uint8_t(needle[k])))
            ++k;
        if (k == n)
            return true;
    }
    return false;
}

// Calls that, together with what they are called from, are how a program hides
// what it does: resolve an API by name at run time, become another process's
// parent, read what the user types.
const char *const kSuspiciousApis[] = {
    "loadlibrarya",     "loadlibraryw",     "getprocaddress",   "virtualalloc",
    "virtualprotect",   "writeprocessmemory", "createremotethread", "createthread",
    "openprocess",      "queueuserapc",     "ntunmapviewofsection", "setthreadcontext",
    "urldownloadtofile", "internetopenurl", "urlmon",           "winexec",
    "shellexecutea",    "shellexecutew",    "cryptencrypt",     "cryptgenkey",
    "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
    "getasynckeystate", "setwindowshookex", "regsetvalueex",    "adjusttokenprivileges",
    "wsa",              "wsasocket",         "connect",          "recv",
    "send",             "setsockopt",        "ping",             "createfilemapping",
    "ntcreatefile",     "rtladdvectoredexceptionhandler",
};

struct Section {
    uint32_t vsize = 0, vaddr = 0, rawsize = 0, rawptr = 0, flags = 0;
    char name[9] = {};
};

} // namespace

const char *const kAiFeatureNames[] = {
    "size_log",        "entropy",          "printable_ratio",   "zero_ratio",
    "sections",        "code_size_log",    "image_size_log",    "headers_size_log",
    "entry_log",       "entry_zero",       "pe32_plus",         "subsystem",
    "dll_characteristics", "section_align_log2", "file_align_log2", "timestamp_zero",
    "checksum_nonzero", "data_dirs",       "dir_export_log",    "dir_import_log",
    "dir_resource_log", "dir_exception_log", "dir_reloc_log",    "dir_debug_log",
    "dir_tls",         "dir_signature",    "dir_bound_import",  "import_dlls_log",
    "import_funcs_log", "import_suspicious", "export_funcs_log", "sec_max_entropy",
    "sec_mean_entropy", "sec_high_entropy", "sec_exec",         "sec_write",
    "sec_write_exec",  "sec_max_raw_log",  "sec_mean_raw_log",  "sec_max_vsize_ratio",
    "overlay_log",     "rich_header",      "urls_log",          "cmd_powershell",
    "dll_strings_log", "loadlib_getproc",  "pdb_path",          "dos_stub_standard",
    "sec_names_dotted",
};

const size_t kAiFeatureCount = sizeof(kAiFeatureNames) / sizeof(kAiFeatureNames[0]);

bool ai_pe_features(const Bytes &b, std::vector<float> *out) {
    if (b.size() < 64 || b[0] != 'M' || b[1] != 'Z')
        return false;
    const size_t pe = u32(b, 0x3c);
    if (pe + 24 > b.size() || std::memcmp(b.data() + pe, "PE\0\0", 4) != 0)
        return false;
    const uint16_t nsec = u16(b, pe + 6), optsize = u16(b, pe + 20);
    const size_t opt = pe + 24;
    if (optsize < 64 || opt + optsize > b.size())
        return false;
    const uint16_t magic = u16(b, opt);
    const bool plus = magic == 0x20b;
    if (!plus && magic != 0x10b)
        return false;

    std::vector<Section> sections;
    for (uint16_t i = 0; i < nsec && i < 96; ++i) {
        const size_t s = opt + optsize + size_t(i) * 40;
        if (s + 40 > b.size())
            break;
        Section sec;
        std::memcpy(sec.name, b.data() + s, 8);
        sec.vsize = u32(b, s + 8);
        sec.vaddr = u32(b, s + 12);
        sec.rawsize = u32(b, s + 16);
        sec.rawptr = u32(b, s + 20);
        sec.flags = u32(b, s + 36);
        sections.push_back(sec);
    }
    auto rva_to_off = [&](uint32_t rva) -> size_t {
        for (const Section &s : sections) {
            const uint32_t span = std::max(s.vsize, s.rawsize);
            if (rva >= s.vaddr && rva < s.vaddr + span) {
                const uint32_t delta = rva - s.vaddr;
                if (delta < s.rawsize)
                    return size_t(s.rawptr) + delta;
            }
        }
        return 0;
    };

    const size_t whole = b.size();
    size_t printable = 0, zeros = 0;
    const size_t counted = std::min<size_t>(whole, 4u << 20);
    for (size_t i = 0; i < counted; ++i) {
        const uint8_t c = uint8_t(b[i]);
        printable += (c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n' || c == '\r';
        zeros += c == 0;
    }

    const uint32_t entry = u32(b, opt + 16);
    const uint32_t image = u32(b, opt + 56);
    const uint32_t align = u32(b, opt + 32);
    const uint32_t file_align = u32(b, opt + 36);
    const uint16_t subsystem = u16(b, opt + 68);
    const uint16_t dllchar = u16(b, opt + 70);
    const uint32_t headers = u32(b, opt + 60);
    const uint32_t timestamp = u32(b, opt + 4);
    const uint32_t checksum = u32(b, opt + 64);
    const size_t dd = opt + (plus ? 112 : 96);
    auto dir = [&](int i) {
        const size_t at = dd + size_t(i) * 8;
        return at + 8 <= b.size() && at + 8 <= opt + optsize ? std::pair<uint32_t, uint32_t>(
                                                                   u32(b, at), u32(b, at + 4))
                                                             : std::pair<uint32_t, uint32_t>(0, 0);
    };

    // imports: the DLLs it needs and the API names it asks for
    size_t dlls = 0, funcs = 0, suspicious = 0;
    bool loadlib = false;
    const auto imp = dir(1);
    if (const size_t off = rva_to_off(imp.first); off && off + 20 <= b.size()) {
        for (size_t d = 0; d < 512; ++d) {
            const size_t at = off + d * 20;
            if (at + 20 > b.size())
                break;
            const uint32_t names = u32(b, at + 12), iat = u32(b, at + 16);
            const uint32_t thunk_rva = u32(b, at) ? u32(b, at) : iat;
            if (!names && !thunk_rva)
                break;
            ++dlls;
            const size_t name_off = rva_to_off(names);
            if (!name_off || name_off >= b.size())
                continue;
            const std::string dll(b.c_str() + name_off,
                                  std::min<size_t>(b.size() - name_off, 64));
            if (contains_ci(dll, 0, dll.size(), "kernel32") ||
                contains_ci(dll, 0, dll.size(), "ntdll"))
                loadlib = true;
            const size_t thunk = rva_to_off(thunk_rva);
            if (!thunk)
                continue;
            const size_t width = plus ? 8 : 4;
            for (size_t k = 0; k < 4096 && thunk + (k + 1) * width <= b.size(); ++k) {
                const uint64_t v = plus ? u64(b, thunk + k * width) : u32(b, thunk + k * width);
                if (!v)
                    break;
                ++funcs;
                const uint64_t ordinal = plus ? 0x8000000000000000ull : 0x80000000ull;
                if (v & ordinal)
                    continue;
                const size_t api_off = rva_to_off(uint32_t(v & 0x7fffffff));
                if (api_off + 2 >= b.size())
                    continue;
                for (const char *api : kSuspiciousApis) {
                    // the name follows the 2-byte hint
                    const size_t len = std::strlen(api);
                    if (api_off + 2 + len > b.size())
                        continue;
                    size_t eq = 0;
                    for (; eq < len; ++eq) {
                        const uint8_t c = uint8_t(b[api_off + 2 + eq]);
                        if (std::tolower(c) != api[eq])
                            break;
                    }
                    if (eq == len && (api_off + 2 + len == b.size() ||
                                      b[api_off + 2 + len] == '\0')) {
                        ++suspicious;
                        break;
                    }
                }
            }
        }
    }

    size_t exports = 0;
    const auto exp = dir(0);
    if (const size_t off = rva_to_off(exp.first); off && off + 24 <= b.size())
        exports = u32(b, off + 24);

    double max_entropy = 0.0, sum_entropy = 0.0;
    size_t high_entropy = 0, exec = 0, write = 0, wxe = 0;
    uint32_t max_raw = 0;
    double sum_raw = 0.0, max_ratio = 0.0;
    size_t dotted = 0;
    for (const Section &s : sections) {
        const double e = entropy_of(b, s.rawptr, s.rawsize);
        max_entropy = std::max(max_entropy, e);
        sum_entropy += e;
        high_entropy += e >= 7.2;
        exec += (s.flags & 0x20000000) != 0;
        write += (s.flags & 0x80000000) != 0;
        wxe += (s.flags & 0x20000000) && (s.flags & 0x80000000);
        max_raw = std::max(max_raw, s.rawsize);
        sum_raw += s.rawsize;
        if (s.rawsize)
            max_ratio = std::max(max_ratio, double(s.vsize) / double(s.rawsize));
        dotted += s.name[0] == '.';
    }
    const size_t n_sections = sections.size();

    uint32_t last = headers;
    for (const Section &s : sections)
        if (s.rawsize && s.rawptr + s.rawsize > last)
            last = s.rawptr + s.rawsize;
    const size_t overlay = whole > last ? whole - last : 0;

    const size_t strings = std::min<size_t>(whole, 4u << 20);
    const bool rich = pe >= 0x40 && b.find("Rich", 0x40) < std::min(pe + 8, b.size());

    const size_t urls = count_text(b, "http://", strings) + count_text(b, "https://", strings);
    const size_t dll_names = count_text(b, ".dll", strings);
    const bool shell =
        find_text(b, "cmd.exe", strings) || find_text(b, "powershell", strings) ||
        find_text(b, "PowerShell", strings);
    const bool getproc = b.find("GetProcAddress") < strings || b.find("LoadLibraryA") < strings ||
                         b.find("LoadLibraryW") < strings;
    const bool pdb = b.find(".pdb") < strings;
    const bool dos_stub =
        find_text(b, "This program cannot be run in DOS mode", 0x400);

    out->assign({
        lg(whole),                                    // size_log
        float(entropy_of(b, 0, counted)),             // entropy
        ratio(printable, counted),                    // printable_ratio
        ratio(zeros, counted),                        // zero_ratio
        float(n_sections),                            // sections
        lg(u32(b, opt + 4)),                          // code_size_log
        lg(image),                                    // image_size_log
        lg(headers),                                  // headers_size_log
        lg(entry),                                    // entry_log
        float(entry == 0),                            // entry_zero
        float(plus),                                  // pe32_plus
        float(subsystem),                             // subsystem
        float(dllchar),                               // dll_characteristics
        lg(align),                                    // section_align_log2
        lg(file_align),                               // file_align_log2
        float(timestamp == 0),                        // timestamp_zero
        float(checksum != 0),                         // checksum_nonzero
        float(nsec),                                  // data_dirs
        lg(dir(0).second),                            // dir_export_log
        lg(dir(1).second),                            // dir_import_log
        lg(dir(2).second),                            // dir_resource_log
        lg(dir(3).second),                            // dir_exception_log
        lg(dir(5).second),                            // dir_reloc_log
        lg(dir(6).second),                            // dir_debug_log
        float(dir(9).first != 0),                     // dir_tls
        float(dir(4).first != 0),                     // dir_signature
        float(dir(11).first != 0),                    // dir_bound_import
        lg(dlls),                                     // import_dlls_log
        lg(funcs),                                    // import_funcs_log
        float(suspicious),                            // import_suspicious
        lg(exports),                                  // export_funcs_log
        float(max_entropy),                           // sec_max_entropy
        float(n_sections ? sum_entropy / double(n_sections) : 0.0), // sec_mean_entropy
        float(high_entropy),                          // sec_high_entropy
        float(exec),                                  // sec_exec
        float(write),                                 // sec_write
        float(wxe),                                   // sec_write_exec
        lg(max_raw),                                  // sec_max_raw_log
        lg(uint64_t(n_sections ? sum_raw / double(n_sections) : 0.0)), // sec_mean_raw_log
        float(max_ratio),                             // sec_max_vsize_ratio
        lg(overlay),                                  // overlay_log
        float(rich),                                  // rich_header
        lg(urls),                                     // urls_log
        float(shell),                                 // cmd_powershell
        lg(dll_names),                                // dll_strings_log
        float(loadlib && getproc),                    // loadlib_getproc
        float(pdb),                                   // pdb_path
        float(dos_stub),                              // dos_stub_standard
        ratio(dotted, n_sections),                    // sec_names_dotted
    });
    return true;
}

// The columns ai_has_code reads, by position in kAiFeatureNames. ai_test.cpp
// checks the names at these positions, so moving a feature cannot silently
// point this at another number.
namespace {
constexpr size_t kEntryZeroColumn = 9; // entry_zero
constexpr size_t kSecExecColumn = 34;  // sec_exec
} // namespace

bool ai_has_code(const std::vector<float> &features) {
    if (features.size() != kAiFeatureCount)
        return false;
    // Nothing to run: resource-only satellite files (.mui, "-RES.dll", .tlb)
    // have no executable section and no entry point. Every malicious sample the
    // model was trained on has both, so this is not a class it knows.
    return features[kSecExecColumn] >= 1.0f && features[kEntryZeroColumn] == 0.0f;
}

std::string ai_features_line(const std::vector<float> &features) {
    std::string line;
    char buf[32];
    for (size_t i = 0; i < features.size(); ++i) {
        std::snprintf(buf, sizeof buf, "%.6g", double(features[i]));
        if (i)
            line.push_back(' ');
        line += buf;
    }
    return line;
}

} // namespace lcscan
