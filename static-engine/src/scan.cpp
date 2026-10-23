#include "scan.h"
#include "malware_scan.h"
#include "protocol.h"
#include "rules.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <map>
#include <set>
#include <string_view>

namespace lcscan {
namespace {

using Bytes = std::string;

uint16_t u16(const Bytes &b, size_t o) {
    return o + 2 <= b.size() ? uint16_t(uint8_t(b[o]) | uint8_t(b[o + 1]) << 8) : 0;
}
uint32_t u32(const Bytes &b, size_t o) {
    return o + 4 <= b.size() ? uint32_t(u16(b, o)) | uint32_t(u16(b, o + 2)) << 16 : 0;
}
uint64_t u64(const Bytes &b, size_t o) {
    return o + 8 <= b.size() ? uint64_t(u32(b, o)) | uint64_t(u32(b, o + 4)) << 32 : 0;
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

std::string base_of(const std::string &path) {
    const size_t s = path.rfind('/');
    return s == std::string::npos ? path : path.substr(s + 1);
}

// "pdf" for "Report.PDF"; "" without a dot.
std::string ext_of(const std::string &name) {
    const size_t d = name.rfind('.');
    return d == std::string::npos || d + 1 == name.size() ? std::string() : lower(name.substr(d + 1));
}

const std::set<std::string> kDocExts = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
                                        "txt", "rtf", "jpg", "jpeg", "png", "gif", "bmp",
                                        "mp3", "mp4", "avi", "mov", "wav", "odt", "ods",
                                        "csv", "mkv", "ico"};
const std::set<std::string> kExecExts = {"exe", "scr", "com", "bat", "cmd", "js", "jse",
                                         "vbs", "vbe", "ps1", "sh", "jar", "lnk", "pif",
                                         "msi", "run", "bin", "wsf", "hta", "cpl"};
const std::set<std::string> kScriptExts = {"sh", "bash", "py", "pl", "rb", "php", "js", "ps1",
                                           "bat", "cmd", "vbs", "awk", "lua", "tcl", "csh",
                                           "zsh", "fish", "jsp", "asp", "aspx", "psm1"};

using lcrules::kWindowsNames;

bool in_windows_dir(const std::string &path) {
    const std::string p = lower(path);
    return p.find("/windows/system32/") != std::string::npos ||
           p.find("/windows/syswow64/") != std::string::npos ||
           p.find("/windows/winsxs/") != std::string::npos ||
           p.find("\\windows\\system32\\") != std::string::npos ||
           p.find("\\windows\\syswow64\\") != std::string::npos;
}

bool transposed(const std::string &a, const std::string &b) {
    if (a.size() != b.size() || a == b)
        return false;
    size_t i = 0;
    while (i < a.size() && a[i] == b[i])
        ++i;
    return i + 1 < a.size() && a[i] == b[i + 1] && a[i + 1] == b[i] &&
           a.compare(i + 2, std::string::npos, b, i + 2, std::string::npos) == 0;
}

// Is `name` one letter, one look-alike or one swap away from `trusted`?
bool lookalike_of(const std::string &name, const std::string &trusted) {
    if (name == trusted || trusted.size() < 5)
        return false;
    char folded[256];
    if (name.size() >= sizeof folded)
        return false;
    lcrules::fold_lookalikes(name.c_str(), name.size(), folded, sizeof folded);
    return trusted == folded || lcrules::one_edit(name.c_str(), trusted.c_str()) ||
           transposed(name, trusted);
}

class Collector {
  public:
    explicit Collector(std::vector<size_t> *more) : more_(more) {}

    void add(const char *type, const std::string &message, size_t offset = 0) {
        for (size_t i = 0; i < hits_.size(); ++i)
            if (hits_[i].type == type) {
                ++extra_[i];
                return;
            }
        hits_.push_back({type, message, offset});
        extra_.push_back(0);
    }

    std::vector<Hit> finish() {
        if (more_)
            *more_ = extra_;
        return std::move(hits_);
    }

  private:
    std::vector<Hit> hits_;
    std::vector<size_t> extra_;
    std::vector<size_t> *more_;
};

// ---- the name -----------------------------------------------------------------

void name_checks(const std::string &path, Kind kind, Collector *c) {
    const std::string name = base_of(path);
    const std::string low = lower(name);
    const bool program = kind == Kind::Elf || kind == Kind::Pe || kind == Kind::MachO ||
                         kind == Kind::Script;

    // ".pdf.exe", "photo.jpg      .scr": the last extension runs, the first is shown
    const std::string last = ext_of(low);
    if (kExecExts.count(last)) {
        std::string stem = low.substr(0, low.size() - last.size() - 1);
        while (!stem.empty() && stem.back() == ' ')
            stem.pop_back();
        const std::string before = ext_of(stem);
        if (kDocExts.count(before))
            c->add(lcproto::kMasquerade,
                   "its name \"" + name + "\" ends in two extensions: it looks like a ." +
                       before + " document and runs as ." + last);
    }
    // right-to-left override and the other direction controls: "photognp.exe"
    for (const char *bidi : {"\xE2\x80\xAE", "\xE2\x80\xAD", "\xE2\x80\xAB", "\xE2\x80\xAA",
                             "\xE2\x81\xA6", "\xE2\x81\xA7", "\xE2\x81\xA8"})
        if (name.find(bidi) != std::string::npos) {
            c->add(lcproto::kMasquerade,
                   "its name contains a text direction control (U+202E and the like): "
                   "the name is shown reversed or rearranged so that a program looks "
                   "like a document");
            break;
        }
    if (!program)
        return;

    // a program named like a system program, where the system's are not
    std::string stem = low;
    if (const std::string e = ext_of(low); e == "exe" || e == "scr" || e == "com" || e == "dll")
        stem = low.substr(0, low.size() - e.size() - 1);
    for (const char *w : kWindowsNames) {
        if (stem == w && !in_windows_dir(path) && (kind == Kind::Pe || ext_of(low) == "exe" || ext_of(low) == "scr")) {
            c->add(lcproto::kMasquerade,
                   "it is called \"" + name + "\", the name of a Windows system process, but "
                   "it is not in the Windows directory: the real one is only ever "
                   "in System32");
            break;
        }
        if (lookalike_of(stem, w) && (kind == Kind::Pe || ext_of(low) == "exe"))
            c->add(lcproto::kMasquerade,
                   "its name \"" + name + "\" is one letter away from \"" + w +
                       "\", a Windows system process: a glance at the process list "
                       "takes it for the real one");
    }
    // a Mach-O binary named like a macOS system process, where the real one is not
    if (kind == Kind::MachO) {
        if (lcrules::mac_name(name.c_str()) && !lcrules::system_dir(path.c_str()))
            c->add(lcproto::kMasquerade,
                   "it is called \"" + name + "\", the name of a macOS system process, but "
                   "it is not under /System or /usr: the real one only ever runs from there");
        for (const char *w : lcrules::kMacNames)
            if (lookalike_of(stem, lower(w)))
                c->add(lcproto::kMasquerade,
                       "its name \"" + name + "\" is one letter away from \"" + w +
                           "\", a macOS system process: a glance at Activity Monitor "
                           "takes it for the real one");
    }
    if (kind != Kind::Pe) {
        if (lcrules::trusted_name(name.c_str()) && !lcrules::system_dir(path.c_str()) &&
            lcrules::hiding_place(path.c_str()))
            c->add(lcproto::kMasquerade,
                   "it is called \"" + name + "\" like a program the system trusts, but it is "
                   "in a place any user can write: malware hides in the process list "
                   "and in PATH under such a name");
        for (const char *t : lcrules::kTrusted)
            if (lookalike_of(name, t) && !lcrules::system_dir(path.c_str()))
                c->add(lcproto::kMasquerade,
                       "its name \"" + name + "\" is one letter away from \"" + t +
                           "\", a program the system trusts");
    }
}

// ---- strings in the bytes ---------------------------------------------------------

bool contains(const Bytes &b, const char *needle) { return b.find(needle) != Bytes::npos; }

// A command line that rules.h knows, or a host name that imitates a trusted one.
void text_checks(const char *s, size_t offset, Collector *c, bool malware) {
    char norm[1024];
    lcrules::normalize(s, norm, sizeof norm);
    for (const lcrules::Cmd &cmd : lcrules::kCmds)
        if (lcrules::has_all(norm, cmd))
            c->add(cmd.type, std::string("it contains a command line that ") + cmd.what + ": " +
                                 std::string(s).substr(0, 100),
                   offset);
    // Windows is case-blind: batch, PowerShell and VBScript lines are matched in lower case.
    char low[sizeof norm];
    size_t li = 0;
    for (; norm[li]; ++li)
        low[li] = norm[li] >= 'A' && norm[li] <= 'Z' ? char(norm[li] | 0x20) : norm[li];
    low[li] = 0;
    for (const lcrules::Cmd &cmd : lcrules::kWinCmds)
        if (lcrules::has_all(low, cmd))
            c->add(cmd.type, std::string("it contains a command line that ") + cmd.what + ": " +
                                 std::string(s).substr(0, 100),
                   offset);
    if (malware)
        for (const lcrules::MalCmd &cmd : lcrules::kMalCmds)
            if (lcrules::has_all_mal(low, cmd))
                c->add(cmd.type, std::string("it contains a command line that ") + cmd.what + ": " +
                                     std::string(s).substr(0, 100),
                       offset);
    if (lcrules::downloads_into_interpreter(norm))
        c->add(lcproto::kDropper,
               std::string("it contains a command line that downloads or decodes code and "
                           "runs it at once: ") + std::string(s).substr(0, 100),
               offset);
    for (const char *p = s; (p = strstr(p, "://")); p += 3) {
        const char *h = p + 3;
        const size_t len = strcspn(h, "/?# \"'<>");
        char host[256];
        const size_t n = len < sizeof host - 1 ? len : sizeof host - 1;
        memcpy(host, h, n);
        host[n] = 0;
        const char *at = strrchr(host, '@');
        if (const char *t = lcrules::imitates(at ? at + 1 : host))
            c->add(lcproto::kMasquerade,
                   std::string("it uses the host name \"") + (at ? at + 1 : host) +
                       "\", made to look like " + t + ": malware names its servers after "
                       "the sites you trust",
                   offset);
    }
}

// Every line of a script, or every printable run of a binary.
void string_checks(const Bytes &b, Kind kind, Collector *c, bool malware) {
    const size_t limit = std::min<size_t>(b.size(), 16u << 20);
    const bool lines = kind == Kind::Script || kind == Kind::Text;
    size_t start = 0;
    auto flush = [&](size_t end) {
        const size_t len = end - start;
        if (len >= (lines ? 8u : 10u) && len <= 2048) {
            std::string s = b.substr(start, len);
            // a command has spaces or slashes; most strings of a binary have neither
            if (s.find_first_of(" /|") != std::string::npos || s.find("://") != std::string::npos)
                text_checks(s.c_str(), start, c, malware);
        }
    };
    for (size_t i = 0; i < limit; ++i) {
        const uint8_t ch = uint8_t(b[i]);
        const bool end = lines ? ch == '\n' : !(ch == '\t' || (ch >= 0x20 && ch < 0x7f));
        if (end) {
            flush(i);
            start = i + 1;
        }
    }
    flush(limit);
}

// ---- signatures --------------------------------------------------------------------

struct Needle {
    const char *text;
    const char *type;
    const char *what;
};

// (the EICAR string is written in pieces: this file is not itself a test file)
const char kEicarHead[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$";
const char kEicarTail[] = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

const Needle kNeedles[] = {
    {"stratum+tcp://", lcproto::kMiner, "the address of a mining pool (stratum+tcp://)"},
    {"stratum+ssl://", lcproto::kMiner, "the address of a mining pool (stratum+ssl://)"},
    {"stratum2+tcp://", lcproto::kMiner, "the address of a mining pool (stratum2+tcp://)"},
    {"--donate-level", lcproto::kMiner, "the donate-level option of the XMRig miner"},
    {"c99shell", lcproto::kMalware, "the name of the c99 web shell"},
    {"r57shell", lcproto::kMalware, "the name of the r57 web shell"},
    {"b374k", lcproto::kMalware, "the name of the b374k web shell"},
    {"FilesMan", lcproto::kMalware, "the menu of the WSO web shell"},
    {"ChinaChopper", lcproto::kMalware, "the name of the China Chopper web shell"},
};

const char *const kRansom[] = {
    "your files have been encrypted", "your files are encrypted", "all your files are encrypted",
    "to decrypt your files", "pay the ransom", "send bitcoin to", "decryption key will be",
    "your documents, photos, databases"};

void signature_checks(const Bytes &b, Kind kind, Collector *c) {
    // Head and tail must be adjacent: the tail alone is quoted in this binary
    // and in the docs, and the two pieces in this file are separated by a NUL.
    if (const size_t at = b.find(kEicarHead); at != Bytes::npos && b.compare(at + sizeof kEicarHead - 1, sizeof kEicarTail - 1, kEicarTail) == 0)
        c->add(lcproto::kMalware,
               "it contains the EICAR test string: the standard file that antivirus programs "
               "are tested with (harmless; it is not malware, it is meant to be found)",
               at);
    for (const Needle &n : kNeedles)
        if (const size_t at = b.find(n.text); at != Bytes::npos)
            c->add(n.type, std::string("it contains ") + n.what, at);
    // ransom notes, in whatever case, in a text or a program
    if (kind != Kind::Binary || b.size() < (8u << 20)) {
        std::string low = lower(std::string_view(b).substr(0, std::min<size_t>(b.size(), 4u << 20)));
        for (const char *r : kRansom)
            if (const size_t at = low.find(r); at != std::string::npos) {
                c->add(lcproto::kMalware,
                       std::string("it contains the text of a ransom note (\"") + r + "\")", at);
                break;
            }
    }
    // a web shell that hides what it runs: code taken from an encoded string
    // and passed straight to something that executes it
    if (kind == Kind::Text && (contains(b, "<?php") || contains(b, "<?="))) {
        static const char *const kWrapped[] = {
            "eval(base64_decode(", "eval(gzinflate(", "eval(gzuncompress(",
            "eval(str_rot13(", "assert(base64_decode(", "preg_replace(\"/e"};
        for (const char *w : kWrapped)
            if (const size_t at = b.find(w); at != Bytes::npos) {
                c->add(lcproto::kMalware,
                       std::string("it runs code from an encoded string (") + w +
                           ")...): a web shell hides what it executes this way",
                       at);
                break;
            }
    }
    // PHP / JSP web shells: input of the request given to something that runs it
    if (kind == Kind::Text && (contains(b, "<?php") || contains(b, "<?="))) {
        static const char *const kInput[] = {"$_POST", "$_GET", "$_REQUEST", "$_COOKIE"};
        static const char *const kRunners[] = {"eval(", "system(", "passthru(", "shell_exec(",
                                               "exec(", "popen(", "proc_open(", "assert(",
                                               "base64_decode("};
        for (const char *run : kRunners)
            for (const char *in : kInput) {
                const std::string direct = std::string(run) + in;
                const std::string spaced = std::string(run) + " " + in;
                size_t at = b.find(direct);
                if (at == Bytes::npos)
                    at = b.find(spaced);
                if (at != Bytes::npos) {
                    c->add(lcproto::kMalware,
                           std::string("it passes ") + in + " to " + run +
                               ") : a web shell, which runs whatever the request sends",
                           at);
                    return;
                }
            }
    }
}

// Windows API names that, together, are what injection and key logging need.
void api_checks(const Bytes &b, Collector *c) {
    if (contains(b, "WriteProcessMemory") && contains(b, "CreateRemoteThread") &&
        (contains(b, "VirtualAllocEx") || contains(b, "OpenProcess")))
        c->add(lcproto::kInjection,
               "it imports WriteProcessMemory and CreateRemoteThread: the calls that put code "
               "into another running program");
    if (contains(b, "SetWindowsHookEx") && contains(b, "GetAsyncKeyState"))
        c->add(lcproto::kCredAccess,
               "it imports SetWindowsHookEx and GetAsyncKeyState: the calls a key logger "
               "uses to read what is typed");
    if (contains(b, "process_vm_writev") || (contains(b, "PTRACE_POKETEXT") && contains(b, "ptrace")))
        c->add(lcproto::kInjection,
               "it uses process_vm_writev or ptrace to write into another running program");
    if (contains(b, "/etc/ld.so.preload") && contains(b, "readdir"))
        c->add(lcproto::kPersistence,
               "it names /etc/ld.so.preload and readdir: the pair a user-land rootkit needs to "
               "load itself into every program and hide its files");
    if (contains(b, "/dev/input/event") && (contains(b, "EV_KEY") || contains(b, "/dev/uinput")))
        c->add(lcproto::kCredAccess,
               "it reads /dev/input/event* key events: what a key logger on Linux reads");
}

// ---- scripts that hide what they run ----------------------------------------------

// Decoded text fed to something that runs it, close together: exec(base64...),
// eval(atob(...)), eval(gzinflate(base64_decode(...))), PowerShell -EncodedCommand;
// or one very long line of base64.
void obfuscation_checks(const Bytes &b, Collector *c) {
    const std::string low = lower(std::string_view(b).substr(0, std::min<size_t>(b.size(), 2u << 20)));
    static const char *const kDecode[] = {"b64decode", "decodebytes", "atob(", "frombase64string",
                                          "base64_decode(", "gzinflate(", "str_rot13(",
                                          "zlib.decompress", "marshal.loads", "fromcharcode",
                                          "unescape("};
    static const char *const kRun[] = {"exec(", "eval(", "invoke-expression", "iex ", "iex(",
                                       "|iex"};
    for (const char *d : kDecode)
        for (size_t at = low.find(d), n = 0; at != std::string::npos && n < 20;
             at = low.find(d, at + 1), ++n) {
            const size_t from = at > 120 ? at - 120 : 0;
            const std::string near = low.substr(from, 240 + (at - from));
            for (const char *r : kRun)
                if (near.find(r) != std::string::npos) {
                    c->add(lcproto::kObfuscated,
                           std::string("it decodes text (") + d + ") next to " + r +
                               ": the code that runs is hidden in the encoded text",
                           at);
                    return;
                }
        }
    if (low.find("powershell") != std::string::npos &&
        (low.find("-encodedcommand") != std::string::npos || low.find(" -enc ") != std::string::npos ||
         low.find(" -e ") != std::string::npos)) {
        c->add(lcproto::kObfuscated, "it runs PowerShell with an encoded command: the command is "
                                     "base64 text, unreadable until it runs");
        return;
    }
    size_t start = 0;
    for (size_t i = 0; i <= b.size(); ++i)
        if (i == b.size() || b[i] == '\n') {
            if (i - start > 4000) {
                size_t b64 = 0;
                for (size_t k = start; k < i; ++k)
                    b64 += std::isalnum(static_cast<unsigned char>(b[k])) || b[k] == '+' ||
                           b[k] == '/' || b[k] == '=';
                if (b64 * 100 >= (i - start) * 95) {
                    c->add(lcproto::kObfuscated,
                           "it has a line of " + std::to_string(i - start) +
                               " characters that is nearly all base64: a payload packed into a script",
                           start);
                    return;
                }
            }
            start = i + 1;
        }
}

// ---- ELF -----------------------------------------------------------------------------

void elf_checks(const Bytes &b, const std::string &path, Collector *c) {
    if (b.size() < 64 || b[5] != 1)
        return; // only little-endian
    const bool is64 = b[4] == 2;
    const uint16_t type = u16(b, 16);
    const uint64_t entry = is64 ? u64(b, 24) : u32(b, 24);
    const uint64_t phoff = is64 ? u64(b, 32) : u32(b, 28);
    const uint64_t shoff = is64 ? u64(b, 40) : u32(b, 32);
    const uint16_t phentsize = u16(b, is64 ? 54 : 42), phnum = u16(b, is64 ? 56 : 44);
    const uint16_t shentsize = u16(b, is64 ? 58 : 46), shnum = u16(b, is64 ? 60 : 48);
    bool entry_in_code = entry == 0, saw_load = false;
    for (uint16_t i = 0; i < phnum && i < 128; ++i) {
        const size_t p = size_t(phoff) + size_t(i) * phentsize;
        if (p + (is64 ? 56u : 32u) > b.size())
            break;
        const uint32_t ptype = u32(b, p);
        const uint32_t flags = is64 ? u32(b, p + 4) : u32(b, p + 24);
        const uint64_t vaddr = is64 ? u64(b, p + 16) : u32(b, p + 8);
        const uint64_t memsz = is64 ? u64(b, p + 40) : u32(b, p + 20);
        if (ptype == 0x6474e551 && (flags & 1)) // PT_GNU_STACK with PF_X
            c->add(lcproto::kSuspiciousBin,
                   "the program asks for an executable stack: code written to the stack can run "
                   "(shell code needs this; modern programs do not)");
        if (ptype == 1) { // PT_LOAD
            saw_load = true;
            if ((flags & 2) && (flags & 1))
                c->add(lcproto::kSuspiciousBin,
                       "a segment of the program is both writable and executable: it can "
                       "rewrite its own code, as packers and shell code do");
            if ((flags & 1) && entry >= vaddr && entry < vaddr + memsz)
                entry_in_code = true;
        }
    }
    if (saw_load && !entry_in_code && (type == 2 || type == 3))
        c->add(lcproto::kSuspiciousBin,
               "the entry point is not inside an executable segment: the program starts in "
               "data, which a packer or a patched file does");
    if (shnum == 0 && phnum > 0 && (type == 2 || type == 3) && entry != 0)
        c->add(lcproto::kSuspiciousBin,
               "the section header table is missing although the program runs: tools like "
               "sstrip and packers cut it off to make analysis harder");
    if (contains(b, "UPX!"))
        c->add(lcproto::kSuspiciousBin,
               "it is packed with UPX (the \"UPX!\" mark): the real code is compressed inside, "
               "which hides it from scanners");
    // a shared library that defines the calls that list files and processes
    if (type == 3 && shoff && shentsize >= (is64 ? 64u : 40u)) {
        const std::string name = base_of(path);
        const bool system_lib = name.rfind("libc", 0) == 0 || name.rfind("ld-", 0) == 0 ||
                                name.rfind("libpthread", 0) == 0 || name.rfind("libleakcheck", 0) == 0;
        for (uint16_t i = 0; i < shnum && i < 128 && !system_lib; ++i) {
            const size_t s = size_t(shoff) + size_t(i) * shentsize;
            if (s + shentsize > b.size() || u32(b, s + 4) != 11) // SHT_DYNSYM
                continue;
            const size_t off = size_t(is64 ? u64(b, s + 24) : u32(b, s + 16));
            const size_t size = size_t(is64 ? u64(b, s + 32) : u32(b, s + 20));
            const uint32_t link = u32(b, s + (is64 ? 40 : 24));
            const size_t ent = is64 ? 24 : 16;
            const size_t t = size_t(shoff) + size_t(link) * shentsize;
            if (link >= shnum || t + shentsize > b.size())
                continue;
            const size_t stroff = size_t(is64 ? u64(b, t + 24) : u32(b, t + 16));
            const size_t strsize = size_t(is64 ? u64(b, t + 32) : u32(b, t + 20));
            for (size_t k = 0; k + ent <= size && off + k + ent <= b.size(); k += ent) {
                const uint32_t nm = u32(b, off + k);
                const uint16_t shndx = u16(b, off + k + (is64 ? 6 : 14));
                if (!shndx || nm >= strsize || stroff + nm >= b.size())
                    continue;
                const char *sym = b.c_str() + stroff + nm;
                for (const char *hook : {"readdir", "readdir64", "getdents", "getdents64"})
                    if (!strcmp(sym, hook))
                        c->add(lcproto::kSuspiciousBin,
                               std::string("this shared library defines ") + hook +
                                   "(): loaded with LD_PRELOAD or /etc/ld.so.preload it changes "
                                   "what every program sees in a directory, so it can hide files "
                                   "and processes (a user-land rootkit does)");
            }
        }
    }
}

// ---- PE ------------------------------------------------------------------------------
//
// The headers as a layout: where each section's bytes are, and where a relative
// virtual address (what the directories hold) lands in the file. The checks read
// the import table and the TLS directory from that, not from strings that happen
// to be in the file.

struct PeDir {
    uint32_t rva = 0, size = 0;
};

struct PeSection {
    char name[9] = {};
    uint32_t vsize = 0, va = 0, rawsize = 0, rawptr = 0, flags = 0;
};

struct PeLayout {
    bool ok = false;
    bool plus = false; // PE32+ (64-bit)
    size_t opt = 0;
    uint32_t headers = 0; // SizeOfHeaders: an RVA below it is already a file offset
    std::vector<PeSection> sections;
    PeDir dirs[16];

    PeDir dir(int i) const { return i >= 0 && i < 16 ? dirs[i] : PeDir{}; }

    size_t offset(uint32_t rva) const {
        if (rva < headers)
            return rva;
        for (const PeSection &s : sections)
            if (rva >= s.va && rva - s.va < s.rawsize)
                return size_t(s.rawptr) + (rva - s.va);
        return 0;
    }
};

PeLayout pe_layout(const Bytes &b) {
    PeLayout p;
    if (b.size() < 64 || b[0] != 'M' || b[1] != 'Z')
        return p;
    const size_t pe = u32(b, 0x3c);
    if (pe + 24 > b.size() || memcmp(b.data() + pe, "PE\0\0", 4) != 0)
        return p;
    const uint16_t nsec = u16(b, pe + 6), optsize = u16(b, pe + 20);
    const size_t opt = pe + 24;
    if (optsize < 64 || opt + optsize > b.size())
        return p;
    const uint16_t magic = u16(b, opt);
    p.plus = magic == 0x20b;
    if (!p.plus && magic != 0x10b)
        return p;
    p.ok = true;
    p.opt = opt;
    p.headers = u32(b, opt + 60);
    const size_t dd = opt + (p.plus ? 112 : 96);
    const size_t count = std::min<size_t>(u32(b, opt + (p.plus ? 108 : 92)), 16);
    for (size_t i = 0; i < count && dd + (i + 1) * 8 <= opt + optsize; ++i) {
        p.dirs[i].rva = u32(b, dd + i * 8);
        p.dirs[i].size = u32(b, dd + i * 8 + 4);
    }
    for (uint16_t i = 0; i < nsec && i < 96; ++i) {
        const size_t s = opt + optsize + size_t(i) * 40;
        if (s + 40 > b.size())
            break;
        PeSection sec;
        memcpy(sec.name, b.data() + s, 8);
        sec.vsize = u32(b, s + 8);
        sec.va = u32(b, s + 12);
        sec.rawsize = u32(b, s + 16);
        sec.rawptr = u32(b, s + 20);
        sec.flags = u32(b, s + 36);
        p.sections.push_back(sec);
    }
    return p;
}

// The API names the import table asks for, lower case, and how many it leaves as
// ordinals. A name chosen at run time (LoadLibrary/GetProcAddress) is not in it.
struct PeImports {
    std::set<std::string> funcs;
    std::vector<std::string> dlls;
    size_t named = 0, ordinals = 0;
};

PeImports pe_imports(const Bytes &b, const PeLayout &p) {
    PeImports out;
    const PeDir imp = p.dir(1);
    const size_t at = imp.rva ? p.offset(imp.rva) : 0;
    if (!at || at + 20 > b.size())
        return out;
    for (size_t d = 0; d < 256; ++d) {
        const size_t desc = at + d * 20;
        if (desc + 20 > b.size())
            break;
        const uint32_t lookup = u32(b, desc), names = u32(b, desc + 12),
                       iat = u32(b, desc + 16);
        if (!names && !lookup && !iat)
            break; // the zero descriptor that ends the table
        const size_t name_at = names ? p.offset(names) : 0;
        if (name_at && name_at < b.size()) {
            const char *s = b.c_str() + name_at;
            size_t n = 0;
            while (name_at + n < b.size() && n < 255 && s[n])
                ++n;
            out.dlls.push_back(lower(std::string_view(s, n)));
        }
        const size_t thunk = (lookup ? lookup : iat) ? p.offset(lookup ? lookup : iat) : 0;
        if (!thunk)
            continue;
        const size_t width = p.plus ? 8 : 4;
        for (size_t k = 0; k < 4096; ++k) {
            const size_t here = thunk + k * width;
            if (here + width > b.size())
                break;
            const uint64_t value = p.plus ? u64(b, here) : u32(b, here);
            if (!value)
                break;
            const bool ordinal = p.plus ? (value >> 63) != 0 : (value & 0x80000000u) != 0;
            if (ordinal) {
                ++out.ordinals;
                continue;
            }
            const size_t api = p.offset(uint32_t(value));
            if (!api || api + 2 >= b.size())
                continue;
            const char *s = b.c_str() + api + 2; // past the two-byte hint
            size_t n = 0;
            while (api + 2 + n < b.size() && n < 255 && s[n])
                ++n;
            if (!n)
                continue;
            ++out.named;
            out.funcs.insert(lower(std::string_view(s, n)));
        }
    }
    return out;
}

// How random a range of bytes looks, 0 to 8 bits per byte.
double entropy_of(const Bytes &b, size_t from, size_t len) {
    if (from >= b.size())
        return 0;
    len = std::min(len, b.size() - from);
    if (!len)
        return 0;
    size_t count[256] = {};
    for (size_t i = 0; i < len; ++i)
        ++count[uint8_t(b[from + i])];
    double h = 0;
    for (size_t k : count)
        if (k) {
            const double p = double(k) / double(len);
            h -= p * std::log2(p);
        }
    return h;
}

std::string entropy_text(double h) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "%.2f", h);
    return buf;
}

void pe_checks(const Bytes &b, Collector *c) {
    const PeLayout p = pe_layout(b);
    if (!p.ok)
        return;
    const PeImports imp = pe_imports(b, p);
    const uint32_t entry = u32(b, p.opt + 16);
    static const char *const kPackers[] = {"UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".themida",
                                           ".vmp0", ".vmp1", ".petite", ".nsp0", ".MPRESS1",
                                           ".MPRESS2", ".enigma1"};
    for (const PeSection &s : p.sections) {
        for (const char *packer : kPackers)
            if (!strcmp(s.name, packer))
                c->add(lcproto::kSuspiciousBin,
                       std::string("it has a section named ") + s.name +
                           ", the mark of a packer: the real code is compressed or encrypted "
                           "inside, which hides it from scanners");
        if ((s.flags & 0x20000000) && (s.flags & 0x80000000))
            c->add(lcproto::kSuspiciousBin,
                   std::string("section ") + s.name + " is both writable and executable: it can "
                   "rewrite its own code, as packers and shell code do");
        if (entry >= s.va && entry < s.va + s.vsize && (s.flags & 0x80000000) &&
            !(s.flags & 0x20000000))
            c->add(lcproto::kSuspiciousBin, "the entry point is in a writable data section");
    }

    // A TLS callback is code the loader runs before the entry point, which is
    // where a packer unpacks itself. On its own it is ordinary: the C runtime of
    // several compilers registers one in every program, so it is only reported
    // beside packed code or on a program that imports nothing.
    const PeDir tls = p.dir(9);
    const size_t tls_at = tls.rva ? p.offset(tls.rva) : 0;
    const size_t callbacks = tls_at + (p.plus ? 24 : 12);
    bool tls_callback = false;
    if (tls_at && callbacks + (p.plus ? 8 : 4) <= b.size())
        tls_callback = (p.plus ? u64(b, callbacks) : u32(b, callbacks)) != 0;
    const char *const kTlsClause =
        ", and it registers a TLS callback: code that runs before the entry point, where an "
        "unpacker does its work";

    // Code that does not look like code: an executable section of real size whose
    // bytes are close to random is compressed or encrypted, which is a packer's
    // job. Resources and overlays are not looked at, as they are usually compressed.
    double worst = 0;
    const char *worst_name = nullptr;
    for (const PeSection &s : p.sections) {
        if (!(s.flags & 0x20000000) || s.rawsize < 2048)
            continue;
        const double e = entropy_of(b, s.rawptr, s.rawsize);
        if (e > worst) {
            worst = e;
            worst_name = s.name;
        }
    }
    if (worst_name && worst >= 7.2)
        c->add(lcproto::kSuspiciousBin,
               std::string("its ") + worst_name + " section looks random (entropy " +
                   entropy_text(worst) +
                   " of 8): the code is compressed or encrypted inside the program, as a "
                   "packer leaves it" +
                   (tls_callback ? kTlsClause : ""));

    // What the imports say it can do. Each pair is a capability on its own; the
    // strings of the same API names are checked separately, for a file whose
    // import table a packer has removed.
    auto has = [&imp](std::initializer_list<const char *> names) {
        for (const char *n : names)
            if (imp.funcs.count(n))
                return true;
        return false;
    };
    if (has({"urldownloadtofilea", "urldownloadtofilew"}) &&
        has({"winexec", "shellexecutea", "shellexecutew"}))
        c->add(lcproto::kDropper,
               "it imports URLDownloadToFile and WinExec or ShellExecute: the calls that fetch "
               "a file from the internet and start it, which is how a first stage installs the "
               "rest of itself");
    // Both halves are needed for the reading to mean anything: CredUnprotectData
    // is how any program reads its own saved secret, CredEnumerate lists every
    // saved one (as a stealer does); Remote Desktop and the sync clients read a
    // named credential and do not enumerate.
    if (has({"cryptunprotectdata"}) && has({"credenumeratew", "credenumeratea"}))
        c->add(lcproto::kCredAccess,
               "it imports CryptUnprotectData and CredEnumerate: the calls that decrypt and "
               "walk every password saved on the machine");
    if (imp.named > 0 && imp.named <= 8 && has({"loadlibrarya", "loadlibraryw", "loadlibraryexa",
                                              "loadlibraryexw"}) &&
        has({"getprocaddress"}))
        c->add(lcproto::kSuspiciousBin,
               "its import table names only " + std::to_string(imp.named) +
                   " functions, among them LoadLibrary and GetProcAddress: everything else it "
                   "calls is chosen at run time, so the table does not say what it does");
}

// ---- Mach-O ---------------------------------------------------------------------------
//
// The load commands of a little-endian Mach-O (arm64, x86_64): where a library comes
// from, what the code signature grants, and whether a segment is writable and
// executable at once. A big-endian file (PowerPC) is left alone, as elf_checks
// leaves big-endian ELF.

struct Macho {
    bool ok = false;
    size_t cmds = 0; // where the load commands start
    uint32_t ncmds = 0;
};

Macho macho_header(const Bytes &b) {
    Macho m;
    const uint32_t magic = u32(b, 0);
    if (b.size() >= 32 && magic == 0xfeedfacf) { // MH_MAGIC_64, little-endian
        m.ok = true;
        m.cmds = 32;
    } else if (b.size() >= 28 && magic == 0xfeedface) { // MH_MAGIC
        m.ok = true;
        m.cmds = 28;
    }
    if (m.ok)
        m.ncmds = u32(b, 16);
    return m;
}

// The install name of the dylib command at `p`, when the name is inside the command.
std::string macho_dylib_name(const Bytes &b, size_t p, uint32_t size) {
    if (size < 24 || p + size > b.size())
        return std::string();
    const uint32_t at = u32(b, p + 8);
    if (at < 24 || at >= size)
        return std::string();
    const char *s = b.data() + p + at;
    size_t n = 0;
    while (n < size - at && n < 255 && s[n])
        ++n;
    return std::string(s, n);
}

// A code-signing blob is big-endian, unlike the rest of a Mach-O.
uint32_t be32(const Bytes &b, size_t o) {
    return o + 4 <= b.size() ? uint32_t(uint8_t(b[o]) << 24 | uint8_t(b[o + 1]) << 16 |
                                        uint8_t(b[o + 2]) << 8 | uint8_t(b[o + 3]))
                             : 0;
}

struct Signature {
    bool adhoc = false;
    std::string entitlements;
};

Signature macho_signature(const Bytes &b, size_t at, size_t size) {
    Signature s;
    if (size < 12 || at + size > b.size() || be32(b, at) != 0xfade0cc0) // the SuperBlob
        return s;
    const uint32_t count = be32(b, at + 8);
    for (uint32_t i = 0; i < count && i < 32; ++i) {
        const size_t slot = at + 12 + size_t(i) * 8;
        if (slot + 8 > b.size())
            break;
        const uint32_t type = be32(b, slot), rel = be32(b, slot + 4);
        const size_t blob = at + rel;
        if (blob + 8 > b.size())
            continue;
        if (type == 0 && be32(b, blob) == 0xfade0c02) { // the CodeDirectory
            if (blob + 16 <= b.size())
                s.adhoc = (be32(b, blob + 12) & 0x2) != 0; // CS_ADHOC
        } else if (type == 5 && be32(b, blob) == 0xfade7171) { // the entitlements
            const uint32_t len = be32(b, blob + 4);
            if (len > 8 && blob + len <= b.size())
                s.entitlements.assign(b.data() + blob + 8, len - 8);
        }
    }
    return s;
}

void macho_checks(const Bytes &b, Collector *c) {
    const Macho m = macho_header(b);
    if (!m.ok)
        return;
    bool wxe = false;
    std::string load, bare; // a library that comes from a place it should not come from
    size_t sig_at = 0, sig_size = 0;
    size_t p = m.cmds;
    for (uint32_t i = 0; i < m.ncmds && i < 512; ++i) {
        if (p + 8 > b.size())
            break;
        const uint32_t cmd = u32(b, p), size = u32(b, p + 4);
        if (size < 8 || p + size > b.size())
            break;
        if (cmd == 0x1 || cmd == 0x19) { // LC_SEGMENT, LC_SEGMENT_64
            const size_t at = p + (cmd == 0x19 ? 60 : 44); // initprot
            if (at + 4 <= p + size && (u32(b, at) & 6) == 6)
                wxe = true; // writable and executable
        } else if (cmd == 0xc || cmd == 0x80000018 || cmd == 0x8000001f || cmd == 0x80000023) {
            // LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB
            const std::string name = macho_dylib_name(b, p, size);
            const std::string low = lower(name);
            const bool temp = low.rfind("/tmp/", 0) == 0 || low.rfind("/private/tmp/", 0) == 0 ||
                              low.rfind("/var/tmp/", 0) == 0 || low.rfind("/users/shared/", 0) == 0;
            const bool climbs = (low.rfind("@executable_path/", 0) == 0 || low.rfind("@loader_path/", 0) == 0) &&
                                low.find("/../") != std::string::npos;
            // the path that leaves the folder is the stronger sign; a bare name is
            // what almost every program has, so it is only used when nothing better is found
            if (load.empty() && (temp || climbs))
                load = "loads the library \"" + name +
                       "\" from a path that points outside its own folder: a file another user can replace is the "
                       "one that runs inside it (the macOS form of DLL sideloading)";
            else if (bare.empty() && name.find('/') == std::string::npos)
                bare = "loads \"" + name +
                       "\" with no directory: dyld takes it from the standard search paths, so a copy planted in one "
                       "of them runs inside this program (the macOS form of DLL sideloading)";
        } else if (cmd == 0x1d && size >= 16) { // LC_CODE_SIGNATURE
            sig_at = u32(b, p + 8);
            sig_size = u32(b, p + 12);
        }
        p += size;
    }
    const Signature sig = macho_signature(b, sig_at, sig_size);
    const std::string ent = lower(sig.entitlements);
    if (load.empty())
        load = bare;
    if (!load.empty())
        c->add(lcproto::kDllHijack, load);
    else if (ent.find("disable-library-validation") != std::string::npos &&
             (ent.find("get-task-allow") != std::string::npos ||
              ent.find("allow-dyld-environment-variables") != std::string::npos ||
              ent.find("allow-unsigned-executable-memory") != std::string::npos))
        c->add(lcproto::kDllHijack,
               "turns off library validation (com.apple.security.cs.disable-library-validation) and keeps another "
               "way in (get-task-allow, DYLD environment variables or unsigned executable memory): any signed "
               "library can be loaded into it, which is how a hijacked dylib gets in");
    if (sig.adhoc && ent.find("com.apple.private.") != std::string::npos)
        c->add(lcproto::kCertAbuse,
               "carries a private Apple entitlement (com.apple.private....) but is only ad-hoc signed: no team was "
               "granted that entitlement, so it was written into the file by hand");
    if (wxe)
        c->add(lcproto::kSuspiciousBin,
               "a segment of the program is both writable and executable (initprot RWX): it can rewrite its own "
               "code at run time, as packers and shell code do");
}

// How random the bytes look, 0 to 8 bits per byte: compressed or encrypted data
// is near 8; code, 5 to 6.5.
double entropy(const Bytes &b) {
    const size_t n = std::min<size_t>(b.size(), 4u << 20);
    if (n == 0)
        return 0;
    size_t count[256] = {};
    for (size_t i = 0; i < n; ++i)
        ++count[uint8_t(b[i])];
    double h = 0;
    for (size_t k : count)
        if (k) {
            const double p = double(k) / double(n);
            h -= p * std::log2(p);
        }
    return h;
}

} // namespace

Kind kind_of(const std::string &b) {
    if (b.size() >= 4 && !memcmp(b.data(), "\x7f"
                                            "ELF",
                                 4))
        return Kind::Elf;
    if (b.size() >= 0x40 && b[0] == 'M' && b[1] == 'Z') {
        const size_t pe = u32(b, 0x3c);
        if (pe + 4 <= b.size() && !memcmp(b.data() + pe, "PE\0\0", 4))
            return Kind::Pe;
    }
    if (b.size() >= 4) {
        const uint32_t m = u32(b, 0);
        if (m == 0xfeedface || m == 0xfeedfacf || m == 0xcefaedfe || m == 0xcffaedfe)
            return Kind::MachO;
    }
    if (b.size() >= 2 && b[0] == '#' && b[1] == '!')
        return Kind::Script;
    const size_t n = std::min<size_t>(b.size(), 4096);
    for (size_t i = 0; i < n; ++i)
        if (b[i] == 0)
            return Kind::Binary;
    return Kind::Text;
}

std::vector<Hit> scan_file(const std::string &path, const std::string &bytes,
                           std::vector<size_t> *more, bool malware) {
    Collector c(more);
    const Kind kind = kind_of(bytes);
    const std::string name = lower(base_of(path));
    const std::string ext = ext_of(name);
    const bool program = kind == Kind::Elf || kind == Kind::Pe || kind == Kind::MachO;

    name_checks(path, kind, &c);
    // a program or script given the name of a document or a picture
    if ((program || kind == Kind::Script) && kDocExts.count(ext))
        c.add(lcproto::kDisguised,
              std::string("it is ") +
                  (kind == Kind::Elf ? "a Linux program" : kind == Kind::Pe ? "a Windows program"
                   : kind == Kind::MachO ? "a macOS program" : "a script") +
                  " named like a ." + ext + " file: opened by double-click it runs instead of "
                  "showing a document");
    signature_checks(bytes, kind, &c);
    // The system's own copies already contain the strings of what they do
    // (bash has /dev/tcp, passwd has /etc/shadow, sudo has ptrace, the debug
    // files are compressed). Those checks are for a file that arrived from
    // somewhere else.
    const bool installed = lcrules::system_dir(path.c_str());
    // text that is code: shell, Python, PHP, ... (not documentation)
    // (--malware also reads source, configuration and markup for command lines, not prose)
    static const std::set<std::string> kProse = {"txt", "md", "rst", "tex", "log", "csv", "adoc", "org", "1", "man", "text"};
    const bool code_text = kind == Kind::Script ||
                           (kind == Kind::Text && (kScriptExts.count(ext) || (malware && !kProse.count(ext))));
    if (!installed && (code_text || program || kind == Kind::Binary))
        string_checks(bytes, code_text ? Kind::Script : Kind::Binary, &c, malware);
    if (!installed && code_text)
        obfuscation_checks(bytes, &c);
    if (program && !installed) {
        api_checks(bytes, &c);
        if (kind == Kind::Elf)
            elf_checks(bytes, path, &c);
        else if (kind == Kind::Pe)
            pe_checks(bytes, &c);
        else if (kind == Kind::MachO)
            macho_checks(bytes, &c);
        if (bytes.size() >= 16384 && entropy(bytes) >= 7.5)
            c.add(lcproto::kSuspiciousBin,
                  "its bytes look random (entropy " + std::to_string(entropy(bytes)).substr(0, 4) +
                      " of 8): compressed or encrypted data inside a program is how a packer or "
                      "a crypter hides what it does");
    }
    if (malware && !installed)
        deep_scan(path, bytes, [&c](const char *type, const std::string &message, size_t offset) {
            c.add(type, message, offset);
        });
    return c.finish();
}

} // namespace lcscan
