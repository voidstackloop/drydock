#pragma once
// Looks for malware in a file without running it: the marks malware leaves in
// its bytes, a program that is not what its name says, and a name made to look
// like something the system or a trusted site owns. Pure functions of the path
// and the bytes, so they can be tested without a file system.
#include <string>
#include <vector>

namespace lcscan {

struct Hit {
    std::string type;    // a finding type of shared/include/protocol.h
    std::string message; // one line
    size_t offset = 0;   // where in the file (0 when the name or the file as a whole)
};

enum class Kind { Elf, Pe, MachO, Script, Text, Binary };

Kind kind_of(const std::string &bytes);

// What `bytes`, the contents of the file named `path`, give away. At most one
// hit per type: the first, with how many more there were in `more`. `malware`
// adds the deep scan for the 100 malware families (malware_scan.h), which is slow.
std::vector<Hit> scan_file(const std::string &path, const std::string &bytes,
                           std::vector<size_t> *more = nullptr, bool malware = false);

} // namespace lcscan
