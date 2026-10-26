// scan reads ELF, PE, Mach-O, scripts and archives. A malformed header must
// become a finding or no finding, never a crash: in a build server that is a
// denial of service on every push.
#include "scan.h"

#include <cstdint>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string bytes(reinterpret_cast<const char *>(data), size);
    std::vector<size_t> more;
    const auto hits = lcscan::scan_file("fuzz.bin", bytes, &more, true);
    volatile size_t n = hits.size();
    (void)n;
    return 0;
}
