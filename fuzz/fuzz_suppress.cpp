// A suppression file is written by hand and reviewed by other humans. A rule
// with a broken reason or an impossible date must be an error, never a crash.
#include "report.h"
#include "temp_file.h"

#include <cstdint>
#include <sstream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const std::string path = fuzz_temp_file(data, size);
    lcreport::Report report;
    report.mode = "static";
    std::string error;
    if (!lcreport::apply_suppressions(path, report, &error)) {
        volatile bool failed = true;
        (void)failed;
    }
    std::ostringstream audit;
    std::string why;
    lcreport::audit_suppressions(path, audit, &why);
    return 0;
}
