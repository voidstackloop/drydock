// The report reader consumes records produced by the preload library inside
// another process. A corrupt record (a short write when the target was killed)
// must leave a partial report, not read past the buffer.
#include "report.h"
#include "temp_file.h"

#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    lcreport::Report report;
    report.mode = "dynamic";
    volatile bool ok = lcreport::parse_runtime_stream(fuzz_temp_file(data, size), report);
    (void)ok;
    return 0;
}
