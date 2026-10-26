#pragma once
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>

// Some parsers take a path (the model loader, suppressions, the runtime
// stream). The fuzzer still feeds them bytes: write one small file and remove
// it on the next input. One name per process, so parallel fuzzers do not race.
inline std::string fuzz_temp_file(const uint8_t *data, size_t size) {
    static const std::string path =
        (std::filesystem::temp_directory_path() / "leakcheck-fuzz-input").string();
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char *>(data), std::streamsize(size));
    out.close();
    return path;
}
