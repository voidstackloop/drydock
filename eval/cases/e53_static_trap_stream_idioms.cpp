// level: expert
// mode: static
// expect: none
// what: trap: stream idioms from real code: if (FILE *f = fopen(..)), a local struct closing in its destructor, a file reopened in a loop and handed to a reader
#include <cstdio>
#include <string>
#include <vector>

struct Row {
    int file;
};

const char *file_name(int id);
bool read_at(std::FILE *f, long off, void *dst, unsigned long n, std::string &err);

long available_kb() {
    long kb = 0;
    if (std::FILE *m = std::fopen("/proc/meminfo", "r")) {
        char line[256];
        while (std::fgets(line, sizeof line, m))
            if (std::sscanf(line, "MemAvailable: %ld kB", &kb) == 1)
                break;
        std::fclose(m);
    }
    if (std::FILE *s = std::fopen("/proc/self/stat", "r")) {
        char buf[256];
        std::fread(buf, 1, sizeof buf, s);
        std::fclose(s);
    }
    return kb;
}

bool read_file(const std::string &path, std::vector<unsigned char> &out) {
    std::FILE *f = std::fopen(path.c_str(), "rb");
    if (f == nullptr)
        return false;
    struct Closer {
        std::FILE *f;
        ~Closer() {
            if (f != nullptr)
                std::fclose(f);
        }
    } closer{f};
    if (std::fseek(f, 0, SEEK_END) != 0)
        return false;
    out.resize(size_t(std::ftell(f)));
    std::rewind(f);
    return std::fread(out.data(), 1, out.size(), f) == out.size();
}

bool load_all(const std::vector<Row> &rows, std::string &err) {
    std::FILE *cur = nullptr;
    int cur_file = -1;
    for (const Row &r : rows) {
        if (r.file != cur_file) {
            if (cur)
                std::fclose(cur);
            cur = std::fopen(file_name(r.file), "rb");
            if (!cur) {
                err = "cannot open";
                return false;
            }
            cur_file = r.file;
        }
        char buf[16];
        if (!read_at(cur, 0, buf, sizeof buf, err)) {
            std::fclose(cur);
            return false;
        }
    }
    if (cur)
        std::fclose(cur);
    return true;
}
