// level: expert
// mode: static
// expect: none
// what: trap: streams tested in every usual way: if, assignment in the condition, short-circuit, assert, a check macro
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(x)                                                               \
    do {                                                                       \
        if (!(x))                                                              \
            abort();                                                           \
    } while (0)

int copy_first_line(const char *from, const char *to) {
    char line[256];
    FILE *in, *out;
    if ((in = fopen(from, "r")) == NULL)
        return -1;
    out = fopen(to, "w");
    if (!out) {
        fclose(in);
        return -1;
    }
    if (fgets(line, sizeof line, in))
        fputs(line, out);
    fclose(out);
    fclose(in);
    return 0;
}

int append(const char *path, const char *text) {
    FILE *f = fopen(path, "a");
    int ok = f != NULL && fputs(text, f) >= 0;
    if (f)
        fclose(f);
    return ok;
}

void must_log(const char *path) {
    FILE *f = fopen(path, "a");
    assert(f);
    fputs("start\n", f);
    fclose(f);
}

int entries(const char *path) {
    DIR *d = opendir(path);
    CHECK(d);
    int n = 0;
    while (readdir(d))
        n++;
    closedir(d);
    return n;
}

int run_status(const char *cmd) {
    FILE *p = popen(cmd, "r");
    if (p == NULL)
        return -1;
    char buf[64];
    while (fgets(buf, sizeof buf, p))
        ;
    return pclose(p);
}
