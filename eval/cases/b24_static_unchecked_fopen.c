// level: basic
// mode: static
// expect: unchecked-stream
// what: a config file is read without checking that it opened
#include <stdio.h>
#include <string.h>

int read_port(const char *path) {
    char line[64];
    FILE *f = fopen(path, "r");
    if (!fgets(line, sizeof line, f))
        line[0] = 0;
    fclose(f);
    return (int)strlen(line);
}
