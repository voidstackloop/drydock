// level: expert
// mode: static
// expect: memory-leak
// what: a config scan copies every entry's value, though it keeps only the one whose key matches
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *find_value(FILE *f, const char *key) {
    char line[256];
    char *value = NULL;
    while (fgets(line, sizeof line, f)) {
        char *eq = strchr(line, '=');
        if (!eq)
            continue;
        value = strdup(eq + 1); // every entry, not only the matching one
        if (strncmp(line, key, (size_t)(eq - line)) == 0)
            break;
    }
    return value;
}
