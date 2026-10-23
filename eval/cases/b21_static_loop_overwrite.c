// level: basic
// mode: static
// expect: memory-leak
// what: each line is copied into the same pointer; only the last copy is freed
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void last_line(FILE *in) {
    char buf[128];
    char *line = NULL;
    while (fgets(buf, sizeof buf, in))
        line = strdup(buf);
    if (line)
        puts(line);
    free(line);
}
