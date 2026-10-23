// level: hard
// mode: static
// expect: unchecked-stream
// what: /proc/self/status is read with getline straight away; inside a sandbox without /proc it is NULL
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int traced(void) {
    FILE *f = fopen("/proc/self/status", "r");
    size_t size = 0;
    char *line = NULL;
    int pid = 0;
    while (getline(&line, &size, f) > 0)
        if (!strncmp(line, "TracerPid:", 10))
            pid = atoi(line + 10);
    free(line);
    fclose(f);
    return pid != 0;
}
