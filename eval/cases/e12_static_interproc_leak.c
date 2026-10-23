// level: expert
// mode: static
// expect: memory-leak
// what: a helper returns allocated memory and the caller drops it (needs reasoning across functions)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *make_label(int id) {
    char *s = malloc(32);
    if (s)
        snprintf(s, 32, "item-%d", id);
    return s;
}

int print_label(int id) {
    char *label = make_label(id);
    if (!label)
        return -1;
    puts(label);
    return 0; // label is never freed
}
