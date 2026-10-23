// level: basic
// mode: dynamic
// expect: memory-leak
// what: a buffer allocated and never freed
#include <stdlib.h>
#include <string.h>

static char *greeting(const char *name) {
    char *s = malloc(64);
    strcpy(s, "hello ");
    strcat(s, name);
    return s;
}

int main(void) {
    char *g = greeting("world");
    g = NULL; // the only pointer to it is gone
    return g != NULL;
}
