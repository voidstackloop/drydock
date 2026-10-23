// level: basic
// mode: static
// expect: memory-leak
// what: a string from a duplicate-or-die helper is lost on an early return
#include <stdlib.h>
#include <string.h>

static char *xstrdup(const char *s) {
    char *c = strdup(s);
    if (!c)
        abort();
    return c;
}

int set_title(const char *t) {
    char *title = xstrdup(t);
    if (strlen(title) > 80)
        return -1; // too long: title is lost
    free(title);
    return 0;
}
