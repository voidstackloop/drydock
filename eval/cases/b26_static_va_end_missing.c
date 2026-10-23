// level: basic
// mode: static
// expect: resource-leak
// what: a variadic logger returns early without ending its va_list
#include <stdarg.h>
#include <stdio.h>

int log_line(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (!fmt)
        return -1;
    int n = vfprintf(stderr, fmt, ap);
    va_end(ap);
    return n;
}
