// level: expert
// mode: static
// expect: resource-leak
// what: a vasprintf-style helper copies the va_list to measure, and only the success path ends the copy
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

char *vformat(const char *fmt, va_list ap) {
    va_list copy;
    va_copy(copy, ap);
    int n = vsnprintf(NULL, 0, fmt, copy);
    if (n < 0)
        return NULL;
    va_end(copy);
    char *buf = malloc((size_t)n + 1);
    if (buf)
        vsnprintf(buf, (size_t)n + 1, fmt, ap);
    return buf;
}
