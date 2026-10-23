// level: expert
// mode: static
// expect: none
// what: trap: variadic functions that end every va_list: goto cleanup, a loop that restarts it, va_copy ended, a switch, and one handed on
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

struct sink {
    FILE *out;
    int lines;
};

int log_to(struct sink *s, const char *fmt, ...) {
    va_list ap;
    int n = -1;
    va_start(ap, fmt);
    if (!s || !s->out)
        goto out;
    n = vfprintf(s->out, fmt, ap);
    s->lines++;
out:
    va_end(ap);
    return n;
}

void repeat(int times, const char *fmt, ...) {
    for (int i = 0; i < times; i++) {
        va_list ap;
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
    }
}

char *vformat(const char *fmt, va_list ap) {
    va_list copy;
    va_copy(copy, ap);
    int n = vsnprintf(NULL, 0, fmt, copy);
    va_end(copy);
    if (n < 0)
        return NULL;
    char *buf = malloc((size_t)n + 1);
    if (buf)
        vsnprintf(buf, (size_t)n + 1, fmt, ap);
    return buf;
}

char *format(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char *s = vformat(fmt, ap);
    va_end(ap);
    return s;
}

int pick(int mode, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    switch (mode) {
    case 0:
        va_end(ap);
        return 0;
    case 1:
        vprintf(fmt, ap);
        break;
    default:
        break;
    }
    va_end(ap);
    return mode;
}

static void vlog(int level, const char *fmt, va_list ap) {
    if (level > 0)
        vfprintf(stderr, fmt, ap);
}

void warn(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog(1, fmt, ap);
    va_end(ap);
}
