// level: expert
// mode: static
// expect: none
// what: trap: helpers whose results the caller does not simply own
#include <stdlib.h>
#include <string.h>

struct conn {
    int fd;
    char *host;
};

static struct conn *g_conns[16];
static int g_nconns;

static struct conn *conn_new(const char *host) { // registered: the table owns it
    struct conn *c = calloc(1, sizeof *c);
    c->host = strdup(host);
    g_conns[g_nconns++] = c;
    return c;
}

static const char *skip_space(const char *s) { // the caller's own memory
    while (*s == ' ')
        s++;
    return s;
}

static char *scratch(void) { // one buffer for the whole program
    static char *buf;
    if (!buf)
        buf = malloc(4096);
    return buf;
}

static struct conn *conn_dup(const struct conn *c) { // released with conn_free
    struct conn *d = malloc(sizeof *d);
    d->fd = c->fd;
    d->host = strdup(c->host);
    return d;
}

static void conn_free(struct conn *c) {
    free(c->host);
    free(c);
}

int connect_all(const char *line) {
    const char *h = skip_space(line);
    struct conn *c = conn_new(h);
    char *buf = scratch();
    strcpy(buf, c->host);
    struct conn *copy = conn_dup(c);
    int fd = copy->fd;
    conn_free(copy);
    return fd;
}
