// level: expert
// mode: static
// expect: resource-leak
// what: a prefetch thread is started, and the early error return never joins it
#include <pthread.h>
#include <stdio.h>

static void *warm_cache(void *path) { return path; }

int load(const char *path, char *buf, size_t n) {
    pthread_t prefetch;
    if (pthread_create(&prefetch, NULL, warm_cache, (void *)path) != 0)
        return -1;
    FILE *f = fopen(path, "r");
    if (!f)
        return -1; // the prefetch thread is never joined
    size_t got = fread(buf, 1, n, f);
    fclose(f);
    pthread_join(prefetch, NULL);
    return (int)got;
}
