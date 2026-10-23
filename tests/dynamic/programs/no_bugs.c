// Correct program: must produce no findings.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <malloc.h>
#endif

int main(int argc, char **argv) {
    char *s = strdup("hello");
    int *a = calloc(100, sizeof *a);
    a = realloc(a, 1000 * sizeof *a);
    for (int i = 0; i < 1000; i++)
        a[i] = i;
    void *p = NULL;
#ifdef _WIN32
    p = _aligned_malloc(100, 64);
    if (!p)
        return 1;
#else
    if (posix_memalign(&p, 64, 100) != 0)
        return 1;
#endif
    printf("%s %d\n", s, a[999]);
#ifdef _WIN32
    _aligned_free(p);
#else
    free(p);
#endif
    free(a);
    free(s);
    free(NULL);
    return argc > 1 ? atoi(argv[1]) : 0;
}
