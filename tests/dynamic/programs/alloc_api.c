// Exercises every allocation entry point and checks the results the program
// can observe: alignment, zeroing, realloc contents, errno, usable size.
#include <errno.h>
#if defined(__APPLE__)
#include <malloc/malloc.h>
#else
#include <malloc.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;
#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #cond); \
            failures++;                                                        \
        }                                                                      \
    } while (0)

int main(void) {
    char *z = calloc(1000, 4);
    for (int i = 0; i < 4000; i++)
        CHECK(z[i] == 0);
    free(z);

    void *zero = malloc(0);
    CHECK(zero != NULL);
    free(zero);

    char *r = malloc(10);
    memcpy(r, "abcdefghi", 10);
    r = realloc(r, 100000);
    CHECK(r && strcmp(r, "abcdefghi") == 0);
    r = realloc(r, 4);
    CHECK(r && memcmp(r, "abcd", 4) == 0);
    free(r);

    for (size_t a = 8; a <= 4096; a *= 2) {
        void *p = NULL;
        CHECK(posix_memalign(&p, a, 100) == 0);
        CHECK(((uintptr_t)p % a) == 0);
        free(p);
        p = aligned_alloc(a, a * 3);
        CHECK(p && ((uintptr_t)p % a) == 0);
        free(p);
#if defined(__APPLE__)
        // Darwin has no memalign(): a second posix_memalign covers the same
        // entry point the runtime hooks there.
        CHECK(posix_memalign(&p, a, 7) == 0);
        CHECK(p && ((uintptr_t)p % a) == 0);
        free(p);
#else
        p = memalign(a, 7);
        CHECK(p && ((uintptr_t)p % a) == 0);
        free(p);
#endif
    }
    void *v = valloc(10);
    CHECK(v && ((uintptr_t)v % (uintptr_t)sysconf(_SC_PAGESIZE)) == 0);
    free(v);

    void *bad = NULL;
    CHECK(posix_memalign(&bad, 3, 10) == EINVAL);
    errno = 0;
    CHECK(aligned_alloc(3, 10) == NULL && errno == EINVAL);
    errno = 0;
    CHECK(calloc(SIZE_MAX / 2, 4) == NULL && errno == ENOMEM);
    errno = 0;
    CHECK(malloc(SIZE_MAX - 4096) == NULL && errno == ENOMEM);

    char *u = malloc(37);
#if defined(__APPLE__)
    CHECK(malloc_size(u) >= 37);
#else
    CHECK(malloc_usable_size(u) >= 37);
#endif
    free(u);

    errno = 1234;
    void *keep_errno = malloc(5);
    free(keep_errno);
    CHECK(errno == 1234);

    char *big = malloc(64 << 20); // larger than a quarter of the quarantine
    memset(big, 1, 64 << 20);
    free(big);

    char *s = strdup("hello");
    char *n = strndup("hello world", 5);
    CHECK(strcmp(s, n) == 0);
    free(s);
    free(n);

#if !defined(__APPLE__) // Darwin has no reallocarray(); the runtime's wrapper
                        // for it stays unused there too
    char *ra = reallocarray(NULL, 10, 10);
    CHECK(ra != NULL);
    free(ra);
#endif

    printf("alloc_api failures=%d\n", failures);
    return failures ? 1 : 0;
}
