// level: basic
// mode: static
// expect: sizeof-pointer
// what: a heap buffer is cleared with memset(p, 0, sizeof(p)): only the pointer is cleared, not the buffer
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = malloc(100);
    if (!p)
        return 1;
    memset(p, 0, sizeof(p));
    free(p);
    return 0;
}
