// level: basic
// mode: dynamic
// expect: heap-use-after-free
// what: a write through a pointer after free()
#include <stdlib.h>

int main(void) {
    int *p = malloc(16 * sizeof *p);
    free(p);
    p[3] = 7;
    return 0;
}
