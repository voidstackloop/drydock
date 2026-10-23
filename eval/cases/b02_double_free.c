// level: basic
// mode: dynamic
// expect: double-free
// what: the same pointer freed twice
#include <stdlib.h>

int main(void) {
    int *p = malloc(10 * sizeof *p);
    p[0] = 1;
    free(p);
    free(p);
    return 0;
}
