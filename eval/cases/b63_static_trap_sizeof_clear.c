// level: basic
// mode: static
// expect: none
// what: trap: sizeof on a real array and on *p clear whole buffers; malloc with a literal size is exact
#include <stdlib.h>
#include <string.h>

int main(void) {
    char buf[100];
    memset(buf, 0, sizeof buf);
    char *p = malloc(100);
    if (!p)
        return 1;
    memset(p, 0, 100);
    memset(p, 0, sizeof *p);
    free(p);
    return 0;
}
