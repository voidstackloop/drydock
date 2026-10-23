// level: basic
// mode: dynamic
// expect: heap-buffer-overflow
// what: an off-by-one loop writes one byte past the end
#include <stdlib.h>

int main(void) {
    char *buf = malloc(16);
    for (int i = 0; i <= 16; i++) // <= : one too many
        buf[i] = 'x';
    free(buf);
    return 0;
}
