// level: basic
// mode: static
// expect: alloc-size-overflow
// what: malloc(n * 4) with n from the command line: a big n wraps the product and the buffer is too small
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2)
        return 1;
    int n = atoi(argv[1]);
    int *v = malloc(n * sizeof(int));
    if (!v)
        return 1;
    for (int i = 0; i < n; i++)
        v[i] = i;
    free(v);
    return 0;
}
