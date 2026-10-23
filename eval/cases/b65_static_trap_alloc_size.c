// level: basic
// mode: static
// expect: none
// what: trap: calloc checks the product, constant sizes are exact, and an outside size added to a literal is not a multiplication
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2)
        return 1;
    int n = atoi(argv[1]);
    int *v = calloc(n, sizeof(int));
    free(v);
    char *f = malloc(4 * sizeof(int));
    free(f);
    char *s = malloc(strlen(argv[1]) + 1);
    strcpy(s, argv[1]);
    free(s);
    return 0;
}
