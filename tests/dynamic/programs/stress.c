// Allocation-heavy workload used to measure overhead; correct, no findings.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SLOTS 4096

int main(int argc, char **argv) {
    long rounds = argc > 1 ? atol(argv[1]) : 1000000;
    char *slot[SLOTS] = {0};
    unsigned x = 12345;
    for (long i = 0; i < rounds; i++) {
        x = x * 1103515245u + 12345u;
        unsigned k = (x >> 8) % SLOTS;
        free(slot[k]);
        size_t n = 8 + (x >> 20) % 512;
        slot[k] = malloc(n);
        memset(slot[k], (int)i, n);
    }
    for (int k = 0; k < SLOTS; k++)
        free(slot[k]);
    puts("stress done");
    return 0;
}
