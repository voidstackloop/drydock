// definite: 100-byte buffer; definite+indirect: a 3-node list whose head
// pointer is lost; possible: a block only referenced through an interior
// pointer; reachable: a block held by a global.
#include <stdlib.h>
#include <string.h>

struct node {
    struct node *next;
    char payload[24];
};

void *keep_global;
char *interior_only;

__attribute__((noinline)) void lose_buffer(void) {
    char *p = malloc(100);
    memset(p, 1, 100);
}

__attribute__((noinline)) void lose_list(void) {
    struct node *head = NULL;
    for (int i = 0; i < 3; i++) {
        struct node *n = malloc(sizeof *n);
        n->next = head;
        head = n;
    }
}

__attribute__((noinline)) void keep_interior(void) {
    char *p = malloc(64);
    interior_only = p + 8;
}

int main(int argc, char **argv) {
    lose_buffer();
    lose_list();
    keep_interior();
    keep_global = malloc(40);
    return argc > 1 ? atoi(argv[1]) : 0;
}
