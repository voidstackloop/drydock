// Pointers to freed blocks left in data the program still uses: nothing goes
// wrong until some later path follows one.
// usage: dangling <case>
#include <stdlib.h>
#include <string.h>

struct node {
    int value;
    struct node *next;
};

static struct node *g_list;
static char *g_cache;

static struct node *make(int value) {
    struct node *n = calloc(1, sizeof *n);
    n->value = value;
    return n;
}

// Freed, and every pointer to it cleared or replaced: no findings.
static int clean(void) {
    g_list = make(1);
    g_list->next = make(2);
    free(g_list->next);
    g_list->next = NULL;
    g_cache = malloc(32);
    free(g_cache);
    g_cache = strdup("again");
    char *local = malloc(8); // a stale copy on the stack does not count
    free(local);
    return local == NULL;
}

// The second node is freed but the first still points to it.
static void in_block(void) {
    g_list = make(1);
    g_list->next = make(2);
    free(g_list->next);
}

static void in_global(void) {
    g_cache = malloc(32);
    free(g_cache);
}

int main(int argc, char **argv) {
    const char *c = argc > 1 ? argv[1] : "clean";
    if (!strcmp(c, "clean"))
        return clean();
    if (!strcmp(c, "block"))
        in_block();
    else if (!strcmp(c, "global"))
        in_global();
    else
        return 64;
    return 0;
}
