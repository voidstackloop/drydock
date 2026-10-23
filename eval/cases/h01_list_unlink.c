// level: hard
// mode: dynamic
// expect: memory-leak
// what: a node unlinked from a list in a helper but never freed
#include <stdlib.h>

struct node {
    int key;
    struct node *next;
};

static struct node *push(struct node *head, int key) {
    struct node *n = malloc(sizeof *n);
    n->key = key;
    n->next = head;
    return n;
}

static struct node *remove_key(struct node *head, int key) {
    for (struct node **p = &head; *p; p = &(*p)->next)
        if ((*p)->key == key) {
            *p = (*p)->next; // unlinked... and gone
            break;
        }
    return head;
}

static void destroy(struct node *head) {
    while (head) {
        struct node *next = head->next;
        free(head);
        head = next;
    }
}

int main(void) {
    struct node *list = NULL;
    for (int i = 0; i < 5; i++)
        list = push(list, i);
    list = remove_key(list, 2);
    destroy(list);
    return 0;
}
