// level: basic
// mode: static
// expect: double-free
// what: an object destroyed twice through its destroy function
#include <stdlib.h>

struct obj {
    char *name;
};

static void obj_destroy(struct obj *o) {
    free(o->name);
    free(o);
}

void finish(struct obj *o, int failed) {
    if (failed)
        obj_destroy(o);
    obj_destroy(o); // also on the failed path
}
