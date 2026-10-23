// level: expert
// mode: dynamic
// expect: use-after-close
// what: fcloseall closes both saved streams; a helper then fgets one and fprintf's the other
#define _GNU_SOURCE
#include <stdio.h>

static void use_both(FILE *in, FILE *out) {
    char buf[8];
    fgets(buf, sizeof buf, in);
    fprintf(out, "late\n");
}

int main(void) {
    FILE *in = fopen("/dev/null", "r");
    FILE *out = fopen("/dev/null", "w");
    if (!in || !out)
        return 1;
    fcloseall();
    use_both(in, out);
    return 0;
}
