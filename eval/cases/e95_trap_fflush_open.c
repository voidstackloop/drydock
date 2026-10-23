// level: expert
// mode: dynamic
// expect: none
// what: trap: fputs and fflush on a stream that is still open, and fflush of every stream
#include <stdio.h>

int main(void) {
    FILE *f = fopen("/dev/null", "w");
    if (!f)
        return 1;
    int (*p)(const char *, FILE *) = fputs;
    p("ok\n", f);
    fflush(f);
    fflush(NULL);
    fclose(f);
    return 0;
}
