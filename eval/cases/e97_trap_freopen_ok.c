// level: expert
// mode: dynamic
// expect: none
// what: trap: freopen(NULL) only changes the mode, and a successful freopen is closed
#include <stdio.h>

int main(void) {
    FILE *mode = fopen("/dev/null", "r+");
    if (!mode)
        return 1;
    mode = freopen(NULL, "r", mode);
    if (mode)
        fclose(mode);
    FILE *sw = fopen("/dev/null", "r");
    if (!sw)
        return 1;
    sw = freopen("/dev/null", "w", sw);
    if (sw)
        fclose(sw);
    return 0;
}
