// level: basic
// mode: static
// expect: unsafe-function
// what: a line is read with gets(), which writes past the buffer when the line is long
#include <stdio.h>

void read_line(void) {
    char buf[64];
    gets(buf);
}
