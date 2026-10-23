// level: basic
// mode: dynamic
// expect: reverse-shell
// what: a python -c one-liner starts /bin/sh through subprocess, with no socket word
#include <stdlib.h>

int main(void) {
    system("true # python3 -c 'import subprocess; subprocess.call([\"/bin/sh\",\"-i\"])'");
    return 0;
}
