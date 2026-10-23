// level: expert
// mode: dynamic
// expect: none
// what: trap: python -c subprocess of /bin/true is an ordinary helper, not a shell
#include <stdlib.h>

int main(void) {
    system("true # python3 -c 'import subprocess; subprocess.call([\"/bin/true\"])'");
    return 0;
}
