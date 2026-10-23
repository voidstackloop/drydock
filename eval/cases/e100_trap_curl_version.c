// level: expert
// mode: dynamic
// expect: none
// what: trap: bash -c "curl --version" asks for a version, it does not run a download
#include <stdlib.h>

int main(void) {
    system("true # bash -c \"curl --version\"");
    return 0;
}
