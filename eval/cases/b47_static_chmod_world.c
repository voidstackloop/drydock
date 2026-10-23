// level: basic
// mode: static
// expect: insecure-permissions
// what: a socket file is created and then chmod'd 0777, so every user on the machine can replace it
#include <sys/stat.h>

void open_up(const char *path) {
    chmod(path, 0777);
}
