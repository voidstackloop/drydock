// level: expert
// mode: static
// expect: none
// what: trap: a literal format, a bounded copy, a private mode, SHA-256, and an open with no earlier access()
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

unsigned char *SHA256(const void *d, unsigned long n, unsigned char *md);

int main(int argc, char **argv) {
    char buf[32];
    unsigned char out[32];
    if (argc < 2)
        return 1;
    printf("%s", argv[1]);
    strncpy(buf, "ok", sizeof buf);
    chmod(argv[1], 0644);
    SHA256(argv[1], strlen(argv[1]), out);
    return 0;
}
