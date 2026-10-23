// level: hard
// mode: dynamic
// expect: inherited-descriptor
// what: a listening socket is open while popen() runs a command, which inherits it
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0); // no SOCK_CLOEXEC
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    bind(s, (struct sockaddr *)&a, sizeof a); // any free port
    listen(s, 1);
    FILE *p = popen("true", "r"); // `true` gets a copy of the socket
    char line[64];
    while (p && fgets(line, sizeof line, p))
        ;
    if (p)
        pclose(p);
    close(s);
    return 0;
}
