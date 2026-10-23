// level: basic
// mode: dynamic
// expect: bind-without-reuseaddr
// what: a server binds its fixed TCP port without SO_REUSEADDR, so a quick restart fails with "Address already in use"
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(41101);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(srv, (struct sockaddr *)&addr, sizeof addr) != 0)
        perror("bind");
    else if (listen(srv, 16) == 0)
        puts("listening on 41101");
    close(srv);
    return 0;
}
