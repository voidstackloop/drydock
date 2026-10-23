// level: expert
// mode: dynamic
// expect: none
// what: trap: a TCP echo server and client in one process doing everything right: SO_REUSEADDR before bind, MSG_NOSIGNAL, stop at end of file, every descriptor closed once
#define _GNU_SOURCE
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int listener;

static void *serve(void *arg) {
    (void)arg;
    int conn = accept(listener, NULL, NULL);
    if (conn < 0)
        return NULL;
    char buf[128];
    ssize_t n;
    while ((n = read(conn, buf, sizeof buf)) > 0)
        send(conn, buf, (size_t)n, MSG_NOSIGNAL);
    close(conn); // n == 0: the client is done
    return NULL;
}

int main(void) {
    listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int one = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(41102);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(listener, 4) != 0) {
        close(listener);
        return 0; // port taken: nothing to test
    }
    pthread_t t;
    pthread_create(&t, NULL, serve, NULL);

    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (connect(client, (struct sockaddr *)&addr, sizeof addr) == 0) {
        send(client, "hello", 5, MSG_NOSIGNAL);
        shutdown(client, SHUT_WR);
        char buf[16];
        while (read(client, buf, sizeof buf) > 0)
            ;
    }
    close(client);
    pthread_join(t, NULL);
    close(listener);
    return 0;
}
