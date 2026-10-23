// Winsock: sockets left open, closed twice, used after closing, and reads that go
// nowhere. One case per argument; a listener and a client on the loopback.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

static SOCKET listener, client, server;

static void start(void) {
    WSADATA d;
    struct sockaddr_in a;
    int len = sizeof a;
    WSAStartup(MAKEWORD(2, 2), &d);
    listener = socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(listener, (struct sockaddr *)&a, sizeof a);
    listen(listener, 1);
    getsockname(listener, (struct sockaddr *)&a, &len);
    client = socket(AF_INET, SOCK_STREAM, 0);
    connect(client, (struct sockaddr *)&a, sizeof a);
    server = accept(listener, NULL, NULL);
}

static void finish(void) {
    closesocket(server);
    closesocket(client);
    closesocket(listener);
}

static void leak(void) {
    start();
    closesocket(listener);
    closesocket(client); // the accepted socket is left open
}
static void double_close(void) {
    SOCKET s;
    WSADATA d;
    WSAStartup(MAKEWORD(2, 2), &d);
    s = socket(AF_INET, SOCK_STREAM, 0);
    closesocket(s);
    closesocket(s);
}
static void use_after_close(void) {
    char b[4];
    SOCKET s;
    WSADATA d;
    WSAStartup(MAKEWORD(2, 2), &d);
    s = socket(AF_INET, SOCK_STREAM, 0);
    closesocket(s);
    recv(s, b, sizeof b, 0);
}
static void eof_spin(int times) {
    char b[16];
    start();
    closesocket(client); // the peer hangs up
    for (int i = 0; i < times; i++)
        if (recv(server, b, sizeof b, 0) != 0)
            break;
    closesocket(server);
    closesocket(listener);
}
static void eof_stops(void) {
    char b[16];
    start();
    closesocket(client);
    while (recv(server, b, sizeof b, 0) > 0) {
    }
    closesocket(server);
    closesocket(listener);
}
static void eagain_spin(int times) {
    char b[16];
    u_long nb = 1;
    start();
    ioctlsocket(client, FIONBIO, &nb);
    for (int i = 0; i < times; i++)
        recv(client, b, sizeof b, 0);
    finish();
}
static void ordinary(void) {
    char b[16];
    start();
    send(client, "hi", 2, 0);
    recv(server, b, sizeof b, 0);
    finish();
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        const char *c = argv[i];
        if (!strcmp(c, "leak")) leak();
        else if (!strcmp(c, "double-close")) double_close();
        else if (!strcmp(c, "use-after-close")) use_after_close();
        else if (!strcmp(c, "eof-spin")) eof_spin(1200);
        else if (!strcmp(c, "eof-few")) eof_spin(200);
        else if (!strcmp(c, "eof-stops")) eof_stops();
        else if (!strcmp(c, "eagain-spin")) eagain_spin(1200);
        else if (!strcmp(c, "eagain-few")) eagain_spin(200);
        else if (!strcmp(c, "ordinary")) ordinary();
        else {
            fprintf(stderr, "unknown case %s\n", c);
            return 64;
        }
    }
    return 0;
}
