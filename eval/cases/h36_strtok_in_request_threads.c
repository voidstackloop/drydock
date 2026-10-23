// level: hard
// mode: dynamic
// expect: thread-unsafe-call
// what: a request parser splits "key=value;key=value" with strtok, called by a pool of two handler threads
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int parsed;

static int parse_pairs(const char *input) {
    char copy[128];
    strncpy(copy, input, sizeof copy - 1);
    copy[sizeof copy - 1] = 0;
    int n = 0;
    for (char *tok = strtok(copy, ";"); tok; tok = strtok(NULL, ";"))
        n++;
    return n;
}

static void *handler(void *arg) {
    const char *req = arg;
    int n = parse_pairs(req);
    __atomic_add_fetch(&parsed, n, __ATOMIC_RELAXED);
    usleep(30000); // answering the client
    return NULL;
}

int main(void) {
    pthread_t a, b;
    pthread_create(&a, NULL, handler, "a=1;b=2;c=3");
    usleep(10000);
    pthread_create(&b, NULL, handler, "x=9;y=8");
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    printf("%d pairs\n", parsed);
    return 0;
}
