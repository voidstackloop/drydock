// C library functions with static state, called from more than one thread.
// usage: unsafe_libc <case>
#define _GNU_SOURCE
#include <pthread.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int worker_called, may_go;

static void nap(void) {
    struct timespec ts = {0, 1000000};
    nanosleep(&ts, NULL);
}

// the worker calls `fn`, then waits (alive) until main has called it too
static int g_case;
static void call(int which) {
    char buf[32] = "a b c";
    time_t t = 0;
    switch (which) {
    case 0:
        strtok(buf, " ");
        break;
    case 1:
        localtime(&t);
        break;
    case 2:
        getpwuid(0);
        break;
    case 3: { // localtime_r: fine
        struct tm tm;
        localtime_r(&t, &tm);
        break;
    }
    case 4: { // one lock around the calls
        pthread_mutex_lock(&lock);
        localtime(&t);
        pthread_mutex_unlock(&lock);
        break;
    }
    }
}

static void *worker(void *arg) {
    (void)arg;
    call(g_case);
    __atomic_store_n(&worker_called, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&may_go, __ATOMIC_ACQUIRE))
        nap();
    return NULL;
}

static void *worker_exits(void *arg) {
    (void)arg;
    call(g_case);
    return NULL;
}

int main(int argc, char **argv) {
    const char *k = argc > 1 ? argv[1] : "strtok";
    pthread_t t;
    if (!strcmp(k, "strtok"))
        g_case = 0;
    else if (!strcmp(k, "localtime"))
        g_case = 1;
    else if (!strcmp(k, "getpwuid"))
        g_case = 2;
    else if (!strcmp(k, "reentrant"))
        g_case = 3;
    else if (!strcmp(k, "locked"))
        g_case = 4;
    else if (!strcmp(k, "sequential")) { // the first caller is gone
        g_case = 1;
        pthread_create(&t, NULL, worker_exits, NULL);
        pthread_join(t, NULL);
        call(g_case);
        return 0;
    } else if (!strcmp(k, "single")) { // one thread, many calls
        g_case = 1;
        for (int i = 0; i < 5; i++)
            call(g_case);
        return 0;
    } else
        return 64;
    pthread_create(&t, NULL, worker, NULL);
    while (!__atomic_load_n(&worker_called, __ATOMIC_ACQUIRE))
        nap();
    call(g_case); // main calls it too, while the worker is alive
    __atomic_store_n(&may_go, 1, __ATOMIC_RELEASE);
    pthread_join(t, NULL);
    return 0;
}
