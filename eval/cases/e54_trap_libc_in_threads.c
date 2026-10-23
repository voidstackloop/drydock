// level: expert
// mode: dynamic
// expect: none
// what: trap: the same libc functions used safely by several threads: the _r variants, one lock around the calls, a result copied out under that lock, and a thread that ended before the next one calls
#define _GNU_SOURCE
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t libc_lock = PTHREAD_MUTEX_INITIALIZER;
static int go;

static void stamp_r(char *out, size_t n) {
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(out, n, "%H:%M:%S", &tm);
}

static void stamp_locked(char *out, size_t n) {
    time_t now = time(NULL);
    pthread_mutex_lock(&libc_lock);
    struct tm *tm = localtime(&now);
    strftime(out, n, "%H:%M:%S", tm);
    pthread_mutex_unlock(&libc_lock);
}

static int split_r(char *s) {
    int n = 0;
    char *save = NULL;
    for (char *tok = strtok_r(s, ";", &save); tok; tok = strtok_r(NULL, ";", &save))
        n++;
    return n;
}

static void *worker(void *arg) {
    (void)arg;
    char buf[32], line[32] = "a;b;c";
    stamp_r(buf, sizeof buf);
    stamp_locked(buf, sizeof buf);
    split_r(line);
    while (!__atomic_load_n(&go, __ATOMIC_ACQUIRE))
        usleep(1000);
    return NULL;
}

static void *short_lived(void *arg) {
    (void)arg;
    char buf[32];
    pthread_mutex_lock(&libc_lock);
    struct passwd *pw = getpwuid(0); // the only user of getpwuid until main
    snprintf(buf, sizeof buf, "%s", pw ? pw->pw_name : "?");
    pthread_mutex_unlock(&libc_lock);
    return NULL;
}

int main(void) {
    pthread_t a, b, c;
    pthread_create(&a, NULL, worker, NULL);
    pthread_create(&b, NULL, worker, NULL);
    pthread_create(&c, NULL, short_lived, NULL);
    pthread_join(c, NULL);
    char buf[32], line[32] = "x;y";
    stamp_r(buf, sizeof buf);
    stamp_locked(buf, sizeof buf);
    split_r(line);
    pthread_mutex_lock(&libc_lock);
    getpwuid(0);
    pthread_mutex_unlock(&libc_lock);
    __atomic_store_n(&go, 1, __ATOMIC_RELEASE);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    return 0;
}
