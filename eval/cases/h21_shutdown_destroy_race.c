// level: hard
// mode: dynamic
// expect: use-after-destroy
// what: shutdown destroys the log mutex while a detached logger thread still writes
#include <pthread.h>
#include <string.h>
#include <time.h>

static pthread_mutex_t log_mu = PTHREAD_MUTEX_INITIALIZER;
static char log_buf[4096];
static size_t log_len;

static void nap_ms(long ms) {
    struct timespec d = {0, ms * 1000000};
    nanosleep(&d, NULL);
}

static void log_line(const char *s) {
    pthread_mutex_lock(&log_mu);
    size_t n = strlen(s);
    if (log_len + n < sizeof log_buf) {
        memcpy(log_buf + log_len, s, n);
        log_len += n;
    }
    pthread_mutex_unlock(&log_mu);
}

static void *heartbeat(void *arg) {
    for (int i = 0; i < 30; i++) {
        log_line("tick\n");
        nap_ms(1);
    }
    return arg;
}

static void shutdown_logging(void) { pthread_mutex_destroy(&log_mu); }

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, heartbeat, NULL);
    pthread_detach(t); // "it stops by itself"
    log_line("started\n");
    nap_ms(5);
    shutdown_logging(); // the heartbeat is still running
    nap_ms(60);
    return 0;
}
