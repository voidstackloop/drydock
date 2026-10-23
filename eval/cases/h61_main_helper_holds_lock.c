// level: hard
// mode: dynamic
// expect: lock-leak
// what: a helper called from main locks the log mutex and returns; main returns too
#include <pthread.h>

static pthread_mutex_t log_mu = PTHREAD_MUTEX_INITIALIZER;

static void begin_log(void) { pthread_mutex_lock(&log_mu); }

int main(void) {
    begin_log();
    return 0;
}
