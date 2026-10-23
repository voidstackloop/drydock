// level: expert
// mode: static
// expect: none
// what: trap: the same order in every file, and opposite orders only between files' own static mutexes
// with: parts/e32_worker.c
#include <pthread.h>

pthread_mutex_t jobs_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t done_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t b = PTHREAD_MUTEX_INITIALIZER;
int jobs, done;

void submit(void) {
    pthread_mutex_lock(&jobs_lock);
    jobs++;
    pthread_mutex_lock(&done_lock);
    done--;
    pthread_mutex_unlock(&done_lock);
    pthread_mutex_unlock(&jobs_lock);
    pthread_mutex_lock(&a);
    pthread_mutex_lock(&b);
    pthread_mutex_unlock(&b);
    pthread_mutex_unlock(&a);
}
