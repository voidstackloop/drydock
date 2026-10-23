#include <pthread.h>

extern pthread_mutex_t jobs_lock, done_lock;
extern int jobs, done;
static pthread_mutex_t a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t b = PTHREAD_MUTEX_INITIALIZER;

void finish(void) {
    pthread_mutex_lock(&jobs_lock); // the same order as submit()
    pthread_mutex_lock(&done_lock);
    jobs--;
    done++;
    pthread_mutex_unlock(&done_lock);
    pthread_mutex_unlock(&jobs_lock);
    pthread_mutex_lock(&b); // this file's own b and a
    pthread_mutex_lock(&a);
    pthread_mutex_unlock(&a);
    pthread_mutex_unlock(&b);
}
