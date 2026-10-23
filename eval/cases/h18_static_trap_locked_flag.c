// level: hard
// mode: static
// expect: none
// what: trap: a 'locked' flag records whether the error path already unlocked
#include <pthread.h>
#include <stdio.h>

struct account {
    pthread_mutex_t mu;
    long balance;
};

int withdraw(struct account *a, long amount) {
    int locked = 1, rc = 0;
    pthread_mutex_lock(&a->mu);
    if (a->balance < amount) {
        pthread_mutex_unlock(&a->mu);
        locked = 0;
        fprintf(stderr, "withdraw: insufficient funds\n");
        rc = -1;
        goto out;
    }
    a->balance -= amount;
out:
    if (locked)
        pthread_mutex_unlock(&a->mu);
    return rc;
}
