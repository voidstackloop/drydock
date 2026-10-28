// Lock misuse (mutexes, read-write locks, spin locks) that hangs only under
// unlucky timing, or right away.
// usage: locks <case>
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t b = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t c = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t rw = PTHREAD_RWLOCK_INITIALIZER;
static pthread_rwlock_t rw2 = PTHREAD_RWLOCK_INITIALIZER;
#if defined(__APPLE__)
// Darwin removed spin locks: a mutex stands in so the same orderings run.
// Spin-specific findings stay Linux-only; those tests remain skipped there.
typedef pthread_mutex_t pthread_spinlock_t;
static pthread_spinlock_t spin;
static int pthread_spin_init(pthread_spinlock_t *l, int p) {
    (void)p;
    return pthread_mutex_init(l, NULL);
}
static int pthread_spin_lock(pthread_spinlock_t *l) { return pthread_mutex_lock(l); }
static int pthread_spin_trylock(pthread_spinlock_t *l) { return pthread_mutex_trylock(l); }
static int pthread_spin_unlock(pthread_spinlock_t *l) { return pthread_mutex_unlock(l); }
static int pthread_spin_destroy(pthread_spinlock_t *l) { return pthread_mutex_destroy(l); }
#else
static pthread_spinlock_t spin;
#endif

static void *a_then_b(void *arg) {
    pthread_mutex_lock(&a);
    pthread_mutex_lock(&b);
    pthread_mutex_unlock(&b);
    pthread_mutex_unlock(&a);
    return arg;
}

static void *b_then_a(void *arg) {
    pthread_mutex_lock(&b);
    pthread_mutex_lock(&a);
    pthread_mutex_unlock(&a);
    pthread_mutex_unlock(&b);
    return arg;
}

static void lock_pair(pthread_mutex_t *x, pthread_mutex_t *y) {
    pthread_mutex_lock(x);
    pthread_mutex_lock(y);
    pthread_mutex_unlock(y);
    pthread_mutex_unlock(x);
}

static void run(void *(*fn)(void *)) {
    pthread_t t;
    pthread_create(&t, NULL, fn, NULL);
    pthread_join(t, NULL);
}

// Consistent orders, try-locks, recursion and condition waits: no findings.
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int ready;

static void *signaller(void *arg) {
    pthread_mutex_lock(&a);
    ready = 1;
    pthread_cond_signal(&cv);
    pthread_mutex_unlock(&a);
    return arg;
}

struct obj {
    pthread_mutex_t mu;
    int refs;
};

static void *drop_last(void *arg) {
    struct obj *o = arg;
    pthread_mutex_lock(&o->mu);
    if (--o->refs == 0) {
        free(o); // the last reference: nobody can take its lock any more
        return NULL;
    }
    pthread_mutex_unlock(&o->mu);
    return NULL;
}

static void *reinit_held(void *arg) {
    pthread_mutex_t *m = arg;
    pthread_mutex_lock(m);
    pthread_mutex_init(m, NULL); // the thread ends without locking it again
    return NULL;
}

// A spin lock has no owner word. Freeing it while held must drop the held
// record, or the thread's end says the lock is still held.
struct held_spin {
    pthread_spinlock_t sp;
};

static void *free_held_spin(void *arg) {
    struct held_spin *o = arg;
    pthread_spin_lock(&o->sp);
    free(o);
    return NULL;
}

static int clean(void) {
    run(a_then_b);
    run(a_then_b);
    // b then a, but only tried: a try-lock never waits, so never deadlocks
    pthread_mutex_lock(&b);
    if (pthread_mutex_trylock(&a) == 0)
        pthread_mutex_unlock(&a);
    pthread_mutex_unlock(&b);
    pthread_mutex_t r;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&r, &attr);
    pthread_mutex_lock(&r);
    pthread_mutex_lock(&r);
    pthread_mutex_unlock(&r);
    pthread_mutex_unlock(&r);
    pthread_mutex_destroy(&r);
    // A mutex destroyed, or initialised again, is a new mutex: its old order
    // does not count. (Each case alone must be enough.)
    static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER, n;
    lock_pair(&a, &m);
    pthread_mutex_destroy(&m);
    memcpy(&m, &(pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER, sizeof m);
    lock_pair(&m, &a);
    pthread_mutex_init(&n, NULL);
    lock_pair(&b, &n);
    pthread_mutex_init(&n, NULL);
    lock_pair(&n, &b);
    pthread_t t;
    pthread_mutex_lock(&a);
    pthread_create(&t, NULL, signaller, NULL);
    while (!ready)
        pthread_cond_wait(&cv, &a);
    pthread_mutex_unlock(&a);
    pthread_join(t, NULL);
    // The last reference frees its object with the lock held, in a thread
    // that then ends: not a lock held at thread exit.
    struct obj *o = malloc(sizeof *o);
    pthread_mutex_init(&o->mu, NULL);
    o->refs = 1;
    pthread_create(&t, NULL, drop_last, o);
    pthread_join(t, NULL);
    // A worker re-inits a mutex it holds and then ends. Main would not be
    // told about a stale held-list record; the worker is.
    pthread_mutex_t fresh;
    pthread_mutex_init(&fresh, NULL);
    pthread_create(&t, NULL, reinit_held, &fresh);
    pthread_join(t, NULL);
    pthread_mutex_lock(&n);
    pthread_mutex_init(&n, NULL);
    lock_pair(&n, &c);
    // Readers never wait for readers: both orders of two read locks, a read
    // lock taken twice, and a mutex around a read lock in both orders.
    pthread_rwlock_rdlock(&rw);
    pthread_rwlock_rdlock(&rw2);
    pthread_rwlock_unlock(&rw2);
    pthread_rwlock_unlock(&rw);
    pthread_rwlock_rdlock(&rw2);
    pthread_rwlock_rdlock(&rw);
    pthread_rwlock_rdlock(&rw);
    pthread_rwlock_unlock(&rw);
    pthread_rwlock_unlock(&rw);
    pthread_rwlock_unlock(&rw2);
    pthread_mutex_lock(&c);
    pthread_rwlock_rdlock(&rw);
    pthread_rwlock_unlock(&rw);
    pthread_mutex_unlock(&c);
    pthread_rwlock_rdlock(&rw);
    pthread_mutex_lock(&c);
    pthread_mutex_unlock(&c);
    pthread_rwlock_unlock(&rw);
    // A spin lock in one consistent order, and a try in the other.
    // (On Darwin `spin` is a mutex stand-in: same ordering, no finding.)
    pthread_spin_init(&spin, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_lock(&spin);
    pthread_mutex_lock(&c);
    pthread_mutex_unlock(&c);
    pthread_spin_unlock(&spin);
    pthread_mutex_lock(&c);
    if (pthread_spin_trylock(&spin) == 0)
        pthread_spin_unlock(&spin);
    pthread_mutex_unlock(&c);
    pthread_spin_destroy(&spin);
    // Re-init forgets the held record. A later lock of another mutex must not
    // still see the old one, or the opposite order is an inversion.
    pthread_mutex_t p, q;
    pthread_mutex_init(&p, NULL);
    pthread_mutex_init(&q, NULL);
    pthread_mutex_lock(&p);
    pthread_mutex_init(&p, NULL);
    pthread_mutex_lock(&q);
    pthread_mutex_unlock(&q);
    pthread_mutex_lock(&q);
    pthread_mutex_lock(&p);
    pthread_mutex_unlock(&p);
    pthread_mutex_unlock(&q);
    pthread_mutex_destroy(&p);
    pthread_mutex_destroy(&q);
    struct held_spin *box = malloc(sizeof *box);
    pthread_spin_init(&box->sp, PTHREAD_PROCESS_PRIVATE);
    pthread_create(&t, NULL, free_held_spin, box);
    pthread_join(t, NULL);
    return 0;
}

// A writer that takes a mutex, and a thread that takes the mutex and then
// writes: the same deadlock as two mutexes.
static void *write_then_b(void *arg) {
    pthread_rwlock_wrlock(&rw);
    pthread_mutex_lock(&b);
    pthread_mutex_unlock(&b);
    pthread_rwlock_unlock(&rw);
    return arg;
}

static void *b_then_write(void *arg) {
    pthread_mutex_lock(&b);
    pthread_rwlock_wrlock(&rw);
    pthread_rwlock_unlock(&rw);
    pthread_mutex_unlock(&b);
    return arg;
}

static void rw_inversion(void) {
    run(write_then_b);
    run(b_then_write);
}

// A reader that then takes b, and a thread holding b that wants to write:
// the writer waits for the reader, the reader for b.
static void read_inversion(void) {
    pthread_rwlock_rdlock(&rw);
    pthread_mutex_lock(&b);
    pthread_mutex_unlock(&b);
    pthread_rwlock_unlock(&rw);
    pthread_mutex_lock(&b);
    pthread_rwlock_wrlock(&rw);
    pthread_rwlock_unlock(&rw);
    pthread_mutex_unlock(&b);
}

// Waits on a condition without holding its mutex (timed: it returns).
static void cond_unlocked(void) {
    pthread_cond_t cv2 = PTHREAD_COND_INITIALIZER;
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_nsec += 20000000;
    if (until.tv_nsec >= 1000000000) {
        until.tv_sec++;
        until.tv_nsec -= 1000000000;
    }
    pthread_cond_timedwait(&cv2, &c, &until); // c is not locked
    pthread_mutex_unlock(&c);                 // the wait took it back
}

// A "signal" from one thread to another through a mutex: undefined.
static void *release_other(void *arg) {
    pthread_mutex_unlock(&b); // main locked it
    return arg;
}

static void foreign_unlock(void) {
    pthread_mutex_lock(&b);
    run(release_other);
}

// The same signal, then main locks again. The worker's unlock released the
// mutex, so this lock takes it; it is not a deadlock on a lock main holds.
static void mutex_signal(void) {
    pthread_mutex_lock(&b);
    run(release_other);
    pthread_mutex_lock(&b);
    pthread_mutex_unlock(&b);
}

static void rw_upgrade(void) {
    pthread_rwlock_rdlock(&rw);
    pthread_rwlock_wrlock(&rw); // waits for its own read lock: never returns
}

static void spin_relock(void) {
    pthread_spin_init(&spin, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_lock(&spin);
    pthread_spin_lock(&spin); // spins forever
}

static void spin_inversion(void) {
    pthread_spin_init(&spin, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_lock(&spin);
    pthread_mutex_lock(&a);
    pthread_mutex_unlock(&a);
    pthread_spin_unlock(&spin);
    pthread_mutex_lock(&a);
    pthread_spin_lock(&spin);
    pthread_spin_unlock(&spin);
    pthread_mutex_unlock(&a);
}

// Thread 1 takes a then b, thread 2 b then a. They ran one after the
// other, so nothing hung; at the same time they would have.
static void inversion(void) {
    run(a_then_b);
    run(b_then_a);
}

static void cycle(void) {
    lock_pair(&a, &b);
    lock_pair(&b, &c);
    lock_pair(&c, &a);
}

static void relock(void) {
    pthread_mutex_lock(&a);
    pthread_mutex_lock(&a); // never returns
}

// A mutex inside a freed block, then a new one at the same address (run
// with --quarantine-mb 0 so the address comes back): opposite order, but a
// different mutex. Exit 3 if the address was not reused.
static int reuse(void) {
    pthread_mutex_t *h = malloc(sizeof *h);
    pthread_mutex_init(h, NULL);
    lock_pair(&c, h);
    free(h); // no pthread_mutex_destroy: only the free says it is gone
    pthread_mutex_t *again = malloc(sizeof *again);
    if (again != h)
        return 3;
    memcpy(again, &(pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER, sizeof *again);
    lock_pair(again, &c);
    free(again);
    return 0;
}

// Destroyed while held: by this thread, or by another one (0: mutex b,
// 1: rw for writing, 2: spin) that then unlocks it.
static void destroy_held(void) {
    pthread_mutex_lock(&a);
    pthread_mutex_destroy(&a); // EBUSY: a stays locked
}

static int holding, may_go;

static void nap(void) {
    struct timespec d = {0, 1000000};
    nanosleep(&d, NULL);
}

static void *hold(void *arg) {
    const int kind = (int)(intptr_t)arg;
    if (kind == 0)
        pthread_mutex_lock(&b);
    else if (kind == 1)
        pthread_rwlock_wrlock(&rw);
    else
        pthread_spin_lock(&spin);
    __atomic_store_n(&holding, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&may_go, __ATOMIC_ACQUIRE))
        nap();
    if (kind == 0)
        pthread_mutex_unlock(&b);
    else if (kind == 1)
        pthread_rwlock_unlock(&rw);
    else
        pthread_spin_unlock(&spin);
    return arg;
}

static void destroy_other(int kind) {
    pthread_spin_init(&spin, PTHREAD_PROCESS_PRIVATE);
    pthread_t t;
    pthread_create(&t, NULL, hold, (void *)(intptr_t)kind);
    while (!__atomic_load_n(&holding, __ATOMIC_ACQUIRE))
        nap();
    if (kind == 0)
        pthread_mutex_destroy(&b);
    else if (kind == 1)
        pthread_rwlock_destroy(&rw);
    else
        pthread_spin_destroy(&spin);
    __atomic_store_n(&may_go, 1, __ATOMIC_RELEASE);
    pthread_join(t, NULL);
}

// Used after pthread_mutex_destroy: glibc answers EINVAL to each.
static void lock_destroyed(void) {
    pthread_mutex_destroy(&c);
    if (pthread_mutex_lock(&c) != 0)
        return;
    pthread_mutex_unlock(&c);
}

static void unlock_destroyed(void) {
    pthread_mutex_destroy(&c);
    pthread_mutex_unlock(&c);
}

static void wait_destroyed(void) {
    pthread_mutex_destroy(&c);
    pthread_cond_wait(&cv, &c);
}

// pthread_atfork: locked before fork() and unlocked in the parent and in the
// child, where glibc still names the parent's thread as the owner.
static void prepare(void) { pthread_mutex_lock(&a); }
static void after(void) { pthread_mutex_unlock(&a); }

static int atfork(void) {
    pthread_atfork(prepare, after, after);
    pid_t child = fork();
    if (child == 0)
        exit(0); // a full exit: the traced child's report ends properly
    waitpid(child, NULL, 0);
    return 0;
}

static void *keep_locked(void *arg) {
    pthread_mutex_lock(&c);
    return arg; // without unlocking
}

static void thread_exit(void) { run(keep_locked); }

static void main_exit(void) { pthread_mutex_lock(&a); }

// A thread ended holding c; locking it again would wait forever.
static void orphan_thread(void) {
    run(keep_locked);
    pthread_mutex_lock(&c);
}

// fork() while another thread holds b: the child has no such thread, so its
// lock of b would wait forever.
static void orphan_child(void) {
    pthread_mutex_lock(&b);
    pthread_mutex_unlock(&b);
}

static void orphan_fork(void) {
    pthread_t t;
    pthread_create(&t, NULL, hold, (void *)(intptr_t)0);
    while (!__atomic_load_n(&holding, __ATOMIC_ACQUIRE))
        nap();
    pid_t child = fork();
    if (child == 0) {
        orphan_child();
        _exit(0);
    }
    waitpid(child, NULL, 0);
    __atomic_store_n(&may_go, 1, __ATOMIC_RELEASE);
    pthread_join(t, NULL);
}

// The forking thread holds c itself: the child locking it is an ordinary
// double lock (glibc still names the parent's thread as the owner there).
static void fork_relock(void) {
    pthread_mutex_lock(&c);
    pid_t child = fork();
    if (child == 0) {
        pthread_mutex_lock(&c);
        _exit(0);
    }
    waitpid(child, NULL, 0);
    pthread_mutex_unlock(&c);
}

// The same fork() with nothing held: the child locks b freely.
static int fork_free(void) {
    pthread_t t;
    pthread_create(&t, NULL, signaller, NULL);
    pthread_join(t, NULL);
    pid_t child = fork();
    if (child == 0) {
        orphan_child();
        _exit(0);
    }
    waitpid(child, NULL, 0);
    return 0;
}

int main(int argc, char **argv) {
    const char *k = argc > 1 ? argv[1] : "clean";
    if (!strcmp(k, "clean"))
        return clean();
    if (!strcmp(k, "reuse"))
        return reuse();
    if (!strcmp(k, "atfork"))
        return atfork();
    if (!strcmp(k, "fork-free"))
        return fork_free();
    if (!strcmp(k, "destroy-held"))
        destroy_held();
    else if (!strcmp(k, "orphan-fork"))
        orphan_fork();
    else if (!strcmp(k, "fork-relock"))
        fork_relock();
    else if (!strcmp(k, "orphan-thread"))
        orphan_thread();
    else if (!strcmp(k, "destroy-other"))
        destroy_other(0);
    else if (!strcmp(k, "destroy-other-rw"))
        destroy_other(1);
    else if (!strcmp(k, "destroy-other-spin"))
        destroy_other(2);
    else if (!strcmp(k, "lock-destroyed"))
        lock_destroyed();
    else if (!strcmp(k, "unlock-destroyed"))
        unlock_destroyed();
    else if (!strcmp(k, "wait-destroyed"))
        wait_destroyed();
    else if (!strcmp(k, "inversion"))
        inversion();
    else if (!strcmp(k, "cycle"))
        cycle();
    else if (!strcmp(k, "relock"))
        relock();
    else if (!strcmp(k, "thread-exit"))
        thread_exit();
    else if (!strcmp(k, "main-exit"))
        main_exit();
    else if (!strcmp(k, "rw-inversion"))
        rw_inversion();
    else if (!strcmp(k, "read-inversion"))
        read_inversion();
    else if (!strcmp(k, "cond-unlocked"))
        cond_unlocked();
    else if (!strcmp(k, "foreign-unlock"))
        foreign_unlock();
    else if (!strcmp(k, "mutex-signal"))
        mutex_signal();
    else if (!strcmp(k, "rw-upgrade"))
        rw_upgrade();
    else if (!strcmp(k, "spin-relock"))
        spin_relock();
    else if (!strcmp(k, "spin-inversion"))
        spin_inversion();
    else
        return 64;
    return 0;
}
