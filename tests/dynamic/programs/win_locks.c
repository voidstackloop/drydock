// Windows locks: critical sections, slim reader/writer locks, mutex handles.
// One case per argument; the threads run one after the other, so a program
// that would deadlock only in an unlucky interleaving finishes here.
#include <windows.h>
#include <stdio.h>
#include <string.h>

static CRITICAL_SECTION a, b, c;
static SRWLOCK s1 = SRWLOCK_INIT, s2 = SRWLOCK_INIT;
static CONDITION_VARIABLE cv = CONDITION_VARIABLE_INIT;

static void init(void) {
    InitializeCriticalSection(&a);
    InitializeCriticalSection(&b);
    InitializeCriticalSection(&c);
}

static void run(DWORD(WINAPI *f)(LPVOID), LPVOID arg) {
    HANDLE t = CreateThread(NULL, 0, f, arg, 0, NULL);
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
}

// ---- critical sections

static DWORD WINAPI a_then_b(LPVOID p) {
    (void)p;
    EnterCriticalSection(&a);
    EnterCriticalSection(&b);
    LeaveCriticalSection(&b);
    LeaveCriticalSection(&a);
    return 0;
}
static DWORD WINAPI b_then_a(LPVOID p) {
    (void)p;
    EnterCriticalSection(&b);
    EnterCriticalSection(&a);
    LeaveCriticalSection(&a);
    LeaveCriticalSection(&b);
    return 0;
}
static DWORD WINAPI b_then_c(LPVOID p) {
    (void)p;
    EnterCriticalSection(&b);
    EnterCriticalSection(&c);
    LeaveCriticalSection(&c);
    LeaveCriticalSection(&b);
    return 0;
}
static DWORD WINAPI c_then_a(LPVOID p) {
    (void)p;
    EnterCriticalSection(&c);
    EnterCriticalSection(&a);
    LeaveCriticalSection(&a);
    LeaveCriticalSection(&c);
    return 0;
}
static DWORD WINAPI keeps_lock(LPVOID p) {
    (void)p;
    EnterCriticalSection(&a); // and ends
    return 0;
}
static DWORD WINAPI unlocks_foreign(LPVOID p) {
    (void)p;
    LeaveCriticalSection(&a);
    return 0;
}

static void cs_inversion(void) {
    init();
    run(a_then_b, NULL);
    run(b_then_a, NULL);
}
static void cs_three_cycle(void) {
    init();
    run(a_then_b, NULL); // a before b, b before c, c before a: a cycle of three
    run(b_then_c, NULL);
    run(c_then_a, NULL);
}
static void cs_consistent_order(void) {
    init();
    run(a_then_b, NULL);
    run(a_then_b, NULL);
}
static void cs_recursive(void) {
    init();
    EnterCriticalSection(&a);
    EnterCriticalSection(&a);
    LeaveCriticalSection(&a);
    LeaveCriticalSection(&a);
}
static void cs_leak(void) {
    init();
    run(keeps_lock, NULL);
}
static DWORD WINAPI takes_it(LPVOID p) {
    (void)p;
    EnterCriticalSection(&a); // would wait forever: the owner is gone
    return 0;
}
static void cs_orphan(void) {
    init();
    run(keeps_lock, NULL);
    run(takes_it, NULL);
}
static void cs_foreign_unlock(void) {
    init();
    EnterCriticalSection(&a);
    run(unlocks_foreign, NULL);
}
static void cs_destroy_locked(void) {
    init();
    EnterCriticalSection(&a);
    DeleteCriticalSection(&a);
}
static void cs_use_after_destroy(void) {
    init();
    DeleteCriticalSection(&a);
    EnterCriticalSection(&a);
    LeaveCriticalSection(&a);
}
static void cs_wait_without_lock(void) {
    init();
    SleepConditionVariableCS(&cv, &a, 1); // times out; the section was never entered
}
static void cs_wait_with_lock(void) {
    init();
    EnterCriticalSection(&a);
    SleepConditionVariableCS(&cv, &a, 1);
    LeaveCriticalSection(&a);
}
static void cs_try_enter_makes_no_order(void) {
    init();
    EnterCriticalSection(&a);
    if (TryEnterCriticalSection(&b))
        LeaveCriticalSection(&b);
    LeaveCriticalSection(&a);
    run(b_then_a, NULL);
}

// ---- slim reader/writer locks

static DWORD WINAPI s1_then_s2(LPVOID p) {
    (void)p;
    AcquireSRWLockExclusive(&s1);
    AcquireSRWLockExclusive(&s2);
    ReleaseSRWLockExclusive(&s2);
    ReleaseSRWLockExclusive(&s1);
    return 0;
}
static DWORD WINAPI s2_then_s1(LPVOID p) {
    (void)p;
    AcquireSRWLockExclusive(&s2);
    AcquireSRWLockExclusive(&s1);
    ReleaseSRWLockExclusive(&s1);
    ReleaseSRWLockExclusive(&s2);
    return 0;
}
static DWORD WINAPI readers_both_ways(LPVOID p) {
    int first = p != NULL;
    SRWLOCK *x = first ? &s2 : &s1, *y = first ? &s1 : &s2;
    AcquireSRWLockShared(x);
    AcquireSRWLockShared(y);
    ReleaseSRWLockShared(y);
    ReleaseSRWLockShared(x);
    return 0;
}

static void srw_inversion(void) {
    run(s1_then_s2, NULL);
    run(s2_then_s1, NULL);
}
static void srw_readers_in_any_order(void) {
    run(readers_both_ways, NULL);
    run(readers_both_ways, (LPVOID)1);
}
static void srw_relock(void) {
    AcquireSRWLockExclusive(&s1);
    AcquireSRWLockExclusive(&s1); // waits for itself forever
}
static void srw_shared_twice(void) {
    AcquireSRWLockShared(&s1);
    AcquireSRWLockShared(&s1);
    ReleaseSRWLockShared(&s1);
    ReleaseSRWLockShared(&s1);
}
static void srw_shared_while_exclusive(void) {
    AcquireSRWLockExclusive(&s1);
    AcquireSRWLockShared(&s1);
}

// ---- mutex handles

static HANDLE m1, m2;
static DWORD WINAPI h1_then_h2(LPVOID p) {
    (void)p;
    WaitForSingleObject(m1, INFINITE);
    WaitForSingleObject(m2, INFINITE);
    ReleaseMutex(m2);
    ReleaseMutex(m1);
    return 0;
}
static DWORD WINAPI h2_then_h1(LPVOID p) {
    (void)p;
    WaitForSingleObject(m2, INFINITE);
    WaitForSingleObject(m1, INFINITE);
    ReleaseMutex(m1);
    ReleaseMutex(m2);
    return 0;
}
static void handle_mutex_inversion(void) {
    m1 = CreateMutexA(NULL, FALSE, NULL);
    m2 = CreateMutexA(NULL, FALSE, NULL);
    run(h1_then_h2, NULL);
    run(h2_then_h1, NULL);
    CloseHandle(m1);
    CloseHandle(m2);
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        const char *k = argv[i];
        if (!strcmp(k, "cs-inversion")) cs_inversion();
        else if (!strcmp(k, "cs-cycle3")) cs_three_cycle();
        else if (!strcmp(k, "cs-ordered")) cs_consistent_order();
        else if (!strcmp(k, "cs-recursive")) cs_recursive();
        else if (!strcmp(k, "cs-leak")) cs_leak();
        else if (!strcmp(k, "cs-foreign-unlock")) cs_foreign_unlock();
        else if (!strcmp(k, "cs-orphan")) cs_orphan();
        else if (!strcmp(k, "cs-destroy-locked")) cs_destroy_locked();
        else if (!strcmp(k, "cs-use-after-destroy")) cs_use_after_destroy();
        else if (!strcmp(k, "cs-wait-unlocked")) cs_wait_without_lock();
        else if (!strcmp(k, "cs-wait-locked")) cs_wait_with_lock();
        else if (!strcmp(k, "cs-try-no-order")) cs_try_enter_makes_no_order();
        else if (!strcmp(k, "srw-inversion")) srw_inversion();
        else if (!strcmp(k, "srw-readers")) srw_readers_in_any_order();
        else if (!strcmp(k, "srw-relock")) srw_relock();
        else if (!strcmp(k, "srw-shared-twice")) srw_shared_twice();
        else if (!strcmp(k, "srw-shared-while-exclusive")) srw_shared_while_exclusive();
        else if (!strcmp(k, "handle-inversion")) handle_mutex_inversion();
        else {
            fprintf(stderr, "unknown case %s\n", k);
            return 64;
        }
    }
    return 0;
}
