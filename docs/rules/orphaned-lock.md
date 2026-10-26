# OrphanedLock (`orphaned-lock`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

A mutex is locked whose owner thread no longer exists.

## What it reports

The mutex is still locked by a thread that ended while holding it, or by another thread of the parent when the process forked: the child has only the thread that called fork(), so nothing will ever unlock it and the next lock waits forever. After fork() in a multi-threaded program the child may only call async-signal-safe functions until it execs; take the lock in a pthread_atfork() handler, or fork before starting threads.

## When it is a false alarm

A rule matches a shape of code, not a proof. This one is wrong when the
program establishes the condition the rule cannot see: a check on another
path, a wrapper that guarantees the invariant, or a value that is fixed by
the time the code runs. Every finding from a rule that exceeded the 2%
false-alarm budget is listed in `eval/PRECISION.md`.

## Silencing one

Add a rule to the suppression file, with a reason and an expiry date:

```
%s:<glob of the function or file> reason="why this is safe" expires=YYYY-MM-DD
```

`leakcheck --audit-suppressions -s <file>` lists every silence and fails
once one has expired, so a suppression is reviewed rather than forgotten.
