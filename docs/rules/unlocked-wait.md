# UnlockedConditionWait (`unlocked-wait`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

A condition variable is waited on without holding its mutex.

## What it reports

pthread_cond_wait() unlocks the mutex and takes it back, so the caller must hold it. Without it, a signal sent between checking the condition and starting the wait is lost and the waiter sleeps on, which shows only under load. Lock the mutex, check the condition in a loop, then wait.

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
