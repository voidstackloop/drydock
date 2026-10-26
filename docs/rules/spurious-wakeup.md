# SpuriousWakeup (`spurious-wakeup`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

A condition wait is not inside a loop that tests the condition.

## What it reports

pthread_cond_wait() may return without a signal (a spurious wakeup), or after another thread has already taken what the signal announced. Code that waits once and then goes on works for years and fails on a busy or different system. Wait in a loop: while (!ready) pthread_cond_wait(&cv, &m);

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
