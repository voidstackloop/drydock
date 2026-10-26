# UseAfterDestroy (`use-after-destroy`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

A mutex is used after it was destroyed.

## What it reports

After pthread_mutex_destroy() glibc marks the mutex invalid: a lock answers EINVAL instead of locking, so a caller that ignores the result enters its critical section unprotected. It is typical of shutdown code that destroys a mutex while another thread can still reach it. Destroy it last, or initialise it again before reuse.

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
