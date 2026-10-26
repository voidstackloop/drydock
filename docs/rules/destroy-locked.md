# DestroyLockedLock (`destroy-locked`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

A lock is destroyed while it is held.

## What it reports

Destroying a locked mutex, read-write lock or spin lock is undefined. glibc answers EBUSY for a mutex, which programs rarely check, and the memory is then freed or reused while a thread may still unlock it or wait for it. Unlock it, and make sure no thread can still use it, before destroying it.

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
