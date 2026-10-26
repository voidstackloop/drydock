# ThreadUnsafeCall (`thread-unsafe-call`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

A function that keeps its state in a static buffer is called from several threads.

## What it reports

strtok(), localtime(), gmtime(), ctime(), asctime(), getpwnam(), gethostbyname(), inet_ntoa() and a few more return a pointer into a buffer, or keep a scan position, that every thread shares. Two threads calling one at the same time overwrite each other's result: a wrong timestamp, a half-split string, a crash, once in a long while. Use the _r variant (localtime_r, strtok_r, getpwnam_r, ...), or take one lock around the call and the use of its result.

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
