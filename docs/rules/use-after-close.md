# UseAfterClose (`use-after-close`)

**CWE:** [CWE-672](https://cwe.mitre.org/data/definitions/672.html) · **Severity:** high · **Default run:** reported

Use of a resource after it was closed.

## What it reports

A stream or descriptor was used after it had been closed. At run time this is a read, write, send, recv, connect, bind, listen or shutdown on a descriptor number that close() released, which the kernel refuses with EBADF, or fread, fwrite, fgets or fprintf on a FILE* that fclose() released. The data is lost, the error is usually ignored, and in a threaded program the number may already name another thread's file. A second fclose() is a double close (the stream's memory would be freed twice) and is not passed on. Stop using the descriptor or the stream when you close it.

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
