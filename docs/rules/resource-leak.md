# ResourceLeak (`resource-leak`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

A file descriptor, stream, directory, thread or child process is never released.

## What it reports

A descriptor (open, socket, pipe, dup, ...), FILE stream (fopen, popen), directory stream (opendir), joinable thread or child process was never closed, joined, detached or waited for. Each one holds a kernel or library resource; a long-running program that leaks them per request runs out. Release it on every path, or use an RAII wrapper.

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
