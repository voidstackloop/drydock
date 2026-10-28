# Return of Stack-Allocated Memory Address (`return-stack-address`)

**CWE:** [CWE-562](https://cwe.mitre.org/data/definitions/562.html) · **Severity:** critical · **Default run:** reported

Function returns a pointer or reference to a local stack variable.

## What it reports

Stack frame contents are invalidated upon returning from the function. Accessing the returned pointer causes undefined behavior, data corruption, or information disclosure. Allocate dynamic memory or have the caller provide a buffer.

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
