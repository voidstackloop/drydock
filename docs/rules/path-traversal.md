# PathTraversal (`path-traversal`)

**CWE:** [CWE-22](https://cwe.mitre.org/data/definitions/22.html) · **Severity:** high · **Default run:** reported

A path is built by joining outside text onto a directory.

## What it reports

open() or fopen() is given a path made with snprintf("%s/%s") or by appending text from outside the program onto a directory. A value such as ../etc/passwd leaves that directory. Reject ".." before opening, or open the directory and use openat().

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
