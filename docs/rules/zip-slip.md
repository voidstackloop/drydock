# Path Traversal via Archive Extraction (Zip Slip) (`zip-slip`)

**CWE:** [CWE-29](https://cwe.mitre.org/data/definitions/29.html) · **Severity:** high · **Default run:** reported

File path from archive entry extracted without path traversal validation.

## What it reports

Archive entry filenames containing '../' directory traversal sequences can write files outside the target extraction directory. Validate that the canonicalized destination path begins with the target extraction root directory.

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
