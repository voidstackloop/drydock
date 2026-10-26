# Out-of-bounds Write (`out-of-bounds-write`)

**CWE:** [CWE-787](https://cwe.mitre.org/data/definitions/787.html) · **Severity:** critical · **Default run:** reported

A fixed-size array is written past its end at a constant index.

## What it reports

A local array of known size is written at a constant index beyond its end. Only constant indices are reported. Check the length before indexing.

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
