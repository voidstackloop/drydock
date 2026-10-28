# Use of a Moved-From Object (`use-after-move`)

**CWE:** [CWE-825](https://cwe.mitre.org/data/definitions/825.html) · **Severity:** medium · **Default run:** reported

A value is used after being passed to std::move() without reassignment.

## What it reports

std::move() leaves the source in a valid but unspecified state. Reading it afterwards (passing it on, returning it, or branching on it) works by accident until the type changes. Assign a new value before using it again, or copy instead of moving.

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
