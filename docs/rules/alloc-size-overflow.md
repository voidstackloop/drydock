# Integer Overflow to Buffer Allocation (`alloc-size-overflow`)

**CWE:** [CWE-680](https://cwe.mitre.org/data/definitions/680.html) · **Severity:** high · **Default run:** reported

An allocation size is computed by multiplying outside text without overflow check.

## What it reports

malloc() or realloc() is passed a size expression like `n * sizeof(T)`. If the multiplication overflows, the allocated buffer is much smaller than required, leading to heap buffer overflows on subsequent writes. Use calloc() or check for overflow before allocating.

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
