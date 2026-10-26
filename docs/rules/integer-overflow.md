# Integer Overflow or Wraparound (`integer-overflow`)

**CWE:** [CWE-190](https://cwe.mitre.org/data/definitions/190.html) · **Severity:** high · **Default run:** strict-only (`--strict`)

Arithmetic on untrusted integers can wrap around before a size check or allocation.

## What it reports

Multiplication or addition on integer values derived from outside text (e.g. `count * elem_size` or `offset + len`) can wrap around to a small positive value, bypassing size checks and causing under-allocation followed by buffer overflows. Validate arithmetic against numeric limits before using the result in memory allocation or indexing.

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
