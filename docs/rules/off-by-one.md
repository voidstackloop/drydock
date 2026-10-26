# Off-by-One Buffer Overflow (`off-by-one`)

**CWE:** [CWE-193](https://cwe.mitre.org/data/definitions/193.html) · **Severity:** high · **Default run:** reported

An array or buffer is accessed at an index equal to its total capacity.

## What it reports

A buffer of size N is accessed at index N (e.g. buf[sizeof(buf)] = '\0'), or a loop condition uses `<= N` instead of `< N`. This writes or reads one byte beyond the buffer boundary, corrupting adjacent stack variables, alignment padding, or heap metadata. Use `< sizeof(buf)` for indices and bounds.

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
