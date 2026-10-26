# MemoryLeak (`memory-leak`)

**CWE:** [CWE-401](https://cwe.mitre.org/data/definitions/401.html) · **Severity:** medium · **Default run:** reported

Heap memory is never released.

## What it reports

A block was still allocated when the program ended and no pointer to it remained (definitely lost), or only pointers into its middle remained (possibly lost). Release it on every path, or hand ownership to a smart pointer or container.

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
