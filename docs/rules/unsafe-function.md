# UnsafeFunction (`unsafe-function`)

**CWE:** [CWE-676](https://cwe.mitre.org/data/definitions/676.html) · **Severity:** high · **Default run:** reported

A function that cannot be used safely.

## What it reports

gets() and getwd() write any amount into the buffer; mktemp(), tmpnam() and tempnam() only choose a name, so another user can create a file or symlink of that name first; scanf("%s") with no width reads a word of any length. Use fgets(), getcwd(), mkstemp() and a width in the format.

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
