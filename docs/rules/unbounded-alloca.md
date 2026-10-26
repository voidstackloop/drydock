# UnboundedAlloca (`unbounded-alloca`)

**CWE:** [CWE-770](https://cwe.mitre.org/data/definitions/770.html) · **Severity:** high · **Default run:** reported

alloca() is given a size that comes from outside the program.

## What it reports

alloca() takes its size from a value that came from outside (an argument, the environment, a read). The stack frame is that big, and a long value walks off the stack. alloca(64) and alloca(sizeof buf) are fixed and are not reported. Use malloc() and reject a size you cannot afford.

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
