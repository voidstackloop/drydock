# Trojan Horse (`trojan-horse`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

A program that is not what it pretends to be and does harm.

## What it reports

A trojan looks like something wanted (a document, a system program, a trusted tool) and carries the harmful part inside. Noticed by combining two findings in one file or one process: a disguise (double extension, system name in the wrong place, a program named like a document) together with any harmful behaviour.

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
