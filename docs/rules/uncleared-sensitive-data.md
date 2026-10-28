# Compiler Removal of Code to Clear Sensitive Data (`uncleared-sensitive-data`)

**CWE:** [CWE-14](https://cwe.mitre.org/data/definitions/14.html) · **Severity:** medium · **Default run:** reported

Sensitive credential memory is cleared with dead-store memset().

## What it reports

Standard memset() used to clear secrets right before deallocation is optimized away as a dead store by optimizing compilers. Use explicit_bzero(), memset_s(), or SecureZeroMemory() to guarantee that memory is scrubbed.

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
