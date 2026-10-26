# Polymorphic Malware (`polymorphic-code`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Encrypts and changes its decryptor on every copy.

## What it reports

A polymorphic program keeps its body encrypted and rewrites the small decryptor in front of it, so no two copies share bytes. Only the technique can be seen, not the changing: an executable section with the entropy of encrypted data, packers, a program that makes memory writable and executable at once at run time, and the words of mutation engines. JIT compilers also write code at run time.

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
