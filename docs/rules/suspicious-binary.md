# SuspiciousBinary (`suspicious-binary`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

A program is built the way malware is built.

## What it reports

The program is packed (UPX, ASPack, Themida, ...) or its bytes look encrypted, a segment is both writable and executable, it asks for an executable stack, it starts outside its code, its section table was cut off, or it is a shared library that defines readdir() or getdents(), which hides files and processes from every program once it is preloaded. Some of these are also done by honest software (UPX is used on legitimate releases); together they are what a packer or a rootkit looks like.

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
