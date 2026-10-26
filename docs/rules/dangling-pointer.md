# DanglingPointer (`dangling-pointer`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Pointer to an object that no longer exists.

## What it reports

The address of a local variable escapes its scope, so the pointer dangles once the function returns; or data the program still uses keeps a pointer to a heap block it freed. Nothing fails until some later path follows the pointer, which then reads or writes freed memory. Clear or replace the pointer when the object goes away.

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
