# Use of sizeof() on a Pointer Type (`sizeof-pointer`)

**CWE:** [CWE-467](https://cwe.mitre.org/data/definitions/467.html) · **Severity:** medium · **Default run:** reported

sizeof(pointer) is passed as a buffer size argument to memset or memcpy.

## What it reports

Applying sizeof to a pointer variable yields the pointer width (4 or 8 bytes) rather than the allocated buffer size, leaving the buffer largely uninitialized or partially copied. Use `sizeof(*ptr) * count` or pass the explicit buffer capacity.

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
