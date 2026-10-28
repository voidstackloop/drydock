# Use of Hard-coded Cryptographic Key or IV (`hardcoded-key-iv`)

**CWE:** [CWE-321](https://cwe.mitre.org/data/definitions/321.html) · **Severity:** high · **Default run:** reported

A fixed cryptographic key or initialization vector is embedded in code.

## What it reports

Passing literal byte sequences or static constants as cipher keys or IVs allows anyone with access to the binary to decrypt encrypted data or forge signatures. Generate random keys with secure CSPRNGs and store them in a key vault or hardware security module.

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
