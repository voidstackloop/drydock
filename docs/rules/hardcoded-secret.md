# HardcodedSecret (`hardcoded-secret`)

**CWE:** [CWE-798](https://cwe.mitre.org/data/definitions/798.html) · **Severity:** high · **Default run:** reported

A password, key or token is written into the program.

## What it reports

A variable named like a password, secret, token or key is set to a literal, a password argument is compared with a literal (a backdoor when the literal is not the real credential), or a string has the shape of a private key or a cloud access token. Everyone who has the binary or the source has it. Read it from the environment or a file only the owner can read.

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
