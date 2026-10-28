# Unchecked Return Value on Security-Critical Function (`unchecked-security-return`)

**CWE:** [CWE-252](https://cwe.mitre.org/data/definitions/252.html) · **Severity:** high · **Default run:** reported

Return value of a privilege management or security function is ignored.

## What it reports

Calls to setuid(), setgid(), seteuid(), or cap_set_proc() can fail due to resource exhaustion or restrictions. If the return value is not verified, the program continues executing with elevated privileges. Check the return value and abort or handle the error on failure.

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
