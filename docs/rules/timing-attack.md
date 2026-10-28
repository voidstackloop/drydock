# Observable Timing Discrepancy in Cryptographic Comparison (`timing-attack`)

**CWE:** [CWE-208](https://cwe.mitre.org/data/definitions/208.html) · **Severity:** medium · **Default run:** reported

Cryptographic digest or secret comparison using non-constant-time functions.

## What it reports

memcmp() and strcmp() exit early upon the first mismatched byte, allowing an attacker to determine secret values byte by byte through latency measurements. Use constant-time comparisons like CRYPTO_memcmp() or timingsafe_bcmp().

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
