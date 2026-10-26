# Use of Cryptographically Weak Pseudo-Random Number Generator (`insecure-prng`)

**CWE:** [CWE-338](https://cwe.mitre.org/data/definitions/338.html) · **Severity:** medium · **Default run:** reported

rand() or random() is used to generate security-sensitive tokens, keys, or nonces.

## What it reports

rand(), srand(), and random() use linear congruential or Mersenne Twister algorithms whose states can be completely reconstructed after observing a few outputs. They must never be used for cryptographic keys, authentication tokens, session IDs, IVs, or password salts. Use getrandom(), /dev/urandom, or OpenSSL's RAND_bytes().

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
