# WeakCrypto (`weak-crypto`)

**CWE:** [CWE-327](https://cwe.mitre.org/data/definitions/327.html) · **Severity:** medium · **Default run:** reported

A broken or weak cryptographic algorithm.

## What it reports

MD5, SHA-1, DES, RC4, ECB mode and crypt() are broken for secrecy and for signatures (collisions can be made, keys can be searched). They are fine as a checksum nobody attacks. For passwords, signatures and encryption use SHA-256 or better, AES-GCM or ChaCha20-Poly1305, and a password hash such as argon2 or bcrypt.

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
