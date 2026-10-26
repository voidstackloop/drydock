# CredentialAccess (`credential-access`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

The program reads passwords, keys, or what is typed.

## What it reports

A file was opened that holds secrets: /etc/shadow, an SSH private key, cloud and registry credentials, a browser's saved logins and cookies, a wallet, the memory or environment of another process, or the keyboard device (a key logger reads it). ssh, git and password managers read them for you; a program that does not need them is stealing them.

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
