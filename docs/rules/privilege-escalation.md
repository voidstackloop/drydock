# PrivilegeEscalation (`privilege-escalation`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

The program tries to gain root rights or keep them.

## What it reports

A file was given the setuid or setgid bit, a command line does so (chmod u+s, chmod 4755, setcap cap_setuid, NOPASSWD in sudoers), or a program that is not root asked to become user 0. A setuid copy of a shell is the classic way to keep root after an exploit.

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
