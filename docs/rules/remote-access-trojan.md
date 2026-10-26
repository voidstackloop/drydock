# Remote Access Trojan (RAT) (`remote-access-trojan`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Lets an attacker control the machine from afar.

## What it reports

A RAT gives its operator a remote command line, the screen, files, the webcam and the keyboard, and stays after a restart. Noticed by the names of known RATs and by the capabilities together: remote command execution, a network channel to a controller, and two or more of screen, keyboard, webcam, file access, persistence, injection. Remote-support software has the same abilities by design.

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
