# Persistence (`persistence`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

The program arranges to run again at login or boot.

## What it reports

A file was opened for writing that the system reads at login or at boot: a shell start-up file, a cron table, an autostart entry, a service, the list of SSH keys, /etc/ld.so.preload, the account or sudo files. A trojan uses it to survive a restart and to get back in. An installer does it on purpose; a program that has no reason to should not.

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
