# LogTampering (`log-tampering`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

The program erases the record of what happened.

## What it reports

A system log (/var/log, utmp, wtmp) or the shell history was removed or emptied, or a command line does so (history -c, rm /var/log/..., HISTFILE=/dev/null). Malware wipes the traces of its break-in; a program has no other reason to delete another program's log.

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
