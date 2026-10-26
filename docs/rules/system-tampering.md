# SystemTampering (`system-tampering`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

The program changes the programs and libraries the system trusts.

## What it reports

A file under /bin, /sbin, /usr/bin, /usr/sbin, /usr/lib, /lib or /boot was opened for writing, replaced, removed or given new permissions. A package manager does it; so does a trojan that swaps ls, ps, ssh or a library for its own copy so that it stays hidden and runs with every login. Nothing else should touch those files.

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
