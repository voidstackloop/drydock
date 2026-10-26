# Worm (`worm`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Code that spreads itself to other machines.

## What it reports

A worm needs no host file: it copies itself over the network, through shared folders, removable drives (autorun.inf), stolen SSH keys or an exploit. Noticed by: propagation commands (scp of its own file, net use + copy, psexec), autorun.inf, exploit names, and a program that tries a hundred addresses in ten seconds.

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
