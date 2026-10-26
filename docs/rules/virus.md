# Virus (`virus`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Code that copies itself into other files.

## What it reports

A virus attaches itself to host files (programs, scripts, documents) and runs when they do. Noticed by: code that walks a directory, opens other programs or scripts for writing and puts its own bytes in them; a run that rewrites several executables. A virus whose copies change from file to file leaves only the technique to find.

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
