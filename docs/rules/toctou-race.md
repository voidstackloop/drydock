# TimeOfCheckTimeOfUse (`toctou-race`)

**CWE:** [CWE-367](https://cwe.mitre.org/data/definitions/367.html) · **Severity:** medium · **Default run:** reported

A file is checked with access() and then used.

## What it reports

Between access(path) and open(path) another process can replace the file, for example with a symlink to one the caller may not read: the check was true for a different file. Call open() directly and look at errno; drop privileges first if the point was to act as the caller.

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
