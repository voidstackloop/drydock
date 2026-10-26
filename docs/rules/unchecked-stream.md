# UncheckedStream (`unchecked-stream`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

A stream is used before checking that it opened.

## What it reports

fopen(), popen() and opendir() return NULL when they fail (no such file, no permission, too many open files). Passing that NULL to fgets(), fprintf(), readdir() or fclose() crashes. Test the result before the first use.

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
