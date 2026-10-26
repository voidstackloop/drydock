# Logic Bomb (`logic-bomb`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Destroys or harms when a condition becomes true.

## What it reports

A logic bomb sleeps until a date, a user name or a machine name matches, and then deletes or corrupts. Noticed by a destructive command or call near a test against a calendar date, a host name or a user name, and by the words 'logic bomb' or 'time bomb' near one. What a bomb waits for is not run, so a run never sees it.

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
