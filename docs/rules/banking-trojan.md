# Banking Trojan (`banking-trojan`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Steals bank logins and changes transactions.

## What it reports

A banking trojan watches the browser and rewrites bank pages. Noticed by web-injection files (set_url, data_before, data_after), a list of bank sites together with hooks of the browser's network calls, and the names of known banking trojans.

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
