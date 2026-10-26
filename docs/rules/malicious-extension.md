# Malicious Extension (`malicious-extension`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Browser add-on that hijacks traffic or steals credentials.

## What it reports

Malicious extensions run inside Chrome, Firefox, or Edge to inject ads, hijack search queries, or steal cookies and credentials. Noticed by browser extension manifest files requesting broad host permissions, webRequestBlocking, and cookie capture.

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
