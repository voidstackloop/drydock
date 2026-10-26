# Browser Hijacker (`browser-hijacker`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Changes the browser's home page, search or proxy.

## What it reports

A hijacker rewrites the start page, the default search engine, the proxy or installs an extension by policy, so that the user's traffic goes through the attacker. Noticed by the settings it writes (Firefox prefs, Chrome policies and preferences, Internet Explorer's start page and search scopes) in files, and by writing them in a run.

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
