# SEO Poisoning Malware (`seo-poisoning`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Injects spam doorways and redirects search engine crawlers.

## What it reports

Compromised websites or web applications serve cloaked content to search engines (Googlebot, Bingbot) while redirecting human visitors to scam or exploit sites. Noticed by user-agent cloaking scripts and doorway link generators.

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
