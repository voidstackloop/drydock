# Server-Side Request Forgery (SSRF) (`ssrf`)

**CWE:** [CWE-918](https://cwe.mitre.org/data/definitions/918.html) · **Severity:** high · **Default run:** reported

A network request is dispatched to a URL supplied directly from untrusted input.

## What it reports

curl_easy_setopt() or socket connection routines use a URL or host derived from user input. An attacker can direct the application to make requests to internal services (e.g., cloud metadata at 169.254.169.254 or localhost loopback). Validate URLs against a strict whitelist of protocols and domains.

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
