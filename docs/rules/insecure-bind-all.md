# Binding Network Service to Unrestricted IP Address (`insecure-bind-all`)

**CWE:** [CWE-1327](https://cwe.mitre.org/data/definitions/1327.html) · **Severity:** medium · **Default run:** reported

Service binds to INADDR_ANY (0.0.0.0) exposing it to public network interfaces.

## What it reports

Binding network listening sockets to all interfaces allows unauthorized external clients to reach internal services. Bind explicitly to 127.0.0.1 or an isolated private IP address unless public exposure is intended.

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
