# InsecurePermissions (`insecure-permissions`)

**CWE:** [CWE-732](https://cwe.mitre.org/data/definitions/732.html) · **Severity:** medium · **Default run:** reported

A file is made writable by every user.

## What it reports

chmod(path, 0777) or 0666, or umask(0), lets any user on the machine change the file or the ones the program creates later. Whoever can write a script, a configuration or a library the program reads later controls the program. Give the owner and a group the write bit and nobody else.

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
