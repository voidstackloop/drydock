# FormatString (`format-string`)

**CWE:** [CWE-134](https://cwe.mitre.org/data/definitions/134.html) · **Severity:** high · **Default run:** reported

A format string that is not a literal, with nothing after it.

## What it reports

printf(buf), fprintf(f, buf), syslog(p, buf) and snprintf(b, n, buf) treat buf as the format. If it holds a %, the function reads arguments that were never passed (a leak of the stack), and %n writes to memory: a classic way to take over a program. Print text with printf("%s", buf). Reported as stronger when the text comes from the environment, a command-line argument or a read.

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
