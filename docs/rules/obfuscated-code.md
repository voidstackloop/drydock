# ObfuscatedCode (`obfuscated-code`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

A script decodes text and runs the result.

## What it reports

The script feeds decoded text (base64, gzip, rot13, character codes) to exec(), eval() or Invoke-Expression, runs PowerShell with -EncodedCommand, or holds one very long base64 line. A reader and a scanner see only the encoded text; whatever it holds runs at the first line. Malware loaders are written this way. Installers and minifiers sometimes are too: read the decoded text before running it.

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
