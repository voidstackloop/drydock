# Dropper (`dropper`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

The program writes or downloads code and runs it.

## What it reports

The program started a file it had written itself, piped a download or a decoded text into a shell, or made a file in /tmp executable. A trojan downloader does exactly this: the harmful part is not in the file you were given, it is fetched and started when the program runs. An installer or a build tool does it on purpose; check where the code comes from.

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
