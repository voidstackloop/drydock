# File-Infector Malware (`file-infector`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Patches executables to carry its code.

## What it reports

A file infector adds its code to a program (a new section, an extended last section, an ELF PT_NOTE turned into code) and redirects the entry point. Noticed by the constructions in source (PT_NOTE to PT_LOAD, entry-point rewriting), a search for *.exe with file mapping, and a run that opens several executables for writing.

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
