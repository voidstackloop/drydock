# Bootkit (`bootkit`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Infects the boot process.

## What it reports

A bootkit runs before the operating system: it rewrites the master boot record or the volume boot sector, or replaces the EFI boot loader. Noticed by a file that is a boot sector (512 bytes ending in 55 AA), code that writes to the raw disk, UEFI programs that hook ExitBootServices to patch the Windows loader, bcdedit settings that allow unsigned code, and a run that opens the raw disk for writing.

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
