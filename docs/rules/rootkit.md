# Rootkit (`rootkit`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Hides itself and other malware from the system.

## What it reports

A rootkit hides files, processes and connections by changing what the system reports: a kernel module that hooks the system-call table, a preloaded library that replaces readdir(), a driver that unlinks processes, an eBPF program that rewrites getdents(). Noticed by those symbols and strings, loading a kernel module, /etc/ld.so.preload and bind-mounts over /proc/<pid>. Malware that hides by other means is not seen.

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
