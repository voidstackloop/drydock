# Masquerade (`masquerade`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

The program pretends to be something the system or a trusted site runs.

## What it reports

A process takes the name of a kernel thread or of a system service (prctl(PR_SET_NAME, "kworker/0:1"), a program started under another name, a program called sshd that runs from /tmp), a file with such a name is made in a temporary or hidden directory, or a command or lookup uses a host name built to look like a site you trust (github.com.update.example, paypa1.com, micros0ft.com). A name proves nothing: where the file lives, and what the host name really ends in, does. Malware picks these names so that a glance at the process list, PATH or the address bar does not stop anyone.

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
