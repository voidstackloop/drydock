# ProcessInjection (`process-injection`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

The program reads or rewrites another running program.

## What it reports

ptrace() attached to another process or wrote into its memory, process_vm_writev() wrote into it, or /proc/<pid>/mem was opened for writing. This is how code is injected into a running program to hide inside it or to steal what it holds. Debuggers do it with your leave; nothing else should.

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
