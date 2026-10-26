# DescriptorLimit (`descriptor-limit`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

The process ran out of file descriptors.

## What it reports

open(), socket(), accept(), pipe() or another call that makes a descriptor failed with EMFILE or ENFILE. A server that leaks one descriptor per connection gets here after hours, and then refuses every client (accept() in a loop fails at full CPU). The report names the call site that opened most of the descriptors still open: that is the leak. Close it on every path, or raise the limit only after that.

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
