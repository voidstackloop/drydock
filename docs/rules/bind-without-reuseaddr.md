# BindWithoutReuseAddr (`bind-without-reuseaddr`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

A server binds a TCP port without SO_REUSEADDR.

## What it reports

bind() to a fixed port on a stream socket that has neither SO_REUSEADDR nor SO_REUSEPORT. After the server exits, or crashes with clients connected, the port stays in TIME_WAIT and the next start fails with "Address already in use" for a minute or more. Call setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) before bind().

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
