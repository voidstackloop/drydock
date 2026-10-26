# SelectOverflow (`select-overflow`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

select() is called with nfds past FD_SETSIZE.

## What it reports

select() and pselect() are told to watch more descriptors than an fd_set can hold (FD_SETSIZE, 1024 on Linux). The kernel copies that many bits from the sets the caller passed, which are only FD_SETSIZE bits, so it reads and writes past them, usually on the stack. nfds up to FD_SETSIZE is fine. Use poll() or epoll_wait(), which take a list instead of a fixed bit set.

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
