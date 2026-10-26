# LockOrderInversion (`lock-order-inversion`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Mutexes are locked in conflicting orders (potential deadlock).

## What it reports

One path locks mutex A and then B while another locks B and then A (or a longer cycle). When two threads run them at the same time, each waits for the other forever; until the timing lines up the program works. Always lock in one order, or take both at once with std::scoped_lock.

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
