# Spyware (`spyware`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Watches the user and sends it out.

## What it reports

Spyware records what the user does: the screen, the webcam, the microphone, the keyboard, the clipboard, the window titles, and sends it away. Noticed by two or more of those abilities together with code that sends data out, and by a run that opens the webcam, the capture devices or the screen buffer.

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
