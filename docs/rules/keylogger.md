# Keylogger (`keylogger`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Records what is typed.

## What it reports

A keylogger captures keystrokes: keyboard hooks, polling every key, reading the raw input devices, X11 recording, accessibility events, key listeners in a web page that send what was typed away. Noticed by those APIs, and in a run by opening the input devices, by a keyboard hook, or by polling the state of sixty different keys.

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
