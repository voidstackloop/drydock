# Botnet Malware (`botnet`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Makes the machine a bot taking orders.

## What it reports

A bot joins a network of machines run by a controller: it checks in to a gate URL, an IRC channel, a Telegram or Discord bot, a Tor hidden service or generated domain names, and carries out commands. Noticed by those constructions and by the combination of a controller channel with command execution and spreading or persistence.

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
