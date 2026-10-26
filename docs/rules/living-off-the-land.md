# Living-off-the-Land Malware (`living-off-the-land`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Does harm with tools already on the machine.

## What it reports

It uses the system's own tools (certutil, mshta, regsvr32, rundll32, wmic, msbuild, bash, python, find, awk) so that no malicious file is needed. Noticed by command lines that use those tools the way attackers do (squiblydoo, mshta URL, wmic process call create, PowerShell hidden with bypass, GTFOBins shells). Administrators use the same tools.

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
