# Seed Phrase Stealer (`seed-phrase-stealer`)

**CWE:** not mapped · **Severity:** n/a · **Default run:** reported

Searches files and clipboard for cryptocurrency recovery seed phrases.

## What it reports

Inspects clipboard contents, text documents, and memory for 12- or 24-word BIP-39 mnemonic recovery phrases to compromise cryptocurrency hardware and software wallets.

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
