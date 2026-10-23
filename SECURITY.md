# Security policy

## What leakcheck does with a file

* `scan` and `static` only read bytes and text. They never execute, unpack or
  follow anything in the file.
* `dynamic` runs the program under test, by design. Run programs you do not
  trust in a virtual machine, not on your desktop.
* Nothing is uploaded, and no signature database is downloaded. The tool does
  not read the network in any mode.
* The `--ai` model is a local text file. Only load one you trust: a model file
  decides its own threshold and the wording of its findings.

## Reporting a missed detection

A false negative (malware scored as normal) or a false alarm (an honest program
scored as malware) is a correctness bug in the classifier and is worth
reporting, even without the file.

Open a normal issue with:

* the SHA-256 and size of the program;
* the score `leakcheck scan --ai` gave it, and the threshold;
* what the program is, and for a false negative, what makes you sure.

**Do not attach live malware to a public issue, and do not attach anything you
are not allowed to redistribute.** A hash, a VirusTotal link and a description
are enough to start.

## Reporting something private

If the report itself is sensitive — an internal binary, an undisclosed incident,
or a vulnerability in leakcheck that could be exploited by a crafted file —
email the maintainers rather than opening an issue. Include the same details:
version, platform, the command line, the hash and the score. If the problem is
a crash or a memory error in a parser, say which mode and which file, and do not
send the file itself unless asked.

There is no bug bounty. Fixes are made public once a release is out.

## Supported versions

The current `main` branch. The binary has no version negotiation with the model:
a model whose feature count does not match the build is refused with the reason,
rather than half-loaded.
