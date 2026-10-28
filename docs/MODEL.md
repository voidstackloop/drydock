# The `--ai` model

`leakcheck scan --ai` gives every Windows program with code in it a second
opinion from a classifier trained on known malware. Everything else in leakcheck
reports what it observed; this reports a probability, so it is off unless asked
for, its finding is a warning, and the message carries the score. Nothing in
this document changes that: a score is not a verdict.

The model ships in the repository as [`../model/pe-malware.ai`](../model/pe-malware.ai),
plain text. Retraining it needs Python and LightGBM; using it needs neither.

## What the classifier is

A gradient-boosted forest of 231 small decision trees (LightGBM) over 49
numbers read out of the PE image: header fields, section layout, entry point,
imports and exports, data directories, overlay size, entropy and a handful of
string counts. The trees add up their leaves, the sum goes through a sigmoid,
and the result is compared with a threshold.

* 42 of the 49 numbers are used by this model; see [What it does not
  read](#what-it-does-not-read).
* A file is called malware only when the score is at least the threshold in the
  model header, 0.50. `--ai-threshold` moves it; `tools/evaluate.py --sweep`
  shows what moving it does to a folder of your own.
* The model is a single 285 KB text file. A change to it can be read in a diff.

## The data

| | |
|---|---|
| normal programs, old corpus | 3,587 DLLs and executables from an older Windows system (3,409 judged) |
| normal programs, modern | 4,171 DLLs, executables, .NET assemblies, drivers and vendor runtime DLLs from a Windows 11 installation (4,001 judged) |
| malicious programs | 3,327 32-bit executables (3,254 judged; 73 are payload images with no code) |
| after dropping rows with identical numbers | 10,413 samples: 3,211 malicious, 7,202 normal |
| normal programs, modern refresh (prepared, not in the shipped model) | 5,100 files (4,869 judged): the previous set resampled with 32-bit .NET assemblies and executables, WinSxS side-by-side DLLs, and `.scr`/`.cpl`/`.ocx` programs added |
| malicious programs, recent (prepared, not in the shipped model) | 770 files (765 judged) from MalwareBazaar hourly batches, October 2026: recent droppers, packed binaries and 64-bit samples, 18% 64-bit where the old corpus has none |
| source | [crovax/CNN_Project](https://huggingface.co/datasets/crovax/CNN_Project) on Hugging Face for both old corpora; the modern programs come from the machine that trained the model; the recent malware from abuse.ch's public bulk feed |
| fetched by | `tools/fetch_dataset.py` (HTTP range requests, size and CRC checked), `tools/fetch_benign.py` (a deterministic sample of the local Windows folder, with a SHA-256 manifest) and `tools/fetch_bazaar.py` (recent MalwareBazaar batches, password-decrypted, MZ-checked, with a manifest) |

Nothing is executed: the files are read as bytes. The malicious samples are live
malware, and the normal modern ones are Microsoft's, so `data/` is in
`.gitignore` and can be deleted once a model is trained. What is in this
repository is the model and its numbers, not the samples.

The malware corpus is real, old and mostly unpacked. Until `benign-modern`
existed, the classifier had never seen a current installer, a .NET assembly, a
protected-media library or a kernel driver — and flagged them by the hundred on
a real machine. The modern half of the normal data is what closed that gap:

| sampled | from | why |
|---|---|---|
| 605 of 609 | `System32\*.exe` | current utilities, installers and resource-heavy programs |
| 1,198 of 3,400 | `System32\*.dll` | current DLLs, resource-only files among them |
| 306 of 306 | `SysWOW64\*.exe` | the same programs, 32-bit |
| 699 of 2,188 | `SysWOW64\*.dll` | the same DLLs, 32-bit |
| 250 of 276 | `Microsoft.NET\Framework64\v4.0.30319\*.dll` | managed assemblies |
| 31 of 31 | the same folder's `.exe` | managed executables |
| 4 of 4 | `WindowsPowerShell\v1.0\*.exe` (both bitnesses) | PowerShell's host programs |
| 451 of 451 | `System32\drivers\*.sys` | kernel drivers, which are judged again |
| 398 of ~10k | `System32\DriverStore\FileRepository\**\*.sys` | third-party drivers |
| 356 of ~10k | the same folder's `*.dll` | vendor runtimes: graphics, audio, protected media |

The prepared refresh (same machine, resampled October 2026; not in the shipped
model yet) keeps the caps and adds three sources aimed at the remaining
32-bit gap: 629 `System32` programs (now including `.scr`/`.cpl`), 324
`SysWOW64` programs and 697 DLLs (likewise), 250 + 31 32-bit .NET assemblies
and executables, and 499 WinSxS side-by-side DLLs (`x86_*`, `wow64_*`,
`msil_*`, flat patterns — a recursive walk is minutes on a slow mount).
5,100 files, manifest beside the folder. The malware side gains 770 files from
MalwareBazaar's public hourly batches, 18% 64-bit, likewise manifested.

The DriverStore rows matter most: the code that ships with other vendors'
hardware is not in `System32`, and it has the shape — large, protected,
resource-heavy — that made the classifier call three Microsoft DLLs malware.

The sample is reproducible on any Windows machine: files are sorted by name and
an evenly spaced subset is taken, and the manifest records the origin and
SHA-256 of every copy. It is not identical across Windows versions, so
`model/pe-malware.metrics.json` names the collection it measured.

## Training and evaluation

`tools/train_ai.py`:

1. runs `leakcheck ai-features` over every `benign*` and `malware*` folder under
   `data/samples/`, so the numbers fed to the trainer are produced by the same
   C++ code the scanner uses, not a reimplementation;
2. drops rows with identical numbers, so one file cannot be both a training and
   a test sample;
3. keeps every sample and balances the classes by **weight** instead of by
   discarding rows: the modern normal files weigh as much as the old corpus
   (`--modern-weight`, default 1.0), and the lighter class is scaled up until
   both sides weigh the same. Cutting rows to fit used to leave 255 of the old
   normal files in training, and those were exactly the ones the model then got
   wrong;
4. splits by **sample family**, not by file: files that share an imphash (   the imported `dll.function` pairs, lowercased and hashed, the clustering
   VirusTotal and the corpora use) stay on one side. The merged collection is
   7,438 clusters; the test split holds 1,147 of them and shares none with
   training. A random split would put copies of one family on both sides and
   flatter the result; `--split random` reproduces that for comparison;
5. trains with early stopping on a validation split, chooses the threshold on
   that validation split alone (best F1, never below 0.5), and reports the test
   split, which neither training nor the choice of threshold ever looked at;
6. exports the text model, re-reads its own export, and refuses to ship it if
   any score differs from LightGBM's by more than 1e-9.

## What it does not read

On the old corpus, seven features say where a file came from rather than what
it contains:

| feature | normal programs | malicious programs |
|---|---|---|
| debug directory present | 100% | 8% |
| `.pdb` path in the file | 98% | 6% |
| Rich header | 98% | 54% |
| non-zero checksum | 99% | 72% |
| DLL characteristics (ASLR/DEP flags) | 100% set | 15% set |
| PE32+ (64-bit) | 64% | 0.03% |

The default list also leaves out the zero-timestamp flag, which says nothing in
this collection (0% of both classes). A model allowed to use the rest scores
100% on the old corpus by learning "built with a debug directory and 64-bit
means safe" — true of that collection, false of a real download, where a
legitimate stripped release has no debug directory either and modern malware is
64-bit. The shipped model leaves all seven out (`--exclude ''` keeps them, and
`tools/train_ai.py --help` lists the default).

The 49 numbers, and what each one is, are listed in
[REFERENCE.md](REFERENCE.md#what-the-model-reads). No file name, path, timestamp
value or hash of the whole file is used.

## What it measured

1,623 held-out files from the merged collection; the model never saw them, and
no cluster they belong to was in training:

| | |
|---|---|
| accuracy | 0.997 (1,618/1,623) |
| balanced accuracy | 0.996 |
| precision | 0.998 (1 of 1,080 normal programs called malware) |
| recall | 0.993 (4 of 543 malicious programs missed) |
| ROC AUC | 1.000 |
| trees | 231 |
| features used | 42 of 49 |
| export drift vs LightGBM | 0 |

The two classes no longer hold equal numbers (the normal side now has two
sources), which is why balanced accuracy sits next to accuracy: a model that
always answered "normal" would score 0.67 on this test set without knowing
anything.

By kind of program, on that test split:

| | tested | called malware |
|---|---|---|
| malicious 32-bit exe | 543 | 539 (99.3%) |
| normal 64-bit dll | 597 | 0 |
| normal 32-bit dll | 269 | 0 |
| normal 64-bit exe | 146 | 0 |
| normal 32-bit exe | 68 | 1 |

Through the command line over all 10,664 judged files (mostly training files, so
this checks the wiring, not the quality): 3,246 of 3,254 malicious files
flagged, 0 of 3,409 old normal programs, 2 of 4,001 modern ones. The 8 malicious
files it does not flag are scored normal; the 73 payload images with no code are
not programs and are not listed at all, by the trainer or by the scanner.

### A real Windows installation, as a false-alarm test

The shipped model was run over this machine's `C:\Windows\System32` (25,637
files) and `SysWOW64` (5,261); the classifier judges the 8,819 that hold code:

| | System32 | SysWOW64 |
|---|---|---|
| judged | 6,149 | 2,670 |
| false alarms | **0** | **2** of 2,670 (0.07%) |

The first version of this model, trained without modern programs, gave 507 and
103 false alarms — almost all of them `.mui` string tables, resource-only DLLs
and kernel drivers it had never seen. Three things closed that: `--ai` asks for
an image with code in it (`ai_has_code`), so a `.mui` file or a `-RES.dll` is not
judged; `ai-features` applies the same rule, so the trainer no longer reads rows
for files the scanner would never score; and the modern training set grew to
cover the DriverStore and every `.sys` driver. The rest was data: with Windows'
own programs in the training set, the installers, .NET assemblies, screen savers
and protected media libraries stopped looking like malware.

What is left is two 32-bit Windows executables, both in `SysWOW64`:
`WindowsPowerShell\v1.0\powershell_ise.exe` (0.998) and `msiexec.exe` (0.800).
Both are in the training sample, and both land in the held-out side of the split,
so this is the classifier failing on a family it has one member of — a 32-bit
signed Microsoft GUI program, which in this corpus means a 32-bit executable,
which means malware. No 64-bit program, no DLL and no driver is flagged on this
installation.

Two files in 8,819 judged is 0.02%, and it is the shape of false alarm to expect
on modern software: a scanner that reports one file in four thousand on a clean
Windows folder is one people will keep installed. The fix for the rest is more
32-bit normal programs of that shape, not another exception in the scanner.

## What the numbers do not say

* The malicious corpus is one old collection. A fresh sample of the modern
  internet will score worse than the table, and nothing here was trained on
  packers, crypters or heavily obfuscated files.
* The normal side is two Windows systems and a malware collection's idea of
  normal; a program from a toolchain neither contains can still be misjudged.
  The measured scale of that is the two executables above, not the 99.7%.
* The model sees the first 16 MB of a file and only Windows images that hold
  code. It says nothing about what the program does, and it does not name a
  family — `--malware` does that with rules. Resource-only files are not judged
  at all.
* The score is a forest's vote pushed through a sigmoid, not a calibrated
  probability: it is usually near 0 or near 1, so 0.93 does not mean "93 times
  out of 100 right". Compare it with the threshold, and use `--ai-threshold`
  rather than reading the digits as a confidence.

## Retraining and evaluating

```sh
python3 -m venv .venv-train && .venv-train/bin/pip install numpy lightgbm
python3 tools/fetch_dataset.py --per-class 3000     # ~3.6 GB under data/samples
python3 tools/fetch_benign.py --windows /mnt/c/Windows   # the modern normal side
python3 tools/fetch_bazaar.py --hours 48 --max-files 1500  # the recent malware side
.venv-train/bin/python tools/train_ai.py            # model/pe-malware.ai + metrics
```

`tools/fetch_benign.py` reads (never runs) the Windows installation it is
pointed at and copies a deterministic, capped sample with a manifest. On Linux
run it against a mounted Windows folder; `--windows` defaults to `%WINDIR%`.

`tools/train_ai.py` writes `model/pe-malware.metrics.json` next to the model,
with the confusion matrix, the per-cell table, the metrics for the modern normal
files alone, the cluster counts and the export drift. Training is deterministic:
the same data and flags produce the same model bytes, in about fifteen seconds
with the cached features. `--modern-weight` moves the modern side's weight
(default 1.0, the same weight as the old corpus; lowering it trades false
alarms on today's programs for the old corpus).

To judge the model on files it has never seen, point `tools/evaluate.py` at
them:

```sh
.venv-train/bin/python tools/evaluate.py --sweep samples/clean samples/bad:malware
```

It prints false alarms and detections per folder, names the worst mistakes, and
shows what a stricter threshold would do. The same estimator the scanner uses
reads the features, so a disagreement with `leakcheck scan --ai` is a bug.

## Reporting a mistake

A false alarm or a miss is useful even without the file. Open an issue with:

* the SHA-256 of the program and its size;
* the score `leakcheck scan --ai` gave it, and the threshold;
* what the program is (a game installer, a dump from a family, ...);
* for a miss, what makes you sure it is malicious.

Do not attach live malware to a public issue. Never attach anything you are not
allowed to redistribute. See [SECURITY.md](../SECURITY.md) if the report itself
is sensitive.

## Warnings about the model file

The model is data the scanner trusts. `static-engine/src/ai_model.cpp` refuses a
model whose version, feature count or tree indices do not fit, but a model is
still arbiter of its own thresholds and messages; only load model files you
trust, the same way you would only load a configuration file you trust.
