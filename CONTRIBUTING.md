# Contributing

Thanks for looking. The most useful contributions here are the unglamorous
ones: a false alarm the classifier should not have made, a rule that fires on an
honest program, a test that shows a finding is wrong.

## Build and test

Linux (CMake 3.28+, a C++20 compiler, Python 3):

```sh
cmake -S . -B build -G Ninja && cmake --build build
ctest --test-dir build --output-on-failure
python3 tests/run_tests.py          # the command-line tests
python3 eval/run_eval.py            # the static analyser's own evaluation
```

Windows (MinGW-w64 `g++` and Python 3; CMake not needed):

```powershell
.\build-windows.ps1 -Test
```

A change is expected to come with the test that would have caught it. `ctest`
covers the units and the CLI; `tests/run_tests.py` has the end-to-end cases.
Neither may be weakened to make a change pass.

## Changing the classifier

The `--ai` model is the one part of leakcheck that reports a probability, so it
has stricter rules than the rest:

* **Never commit samples.** `data/` is ignored on purpose. A bug report or a
  pull request names a file by SHA-256 and score, or adds a small synthetic PE
  to `tests/`, never a real binary.
* **Keep the honest split.** `tools/train_ai.py` groups files by imphash so one
  family cannot sit on both sides of the split. A change that reports a better
  number by splitting at random instead is a regression, not an improvement.
* **Keep the export proof.** The trainer re-reads its own text model and refuses
  to ship it if any score differs from LightGBM's. Models that fail it are not
  merged.
* **Only claim what the metrics show.** The README, this repository's docs and
  the model header quote `model/pe-malware.metrics.json`. If a change improves a
  number, the metrics file and the docs change with it, in the same commit.
* **Features must be explainable.** A new number in `ai_features.cpp` needs a
  sentence in `docs/REFERENCE.md` saying what it measures, and evidence that it
  helps on the family-grouped split. Features that describe how a file was built
  or collected (debug directory, PDB path, Rich header, bitness on this dataset)
  have been measured as shortcuts; see [docs/MODEL.md](docs/MODEL.md).

Retraining:

```sh
python3 -m venv .venv-train && .venv-train/bin/pip install numpy lightgbm
python3 tools/fetch_dataset.py --per-class 3000          # the old corpus
python3 tools/fetch_benign.py --windows /mnt/c/Windows  # modern normal programs, drivers too
.venv-train/bin/python tools/train_ai.py
.venv-train/bin/python tools/evaluate.py --sweep data/samples/benign data/samples/malware
```

The modern normal files come from whatever Windows installation the model is
trained on; `fetch_benign.py` writes a manifest with their SHA-256 and origin,
which is how a training run is described later. Do not commit them (they are
Microsoft's), and do not replace the manifest to make a number look better.

## Style

* C++20, `clang-format` (there is a `.clang-format`), no new dependencies.
* Comments say why, not what; a finding's message says what was seen and where.
* Python in `tools/` stays dependency-light: standard library, plus numpy and
  LightGBM for training. It must run with `python3` and print plain text.

## Licensing

Contributions are accepted under the [MIT license](LICENSE). By opening a pull
request you confirm you have the right to submit the code.

## Reporting rather than fixing

You do not need to write C++ to help. A false alarm with its score, the SHA-256
of the file and what the program is gives the model a new failure to measure
against, and that is often worth more than a patch. See
[docs/MODEL.md](docs/MODEL.md#reporting-a-mistake) and
[SECURITY.md](SECURITY.md).
