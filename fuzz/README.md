# Fuzzing leakcheck

Six libFuzzer targets cover everything that reads bytes somebody else wrote:
the lexer, the file-format readers behind `scan`, the Windows feature extractor,
the model loader, the suppression parser and the runtime report reader.

| target | input | what it must never do |
|---|---|---|
| `fuzz_lexer` | C or C++ source | overrun a buffer, loop forever |
| `fuzz_scan` | any file bytes | crash on a corrupt ELF, PE or Mach-O |
| `fuzz_features` | any file bytes | crash while reading PE headers |
| `fuzz_model` | a `--ai` model file | allocate from a count the file invented |
| `fuzz_suppress` | a suppression file | crash on a broken rule |
| `fuzz_runtime` | a runtime stream record | read past a short or corrupt record |

## Locally

```sh
CC=clang CXX=clang++ cmake -S . -B build-fuzz -G Ninja \
    -DLEAKCHECK_BUILD_FUZZERS=ON \
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
cmake --build build-fuzz --parallel
sh fuzz/smoke.sh build-fuzz 60
```

`fuzz/smoke.sh` runs every target against `fuzz/corpus/<target>` for the given
number of seconds per target and fails on the first crash. A crash is written
next to where the fuzzer ran; add it to the corpus, fix the reader, and run the
target on the file again with `-runs=1`.

The corpus is checked in. Keep new inputs small: one file that reaches a new
path is worth more than a large blob.

## OSS-Fuzz

`fuzz/oss-fuzz/` holds the files the project needs in the OSS-Fuzz repository.
They are copied there by a pull request to
[google/oss-fuzz](https://github.com/google/oss-fuzz):
`projects/drydock/{project.yaml,build.sh,Dockerfile}`. Until that pull request
lands, the CI job in `.github/workflows/ci.yml` is the continuous fuzzer.
