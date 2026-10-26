#!/bin/sh
# Runs every libFuzzer target for a few seconds against its corpus.
# Usage: fuzz/smoke.sh <build-dir> [seconds]   (default 30)
# Any crash, leak or sanitizer report fails the script.
set -eu

build=${1:?usage: fuzz/smoke.sh <build-dir> [seconds]}
seconds=${2:-30}
here=$(cd "$(dirname "$0")" && pwd)

for target in lexer scan features suppress runtime model; do
    dir="$build/fuzz_$target"
    if [ ! -x "$dir" ]; then
        echo "fuzz: $dir is missing; configure with -DLEAKCHECK_BUILD_FUZZERS=ON" >&2
        exit 1
    fi
    echo "== fuzz_$target: ${seconds}s"
    # -rss_limit_mb keeps one target from eating the runner; -timeout catches
    # a non-terminating input.
    "$dir" "$here/corpus/$target" \
        -max_total_time="$seconds" -timeout=10 -rss_limit_mb=2048 \
        -print_final_stats=1 >"/tmp/fuzz_$target.log" 2>&1 || {
        echo "fuzz_$target failed; tail of its log:" >&2
        tail -40 "/tmp/fuzz_$target.log" >&2
        exit 1
    }
    tail -1 "/tmp/fuzz_$target.log"
done
