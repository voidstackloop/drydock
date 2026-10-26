#!/bin/bash -eu
# OSS-Fuzz build for leakcheck. The project has no third-party dependencies, so
# there is nothing to fetch: build the library every front end shares, then link
# each fuzz target against $LIB_FUZZING_ENGINE (the sanitizer flags are already
# in $CFLAGS/$CXXFLAGS) and zip its seed corpus.

cd "$SRC/drydock"

cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DLEAKCHECK_BUILD_TESTS=OFF \
    -DLEAKCHECK_BUILD_PRELOAD=OFF
cmake --build build --parallel --target leakcheck_core

INCLUDES="-I static-engine/src -I static-engine/include -I dynamic-engine/include
          -I reporter/include -I shared/include"
for target in lexer scan features suppress runtime model; do
    # shellcheck disable=SC2086
    $CXX $CXXFLAGS -std=c++20 $INCLUDES \
        "fuzz/fuzz_${target}.cpp" build/libleakcheck_core.a \
        $LIB_FUZZING_ENGINE -pthread -o "$OUT/fuzz_${target}"
    if [ -d "fuzz/corpus/${target}" ] && [ -n "$(ls -A "fuzz/corpus/${target}")" ]; then
        (cd "fuzz/corpus/${target}" && zip -q -j "$OUT/fuzz_${target}_seed_corpus.zip" ./*)
    fi
done
