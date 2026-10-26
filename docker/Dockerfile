# A distroless image for a build server: no shell, no package manager, no
# network at run time. Build from the repository root:
#
#   docker build -f docker/Dockerfile -t leakcheck:1.0.0 .
#   docker run --rm --network none -v "$PWD:/src:ro" leakcheck:1.0.0 \
#       static -f sarif -o /dev/stdout /src
#
# The binary and its preload library sit together in /usr/local/bin; the model
# is in /usr/local/share/leakcheck/model, where bin/../share finds it.
FROM debian:bookworm-slim AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake ninja-build g++ ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DLEAKCHECK_BUILD_TESTS=OFF \
    && cmake --build build --parallel \
    && cmake --install build --prefix /stage/usr/local

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /stage/usr/local/ /usr/local/
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/leakcheck"]
