FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake ninja-build && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/voidstackloop/drydock.git drydock

COPY build.sh $SRC/
WORKDIR $SRC/drydock
