FROM aflplusplus/aflplusplus:v4.21c

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl-dev \
        build-essential \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

# The AFL++ base image currently exposes Ubuntu 22.04's cmake 3.22.x,
# but this repo requires cmake 3.25+.
RUN python3 -m pip install --no-cache-dir "cmake>=3.25,<4"

WORKDIR /src
COPY . .

# Compile with AFL++ instrumentation and AddressSanitizer.
# The --fuzz mode in main.cpp reads one request from stdin per process,
# which matches AFL's standard execution model in CI.
ENV AFL_USE_ASAN=1
RUN cmake -S . -B build \
        -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
        -DCMAKE_C_COMPILER=afl-clang-fast \
        -DENABLE_ASAN=ON \
    && cmake --build build -j

# Fuzzing directories.
RUN mkdir -p fuzz/out
VOLUME /src/fuzz/out

CMD ["/usr/local/bin/afl-fuzz", \
     "-i", "/src/fuzz/corpus", \
     "-o", "/src/fuzz/out", \
     "-m", "none", \
     "-x", "/src/fuzz/dict.txt", \
     "--", "/src/build/damn_vulnerable_web_server", "/src/serve", "8081", "--fuzz"]
