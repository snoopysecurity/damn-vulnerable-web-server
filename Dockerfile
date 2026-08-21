FROM aflplusplus/aflplusplus:v4.21c

RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        libssl-dev \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Compile with AFL++ instrumentation and AddressSanitizer.
# The --fuzz mode in main.cpp uses __AFL_LOOP for persistent-mode
# throughput (10-100x faster than fork-server-per-input).
ENV AFL_USE_ASAN=1
RUN cmake -S . -B build \
        -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
        -DCMAKE_C_COMPILER=afl-clang-fast \
        -DENABLE_ASAN=ON \
    && cmake --build build -j

# Fuzzing directories.
RUN mkdir -p fuzz/out
VOLUME /src/fuzz/out

# Corpus + dictionary live under fuzz/ in the repo; symlink for AFL's -i.
RUN ln -sf /src/fuzz/corpus /src/fuzz/in

CMD ["/usr/local/bin/afl-fuzz", \
     "-i", "/src/fuzz/in", \
     "-o", "/src/fuzz/out", \
     "-m", "none", \
     "-x", "/src/fuzz/dict.txt", \
     "--", "/src/build/damn_vulnerable_web_server", "/src/serve", "8081", "--fuzz"]
