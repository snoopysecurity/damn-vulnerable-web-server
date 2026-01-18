FROM aflplusplus/aflplusplus:latest

# Install dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /src

# Copy project files
COPY . .

# Create build directory
RUN mkdir build

# Compile with AFL++ instrumentation and AddressSanitizer
# AFL_USE_ASAN=1 automatically sets up ASan integration for AFL
# We also manually enable our CMake ASAN option for good measure, though AFL wrappers usually handle flags.
WORKDIR /src/build
ENV AFL_USE_ASAN=1
RUN cmake -DCMAKE_CXX_COMPILER=afl-clang-fast++ -DCMAKE_C_COMPILER=afl-clang-fast -DENABLE_ASAN=ON .. && \
    make

# Setup fuzzing directories
WORKDIR /src
RUN mkdir -p fuzz/in fuzz/out
VOLUME /src/fuzz/out

# Create dictionary
RUN echo '"GET"\n"POST"\n"HTTP/1.1"\n"Host"\n"Authorization"\n"Basic"\n"YWRtaW46YWRtaW4="\n"Content-Length"\n"Content-Type"\n"/admin/"\n"/admin/system_status"\n"/admin/upload_file"\n"/admin/logger_config"\n"/logs"\n"status="\n"filter="\n"action="\n"format="\n"set"\n"reset"' > http.dict

# Create initial corpus (seed inputs)
RUN echo "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" > fuzz/in/req_base.txt
# Heap Overflow seed
RUN echo "GET /admin/system_status?status=test HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n" > fuzz/in/req_heap.txt
# Stack Overflow seed (Long path)
RUN echo "GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA HTTP/1.1\r\nHost: localhost\r\n\r\n" > fuzz/in/req_stack.txt
# Integer Overflow seed
RUN echo "POST /admin/upload_file HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nContent-Length: 100\r\n\r\n" > fuzz/in/req_int.txt
# Format String seed
RUN echo "GET /?param=%s%s%s%s HTTP/1.1\r\nHost: localhost\r\n\r\n" > fuzz/in/req_fmt.txt

# Create a simple wrapper script for the fuzzer
# Note: Since this is a network server, we would typically need to modify it to read from stdin (AFL persistent mode)
# or use a preloader like desock.
# For simplicity in this "clone and run" setup, we will use a basic approach.
# However, standard AFL fuzzes STDIN. Our server listens on a socket.
# We need to use 'desock' or similar, OR we modify main.cpp to support a "fuzz mode" reading from stdin.
# Given the user wants to "catch vulnerabilities", modifying main.cpp is the most reliable way for AFL.

# Let's verify if main.cpp needs modification in the next step. 
# For now, we assume we will add a -fuzz flag to the binary.

CMD ["/usr/local/bin/afl-fuzz", "-i", "fuzz/in", "-o", "fuzz/out", "-m", "none", "-x", "http.dict", "--", "./build/damn_vulnerable_web_server", "serve", "8081", "--fuzz"]
