### Damn Vulnerable Web Server

Vulnerable Web Server written in C++



#### How to build and run Damn Vulnerable Web Server

**Standard Build (Vulnerable)**
This builds the server with security features disabled (ASLR/PIE disabled where possible) to facilitate exploit testing.
1) `mkdir build && cd build`
2) `cmake -DENABLE_ASLR=OFF ..`
3) `make`
4) `./damn_vulnerable_web_server ../serve/ 8081`

**Secure Build (ASLR Enabled)**
This builds the server with ASLR and Stack Protectors enabled.
1) `mkdir build && cd build`
2) `cmake -DENABLE_ASLR=ON ..`
3) `make`
4) `./damn_vulnerable_web_server ../serve/ 8081`

**Testing ASLR**
You can verify the ASLR status of the build using the provided test script:
`python3 ../tests/test_aslr.py`



#### Vulnerabilities 
* Buffer Overflow
* Path Traversal
* Uncontrolled format string
* Command Injection
* Session Fixation
* Insecure Temporary File Creation Race Condition
* Use-After-Free (Heap)
* Heap Buffer Overflow
* Integer Overflow
* Type Confusion


#### Solutions
Read solutions.md

#### Fuzzing with AFL++

To find vulnerabilities automatically using AFL++, we have provided a Docker setup.

1.  **Build the Docker image**:
    ```bash
    docker build -t vuln-server-fuzz .
    ```

2.  **Run the fuzzer**:
    ```bash
    docker run --rm -it vuln-server-fuzz
    ```

This will compile the server with ASan (Address Sanitizer) and run AFL++ in a container. The server has been modified to support a `--fuzz` flag which reads requests from stdin, making it compatible with AFL's standard mode.

Crashes will be saved in `fuzz/out/default/crashes/`.
