# Damn Vulnerable Web Server

A tiny, deliberately-broken HTTP server written in C++ for CTFs and
exploit-development workshops. Every bug is intentional and documented
in [`CHALLENGES.md`](CHALLENGES.md).

## Repository layout

| Path                                | What lives there                                     |
|-------------------------------------|------------------------------------------------------|
| `main.cpp`                          | arg parsing + accept loop                            |
| `router.cpp` / `router.h`           | request dispatcher                                   |
| `http/`                             | `HttpRequest` parser + `send_status` helpers         |
| `handlers/`                         | one file per intentional vuln (admin / cgi / static) |
| `authentication.cpp`, `session_manager.cpp`, `request_logger.cpp`, `mime_type_handler.cpp` | supporting subsystems |
| `serve/`                            | web-root served on the wire                          |
| `challenges/`                       | player-facing challenge cards + solutions (spoilers) |
| `tests/exploit/`                    | regression tests: prove each vuln still triggers     |

## Build

Two flavours. Both use the same tree.

**Vulnerable build (default)** — no PIE, no stack protector:
```bash
mkdir -p build && cd build
cmake ..
make -j
./damn_vulnerable_web_server ../serve/ 8081
```

**Hardened build** — PIE + stack protector on, so you can see the
mitigations kick in:
```bash
cmake -DENABLE_HARDENING=ON ..
```

**ASan build** — for the memory-safety challenges (UAF, heap BOF,
integer overflow) that don't reliably crash without instrumentation:
```bash
cmake -DENABLE_ASAN=ON ..
```

> `ENABLE_ASLR` still works as a deprecated alias for `ENABLE_HARDENING`.
> Note: what the flag actually controls is PIE + `-fstack-protector`.
> True ASLR is a kernel/loader feature and cannot be toggled at compile time.

## Play

Start with [`CHALLENGES.md`](CHALLENGES.md) for a table of every bug,
its endpoint, and its difficulty. Each row links to a hint card. When
you're stuck, `challenges/solutions/` has full exploits (spoilers).

## Regression suite

Prove every intentional vuln still fires — useful when hacking on the
server or grading a proposed patch:

```bash
python3 tests/exploit/run_all.py           # against the default build
python3 tests/exploit/run_all.py --asan    # rebuild with ASan first
```

Expected output: `14/14 vulnerabilities still trigger.`

## Fuzzing with AFL++

```bash
docker build -t vuln-server-fuzz .
docker run --rm -v $(pwd)/fuzz_output:/src/fuzz/out vuln-server-fuzz
```

The server exposes a `--fuzz` mode that reads a single request from
stdin, so it plugs straight into AFL's standard mode. Crashes end up in
`fuzz/out/default/crashes/`.

## Threat model

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the trust-boundary diagram
and per-bug "what a real server should do here" notes.

## Reporting unintended bugs

If you find something that isn't listed in `CHALLENGES.md`, open an issue
tagged `unintended-bug`. Please do **not** open PRs that remove existing
challenges.
