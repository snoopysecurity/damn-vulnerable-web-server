# Damn Vulnerable Web Server

A tiny, deliberately-broken HTTP server written in C++ for CTFs and
exploit-development workshops. Every bug is intentional and documented
in [`CHALLENGES.md`](CHALLENGES.md).

## Repository layout

| Path                                | What lives there                                     |
|-------------------------------------|------------------------------------------------------|
| `main.cpp`                          | arg parsing + accept loop                            |
| `router.cpp` / `router.h`           | request dispatcher                                   |
| `http/`                             | `HttpRequest` parser + response/error-page helpers   |
| `handlers/`                         | one file per intentional vuln (admin / cgi / static) |
| `authentication.cpp`, `session_manager.cpp`, `request_logger.cpp`, `mime_type_handler.cpp` | supporting subsystems |
| `serve/`                            | web-root served on the wire                          |
| `challenges/README.md`               | all challenge cards + solutions in one file (spoilers) |
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

## Server behaviour

The server talks enough real HTTP to feel like a production front-end,
while every intentional bug from [`CHALLENGES.md`](CHALLENGES.md) stays
byte-for-byte intact:

- **Methods** — `GET`, `POST` and `HEAD` are served. Anything else gets
  `405 Method Not Allowed` + `Allow:`; malformed request lines get `400`.
- **Directories** — `DirectoryIndex` (`index.html`, then `index.php`),
  trailing-slash `301` redirects, and nginx-style autoindex listings for
  directories without an index document.
- **Headers** — every response carries `Server: DVWS/1.0`, `Date:`,
  `Content-Length:` and `Connection: close`. Static files also send
  `Last-Modified:` and honour `If-Modified-Since` with `304 Not Modified`.
- **Content types** — nginx-style MIME table (svg, ico, woff2, webp, mp4,
  …), `charset=utf-8` on text types, `application/octet-stream` default.
- **Admin API** — `/admin/*` endpoints respond with JSON; `/status`
  reports version, docroot, PHP path, uptime and request count.
- **Lifecycle** — nginx-style startup banner; graceful shutdown on
  SIGTERM/SIGINT (drains the worker pool, exits 0), which is what
  `docker compose stop` exercises.
- **PHP** — `.php` files under the docroot execute via `php-cli` when
  installed (see CH-06 for why that code path is interesting).
- **Site content** — `serve/` is a whole small site, not a stub: landing
  page, `about.html`, `blog/` (3 posts), `projects.html` (the challenge
  endpoints framed as hosted tools), and `downloads/` with real files
  (quickstart guide, sample access-log CSV, press-kit zip). Shared chrome
  in `static/` (`style.css`, `app.js`, `logo.svg`) matches the generated
  error pages, plus `favicon.ico`, `robots.txt` (`Disallow: /admin/`),
  `humans.txt` and a site `404.html`. `/echo.php` is a request-echo/debug
  page and `/admin/` a PHP dashboard with functional forms for the admin
  API. The `DVWS/1.0` fingerprint is identical in the `Server:` header,
  the `/status` JSON and every site footer.

## Play

Start with [`CHALLENGES.md`](CHALLENGES.md) for a table of every bug,
its endpoint, and its difficulty. Each row links to a hint card. When
you're stuck, the full exploits follow each card in
[`challenges/README.md`](challenges/README.md) (spoilers).

Quick tour of the non-broken surface:

```bash
curl -i http://localhost:8081/            # site landing page
curl -i http://localhost:8081/blog/       # blog index
curl -i http://localhost:8081/downloads/  # downloads page
curl -i http://localhost:8081/status      # service info (JSON)
curl -I http://localhost:8081/index.html  # HEAD + Last-Modified
curl -i http://localhost:8081/robots.txt  # classic misconfig realism
curl -i http://localhost:8081/echo.php    # PHP debug page (needs php-cli)
curl -i -u admin:admin http://localhost:8081/admin/   # admin dashboard
```

## Regression suite

Prove every intentional vuln still fires — useful when hacking on the
server or grading a proposed patch:

```bash
python3 tests/exploit/run_all.py           # against the default build
python3 tests/exploit/run_all.py --asan    # ASan build (see note)
```

Expected output: `14/14 vulnerabilities still trigger.`

> Note: `--asan` only (re)builds when `build/damn_vulnerable_web_server`
> is missing — it will not replace an existing default build. For a real
> ASan pass, reconfigure `build/` first (this leaves it configured for
> ASan; rebuild without the flag to go back):
> ```bash
> rm -rf build && cmake -S . -B build -DENABLE_ASAN=ON && cmake --build build -j
> python3 tests/exploit/run_all.py
> ```

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
