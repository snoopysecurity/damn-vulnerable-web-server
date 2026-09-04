# Challenges

The bugs planted in this server. Click a row for the card with the sink and hints.

| #  | Vulnerability                 | Class      | CWE     | Endpoint / Trigger                                     | Card |
|----|-------------------------------|------------|---------|--------------------------------------------------------|------|
| 01 | Path Traversal                | Web        | CWE-22  | `GET /../../etc/passwd`                                | [card](challenges/README.md#challenge-01) |
| 02 | Command Injection             | Web        | CWE-78  | `GET /logs?search=`                                    | [card](challenges/README.md#challenge-02) |
| 03 | Uncontrolled Format String    | Memory     | CWE-134 | `X-Forwarded-For` header → log                         | [card](challenges/README.md#challenge-03) |
| 04 | Session Fixation              | Web        | CWE-384 | `Cookie: session_id=...`                               | [card](challenges/README.md#challenge-04) |
| 05 | Predictable Session ID        | Crypto/Web | CWE-330 | `Set-Cookie: SESSION_<hex>`                            | [card](challenges/README.md#challenge-05) |
| 06 | Insecure Temp Executable Race | System     | CWE-377 | `/tmp/dvws_cgi_<pid>`                                  | [card](challenges/README.md#challenge-06) |
| 07 | Username Info Leak            | Memory     | CWE-125 | `GET /whoami`                                          | [card](challenges/README.md#challenge-07) |
| 08 | Use-After-Free (LogSink)      | Memory     | CWE-416 | `/admin/logging`                                       | [card](challenges/README.md#challenge-08) |
| 09 | Heap Buffer Overflow          | Memory     | CWE-122 | `POST /admin/system_status`                            | [card](challenges/README.md#challenge-09) |
| 10 | Integer Overflow              | Memory     | CWE-190 | `POST /admin/upload_file`                              | [card](challenges/README.md#challenge-10) |
| 11 | Type Confusion                | Memory     | CWE-843 | `/admin/add_rule` + `/admin/update_rule` + `/cgi-bin/*`| [card](challenges/README.md#challenge-11) |
| 12 | Stack Buffer Overflow (path)  | Memory     | CWE-121 | long request path                                      | [card](challenges/README.md#challenge-12) |
| 13 | Global BOF (argv)             | Memory     | CWE-121 | `./damn_vulnerable_web_server $(...)`                  | [card](challenges/README.md#challenge-13) |
| 14 | Zip Slip                      | Web        | CWE-22  | `POST /admin/deploy_site`                              | [card](challenges/README.md#challenge-14) |



# Challenge cards

One card per bug: what it does, where it lives, and a few nudges toward
the trigger. The regression test at the bottom of each card fires the
primitive if you want to see it without writing the exploit yourself.

Chaining is up to you. A few obvious combinations:

- **04/05 → 11** — grab an admin session (fixation or prediction), plant a
  rule via `/admin/add_rule`, flip its tag with `/admin/update_rule`,
  fire it at `/cgi-bin/*` without credentials.
- **07 → 09 → 08** — leak stack pointers from `/whoami`, groom a chunk
  through the decode-sizing bug, swap the log sink to fire a controlled
  virtual call.
- **04/05 → 14 → 06** — write to `/tmp/dvws_cgi_<pid>` via Zip Slip, then
  race `/cgi-helper` for code execution.
- **12** — a plain stack smash on a long request path. Add a leak from
  01/03/07 and rebuild `-DENABLE_HARDENING=ON` for the ROP version.

---

<a id="challenge-01"></a>

## 01 · Path Traversal (CWE-22)

### Scenario

The static handler joins docroot + request path, then canonicalizes the
result (resolving `..` and symlinks) behind a containment check. The
check runs on the *pre-canonicalized* string — which starts with the
docroot by construction and can never fail. The canonicalized path is
then handed to the filesystem without a second check.

### Endpoint

Any URL served by the static handler, e.g. `GET /index.html`.

### Affected code

`src/handlers/static_files.cpp`:

```cpp
std::string joined = docroot + req.clean_path;

// Requests that map outside the document root are rejected.
if (joined.rfind(docroot, 0) != 0) {
    http::send_status(client_socket, "403 Forbidden", ...);
    return;
}

// Resolve `..` segments and symlinks.
std::string file_path =
    std::filesystem::weakly_canonical(std::filesystem::path(joined), ec).string();
```

`joined` is `docroot` concatenated with a controlled path — it always
starts with `docroot`, so the `rfind` guard is a tautology.
`weakly_canonical` then collapses `..` segments *after* the check, and
the result (`file_path`) is what gets served. The order is wrong: the
guard must inspect the canonicalized path, not the raw join.

### Hints

1. Which string does the guard actually inspect?
2. What does `weakly_canonical()` do to `..` segments?
3. A check that always passes is not a check.

### Primitive

Arbitrary file read as the server user.

### Combines with

`/proc/self/maps` gives you an ASLR bypass for the memory-corruption
challenges without needing a separate leak.

### Regression test

`tests/exploit/test_path_traversal.py`

---

<a id="challenge-02"></a>

## 02 · Command Injection (CWE-78)

### Scenario

The log viewer's `search` parameter is URL-decoded and run through
`shell_escape()` before being concatenated into a `grep` pipeline.
`shell_escape()` just wraps the argument in double quotes. Double
quotes don't stop `"`, and they don't stop `$(...)` or backticks.

### Endpoint

`GET /logs` · `GET /logs?level=error|warning|info` · `GET /logs?search=<free text>`

### Affected code

`src/request_logger.cpp`:

```cpp
static std::string shell_escape(const std::string& s) {
    return "\"" + s + "\"";
}
...
if (!search.empty()) {
    command += " | grep -i " + shell_escape(url_decode(search));
}
FILE* pipe = popen(command.c_str(), "r");
```

Quoting is not escaping. A user-supplied `"` closes the argument early
and lets everything after it parse as shell. Even without breaking out
of the quotes, `$(...)` and backticks trigger command substitution
*inside* double quotes. The only correct fix is to stop building a
shell string and `execve`/`posix_spawn` `grep` directly with an argv
array.

### Hints

1. What character ends a double-quoted string?
2. What happens to `$(...)` inside double quotes?
3. The `level` param is whitelisted; `search` is not.

### Primitive

OS command execution as the server user.

### Combines with

Gives you a local shell, which 06 needs.

### Regression test

`tests/exploit/test_cmd_injection.py`

---

<a id="challenge-03"></a>

## 03 · Uncontrolled Format String (CWE-134)

### Scenario

Query values are logged with `"%s"`. The `X-Forwarded-For` header is
logged through a different helper that passes the field straight to
`fprintf` as the format string.

### Endpoint

Any request carrying an `X-Forwarded-For` header.

### Affected code

`src/request_logger.cpp`:

```cpp
void write_custom_field(FILE* log_file, const char* timestamp,
                        const std::string& field) {
    fprintf(log_file, "[%s] X-Forwarded-For: ", timestamp);
    fprintf(log_file, field.c_str());   // <-- field IS the format string
    fprintf(log_file, "\n");
}
```

`field` is an attacker-controlled header value. `%p` walks up the
varargs area and prints stack slots (return addresses, saved
registers, heap pointers); `%s` dereferences one of those slots as a
`char*`; `%n` writes the count-so-far to the address stored at the
next slot. Glibc historically disables `%n` in writeable format
strings, so the write primitive depends on the runtime — the leak is
reliable everywhere.

### Hints

1. Query values go in via `"%s"`. Which other logged string doesn't?
2. `%p` reads stack slots.
3. `%n` writes — glibc-dependent.

### Primitive

Stack disclosure via `%p`. `%n` gives an arbitrary write on glibc.

### Combines with

The `%p` leak is another way to defeat ASLR for 08 / 12.

### Regression test

`tests/exploit/test_format_string.py`

---

<a id="challenge-04"></a>

## 04 · Session Fixation (CWE-384)

### Scenario

Login upgrades the existing session object to `authenticated:admin`
without rotating the session ID. `/admin/*` admits any session in that
state — no password required. Whoever holds the pre-auth ID inherits
the admin session once the real user logs in.

### Endpoint

`/admin/*` with `Cookie: session_id=...`.

### Affected code

`src/router.cpp`:

```cpp
if (!whoami_route && !session_id.empty() &&
    get_session_data(session_id) == "authenticated:admin") {
    authorized = true;                          // <-- session alone unlocks /admin/*
} else if (require_basic_auth(client_socket, req)) {
    authorized = true;
    if (!whoami_route && !session_id.empty()) {
        set_session_data(session_id, "authenticated:admin");  // <-- no rotation
    }
}
```

The ID never changes across the privilege boundary. Nothing on the
login path issues a `Set-Cookie` after auth succeeds. An attacker
plants a cookie in the victim's browser, the victim logs in, and
now the attacker's cookie is an admin cookie. The correct pattern is
to mint a fresh ID at login, invalidate the pre-auth one, and reject
client-chosen IDs that the server never issued.

### Hints

1. What should happen to a session ID on privilege change?
2. Seed a cookie, log in with it, replay the same cookie alone.
3. Look at the login response — no `Set-Cookie`.

### Primitive

Account takeover after victim login.

### Combines with

Unlocks every `/admin/*` route — the setup steps for 08, 09, 10, 11
and 14.

### Regression test

`tests/exploit/test_session_fixation.py`

---

<a id="challenge-05"></a>

## 05 · Predictable Session ID (CWE-330)

### Scenario

Session IDs are `SESSION_<8 hex>` where the value is `rand() ^ pid`,
with `rand()` seeded from `time(0)`. Both ingredients are predictable
and the PID is externally observable. Two sessions minted in the same
second are identical.

### Endpoint

Any endpoint that sets `session_id=SESSION_<hex8>`.

### Affected code

`src/session_manager.cpp`:

```cpp
std::string generate_session_id() {
    srand(time(0));
    uint32_t a = (uint32_t)rand();
    uint32_t b = (uint32_t)getpid();
    char buf[32];
    snprintf(buf, sizeof(buf), "SESSION_%08x", a ^ b);
    return std::string(buf);
}
```

`srand(time(0))` gives one-second resolution — every session minted
in the same wall-clock second reseeds the PRNG identically, so
`rand()` returns the same value. XORing with `pid` (16 bits on Linux,
often visible in `/status` or process listings) doesn't add entropy;
it just masks the PRNG output with a known constant. Total attacker
work: a small window of `time(0)` values × one XOR per candidate.

### Hints

1. Two ingredients — how much entropy does each really have?
2. Two sessions in the same second: compare them.
3. Where is the PID visible?

### Primitive

Predict / hijack any authenticated session.

### Combines with

Same downstream as 04; you don't need to plant a cookie first.

### Regression test

`tests/exploit/test_predictable_session.py`

---

<a id="challenge-06"></a>

## 06 · Insecure Temporary Executable Race (CWE-377 / CWE-367)

### Scenario

`GET /cgi-helper` stages the bundled CGI helper at
`/tmp/dvws_cgi_<pid>`, closes the file, waits, then `chmod`s it and
runs it through `popen()`. Classic TOCTOU: predictable filename in
world-writable `/tmp`, and a window where the file sits closed and
replaceable.

### Endpoint

`GET /cgi-helper`

### Affected code

`src/mime_type_handler.cpp`:

```cpp
char temp_file_path[200];
snprintf(temp_file_path, sizeof(temp_file_path), "/tmp/dvws_cgi_%d", pid);

FILE* temp_file = fopen(temp_file_path, "wb");           // no O_EXCL
...write staged bytes...
fclose(temp_file);                                       // <-- close

if (!g_config.fuzz_mode) usleep(100000);                 // 100 ms window

chmod(temp_file_path, 0755);
FILE* helper_output = popen(temp_file_path, "r");        // <-- execute
```

Three separate primitives compose the bug: the path is predictable
(`/tmp/<constant>_<pid>`, PID exposed via `/status`), the file is
opened without `O_EXCL` so a preexisting file gets truncated and
reused (or a symlink gets followed), and the close-then-execute gap
gives an attacker who can `write(2)` to `/tmp` a 100 ms window to swap
in a different binary. The fix is `mkstemp` in a private directory,
never re-open the path by name, and `fexecve` the descriptor.

### Hints

1. `/status` gives you the server PID.
2. The file is closed before it's run.
3. What can you do to a closed file at a predictable path in `/tmp`?

### Primitive

Native code execution as the server user, given local access or a
write to `/tmp`.

### Combines with

Consumes a local shell (from 02 / 11) or a file write to `/tmp`
(from 14).

### Regression test

`tests/exploit/test_temp_exec_race.py`

---

<a id="challenge-07"></a>

## 07 · Username Info Leak (CWE-125)

### Scenario

`/whoami` returns a fixed 128-byte identity record. `snprintf` writes
`username=%s\n` into it, but the response transmits the whole buffer.
Everything past the NUL is stale stack memory from earlier requests
this worker handled.

### Endpoint

`GET /whoami` (requires `Authorization: Basic ...`)

### Affected code

`src/handlers/admin.cpp`:

```cpp
char response[128];                                       // uninitialized
snprintf(response, sizeof(response), "username=%s\n", username.c_str());

http::send_status(client_socket, "200 OK", "application/octet-stream",
                  std::string(response, sizeof(response)),   // <-- whole buffer
                  "", req.method == "HEAD");
```

`snprintf` writes `strlen("username=") + strlen(username) + 2` bytes
into a 128-byte stack buffer, then NUL-terminates. The
`std::string(response, sizeof(response))` constructor is length-based —
it ignores the NUL and copies all 128 bytes into the response body.
For a short username like `admin`, ~112 bytes of stack memory the
compiler happened to place next to `response` go out on the wire:
saved registers, string pointers from earlier handling on this same
worker thread, potentially heap addresses.

### Hints

1. Content-Length is always 128. How many bytes did `snprintf` write?
2. What did this worker thread do before your request?
3. Send a long-header request first, then `/whoami`.

### Primitive

Uninitialized stack read — pointers, request fragments, session state.

### Combines with

Feeds 08 (fake vtable pointer) and 12 (ROP against a hardened build).

### Regression test

`tests/exploit/test_username_leak.py`

---

<a id="challenge-08"></a>

## 08 · Use-After-Free — Logging Sinks (CWE-416)

### Scenario

`/admin/logging?output=file|syslog` swaps the installed `LogSink` and
deletes the old one immediately. Request threads don't log
synchronously — they enqueue `{record, LogSink*}` for a background
worker that batches for ≥ 250 ms before flushing. Records queued
before the swap still hold the deleted sink; the worker's
`sink->write()` dispatches through a vtable read from freed memory.

### Endpoint

`GET /admin/logging?output=file` · `GET /admin/logging?output=syslog`

### Affected code

`src/logging_sink.cpp`:

```cpp
constexpr std::chrono::milliseconds kFlushInterval{250};

struct QueueEntry {
    LogRecord record;
    LogSink* sink;                          // captured at enqueue time
    std::chrono::steady_clock::time_point enqueued_at;
};

void install_log_sink(LogSink* sink) {
    LogSink* old = g_sink;
    g_sink = sink;
    delete old;                             // <-- freed while records still hold it
}

void worker_loop() {
    ...
    for (const auto& entry : due) {
        if (entry.sink != nullptr) {
            entry.sink->write(entry.record);  // <-- virtual call on freed memory
        }
    }
}
```

The queue entry owns a raw pointer. When `install_log_sink` runs, any
record queued in the last 250 ms suddenly points at freed memory. The
worker's `entry.sink->write(entry.record)` is a virtual call: it reads
the vtable pointer from `*entry.sink`. If nothing has reclaimed the
chunk yet, the read succeeds and dispatch works — the UAF is silent.
If challenge 09 has reclaimed that chunk with a chosen size class and
chosen bytes, the first 8 bytes of the reclaiming allocation *are*
the vtable pointer, and dispatch jumps wherever they say. The fix is
shared ownership (`std::shared_ptr<LogSink>` in the queue) or
draining the queue before deleting a sink.

### Hints

1. The record captures the sink pointer at enqueue time.
2. You have ~250 ms between the delete and the dispatch.
3. To land a fake vtable, you need to reclaim the freed chunk with
   chosen bytes. See 09.

### Primitive

Virtual call through a dangling vtable → RIP control once the freed
chunk is reclaimed.

### Combines with

Needs a leak (01 / 03 / 07) for addresses and 09 to reclaim the chunk.

### Regression test

`tests/exploit/test_uaf_logger.py` (hard crash under `--asan`).

---

<a id="challenge-09"></a>

## 09 · Heap Buffer Overflow — Decode Sizing (CWE-122)

### Scenario

`system_status` sizes its decode buffer with `estimate_decoded_length()`,
which assumes every `%` starts a valid three-byte `%XX` escape and
counts one output byte per escape. The actual decoder leaves malformed
escapes verbatim — `%GZ` copies all three bytes. Two implementations
of "the same" rule; malformed escapes decode to up to 3× the estimate.

### Endpoint

`POST /admin/system_status` (Basic auth)

### Affected code

`src/utils.cpp` — the estimator:

```cpp
size_t estimate_decoded_length(const char* s) {
    size_t n = 0;
    for (size_t i = 0; s[i] != '\0' && s[i] != '\n' && s[i] != '\r'; i++) {
        if (s[i] == '%') { i += 2; n += 1; }    // <-- assumes valid %XX
        else             {         n += 1; }
    }
    return n;
}
```

`src/handlers/admin.cpp` — the decoder:

```cpp
void decode_status_param(const char* src, char* dst) {
    while (src[i] != '\0' && ...) {
        if (src[i] == '%') {
            int hi = hex_val(src[i+1]);
            int lo = (hi >= 0) ? hex_val(src[i+2]) : -1;
            if (hi >= 0 && lo >= 0) {           // valid  -> 1 byte out
                dst[o++] = (char)((hi << 4) | lo);
                i += 3; continue;
            }
        }
        dst[o++] = src[i++];                    // malformed -> byte-for-byte copy
    }
}
...
size_t decoded_len = estimate_decoded_length(status_pos);
char* status_msg = (char*)malloc(decoded_len + 1);
decode_status_param(status_pos, status_msg);    // <-- writes past the estimate
```

The estimator and decoder disagree on malformed escapes. `%GZ`: the
estimator counts 1, the decoder writes 3. 200 copies of `%GZ` sizes
the allocation to 201 bytes but decodes to 600 bytes on the wire.
Because the attacker picks the size class (chosen by well-formed
prefix bytes) *and* the overflowing bytes, this is a heap-grooming
primitive suitable for fake-vtable construction.

### Hints

1. Compare `%41` vs `%GZ` in the estimator and the decoder.
2. You control both the size class and the bytes written.
3. Pair with 08.

### Primitive

Heap overflow with fully controlled size class and contents. Suitable
for building a fake vtable pointer.

### Combines with

The groom step of 08's chain.

### Regression test

`tests/exploit/test_heap_overflow.py` (build with `--asan`).

---

<a id="challenge-10"></a>

## 10 · Integer Overflow → Heap Overflow (CWE-190)

### Scenario

`upload_file` allocates `sizeof(UploadHeader) + content_len + filename_len`
in 32-bit arithmetic. Values near `UINT_MAX` wrap the sum to something
tiny, but the `recv()` below still uses the original `Content-Length`
for its offset and length.

### Endpoint

`POST /admin/upload_file` (Basic auth)

### Affected code

`src/handlers/admin.cpp`:

```cpp
unsigned int content_len  = (unsigned int)strtoul(content_length_str.c_str(), ..., 10);
unsigned int filename_len = (unsigned int)strtoul(filename_length_str.c_str(), ..., 10);

uint32_t allocation = (uint32_t)sizeof(UploadHeader) + content_len + filename_len;
char* file_buffer = (char*)malloc(allocation);
if (file_buffer) {
    UploadHeader header{};
    ...
    memcpy(file_buffer, &header, sizeof(header));
    recv(client_socket, file_buffer + sizeof(UploadHeader), content_len, 0);
                                             //  ^^^^^^^^^^^ original, unwrapped
}
```

`Content-Length: 4294967232` and `X-Filename-Length: 64` sum with the
64-byte header to `0` mod 2³². `malloc(0)` returns a small allocation
(typically 16-24 bytes on glibc), then `recv` writes up to 4 GB into
it starting at offset 64. Two things make this exploitable: the sum
is unchecked before allocation, and the write uses the *pre-wrap*
lengths. Same class of bug as 09, but the wrap chooses the size —
less precise, larger overflow.

### Hints

1. Three fields, each fine on its own — sum them mod 2³².
2. The declared body doesn't have to arrive; ASan trips on the sizing.

### Primitive

Bulk heap overflow.

### Combines with

Same class of bug as 09, but the wrap picks the size — less precise.

### Regression test

`tests/exploit/test_int_overflow.py` (build with `--asan`).

---

<a id="challenge-11"></a>

## 11 · Type Confusion — Route Metadata (CWE-843)

### Scenario

Routes are C++ objects (`StaticRoute`, `CgiRoute`), and the router
keeps a parallel `path → RouteType` map for dispatch. `/admin/update_rule`
rewrites the metadata but leaves the object alone. A `StaticRoute`
tagged `CGI` reaches `static_cast<CgiRoute*>(rule)->execute()`, which
reads the `directory` string at the same offset `executable` would sit
and hands it to `popen()`.

### Endpoint

1. `GET /admin/add_rule?type=static&path=/cgi-bin/pwn&directory=<command>` (Basic auth)
2. `GET /admin/update_rule?path=/cgi-bin/pwn&type=cgi` (Basic auth)
3. `GET /cgi-bin/pwn` (no auth)

### Affected code

`src/cgi_rules.h` — the class layout:

```cpp
class Route      { public: virtual ~Route() = default;
                          std::string path; };
class StaticRoute : public Route { public: std::string directory;  };
class CgiRoute    : public Route { public: std::string executable;
                                           void execute(int) const; };
```

`src/handlers/admin.cpp` — `update_rule` rewrites metadata only:

```cpp
route_types()[path] = new_type;              // <-- object untouched
```

`src/handlers/cgi.cpp` — dispatch trusts the metadata, not the object:

```cpp
if (route_types()[rule->path] != RouteType::CGI) continue;
CgiRoute* cgi = static_cast<CgiRoute*>(rule);   // <-- may still be a StaticRoute
cgi->execute(client_socket);                    // reads first std::string field
```

`StaticRoute::directory` and `CgiRoute::executable` occupy the same
offset (first non-inherited member, after `Route::path`). Register a
`StaticRoute` with `directory=id`, flip its metadata to CGI, hit
`/cgi-bin/pwn`, and `execute()` reads the `directory` string as
`executable` and passes it to `popen()`. Because `/cgi-bin/*` isn't
gated by auth, the trigger is anonymous — only the setup needs a
session.

### Hints

1. Two sources of truth for the same object's type.
2. Compare the memory layout of `StaticRoute::directory` and `CgiRoute::executable`.
3. The trigger doesn't need credentials — see 04 / 05 for the setup.

### Primitive

Unauthenticated command execution via `/cgi-bin/*`.

### Combines with

Setup needs an admin session (04 / 05). Trigger is anonymous.

### Regression test

`tests/exploit/test_type_confusion.py`

---

<a id="challenge-12"></a>

## 12 · Stack Buffer Overflow — Request Path (CWE-121)

### Scenario

`HttpRequest::parse()` copies the request path into a 200-byte stack
buffer with `strcpy`. Paths over 200 bytes trample the parser's saved
registers.

### Endpoint

Any HTTP request with a path longer than 200 bytes.

### Affected code

`src/http/request.cpp`:

```cpp
// Copy the raw path, unbounded, into the 200-byte clean_path.
strcpy(out.clean_path, path_with_query);
```

`out.clean_path` is a `char[200]` on the caller's stack. `strcpy`
copies until the source NUL, so any path longer than 199 bytes
overwrites whatever the compiler placed after `clean_path` — saved
frame pointer, saved return address, adjacent locals. The 1024-byte
`recv()` cap in the accept loop is the real bound on your payload
size in HTTP mode; `--fuzz` mode reads from stdin without that cap
and lets you smash bigger.

### Hints

1. What's the server's `recv()` cap?
2. `--fuzz` mode drives the parser from stdin without the network cap.

### Primitive

RIP control on the default build. ROP on a hardened build if paired
with a leak.

### Combines with

Rebuild `-DENABLE_HARDENING=ON` and use a leak (01 / 03 / 07) for
addresses.

### Regression test

`tests/exploit/test_stack_bof.py`

---

<a id="challenge-14"></a>

## 14 · Zip Slip (CWE-22)

### Scenario

`/admin/deploy_site` extracts an uploaded ZIP into `serve/deploy/` and
serves the result at `/deploy/`. Output paths are built by
concatenating the deploy dir with each entry's filename with no
validation. Entries named `../../../../tmp/evil.sh` land wherever you
want.

### Endpoint

`POST /admin/deploy_site` (Basic auth: `admin:admin`)

### Affected code

`src/handlers/deploy.cpp`:

```cpp
char output_path[1024];
snprintf(output_path, sizeof(output_path), "%s/%s",
         deploy_dir, filename);           // filename is attacker-controlled

// No canonicalization! No containment check!
void* file_data = mz_zip_reader_extract_to_heap(&zip, i, &uncompressed_size, 0);
if (file_data) {
    if (write_file(output_path, file_data, uncompressed_size)) {
        extracted_count++;
    }
    mz_free(file_data);
}
```

`filename` comes from the ZIP central directory — an attacker controls
it end-to-end. `snprintf("%s/%s", deploy_dir, "../../../../tmp/x")`
produces `serve/deploy/../../../../tmp/x`, and the OS resolves the
`..` segments during `open(2)`. Writing arbitrary content to arbitrary
paths as the server user is the primitive. Web-facing consequences:
overwrite `serve/index.html` for defacement, drop a file at
`/tmp/dvws_cgi_<pid>` and race 06 for RCE. The fix is to canonicalize
each output path and reject anything that doesn't stay under
`deploy_dir`.

### Hints

1. What happens when the entry filename contains `../`?
2. Where is `serve/deploy/` relative to the docroot?
3. What can you overwrite that the server later runs? See 06.

### Primitive

Arbitrary file write, chosen path and content, wherever the server
user has permission.

### Combines with

Needs an admin session (04 / 05). Write to `/tmp/dvws_cgi_<pid>` and
chain into 06 for RCE, or overwrite files under `serve/` for defacement.

### Regression test

`tests/exploit/test_zip_slip.py`

---

<a id="challenge-13"></a>

## 13 · Global Buffer Overflow — argv (CWE-121)

### Scenario

`main()` `strcpy`s `argv[1]` into the 200-byte global `SERVER_DIR`.
Destination sits in `.bss`, so this is adjacent-global corruption
rather than a saved-return-address smash. Damage depends on what the
linker put next to `SERVER_DIR`.

### Endpoint

Local process invocation; not network-reachable.

### Affected code

`src/server_config.h`:

```cpp
struct ServerConfig {
    char server_dir[200];  // document root, copied from argv[1]
    ...
};
extern ServerConfig g_config;
```

`src/main.cpp`:

```cpp
strcpy(g_config.server_dir, argv[1]);       // no length check
```

`g_config` lives in `.bss` alongside other globals — the session map,
the log sink pointer, OpenSSL state. Overrunning `server_dir[200]`
corrupts whatever the linker placed next; the actual layout depends on
build order and is inspectable in the link map. Any later `strcat`
onto `server_dir` (e.g. inside the static-file handler) inherits the
corruption and extends it. Not remotely reachable — the user has to
launch the process — but a useful demo of `.bss` overflow mechanics.

### Hints

1. Check the link map for globals adjacent to `SERVER_DIR`.
2. Anything the server later `strcat`s onto `SERVER_DIR` inherits the
   corruption.

### Primitive

Adjacent-global corruption.

### Regression test

`tests/exploit/test_argv_bof.py`
