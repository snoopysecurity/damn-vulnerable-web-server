# Threat Model

A short, honest sketch of where trust boundaries *should* be — and where
this server intentionally ignores them.

```
                  ┌─────────────────────────────────────────────────────┐
   attacker ───►  │ 1. socket recv() — MAX_REQUEST_SIZE=1024, no TLS    │
                  ├─────────────────────────────────────────────────────┤
                  │ 2. HttpRequest::parse — strcpy → 200-byte buffer    │  ← CH-12
                  ├─────────────────────────────────────────────────────┤
                    │ 3. router.cpp dispatch                              │
                    │    ├── /logs       → popen + "escaped" user input   │  ← CH-02
                    │    ├── /admin/*    → Basic auth (admin:admin)      │
                    │    │      │           or authenticated session    │  ← CH-04
                    │    │      ├── system_status  → est. length ≠       │  ← CH-09
                    │    │      │                   decoded length
                    │    │      ├── upload_file    → 3-field 32-bit sum  │  ← CH-10
                    │    │      ├── add_rule       → Route objects +     │  ← CH-11 setup
                    │    │      ├── update_rule    → tag-only rewrite
                    │    │      └── logging        → delete live sink    │  ← CH-08
                    │    ├── /whoami     → fixed 128-byte record,        │  ← CH-07
                    │    │                  only prefix initialized
                    │    ├── /cgi-bin/*  → metadata-tag static_cast      │  ← CH-11 trigger
                    │    └── static file → docroot check, then            │  ← CH-01
                    │                     canonicalize (order inverted)
                    ├─────────────────────────────────────────────────────┤
                     │ 4. request_logger — fprintf(f, X-Forwarded-For)    │  ← CH-03
                     │    /cgi-helper  — stage+exec /tmp/dvws_cgi_<pid>   │  ← CH-06
                   ├─────────────────────────────────────────────────────┤
                   │ 5. session_manager — srand(time(0));               │  ← CH-04, CH-05
                   │                      rand() ^ getpid()             │
                  └─────────────────────────────────────────────────────┘
```

## What a real server should do here

| Layer                | Wrong in DVWS                                      | Right in production                                                        |
|----------------------|----------------------------------------------------|----------------------------------------------------------------------------|
| Request buffer       | fixed 1024 recv into stack                         | streaming parser with hard byte limit and slow-loris timeouts              |
| Path parsing         | `strcpy` into fixed buffer                         | length-checked copy + rejection on overflow                                |
| Path canonicalization| check lexical path, canonicalize after          | canonicalize first, then prefix check on the canonical result              |
| Shell interop        | `popen("grep ... " + quoted_input)`               | never; use `execve`/`posix_spawn` with argument vectors                    |
| String formatting    | user input as format string                        | always `%s` with format literal                                            |
| Temp files           | predictable `/tmp/dvws_cgi_<pid>` executable      | `mkstemp` with `O_EXCL` in a dir the server owns                           |
| Sessions             | `rand()^getpid()` seeded by `time(0)`              | 128+ bits from `/dev/urandom` (or `getrandom`)                             |
| Session lifecycle    | client-supplied ID reused after auth               | rotate ID on privilege change; reject unknown IDs                          |
| Auth                 | hard-coded `admin:admin`                           | passwd hashing (Argon2/bcrypt) + rate limiting + MFA                       |
| Downcasts            | blind `static_cast<Derived*>` driven by router metadata that can disagree with the object's class | `dynamic_cast` with null check, or a single in-object source of type truth |
| Buffer arithmetic    | 32-bit sum of header + body + filename lengths     | checked addition (`__builtin_add_overflow`) + cap on max upload            |
| Decode sizing        | estimate and decode implement different escape rules | one implementation, or bounded decode that reports bytes written          |
| Async sink lifecycle | `delete` of an object still referenced by queued work | `shared_ptr` captured per record, or drain before delete                  |
| Fixed-size records   | whole buffer sent, only a prefix initialized       | send `strlen`/`size()` of the initialized region only                     |
| C-string temp bufs   | `strcpy` / `sprintf`                               | `snprintf` with size, or `std::string` end-to-end                          |

## Non-goals

- Confidentiality (no TLS)
- Concurrency safety (single-threaded)
- DoS resistance
- Portability to Windows

## Deployment guidance

Do not expose this server to a network you do not control. It is designed
to be trivially exploitable and will happily execute attacker-controlled
code as its own uid.
