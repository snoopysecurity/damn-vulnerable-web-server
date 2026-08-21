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
                  │    ├── /logs       → popen + user input             │  ← CH-02
                  │    ├── /admin/*    → Basic auth (admin:admin)       │
                  │    │      ├── system_status  → malloc(32) + memcpy  │  ← CH-09
                  │    │      ├── upload_file    → content_len + 64     │  ← CH-10
                  │    │      ├── add_rule       → AliasRule/ExecRule   │  ← CH-11 setup
                  │    │      └── logger_config  → free w/o null        │  ← CH-08
                  │    ├── /whoami     → send 64 bytes of std::string   │  ← CH-07
                  │    ├── /cgi-bin/*  → static_cast<ExecRule*>         │  ← CH-11 trigger
                  │    └── static file → strcat(SERVER_DIR, path)       │  ← CH-01
                  ├─────────────────────────────────────────────────────┤
                  │ 4. request_logger — fprintf(f, user_string)         │  ← CH-03
                  │                  ── /tmp/php_script_<pid>.php       │  ← CH-06
                  ├─────────────────────────────────────────────────────┤
                  │ 5. session_manager — srand(time(0)) + rand()        │  ← CH-04, CH-05
                  └─────────────────────────────────────────────────────┘
```

## What a real server should do here

| Layer                | Wrong in DVWS                                      | Right in production                                                        |
|----------------------|----------------------------------------------------|----------------------------------------------------------------------------|
| Request buffer       | fixed 1024 recv into stack                         | streaming parser with hard byte limit and slow-loris timeouts              |
| Path parsing         | `strcpy` into fixed buffer                         | length-checked copy + rejection on overflow                                |
| Path canonicalization| `strcat(root, user_path)`                          | `realpath()` + prefix check; reject `..` segments                          |
| Shell interop        | `popen("sh -c ... " + user_input)`                 | never; use `execve`/`posix_spawn` with argument vectors                    |
| String formatting    | user input as format string                        | always `%s` with format literal                                            |
| Temp files           | predictable `/tmp/<pid>.php`                       | `mkstemp` with `O_EXCL` in a dir the server owns                           |
| Sessions             | `rand()` seeded by `time(0)`                       | 128+ bits from `/dev/urandom` (or `getrandom`)                             |
| Session lifecycle    | client-supplied ID reused after auth               | rotate ID on privilege change; reject unknown IDs                          |
| Auth                 | hard-coded `admin:admin`                           | passwd hashing (Argon2/bcrypt) + rate limiting + MFA                       |
| Downcasts            | blind `static_cast<Derived*>`                      | `dynamic_cast` with null check, or type-tagged unions                      |
| Buffer arithmetic    | `content_len + 64` in `unsigned int`               | checked addition (`__builtin_add_overflow`) + cap on max upload            |
| Free lists           | `free(p);` without `p = nullptr;`                  | RAII (`std::unique_ptr`), or immediately null on free                      |
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
