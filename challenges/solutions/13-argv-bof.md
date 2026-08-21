# Solution — 13 · Global Buffer Overflow (argv)

**Code**: `main.cpp` → `strcpy(SERVER_DIR, argv[1]);`

```bash
./damn_vulnerable_web_server "$(python3 -c 'print("A"*400)')" 8081
```

Because `SERVER_DIR` sits in `.bss`, the damage depends on what the
linker placed after it. On the current build layout, adjacent globals
include the sessions map and OpenSSL state; sending any request that
touches those triggers observable corruption.
