# 06 · Insecure Temporary File Race (CWE-377 / CWE-367)

## Scenario
Every request for a `.php` file writes the file's contents to
`/tmp/php_script_<pid>.php` and then executes it with the PHP CLI. The
filename is predictable and world-writable; there is a small TOCTOU
window between `fclose(temp_file)` and `popen("php <path>")`.

## Endpoint
`GET /*.php`

## Sink
`mime_type_handler.cpp` — `snprintf(temp_file_path, ..., "/tmp/php_script_%d.php", pid)`

## Hints
1. What is the PID of the server process?
2. Can you win the write between `fclose()` and `popen()`?

## Expected primitive
Arbitrary PHP code execution as the server user given local shell access.

## Regression test
`tests/exploit/test_php_tmp_race.py`
