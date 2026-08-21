# 02 · Command Injection (CWE-78)

## Scenario
The unauthenticated log viewer takes a `filter` query parameter, URL-decodes
it, and interpolates it directly into a shell command passed to `popen()`.

## Endpoint
`GET /logs?filter=<user input>`

## Sink
`request_logger.cpp` — `popen("sh -c \"grep " + decoded_filter + " ...")`

## Hints
1. What character terminates a shell command?
2. The filter is URL-decoded before being placed in the shell string.
3. You do not need authentication for this route.

## Expected primitive
Arbitrary OS command execution as the server user.

## Regression test
`tests/exploit/test_cmd_injection.py`
