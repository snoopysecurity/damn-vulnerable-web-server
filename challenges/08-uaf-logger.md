# 08 · Use-After-Free (Logger Config, CWE-416)

## Scenario
`action=reset` frees the `current_log_format` struct but does not null
the pointer. The next request that goes through the logger derefs the
dangling pointer and, if the heap has been groomed, calls an
attacker-controlled function pointer at `log_func`.

## Endpoint
`GET /admin/logger_config?action=set&format=...`
`GET /admin/logger_config?action=reset`

## Sink
`request_logger.cpp` — `free(current_log_format);` without setting to `nullptr`.

## Hints
1. `LogFormat` is 64 bytes of char + 8 bytes of function pointer.
2. What other route lets you allocate 72 bytes with attacker-controlled contents?
3. `/admin/system_status` (challenge 09) is your friend here.

## Expected primitive
Controlled call of an arbitrary function pointer.

## Regression test
`tests/exploit/test_uaf_logger.py` (needs `--asan` for a hard signal)
