# 03 · Uncontrolled Format String (CWE-134)

## Scenario
The request logger writes query parameter values to disk using
`fprintf(log_file, value.c_str())` — value is used as the format string
itself, giving an attacker `%p` / `%n` primitives against the logger's
stack frame.

## Endpoint
Any request with a query string.

## Sink
`request_logger.cpp` — `fprintf(log_file, value.c_str());`

## Hints
1. Where does the value end up?
2. Which `printf` conversion specifier reads a stack slot?
3. `%n` isn't the only interesting one; leakage matters too.

## Expected primitive
Memory disclosure via `%p`; write primitive via `%n` (glibc-dependent).

## Regression test
`tests/exploit/test_format_string.py`
