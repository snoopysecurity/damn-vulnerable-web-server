# 07 · Username Object Info Leak (CWE-125)

## Scenario
`handle_authentication()` casts a `std::string`'s `c_str()` result and
then `send()`s **64 bytes** starting from there. For short-string
optimized (SSO) strings this leaks adjacent bytes of the `std::string`
object; for long strings it leaks bytes past the heap allocation.

## Endpoint
`GET /whoami` (requires `Authorization: Basic ...`)

## Sink
`authentication.cpp` — `send(client_socket, leaked_ptr, 64, 0);`

## Hints
1. Try both short and long usernames.
2. What lives immediately after a `std::string`'s SSO buffer?

## Expected primitive
Out-of-bounds read → memory disclosure.

## Regression test
`tests/exploit/test_username_leak.py`
