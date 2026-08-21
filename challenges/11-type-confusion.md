# 11 · Type Confusion (CWE-843)

## Scenario
`AliasRule` and `ExecRule` inherit from a common `Rule` base. The CGI
dispatcher blindly `static_cast`s any `Rule*` whose path starts with
`/cgi-bin/` to `ExecRule*`. Because `AliasRule::target` (a 64-byte char
array) lives at the same offset as `ExecRule::callback` (a function
pointer), attacker-controlled bytes in `target` become the callee.

## Endpoint
1. `GET /admin/add_rule?type=alias&path=/cgi-bin/pwn&target=<8 bytes>` (Basic auth)
2. `GET /cgi-bin/pwn`

## Sink
`handlers/cgi.cpp` — `ExecRule* exec = static_cast<ExecRule*>(rule);`

## Hints
1. What are the first 8 bytes of `target` doing at that memory offset?
2. Try `target=AAAAAAAA` first and observe the crash address.
3. Where would you point a real exploit?

## Expected primitive
Controlled call of an arbitrary 8-byte function pointer → RIP control.

## Regression test
`tests/exploit/test_type_confusion.py`
