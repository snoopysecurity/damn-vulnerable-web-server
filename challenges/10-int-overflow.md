# 10 · Integer Overflow → Heap Overflow (CWE-190)

## Scenario
`upload_file` computes `buffer_size = content_len + 64` as an unsigned
32-bit int. Setting `Content-Length` close to `UINT_MAX` wraps the
result to a tiny number; the subsequent `recv()` writes the full,
attacker-declared body length into the undersized allocation.

## Endpoint
`POST /admin/upload_file` (Basic auth)

## Sink
`handlers/admin.cpp` — `unsigned int buffer_size = content_len + 64;`

## Hints
1. What is `UINT_MAX + 64`?
2. `recv()`'s length is `content_len`, not `buffer_size`.

## Expected primitive
Massive controlled heap overflow.

## Regression test
`tests/exploit/test_int_overflow.py` (build with `--asan`)
