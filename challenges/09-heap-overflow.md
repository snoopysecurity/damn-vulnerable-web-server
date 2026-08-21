# 09 · Heap Buffer Overflow (CWE-122)

## Scenario
`system_status` allocates a fixed 32-byte heap buffer and copies bytes
from the `status=` parameter until it sees a NUL, `\n`, or `\r`.

## Endpoint
`POST /admin/system_status` (Basic auth)

## Sink
`handlers/admin.cpp` — `char* status_msg = (char*)malloc(32);` then unbounded copy.

## Hints
1. What are you overwriting once you go past 32 bytes?
2. Consider chunk metadata *or* the next allocation.
3. Combine with challenge 08 to line up the primitives.

## Expected primitive
Adjacent heap corruption; controlled function-pointer overwrite when
chained with the UAF.

## Regression test
`tests/exploit/test_heap_overflow.py` (build with `--asan` for a clear crash)
