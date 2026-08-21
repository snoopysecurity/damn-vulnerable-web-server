# 13 · Global Buffer Overflow — argv (CWE-121)

## Scenario
`main()` copies `argv[1]` (the server document root) into the 200-byte
global `SERVER_DIR` with `strcpy`. Because the destination is in `.bss`
and not on the stack, the primitive is *adjacent-global corruption* rather
than a classic saved-return-address smash — but it still corrupts nearby
program state.

## Endpoint
Not network-reachable: local process invocation.

## Sink
`main.cpp` — `strcpy(SERVER_DIR, argv[1]);`

## Hints
1. What globals live near `SERVER_DIR` in the linker map?
2. Anything the server later `strcat`s onto `SERVER_DIR` will inherit the corruption.

## Expected primitive
Adjacent-global corruption; realistic damage depends on link order.

## Regression test
`tests/exploit/test_argv_bof.py` (asserts the vulnerable pattern is still present)
