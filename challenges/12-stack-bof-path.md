# 12 · Stack Buffer Overflow — Request Path (CWE-121)

## Scenario
`HttpRequest::parse()` copies the request path with a raw `strcpy` into
`clean_path[200]`. Any path longer than 200 bytes overwrites the parser's
saved registers.

## Endpoint
Any HTTP request whose path is longer than 200 bytes.

## Sink
`http/request.cpp` — `strcpy(out.clean_path, path_with_query);`

## Hints
1. What is the maximum request size the server will `recv()`?
2. That upper bound shapes your payload space.
3. `--fuzz` mode runs the same parser from stdin without the network cap.

## Expected primitive
RIP control (given the hardening-disabled build).

## Regression test
`tests/exploit/test_stack_bof.py`
