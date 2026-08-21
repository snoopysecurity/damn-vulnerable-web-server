# 01 · Path Traversal (CWE-22)

## Scenario
The static file handler joins the server document root with the request
path using nothing more than `strcat`. There is no canonicalization and
no rejection of `..` segments.

## Endpoint
Any URL served by the static handler, e.g. `GET /index.html`.

## Sink
`handlers/static_files.cpp` — `strcat(file_path, req.clean_path);`

## Hints
1. What does the server do with `/`-prefixed paths on disk?
2. Standard clients normalize `..` before sending. What tools *don't*?
3. Can you send a raw HTTP request with a literal `..` in the path?

## Expected primitive
Arbitrary file read within the process's uid.

## Regression test
`tests/exploit/test_path_traversal.py`
