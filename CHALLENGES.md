# Challenges

The bugs planted in this server. Click a row for the card with the sink and hints.

| #  | Vulnerability                 | Class      | CWE     | Endpoint / Trigger                                     | Card |
|----|-------------------------------|------------|---------|--------------------------------------------------------|------|
| 01 | Path Traversal                | Web        | CWE-22  | `GET /../../etc/passwd`                                | [card](challenges/README.md#challenge-01) |
| 02 | Command Injection             | Web        | CWE-78  | `GET /logs?search=`                                    | [card](challenges/README.md#challenge-02) |
| 03 | Uncontrolled Format String    | Memory     | CWE-134 | `X-Forwarded-For` header → log                         | [card](challenges/README.md#challenge-03) |
| 04 | Session Fixation              | Web        | CWE-384 | `Cookie: session_id=...`                               | [card](challenges/README.md#challenge-04) |
| 05 | Predictable Session ID        | Crypto/Web | CWE-330 | `Set-Cookie: SESSION_<hex>`                            | [card](challenges/README.md#challenge-05) |
| 06 | Insecure Temp Executable Race | System     | CWE-377 | `/tmp/dvws_cgi_<pid>`                                  | [card](challenges/README.md#challenge-06) |
| 07 | Username Info Leak            | Memory     | CWE-125 | `GET /whoami`                                          | [card](challenges/README.md#challenge-07) |
| 08 | Use-After-Free (LogSink)      | Memory     | CWE-416 | `/admin/logging`                                       | [card](challenges/README.md#challenge-08) |
| 09 | Heap Buffer Overflow          | Memory     | CWE-122 | `POST /admin/system_status`                            | [card](challenges/README.md#challenge-09) |
| 10 | Integer Overflow              | Memory     | CWE-190 | `POST /admin/upload_file`                              | [card](challenges/README.md#challenge-10) |
| 11 | Type Confusion                | Memory     | CWE-843 | `/admin/add_rule` + `/admin/update_rule` + `/cgi-bin/*`| [card](challenges/README.md#challenge-11) |
| 12 | Stack Buffer Overflow (path)  | Memory     | CWE-121 | long request path                                      | [card](challenges/README.md#challenge-12) |
| 13 | Global BOF (argv)             | Memory     | CWE-121 | `./damn_vulnerable_web_server $(...)`                  | [card](challenges/README.md#challenge-13) |
| 14 | Zip Slip                      | Web        | CWE-22  | `POST /admin/deploy_site`                              | [card](challenges/README.md#challenge-14) |

## Regression tests

Every challenge has a matching test under `tests/exploit/`:

```bash
python3 tests/exploit/run_all.py           # normal build
python3 tests/exploit/run_all.py --asan    # ASan build; needed for UAF, heap, and int-overflow
```
