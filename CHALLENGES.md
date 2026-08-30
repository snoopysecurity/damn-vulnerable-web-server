# Challenges

Every intentional vulnerability in this server is a numbered challenge.
Each row links to a *card* (scenario + progressive hints) and a *solution*
(full exploit). Difficulty is a rough guide for CTF workshops.

| #  | Vulnerability                | Class          | CWE   | Endpoint / Trigger                     | Difficulty | Card | Solution |
|----|------------------------------|----------------|-------|----------------------------------------|------------|------|----------|
| 01 | Path Traversal               | Web            | CWE-22  | `GET /../../etc/passwd`               | easy       | [card](challenges/README.md#challenge-01) | [sol](challenges/README.md#solution-01) |
| 02 | Command Injection            | Web            | CWE-78  | `GET /logs?filter=`                   | easy       | [card](challenges/README.md#challenge-02) | [sol](challenges/README.md#solution-02) |
| 03 | Uncontrolled Format String   | Memory         | CWE-134 | any query parameter → log             | medium     | [card](challenges/README.md#challenge-03) | [sol](challenges/README.md#solution-03) |
| 04 | Session Fixation             | Web            | CWE-384 | `Cookie: session_id=...`              | easy       | [card](challenges/README.md#challenge-04) | [sol](challenges/README.md#solution-04) |
| 05 | Predictable Session ID       | Crypto/Web     | CWE-330 | `Set-Cookie: SESSION_<rand>`          | medium     | [card](challenges/README.md#challenge-05) | [sol](challenges/README.md#solution-05) |
| 06 | Insecure Temp File (race)    | System         | CWE-377 | `/tmp/php_script_<pid>.php`           | hard       | [card](challenges/README.md#challenge-06) | [sol](challenges/README.md#solution-06) |
| 07 | Username Info Leak           | Memory         | CWE-125 | `GET /whoami`                          | medium     | [card](challenges/README.md#challenge-07) | [sol](challenges/README.md#solution-07) |
| 08 | Use-After-Free (logger)      | Memory         | CWE-416 | `/admin/logger_config`                | hard       | [card](challenges/README.md#challenge-08) | [sol](challenges/README.md#solution-08) |
| 09 | Heap Buffer Overflow         | Memory         | CWE-122 | `POST /admin/system_status`           | medium     | [card](challenges/README.md#challenge-09) | [sol](challenges/README.md#solution-09) |
| 10 | Integer Overflow             | Memory         | CWE-190 | `POST /admin/upload_file`             | medium     | [card](challenges/README.md#challenge-10) | [sol](challenges/README.md#solution-10) |
| 11 | Type Confusion               | Memory         | CWE-843 | `/admin/add_rule` + `/cgi-bin/*`      | hard       | [card](challenges/README.md#challenge-11) | [sol](challenges/README.md#solution-11) |
| 12 | Stack Buffer Overflow (path) | Memory         | CWE-121 | long request path                     | medium     | [card](challenges/README.md#challenge-12) | [sol](challenges/README.md#solution-12) |
| 13 | Global BOF (argv)            | Memory         | CWE-121 | `./damn_vulnerable_web_server $(...)` | easy       | [card](challenges/README.md#challenge-13) | [sol](challenges/README.md#solution-13) |

## Regression suite

Each challenge has a corresponding regression test under `tests/exploit/`.
Run them all with:

```bash
python3 tests/exploit/run_all.py           # normal build
python3 tests/exploit/run_all.py --asan    # ASan build (catches latent UAF / heap / int overflow)
```

## Reporting scope

If you spot a bug that is *not* listed above, it's an accidental one and
we'd like to know. Open an issue tagged `unintended-bug`.
