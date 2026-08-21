# Challenges

Every intentional vulnerability in this server is a numbered challenge.
Each row links to a *card* (scenario + progressive hints) and a *solution*
(full exploit). Difficulty is a rough guide for CTF workshops.

| #  | Vulnerability                | Class          | CWE   | Endpoint / Trigger                     | Difficulty | Card | Solution |
|----|------------------------------|----------------|-------|----------------------------------------|------------|------|----------|
| 01 | Path Traversal               | Web            | CWE-22  | `GET /../../etc/passwd`               | easy       | [card](challenges/01-path-traversal.md) | [sol](challenges/solutions/01-path-traversal.md) |
| 02 | Command Injection            | Web            | CWE-78  | `GET /logs?filter=`                   | easy       | [card](challenges/02-command-injection.md) | [sol](challenges/solutions/02-command-injection.md) |
| 03 | Uncontrolled Format String   | Memory         | CWE-134 | any query parameter → log             | medium     | [card](challenges/03-format-string.md) | [sol](challenges/solutions/03-format-string.md) |
| 04 | Session Fixation             | Web            | CWE-384 | `Cookie: session_id=...`              | easy       | [card](challenges/04-session-fixation.md) | [sol](challenges/solutions/04-session-fixation.md) |
| 05 | Predictable Session ID       | Crypto/Web     | CWE-330 | `Set-Cookie: SESSION_<rand>`          | medium     | [card](challenges/05-predictable-session.md) | [sol](challenges/solutions/05-predictable-session.md) |
| 06 | Insecure Temp File (race)    | System         | CWE-377 | `/tmp/php_script_<pid>.php`           | hard       | [card](challenges/06-php-tmp-race.md) | [sol](challenges/solutions/06-php-tmp-race.md) |
| 07 | Username Info Leak           | Memory         | CWE-125 | `GET /whoami`                          | medium     | [card](challenges/07-username-leak.md) | [sol](challenges/solutions/07-username-leak.md) |
| 08 | Use-After-Free (logger)      | Memory         | CWE-416 | `/admin/logger_config`                | hard       | [card](challenges/08-uaf-logger.md) | [sol](challenges/solutions/08-uaf-logger.md) |
| 09 | Heap Buffer Overflow         | Memory         | CWE-122 | `POST /admin/system_status`           | medium     | [card](challenges/09-heap-overflow.md) | [sol](challenges/solutions/09-heap-overflow.md) |
| 10 | Integer Overflow             | Memory         | CWE-190 | `POST /admin/upload_file`             | medium     | [card](challenges/10-int-overflow.md) | [sol](challenges/solutions/10-int-overflow.md) |
| 11 | Type Confusion               | Memory         | CWE-843 | `/admin/add_rule` + `/cgi-bin/*`      | hard       | [card](challenges/11-type-confusion.md) | [sol](challenges/solutions/11-type-confusion.md) |
| 12 | Stack Buffer Overflow (path) | Memory         | CWE-121 | long request path                     | medium     | [card](challenges/12-stack-bof-path.md) | [sol](challenges/solutions/12-stack-bof-path.md) |
| 13 | Global BOF (argv)            | Memory         | CWE-121 | `./damn_vulnerable_web_server $(...)` | easy       | [card](challenges/13-argv-bof.md) | [sol](challenges/solutions/13-argv-bof.md) |

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
