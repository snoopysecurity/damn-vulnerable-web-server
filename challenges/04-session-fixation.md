# 04 · Session Fixation (CWE-384)

## Scenario
The router only issues a `Set-Cookie` when the client didn't send one.
An attacker who chooses a session ID and tricks a victim into sending it
can then reuse the same ID after the victim authenticates.

## Endpoint
Any endpoint, but the auth flow is on `/admin/*`.

## Sink
`router.cpp` — the `set_cookie_header` branch that skips rotation when
`session_id` is already present in the request.

## Hints
1. What does a real login flow do to the session ID after authentication?
2. Send `Cookie: session_id=EVIL` and watch the response headers.

## Expected primitive
Account takeover after victim login (given the ability to plant a cookie).

## Regression test
`tests/exploit/test_session_fixation.py`
