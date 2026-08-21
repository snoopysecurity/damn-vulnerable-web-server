# 05 · Predictable Session ID (CWE-330)

## Scenario
`generate_session_id()` calls `srand(time(0))` and returns
`"SESSION_" + std::to_string(rand())`. Because the seed is a low-entropy
wall-clock value, an attacker who knows (or can guess) the second in
which a session was minted can brute-force the ID space in trivial time.

## Endpoint
Any endpoint whose response contains `Set-Cookie: session_id=SESSION_<n>`.

## Sink
`session_manager.cpp` — `srand(time(0)); ... "SESSION_" + std::to_string(rand())`

## Hints
1. What entropy source is the ID derived from?
2. How many possible values are there for a given second?

## Expected primitive
Session-ID prediction leading to hijack of a victim's authenticated session.

## Regression test
`tests/exploit/test_predictable_session.py`
