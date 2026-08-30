# Runtime API Security Test — 2026-08-15

- Health response: HTTP 200
- Required security headers missing: 0
- Protected `/api/v1/profile` without token: HTTP 401
- Malformed login JSON: HTTP 400
- SQL-injection-shaped login input: HTTP 400
- Metrics without bearer token: HTTP 401
- TRACE request: HTTP 404
- Load requests: 100
- Concurrency: 10
- Failed load requests: 0
- Test duration: 1,083 ms
- Observed throughput: 92.28 requests/second

This is a bounded local smoke test, not an external penetration-test or a
production capacity benchmark.
