# Web Security Headers Checker

A portfolio security-automation project by Dheeraj Mendu. This tool audits
HTTP security response headers on web applications and grades the result —
the kind of check security engineers run when hardening public web apps.

Built as a 3-day project:
- **Day 1:** Core header checks + A–F grading
- **Day 2:** Redirect/HTTPS-upgrade tracking, cookie flag checks, batch mode
- **Day 3:** JSON/Markdown reporting, pytest unit tests, usage docs

## Quickstart

```bash
pip install -r requirements.txt
python3 run.py https://example.com
```

Batch mode (one URL per line):

```bash
python3 run.py --targets targets.txt
```

Cookie checks run automatically on every target.

## What it checks

Response headers: `Content-Security-Policy`, `Strict-Transport-Security`,
`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`,
`Permissions-Policy`. Cookies: `Secure`, `HttpOnly`, `SameSite`.

Each check produces a finding (`header`, `status`, `detail`), and the overall
result is graded A–F.
