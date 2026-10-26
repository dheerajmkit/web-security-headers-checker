# Web Security Headers Checker

A portfolio security-automation project by Dheeraj Mendu. This tool audits
HTTP security response headers on web applications and grades the result —
the kind of check security engineers run when hardening public web apps.

## Quickstart

```bash
pip install -r requirements.txt
python3 run.py https://example.com
```

Each check produces a finding (`header`, `status`, `detail`), and the
overall result is graded A–F.
