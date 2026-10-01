"""Check Set-Cookie flags: Secure, HttpOnly, SameSite -> findings.

Finding shape mirrors checks.py: {"cookie", "status", "detail"}.
"""

import re

FLAGS = ("Secure", "HttpOnly", "SameSite")


def split_set_cookie(headers):
    """Return list of raw Set-Cookie values from a headers dict.

    requests merges multiple Set-Cookie headers into one comma-joined
    value; split conservatively on commas followed by a token containing '='.
    """
    raw = headers.get("Set-Cookie")
    if not raw:
        return []
    return [c.strip() for c in re.split(r",(?=\s*[^;,=]+=[^;]*)", raw)]


def check_cookies(headers):
    """Check cookie flags; return findings list."""
    cookies = split_set_cookie(headers)
    if not cookies:
        return [{"cookie": "(none)", "status": "warn",
                 "detail": "No Set-Cookie headers observed"}]
    findings = []
    for entry in cookies:
        name = entry.split(";", 1)[0].split("=", 1)[0].strip() or "(unnamed)"
        lowered = entry.lower()
        missing = [f for f in FLAGS if f.lower() not in lowered]
        same_site = re.search(r"samesite=(\w+)", lowered)
        if same_site and same_site.group(1) not in ("lax", "strict"):
            status = "warn"
            detail = "SameSite=%s is weak; use Lax or Strict" % (
                same_site.group(1))
        elif missing:
            status = "warn"
            detail = "Missing flags: %s" % ", ".join(missing)
        else:
            status = "pass"
            detail = "Secure, HttpOnly, SameSite set"
        findings.append({"cookie": name, "status": status, "detail": detail})
    return findings
