"""Core security-header checks. Each check returns a finding dict."""

import re

# header -> (description, check function)
def _csp(headers):
    v = headers.get("Content-Security-Policy")
    if not v:
        return {"header": "Content-Security-Policy", "status": "fail",
                "detail": "Missing; XSS/injection mitigations not enforced"}
    if "unsafe-inline" in v or "unsafe-eval" in v:
        return {"header": "Content-Security-Policy", "status": "warn",
                "detail": "Present but weakened by unsafe-inline/unsafe-eval"}
    return {"header": "Content-Security-Policy", "status": "pass",
            "detail": "Present and restrictive"}


def _hsts(headers):
    v = headers.get("Strict-Transport-Security")
    if not v:
        return {"header": "Strict-Transport-Security", "status": "fail",
                "detail": "Missing; downgrade/SSL-stripping attacks possible"}
    m = re.search(r"max-age=(\d+)", v)
    max_age = int(m.group(1)) if m else 0
    if max_age < 31536000:
        return {"header": "Strict-Transport-Security", "status": "warn",
                "detail": "max-age under 1 year (%d)" % max_age}
    return {"header": "Strict-Transport-Security", "status": "pass",
            "detail": "Enforced with max-age=%d" % max_age}


def _frame_options(headers):
    v = headers.get("X-Frame-Options")
    if not v:
        return {"header": "X-Frame-Options", "status": "fail",
                "detail": "Missing; clickjacking risk"}
    if v.upper() not in ("DENY", "SAMEORIGIN"):
        return {"header": "X-Frame-Options", "status": "warn",
                "detail": "Unexpected value: %s" % v}
    return {"header": "X-Frame-Options", "status": "pass",
            "detail": "Set to %s" % v.upper()}


def _content_type_options(headers):
    v = headers.get("X-Content-Type-Options")
    if not v:
        return {"header": "X-Content-Type-Options", "status": "fail",
                "detail": "Missing; MIME-sniffing risk"}
    if v.lower() != "nosniff":
        return {"header": "X-Content-Type-Options", "status": "warn",
                "detail": "Unexpected value: %s" % v}
    return {"header": "X-Content-Type-Options", "status": "pass",
            "detail": "Set to nosniff"}


def _referrer_policy(headers):
    v = headers.get("Referrer-Policy")
    if not v:
        return {"header": "Referrer-Policy", "status": "warn",
                "detail": "Missing; referrer leakage may occur"}
    return {"header": "Referrer-Policy", "status": "pass",
            "detail": "Set to %s" % v}


def _permissions_policy(headers):
    v = headers.get("Permissions-Policy")
    if not v:
        return {"header": "Permissions-Policy", "status": "warn",
                "detail": "Missing; browser features left unrestricted"}
    return {"header": "Permissions-Policy", "status": "pass",
            "detail": "Present"}


CHECKS = [_csp, _hsts, _frame_options, _content_type_options,
          _referrer_policy, _permissions_policy]


def run_checks(headers):
    """Run all header checks against a headers dict; return findings list."""
    return [fn(headers) for fn in CHECKS]


def grade(findings):
    """Grade a findings list as A-F based on pass/warn/fail counts."""
    fails = sum(1 for f in findings if f["status"] == "fail")
    warns = sum(1 for f in findings if f["status"] == "warn")
    if fails == 0 and warns == 0:
        return "A"
    if fails == 0 and warns <= 2:
        return "B"
    if fails <= 1:
        return "C"
    if fails <= 2:
        return "D"
    return "F"
