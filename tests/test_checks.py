"""Unit tests for checker/checks.py — canned header dicts, no network."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from checker.checks import run_checks, grade  # noqa: E402


def good_headers():
    return {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
    }


def test_all_pass_is_grade_a():
    findings = run_checks(good_headers())
    assert all(f["status"] == "pass" for f in findings)
    assert grade(findings) == "A"


def test_missing_csp_fails():
    h = good_headers()
    del h["Content-Security-Policy"]
    findings = run_checks(h)
    csp = next(f for f in findings if f["header"] == "Content-Security-Policy")
    assert csp["status"] == "fail"
    assert grade(findings) == "C"


def test_weak_csp_warns():
    h = good_headers()
    h["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline'"
    findings = run_checks(h)
    csp = next(f for f in findings if f["header"] == "Content-Security-Policy")
    assert csp["status"] == "warn"
    assert grade(findings) == "B"


def test_short_hsts_warns():
    h = good_headers()
    h["Strict-Transport-Security"] = "max-age=86400"
    findings = run_checks(h)
    hsts = next(f for f in findings if f["header"] == "Strict-Transport-Security")
    assert hsts["status"] == "warn"


def test_frame_options_invalid_warns():
    h = good_headers()
    h["X-Frame-Options"] = "ALLOW-FROM https://x.example"
    findings = run_checks(h)
    xf = next(f for f in findings if f["header"] == "X-Frame-Options")
    assert xf["status"] == "warn"


def test_content_type_options_must_be_nosniff():
    h = good_headers()
    h["X-Content-Type-Options"] = "sniff"
    findings = run_checks(h)
    ct = next(f for f in findings if f["header"] == "X-Content-Type-Options")
    assert ct["status"] == "warn"


def test_missing_referrer_and_permissions_warn():
    h = good_headers()
    del h["Referrer-Policy"]
    del h["Permissions-Policy"]
    findings = run_checks(h)
    assert grade(findings) == "B"  # two warns, no fails


def test_grade_boundaries():
    assert grade([{"status": "pass"}] * 6) == "A"
    assert grade([{"status": "warn"}] * 2) == "B"
    assert grade([{"status": "fail"}]) == "C"
    assert grade([{"status": "fail"}] * 2) == "D"
    assert grade([{"status": "fail"}] * 3) == "F"


def test_finding_shape():
    for f in run_checks(good_headers()):
        assert set(f.keys()) == {"header", "status", "detail"}
        assert f["status"] in ("pass", "warn", "fail")
