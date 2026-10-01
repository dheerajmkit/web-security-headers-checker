"""CLI entry point: audit a single URL's security headers and print a grade."""

import sys

from checker.fetcher import fetch
from checker.checks import run_checks, grade


def audit(url):
    fetched = fetch(url)
    if fetched.get("error"):
        return {"url": url, "error": fetched["error"], "findings": [],
                "grade": "F"}
    findings = run_checks(fetched["headers"])
    return {"url": url, "status_code": fetched["status_code"],
            "findings": findings, "grade": grade(findings)}


def main(argv):
    if len(argv) != 2:
        print("usage: python3 run.py <url>")
        sys.exit(2)
    result = audit(argv[1])
    if result.get("error"):
        print("ERROR:", result["error"])
        sys.exit(1)
    print("URL:    %s" % result["url"])
    print("Grade:  %s" % result["grade"])
    for f in result["findings"]:
        print("[%s] %s: %s" % (f["status"].upper(), f["header"], f["detail"]))


if __name__ == "__main__":
    main(sys.argv)
