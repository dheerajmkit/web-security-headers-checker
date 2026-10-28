"""CLI: audit security headers (single URL or batch file) and print grades."""

import sys

from checker.fetcher import fetch
from checker.checks import run_checks, grade
from checker.cookies import check_cookies
from checker.reporter import to_json, to_markdown


def audit(url):
    fetched = fetch(url)
    if fetched.get("error"):
        return {"url": url, "error": fetched["error"], "findings": [],
                "grade": "F"}
    findings = run_checks(fetched["headers"])
    cookie_findings = check_cookies(fetched["headers"])
    all_findings = findings + cookie_findings
    return {"url": url,
            "final_url": fetched.get("final_url"),
            "https_upgrade": fetched.get("https_upgrade"),
            "status_code": fetched["status_code"],
            "findings": all_findings,
            "grade": grade(all_findings)}


def print_result(result):
    if result.get("error"):
        print("%s -> ERROR: %s" % (result["url"], result["error"]))
        return
    print("URL:    %s" % result["url"])
    if result.get("final_url") and result["final_url"] != result["url"]:
        print("Final:  %s%s" % (result["final_url"],
                                " (HTTP->HTTPS upgrade)" if result.get(
                                    "https_upgrade") else ""))
    print("Grade:  %s" % result["grade"])
    for f in result["findings"]:
        label = f.get("header") or f.get("cookie")
        print("[%s] %s: %s" % (f["status"].upper(), label, f["detail"]))


def main(argv):
    targets = []
    args = argv[1:]
    json_out = markdown_out = None
    rest = []
    it = iter(args)
    for a in it:
        if a == "--json":
            json_out = next(it, None)
        elif a == "--markdown":
            markdown_out = next(it, None)
        else:
            rest.append(a)
    if len(rest) == 1:
        targets = [rest[0]]
    elif len(rest) == 2 and rest[0] == "--targets":
        with open(rest[1]) as fh:
            targets = [line.strip() for line in fh
                       if line.strip() and not line.startswith("#")]
    else:
        print("usage: python3 run.py <url> | --targets <file> "
              "[--json f] [--markdown f]")
        sys.exit(2)
    results = [audit(u) for u in targets]
    for r in results:
        print_result(r)
        print()
    if json_out:
        with open(json_out, "w") as fh:
            fh.write(to_json(results[0] if len(results) == 1 else results))
    if markdown_out:
        with open(markdown_out, "w") as fh:
            fh.write(to_markdown(results[0]))


if __name__ == "__main__":
    main(sys.argv)
