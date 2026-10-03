"""Render audit results as JSON or Markdown."""

import json


def to_json(result):
    """Return a pretty JSON string for one audit result."""
    return json.dumps(result, indent=2)


def to_markdown(result):
    """Return a Markdown report with a grade summary table."""
    lines = ["# Security Headers Report", ""]
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append("| URL | %s |" % result.get("url", "-"))
    lines.append("| Final URL | %s |" % result.get("final_url", "-"))
    lines.append("| Status code | %s |" % result.get("status_code", "-"))
    lines.append("| Grade | **%s** |" % result.get("grade", "-"))
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    lines.append("| Check | Status | Detail |")
    lines.append("|---|---|---|")
    for f in result.get("findings", []):
        label = f.get("header") or f.get("cookie")
        lines.append("| %s | %s | %s |" % (label, f["status"].upper(),
                                          f["detail"]))
    return "\n".join(lines) + "\n"
