"""Fetch response headers for a URL without following redirects."""

import requests

TIMEOUT = 10


def fetch(url):
    """Return a dict of response headers (and final URL/HTTPS notes in day 2)."""
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException as exc:
        return {"url": url, "error": str(exc)}
    return {
        "url": url,
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
    }
