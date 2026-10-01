"""Fetch response headers, following redirects and noting HTTPS upgrades."""

import requests

TIMEOUT = 10


def fetch(url):
    """Follow redirects; return headers plus final URL and upgrade info."""
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException as exc:
        return {"url": url, "error": str(exc)}
    final_url = resp.url
    upgraded = (url.startswith("http://")
                and final_url.startswith("https://"))
    return {
        "url": url,
        "final_url": final_url,
        "redirects": [r.url for r in resp.history],
        "https_upgrade": upgraded,
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
    }
