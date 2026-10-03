# Usage Guide

## Single URL

```bash
python3 run.py https://example.com
```

The tool follows redirects and notes the final URL. If an `http://` URL
redirects to `https://`, that upgrade is flagged in the output.

## Batch mode

Put one URL per line in a file (lines starting with `#` are ignored):

```
# targets.txt
https://example.com
https://shop.example.com
```

```bash
python3 run.py --targets targets.txt
```

## Interpreting grades

Each check returns `pass`, `warn`, or `fail`:

| Grade | Meaning |
|---|---|
| A | All checks pass |
| B | No failures, at most two warnings |
| C | One failure |
| D | Two failures |
| F | Three or more failures, or the URL could not be fetched |

`fail` means a header that blocks a real attack class (e.g. CSP, HSTS,
X-Frame-Options) is missing. `warn` means a best-practice header is missing
or a value is weak — worth fixing, not urgent.

## CI usage

Generate machine-readable reports for a pipeline gate:

```bash
python3 run.py https://example.com --json report.json
python3 run.py https://example.com --markdown report.md
```

Fail the pipeline when the grade is below your bar, e.g. parse
`report.json` and exit non-zero unless `grade` is `A` or `B`.
