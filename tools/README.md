# tools/

Developer tooling for generating demo artifacts. Not part of the installed package.

| Script | Purpose |
|--------|---------|
| `ansi_to_image.py` | Render a captured ANSI terminal session to SVG (via `rich`) and PNG (via Playwright headless Chromium). Usage: `venv/bin/python tools/ansi_to_image.py <capture.ansi> <out.png> [title] [max_lines]` |
| `make_cast.py` | Convert an ANSI capture into an asciinema v2 `.cast` recording with realistic typing/output pacing. Usage: `venv/bin/python tools/make_cast.py <capture.ansi> <out.cast> [command]` |

Typical regeneration flow for the README screenshots and demo cast:

```bash
source venv/bin/activate
FORCE_COLOR=1 COLUMNS=110 tf-eu-guard scan examples/vulnerable-aws/ --output dev > /tmp/v.ansi
python tools/ansi_to_image.py /tmp/v.ansi docs/screenshots/vulnerable-scan.png "tf-eu-guard — vulnerable-aws" 55
python tools/make_cast.py /tmp/v.ansi docs/demo/tf-eu-guard-demo.cast
```

Requires `playwright` + its Chromium build (`pip install playwright && playwright install chromium`).
