"""Presentation constants: severity/framework palettes, orderings, and CSS.

Pure presentation data shared by the report generators, so a finding looks
the same wherever it appears. The rendering *functions* stay in
:mod:`tf_eu_guard.reporting._html_common` and the per-report generators;
this module holds only the values they render with.

Two severity palettes exist on purpose: :data:`SEVERITY_COLOR` holds the
hex colors used by the self-contained HTML reports, while
:data:`SEVERITY_COLOR_TERMINAL` holds Rich color names for the terminal
``dev`` report — the same severity maps to a different palette per medium.
"""

from tf_eu_guard.models import Framework, Severity

# Severity display order (most to least severe). INFO is included for
# completeness even though the registry currently only emits CRITICAL/HIGH/MEDIUM.
SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

# Accessible, print-friendly palette (works on white backgrounds and in PDF export)
# for the HTML reports.
SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "#c0392b",
    Severity.HIGH: "#e67e22",
    Severity.MEDIUM: "#d4ac0d",
    Severity.LOW: "#2980b9",
    Severity.INFO: "#7f8c8d",
}

# Rich color names for the terminal dev report — same severities, different
# medium (terminal color names instead of HTML hex values).
SEVERITY_COLOR_TERMINAL: dict[Severity, str] = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
}

# Framework display order and the mapping-doc each framework links to
# (auditor report).
FRAMEWORK_ORDER: list[Framework] = [Framework.NIS2, Framework.GDPR]
FRAMEWORK_DOC: dict[Framework, str] = {
    Framework.NIS2: "docs/nis2-mapping.md",
    Framework.GDPR: "docs/gdpr-mapping.md",
}

# Per-report embedded stylesheets. Each is layout-specific (the security
# report groups by severity, the auditor report by article, the dev HTML
# report by file) — deliberately NOT merged into one base stylesheet.
SECURITY_CSS = """
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    max-width: 1100px; margin: 40px auto; padding: 0 20px;
    color: #1a1a1a; background: #fafafa; line-height: 1.5;
  }
  header { border-bottom: 3px solid #2c3e50; padding-bottom: 16px; margin-bottom: 28px; }
  header h1 { margin: 0 0 6px; font-size: 1.7rem; }
  header .meta { color: #555; font-size: 0.9rem; }
  header .meta span { margin-right: 18px; white-space: nowrap; }
  h2 { font-size: 1.25rem; margin: 32px 0 12px; }

  .summary { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 8px; }
  .stat {
    flex: 1 1 120px; background: #fff; border: 1px solid #e2e2e2; border-radius: 8px;
    padding: 14px 16px; box-shadow: 0 1px 2px rgba(0,0,0,.04);
  }
  .stat .num { font-size: 1.7rem; font-weight: 700; line-height: 1; }
  .stat .label { font-size: 0.78rem; color: #666; text-transform: uppercase; letter-spacing: .04em; }

  .chart { background: #fff; border: 1px solid #e2e2e2; border-radius: 8px; padding: 18px 20px; }
  .chart .row { display: flex; align-items: center; gap: 12px; margin: 8px 0; }
  .chart .rlabel { flex: 0 0 90px; font-size: 0.85rem; font-weight: 600; }
  .chart .track { flex: 1; background: #eee; border-radius: 4px; overflow: hidden; }
  .chart .bar { height: 20px; border-radius: 4px 0 0 4px; min-width: 2px; }
  .chart .rcount { flex: 0 0 40px; text-align: right; font-variant-numeric: tabular-nums; }
  .unmapped { color: #555; font-size: 0.9rem; margin: 10px 0 0; }

  .finding {
    background: #fff; border: 1px solid #e2e2e2; border-left-width: 5px;
    border-radius: 6px; padding: 14px 18px; margin: 12px 0;
  }
  .finding-head { display: flex; align-items: baseline; flex-wrap: wrap; gap: 8px; }
  .finding-head .cid { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-weight: 700; }
  .finding-head .cname { color: #333; }
  .badge {
    display: inline-block; color: #fff; font-size: 0.7rem; font-weight: 700;
    padding: 2px 8px; border-radius: 10px; text-transform: uppercase; letter-spacing: .03em;
  }
  dl.meta { display: grid; grid-template-columns: max-content 1fr; gap: 2px 14px; margin: 10px 0; font-size: 0.9rem; }
  dl.meta dt { color: #777; font-weight: 600; }
  dl.meta dd { margin: 0; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .art {
    display: inline-block; background: #eef2f7; border: 1px solid #d6e0ea; color: #2c3e50;
    font-size: 0.78rem; padding: 1px 7px; border-radius: 4px; margin: 1px 4px 1px 0;
  }
  .risk { margin: 8px 0; }
  .remediation h4 { margin: 10px 0 4px; font-size: 0.85rem; text-transform: uppercase; color: #777; letter-spacing: .04em; }
  .remediation pre {
    background: #f5f5f5; border: 1px solid #e2e2e2; border-radius: 6px;
    padding: 10px 12px; overflow-x: auto; margin: 0; font-size: 0.85rem;
  }
  .doc { display: inline-block; margin-top: 10px; font-size: 0.85rem; color: #2980b9; text-decoration: none; }
  .doc:hover { text-decoration: underline; }
  .empty { background: #eafaf1; border: 1px solid #abebc6; color: #1e6b43; padding: 24px; border-radius: 8px; text-align: center; }
  footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e2e2e2; color: #888; font-size: 0.82rem; }
  @media (prefers-color-scheme: dark) {
    body { color: #e6e6e6; background: #16181c; }
    .stat, .chart, .finding { background: #21242b; border-color: #33373f; }
    .chart .track { background: #33373f; }
    dl.meta dt, .stat .label, header .meta { color: #aab; }
    .remediation pre { background: #1b1d22; border-color: #33373f; }
    .art { background: #2b3140; border-color: #3a4256; color: #cdd7e5; }
  }
"""

AUDITOR_CSS = """
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    font-family: Georgia, "Times New Roman", serif;
    max-width: 980px; margin: 40px auto; padding: 0 24px;
    color: #1a1a1a; background: #fff; line-height: 1.6;
  }
  header { border-bottom: 3px double #2c3e50; padding-bottom: 18px; margin-bottom: 24px; }
  header h1 { margin: 0 0 6px; font-size: 1.8rem; }
  header .meta { color: #555; font-size: 0.9rem; font-family: system-ui, sans-serif; }
  header .meta span { margin-right: 18px; }
  h2 { font-size: 1.35rem; border-bottom: 1px solid #ccc; padding-bottom: 4px; margin-top: 40px; }
  h3 { font-size: 1.1rem; margin: 28px 0 6px; }

  .scope {
    background: #fff8e1; border: 1px solid #f0d98c; border-radius: 6px;
    padding: 12px 16px; font-family: system-ui, sans-serif; font-size: 0.9rem; margin: 18px 0;
  }
  table { border-collapse: collapse; width: 100%; font-family: system-ui, sans-serif; font-size: 0.92rem; margin: 12px 0; }
  th, td { border: 1px solid #ddd; padding: 8px 10px; text-align: left; vertical-align: top; }
  th { background: #f2f4f7; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }

  nav.toc { font-family: system-ui, sans-serif; font-size: 0.92rem; background: #f7f8fa; border: 1px solid #e2e2e2; border-radius: 6px; padding: 14px 20px; }
  nav.toc ul { margin: 6px 0; padding-left: 20px; }
  nav.toc a { color: #2c3e50; text-decoration: none; }
  nav.toc a:hover { text-decoration: underline; }

  .article { margin-bottom: 8px; }
  .article .title-note { color: #555; font-weight: normal; }
  .status {
    display: inline-block; font-family: system-ui, sans-serif; font-size: 0.8rem; font-weight: 700;
    background: #fdecea; color: #b03a2e; border: 1px solid #f5b7b1; border-radius: 12px; padding: 2px 10px;
  }
  .badge {
    display: inline-block; color: #fff; font-size: 0.7rem; font-weight: 700; font-family: system-ui, sans-serif;
    padding: 1px 7px; border-radius: 10px; text-transform: uppercase;
  }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.88rem; }
  .doclink { font-family: system-ui, sans-serif; font-size: 0.85rem; }
  .backtop { font-family: system-ui, sans-serif; font-size: 0.78rem; margin-left: 10px; }
  .backtop a { color: #888; text-decoration: none; }
  footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid #ccc; color: #777; font-size: 0.82rem; font-family: system-ui, sans-serif; }
  .empty { background: #eafaf1; border: 1px solid #abebc6; color: #1e6b43; padding: 24px; border-radius: 8px; text-align: center; font-family: system-ui, sans-serif; }
  @media print { body { max-width: none; margin: 0; } nav.toc { page-break-after: always; } }
"""

DEV_HTML_CSS = """
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    max-width: 1000px; margin: 40px auto; padding: 0 20px;
    color: #1a1a1a; background: #fafafa; line-height: 1.5;
  }
  header { border-bottom: 3px solid #2c3e50; padding-bottom: 16px; margin-bottom: 24px; }
  header h1 { margin: 0 0 6px; font-size: 1.7rem; }
  header .meta { color: #555; font-size: 0.9rem; }
  header .meta span { margin-right: 18px; white-space: nowrap; }

  .chips { display: flex; flex-wrap: wrap; gap: 8px; margin: 4px 0 8px; }
  .chip {
    background: #fff; border: 1px solid #e2e2e2; border-radius: 999px;
    padding: 4px 12px; font-size: 0.85rem; box-shadow: 0 1px 2px rgba(0,0,0,.04);
  }
  .chip b { font-variant-numeric: tabular-nums; }

  .file-group { margin: 26px 0 8px; }
  h2.file {
    font-size: 1.05rem; margin: 0 0 8px; padding: 8px 12px;
    background: #eef2f7; border: 1px solid #d6e0ea; border-radius: 6px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all;
  }
  h2.file .fcount { float: right; color: #667; font-size: 0.82rem; font-weight: 400; }

  .finding {
    background: #fff; border: 1px solid #e2e2e2; border-left-width: 5px;
    border-radius: 6px; padding: 14px 18px; margin: 12px 0;
  }
  .finding-head { display: flex; align-items: baseline; flex-wrap: wrap; gap: 8px; }
  .finding-head .cid { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-weight: 700; }
  .finding-head .cname { color: #333; }
  .badge {
    display: inline-block; color: #fff; font-size: 0.7rem; font-weight: 700;
    padding: 2px 8px; border-radius: 10px; text-transform: uppercase; letter-spacing: .03em;
  }
  dl.meta { display: grid; grid-template-columns: max-content 1fr; gap: 2px 14px; margin: 10px 0; font-size: 0.9rem; }
  dl.meta dt { color: #777; font-weight: 600; }
  dl.meta dd { margin: 0; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .art {
    display: inline-block; background: #eef2f7; border: 1px solid #d6e0ea; color: #2c3e50;
    font-size: 0.78rem; padding: 1px 7px; border-radius: 4px; margin: 1px 4px 1px 0;
  }
  .risk { margin: 8px 0; }
  .remediation h4 { margin: 10px 0 4px; font-size: 0.85rem; text-transform: uppercase; color: #777; letter-spacing: .04em; }
  .remediation pre {
    background: #f5f5f5; border: 1px solid #e2e2e2; border-radius: 6px;
    padding: 10px 12px; overflow-x: auto; margin: 0; font-size: 0.85rem;
  }
  .doc { display: inline-block; margin-top: 10px; font-size: 0.85rem; color: #2980b9; text-decoration: none; }
  .doc:hover { text-decoration: underline; }
  .empty { background: #eafaf1; border: 1px solid #abebc6; color: #1e6b43; padding: 24px; border-radius: 8px; text-align: center; }
  .unmapped { color: #555; font-size: 0.9rem; margin: 10px 0 0; }
  footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e2e2e2; color: #888; font-size: 0.82rem; }
  @media (prefers-color-scheme: dark) {
    body { color: #e6e6e6; background: #16181c; }
    .chip, .finding { background: #21242b; border-color: #33373f; }
    h2.file { background: #2b3140; border-color: #3a4256; }
    dl.meta dt, header .meta { color: #aab; }
    .remediation pre { background: #1b1d22; border-color: #33373f; }
    .art { background: #2b3140; border-color: #3a4256; color: #cdd7e5; }
  }
"""
