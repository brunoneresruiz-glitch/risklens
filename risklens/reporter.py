import os
from datetime import datetime


REPORT_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "report.html")


def generate_report(findings: dict, evaluation: dict) -> str:
    """
    Generates an HTML investigation report and saves it to logs/report.html.
    """
    verdict   = evaluation["verdict"]
    signals   = evaluation["signals"]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    verdict_bg, verdict_fg = _verdict_colours(verdict)
    signals_html           = _build_signals(signals)

    html = _build_html(findings, verdict, verdict_bg, verdict_fg, signals_html, timestamp)

    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(html)

    return REPORT_PATH


def _display_verdict(verdict: str) -> str:
    """Maps internal verdict to display label."""
    labels = {
        "HIGH RISK":"HIGH RISK",
        "MEDIUM RISK":"MEDIUM RISK",
        "LOW RISK":"LOW RISK",
        "SAFE": "SAFE",
    }
    return labels.get(verdict, verdict)


def _verdict_colours(verdict: str):
    colours = {
        "HIGH RISK":   ("#A6452E", "#FAF0E6"),
        "MEDIUM RISK": ("#E0B44B", "#1A1006"),
        "LOW RISK":  ("#49714B", "#FAF0E6"),
        "SAFE":       ("#49714B", "#FAF0E6"),
    }
    return colours.get(verdict, ("#1A1006", "#FAF0E6"))


def _build_signals(signals: list) -> str:
    if not signals:
        return '<p class="clean-msg">No suspicious signals detected.</p>'

    sev_labels = {
        "high":"HIGH",
        "medium":"MED",
        "low":"LOW",
    }

    sev_colours = {
        "high":("#A6452E", "#FAF0E6"),
        "medium":("#E0B44B", "#1A1006"),
        "low": ("#49714B", "#FAF0E6"),
    }

    rows = ""
    for signal in signals:
        sev    = signal["severity"]
        label  = sev_labels.get(sev, sev.upper())
        bg, fg = sev_colours.get(sev, ("#1A1006", "#FAF0E6"))
        rows += f"""
        <div class="signal-row">
            <span class="sev-tag" style="background:{bg}; color:{fg};">{label}</span>
            <span class="signal-text">{signal['description']}</span>
        </div>"""

    return rows


def _build_html(findings, verdict, verdict_bg, verdict_fg, signals_html, timestamp):
    https_label    = "YES" if findings["is_https"] else "NO"
    https_style    = "color:#49714B;" if findings["is_https"] else "color:#A6452E; font-weight:700;"
    display_verdict = _display_verdict(verdict)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RiskLens — Investigation Report</title>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      background: #E5D0B1;
      color: #1A1006;
      font-family: 'IBM Plex Mono', monospace;
      padding: 3rem 2rem;
      min-height: 100vh;
    }}

    .container {{
      max-width: 720px;
      margin: 0 auto;
    }}

    .header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      padding-bottom: 1rem;
      border-bottom: 3px solid #1A1006;
      margin-bottom: 2rem;
    }}

    .logo {{
      font-family: 'IBM Plex Mono', monospace;
      font-size: 1.6rem;
      font-weight: 700;
      color: #1A1006;
      letter-spacing: 0.02em;
    }}

    .header-sub {{
      font-size: 0.72rem;
      color: #6B5744;
      text-transform: uppercase;
      letter-spacing: 0.1em;
    }}

    .box {{
      border: 2px solid #1A1006;
      padding: 1.5rem;
      margin-bottom: 1.2rem;
      background: #EDD9B8;
    }}

    .box-label {{
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.78rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: #6B5744;
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid #1A1006;
    }}

    .info-row {{
      display: grid;
      grid-template-columns: 140px 1fr;
      margin-bottom: 0.6rem;
      font-size: 0.82rem;
      line-height: 1.5;
    }}

    .info-key {{
      color: #6B5744;
      text-transform: uppercase;
      font-size: 0.72rem;
      letter-spacing: 0.06em;
      padding-top: 1px;
    }}

    .info-val {{
      color: #1A1006;
      word-break: break-all;
    }}

    .verdict-box {{
      border: 2px solid #1A1006;
      padding: 1.2rem 1.5rem;
      margin-bottom: 1.2rem;
      background: {verdict_bg};
      display: flex;
      align-items: center;
      gap: 1.5rem;
    }}

    .verdict-label {{
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: {verdict_fg};
      opacity: 0.7;
    }}

    .verdict-value {{
      font-family: 'IBM Plex Mono', monospace;
      font-size: 1.3rem;
      font-weight: 700;
      color: {verdict_fg};
      letter-spacing: 0.05em;
    }}

    .signal-row {{
      display: flex;
      align-items: flex-start;
      gap: 1rem;
      margin-bottom: 0.8rem;
    }}

    .sev-tag {{
      font-size: 0.65rem;
      font-weight: 700;
      letter-spacing: 0.1em;
      padding: 3px 8px;
      flex-shrink: 0;
      border: 1px solid #1A1006;
      font-family: 'IBM Plex Mono', monospace;
    }}

    .signal-text {{
      font-size: 0.82rem;
      color: #1A1006;
      padding-top: 2px;
      line-height: 1.5;
    }}

    .clean-msg {{
      font-size: 0.85rem;
      color: #49714B;
      font-weight: 500;
    }}

    .footer {{
      margin-top: 2rem;
      padding-top: 1rem;
      border-top: 2px solid #1A1006;
      font-size: 0.7rem;
      color: #6B5744;
      display: flex;
      justify-content: space-between;
    }}
  </style>
</head>
<body>
  <div class="container">

    <div class="header">
      <div class="logo">RiskLens</div>
      <div class="header-sub">Investigation Report</div>
    </div>

    <div class="box">
      <div class="box-label">URL Analysis</div>
      <div class="info-row">
        <span class="info-key">URL</span>
        <span class="info-val">{findings['url']}</span>
      </div>
      <div class="info-row">
        <span class="info-key">Hash SHA-256</span>
        <span class="info-val">{findings['url_hash']}</span>
      </div>
      <div class="info-row">
        <span class="info-key">Domain</span>
        <span class="info-val">{findings['domain']}</span>
      </div>
      <div class="info-row">
        <span class="info-key">HTTPS</span>
        <span class="info-val" style="{https_style}">{https_label}</span>
      </div>
      <div class="info-row">
        <span class="info-key">URL Length</span>
        <span class="info-val">{findings['url_length']} chars</span>
      </div>
    </div>

    <div class="verdict-box">
      <div>
        <div class="verdict-label">Verdict</div>
        <div class="verdict-value">{display_verdict}</div>
      </div>
    </div>

    <div class="box">
      <div class="box-label">Signals Detected</div>
      {signals_html}
    </div>

    <div class="footer">
      <span>RiskLens · Rule-based URL Risk Analysis</span>
      <span>{timestamp}</span>
    </div>

  </div>
</body>
</html>"""