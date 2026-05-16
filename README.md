# RiskLens

A simple URL investigation tool built in Python.  
Not an AI. Not a platform. Just a clean, rule-based tool that tells you what it found and why.This is a portfolio project built while learning Python properly. It's not production software. But it was designed with real Trust & Safety reasoning in mind and every decision in it can be explained.

# What it does:

You give it a URL. It checks it against a set of signals like suspicious TLDs, brand impersonation patterns, missing HTTPS, obfuscated structure also it returns a verdict with a breakdown of exactly what triggered it.

Every analysis gets logged to JSON and generates an HTML report you can actually read. Each URL also gets a SHA-256 fingerprint, so if the same URL appears again, you know you've seen it before.

# Why I built it this way:

I wanted something that felt closer to how Trust & Safety and Security Operations teams actually think.

The risk scoring is rule-based and intentional. Every signal has a severity. The verdict follows from the signals. No magic numbers. No fake ML.


# Signal detection logic:

| Signal | Severity |

| Raw IP used as domain | High |
| Suspicious TLD (.ru, .tk, .xyz...) | High |
| Brand impersonation pattern | High |
| URL obfuscation detected | High |
| No HTTPS | Medium |
| Excessive subdomains | Medium |
| Suspicious keywords in URL | Medium |
| URL abnormally long | Low |

Verdict logic: any `high` signal → `HIGH RISK` · two or more `medium` → `MEDIUM RISK` · only `low` → `LOW RISK` · nothing → `SAFE`

## SHA-256 fingerprinting

Every URL gets a SHA-256 hash. The same URL always produces the same hash which is useful for tracking whether a suspicious URL has been seen before without storing it in plaintext. Full hash in the JSON log, truncated version in the terminal and HTML report.

## Running it

```bash
git clone https://github.com/brunoneresruiz-glitch/risklens.git
cd risklens
python -m venv venv
source venv/Scripts/activate
pip install -r requirements.txt
python main.py https://suspicious-url.com
```

Python 3, argparse, rich, hashlib, urllib.parse, HTML/CSS



Built by [Bruno Neres Ruiz](https://linkedin.com/in/brunoneresruiz)