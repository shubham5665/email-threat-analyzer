# Phish Analyzer (CLI)

A lightweight, resume-ready phishing analysis tool that:
- Parses `.eml` files (email headers, body, attachments)
- Extracts IOCs (URLs, IPs, hashes) and saves a CSV/JSON report
- (Optional) Looks up indicators against VirusTotal and urlscan.io via API keys
- Produces a minimal HTML report
- Can export IOC CSV for SIEM ingestion (Splunk/ELK)

## Quick Start

```bash
# 1) Create venv and install deps
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2) Copy & edit config
cp config/config.example.yaml config/config.yaml
# Add your VirusTotal and urlscan API keys if you have them

# 3) Run on sample email
python src/phish_analyzer.py --eml samples/sample_phish.eml --outdir output

# 4) View outputs
# - output/iocs.csv
# - output/report.json
# - output/report.html
# - output/attachments/*
```

## Command Options

```bash
python src/phish_analyzer.py --eml <path.eml> --outdir <dir> [--vt] [--urlscan] [--stix]
```

- `--vt` enables VirusTotal lookups (needs `config/config.yaml` with `vt_api_key`).
- `--urlscan` enables urlscan.io submissions (needs `urlscan_api_key`).
- `--stix` emits a minimal STIX 2.1 bundle (`output/stix_bundle.json`) for threat intel sharing.

## What It Extracts

- **Headers**: From, To, Subject, Date, Message-ID, Received path, SPF/DKIM/DMARC (if present)
- **URLs** in body (text + HTML), deobfuscated
- **Attachments**: saved to `output/attachments/` and hashed (SHA256)
- **IOCs**: domains, IPs (if present), URLs, file hashes

## SIEM Ingestion

Use `output/iocs.csv` to ingest into Splunk/ELK.
- Splunk sourcetype idea: `phish:ioc`
- ELK index idea: `phish-iocs`

## Notes

- This tool does NOT fetch from your mailbox; it analyzes `.eml` files you provide.
- VT/urlscan calls are optional. Without keys, the tool still runs and generates local results.
- Internet access is required only for VT/urlscan lookups.

## Educational Purpose

Use responsibly. Analyze only emails you are authorized to handle.
