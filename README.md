📧 Phish Analyzer (CLI)

A lightweight phishing email analysis CLI tool for SOC Analysts, Threat Hunters, and Security Enthusiasts.
It parses .eml files, extracts IOCs, and generates structured reports — ready for SIEM ingestion (Splunk/ELK) or Threat Intel sharing (STIX).

🚀 Features

📩 Email Parsing: Extracts headers, subject, sender, message-id, SPF/DKIM/DMARC results

🌐 IOC Extraction: Detects URLs, domains, IPs, and file hashes

📂 Attachment Handling: Saves attachments and computes SHA256 hashes

🔍 Threat Intel Integration (optional):

VirusTotal
 lookups

urlscan.io
 submissions

📊 Report Generation:

CSV (for SIEMs)

JSON

HTML (human-readable)

STIX 2.1 (threat intel sharing)

⚡ Quick Start
# 1) Setup virtual environment
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate

# 2) Install dependencies
pip install -r requirements.txt

# 3) Configure API keys (optional)
cp config/config.example.yaml config/config.yaml
# Add VirusTotal / urlscan API keys

# 4) Run on sample email
python src/phish_analyzer.py --eml samples/sample_phish.eml --outdir output

📂 Outputs

output/iocs.csv → IOC list (domains, IPs, URLs, hashes)

output/report.json → JSON report

output/report.html → Minimal HTML report

output/attachments/ → Saved + hashed attachments

output/stix_bundle.json (if --stix enabled)

🔧 Command Options
python src/phish_analyzer.py --eml <path.eml> --outdir <dir> [--vt] [--urlscan] [--stix]


--vt → Enables VirusTotal lookups (needs API key)

--urlscan → Submits URLs to urlscan.io (needs API key)

--stix → Exports STIX 2.1 bundle

📊 SIEM Ingestion

You can directly ingest iocs.csv into your SIEM:

Splunk → Suggested sourcetype: phish:ioc

ELK Stack → Suggested index: phish-iocs

🏗️ Architecture (High-Level)
.eml file
   │
   ├── Parse headers & body
   │       ├── Extract metadata (From, Subject, Received…)
   │       └── Deobfuscate + extract URLs
   │
   ├── Save & hash attachments
   │
   ├── Optional lookups:
   │       ├── VirusTotal API
   │       └── urlscan.io API
   │
   └── Generate Reports (CSV, JSON, HTML, STIX)

📘 Example Usage
python src/phish_analyzer.py --eml suspicious_mail.eml --outdir results --vt --urlscan


Output:

results/report.html → Full summary of email

results/iocs.csv → IOC list for Splunk/ELK

results/attachments/ → Extracted attachments

⚠️ Notes

This tool does not connect to mailboxes; you must provide .eml files.

Works fully offline (except optional API lookups).

Built for educational and SOC training purposes.
