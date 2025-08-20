📧 Phish Analyzer (CLI)

A simple command-line tool to analyze phishing emails (.eml files).
It extracts important details like headers, URLs, attachments, IOCs and generates reports (CSV, JSON, HTML).

🚀 Features

Parse .eml emails (headers, body, attachments).

Extract IOCs (URLs, IPs, file hashes).

Save results in CSV, JSON, and HTML reports.

(Optional) Check IOCs with VirusTotal & urlscan.io.

Export IOC CSV for SIEM ingestion (Splunk/ELK).

⚡ Quick Start
# 1) Setup
python -m venv .venv
.venv\Scripts\activate   # Windows
pip install -r requirements.txt

# 2) Run tool
python src/phish_analyzer.py --eml samples/sample_phish.eml --outdir output

📂 Outputs

output/iocs.csv → All extracted indicators

output/report.json → Detailed JSON report

output/report.html → Human-readable HTML report

output/attachments/ → Saved attachments

🛡️ Use Cases

Analyze suspicious emails safely

Generate quick reports for investigations

Export IOCs to SIEM (Splunk/ELK)

⚠️ Note

This tool does not fetch emails from inbox, only works with .eml files.

VirusTotal / urlscan lookups are optional.

For educational and research purposes only.
