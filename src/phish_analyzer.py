#!/usr/bin/env python3
import argparse
import os
import re
import csv
import json
import hashlib
import base64
import email
import pathlib
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from urlextract import URLExtract
import requests
import yaml
from datetime import datetime
from rich import print

SAFE_URL_OBFUSCATIONS = [
    ("hxxp://", "http://"),
    ("hxxps://", "https://"),
    ("[.]", "."),
    ("(dot)", "."),
]

def deobfuscate_url(u: str) -> str:
    s = u
    for old, new in SAFE_URL_OBFUSCATIONS:
        s = s.replace(old, new)
    return s

def load_config(cfg_path: str):
    if not os.path.exists(cfg_path):
        return {}
    with open(cfg_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def vt_lookup_filehash(vt_api_key: str, file_hash: str):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": vt_api_key}
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "link": f"https://www.virustotal.com/gui/file/{file_hash}"
            }
        else:
            return {"error": f"VT HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def urlscan_submit(urlscan_api_key: str, url: str):
    submit_url = "https://urlscan.io/api/v1/scan/"
    headers = {
        "API-Key": urlscan_api_key,
        "Content-Type": "application/json"
    }
    payload = {"url": url, "visibility": "private"}
    try:
        r = requests.post(submit_url, headers=headers, json=payload, timeout=20)
        if r.status_code in (200, 201):
            data = r.json()
            return {
                "scan_id": data.get("uuid"),
                "result": data.get("result")
            }
        return {"error": f"urlscan HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"error": str(e)}

def parse_eml(path: str):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg

def extract_headers(msg):
    headers = {}
    for k in ["From", "To", "Subject", "Date", "Message-ID", "Return-Path", "Received", "DKIM-Signature", "Authentication-Results"]:
        v = msg.get_all(k)
        if not v:
            continue
        headers[k] = v if len(v) > 1 else v[0]
    return headers

def get_body_parts(msg):
    text, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                try:
                    text += part.get_content()
                except Exception:
                    pass
            elif ctype == "text/html":
                try:
                    html += part.get_content()
                except Exception:
                    pass
    else:
        ctype = msg.get_content_type()
        if ctype == "text/plain":
            text = msg.get_content()
        elif ctype == "text/html":
            html = msg.get_content()
    return text, html

def extract_urls(text: str, html: str):
    extractor = URLExtract()
    found = set(extractor.find_urls(text or ""))
    if html:
        soup = BeautifulSoup(html, "lxml")
        for a in soup.find_all("a", href=True):
            found.add(a["href"])
        # also text content
        found.update(extractor.find_urls(soup.get_text(" ", strip=True)))
    # deobfuscate common tricks
    deobf = set()
    for u in list(found):
        deobf.add(deobfuscate_url(u))
    # basic sanity
    clean = sorted({u for u in deobf if len(u) <= 2048})
    return clean

def save_attachments(msg, outdir):
    att_dir = os.path.join(outdir, "attachments")
    os.makedirs(att_dir, exist_ok=True)
    saved = []
    for part in msg.iter_attachments():
        filename = part.get_filename() or "attachment.bin"
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        # prevent path traversal
        safe_name = os.path.basename(filename)
        dest = os.path.join(att_dir, safe_name)
        with open(dest, "wb") as f:
            f.write(payload)
        saved.append(dest)
    return saved

def write_csv_iocs(rows, out_csv):
    fields = ["type", "value", "source", "note"]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)

def write_html_report(data, out_html):
    from html import escape
    html = ["<html><head><meta charset='utf-8'><title>Phish Analyzer Report</title></head><body>"]
    html.append("<h1>Phish Analyzer Report</h1>")
    html.append(f"<p>Generated: {escape(datetime.utcnow().isoformat())}Z</p>")

    html.append("<h2>Headers</h2><pre>")
    html.append(escape(json.dumps(data['headers'], indent=2)))
    html.append("</pre>")

    html.append("<h2>URLs</h2><ul>")
    for u in data.get("urls", []):
        safe_u = escape(u)
        if u.startswith("http://") or u.startswith("https://"):
            html.append(f"<li><a href='{safe_u}' target='_blank' rel='noopener noreferrer'>{safe_u}</a></li>")
        else:
            html.append(f"<li>{safe_u}</li>")
    html.append("</ul>")

    if data.get("attachments"):
        html.append("<h2>Attachments</h2><ul>")
        for a in data["attachments"]:
            html.append(f"<li>{escape(a)}</li>").strip()
        html.append("</ul>")

    if data.get("vt_results"):
        html.append("<h2>VirusTotal Results</h2><pre>")
        html.append(escape(json.dumps(data["vt_results"], indent=2)))
        html.append("</pre>")

    if data.get("urlscan_results"):
        html.append("<h2>urlscan.io Results</h2><pre>")
        html.append(escape(json.dumps(data["urlscan_results"], indent=2)))
        html.append("</pre>")

    html.append("</body></html>")
    with open(out_html, "w", encoding="utf-8") as f:
        f.write("\n".join(html))

def stix_bundle(iocs):
    # very light STIX example with indicators
    bundle = {
        "type": "bundle",
        "id": f"bundle--{hashlib.md5(str(datetime.utcnow()).encode()).hexdigest()}",
        "objects": []
    }
    for idx, ioc in enumerate(iocs, 1):
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{hashlib.md5((ioc['type']+ioc['value']).encode()).hexdigest()}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"Phish IOC: {ioc['type']}",
            "pattern_type": "stix",
        }
        if ioc["type"] == "url":
            indicator["pattern"] = f"[url:value = '{ioc['value']}']"
        elif ioc["type"] == "domain":
            indicator["pattern"] = f"[domain-name:value = '{ioc['value']}']"
        elif ioc["type"] == "ip":
            indicator["pattern"] = f"[ipv4-addr:value = '{ioc['value']}']"
        elif ioc["type"] == "hash":
            indicator["pattern"] = f"[file:hashes.'SHA-256' = '{ioc['value']}']"
        else:
            indicator["pattern"] = f"[x-opencti-custom:value = '{ioc['value']}']"
        bundle["objects"].append(indicator)
    return bundle

def main():
    ap = argparse.ArgumentParser(description="Phishing email analyzer")
    ap.add_argument("--eml", required=True, help="Path to .eml file")
    ap.add_argument("--outdir", required=True, help="Output directory")
    ap.add_argument("--cfg", default="config/config.yaml", help="YAML config with API keys")
    ap.add_argument("--vt", action="store_true", help="Enable VirusTotal lookups for file hashes")
    ap.add_argument("--urlscan", action="store_true", help="Enable urlscan.io submissions for URLs")
    ap.add_argument("--stix", action="store_true", help="Emit STIX 2.1 bundle for IOCs")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    cfg = load_config(args.cfg)

    msg = parse_eml(args.eml)
    headers = extract_headers(msg)
    text, html = get_body_parts(msg)
    urls = extract_urls(text, html)

    # Save attachments & hash
    attachments = save_attachments(msg, args.outdir)
    hash_rows = []
    for a in attachments:
        h = sha256_file(a)
        hash_rows.append({"path": a, "sha256": h})

    # Build IOC list
    iocs = []
    for u in urls:
        iocs.append({"type": "url", "value": u, "source": "email-body", "note": ""})
    for h in hash_rows:
        iocs.append({"type": "hash", "value": h["sha256"], "source": "attachment", "note": os.path.basename(h["path"])})

    # Optional VirusTotal
    vt_results = {}
    if args.vt and cfg.get("vt_api_key"):
        for h in hash_rows:
            vt_results[h["sha256"]] = vt_lookup_filehash(cfg["vt_api_key"], h["sha256"])

    # Optional urlscan
    urlscan_results = {}
    if args.urlscan and cfg.get("urlscan_api_key"):
        for u in urls[:5]:  # limit a bit
            urlscan_results[u] = urlscan_submit(cfg["urlscan_api_key"], u)

    # Write CSV
    out_csv = os.path.join(args.outdir, "iocs.csv")
    write_csv_iocs(iocs, out_csv)

    # JSON report
    report = {
        "headers": headers,
        "urls": urls,
        "attachments": [x["path"] if isinstance(x, dict) else x for x in attachments],
        "hashes": hash_rows,
        "vt_results": vt_results,
        "urlscan_results": urlscan_results,
        "generated_utc": datetime.utcnow().isoformat()+"Z"
    }
    out_json = os.path.join(args.outdir, "report.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # HTML report
    out_html = os.path.join(args.outdir, "report.html")
    write_html_report(report, out_html)

    # Optional STIX
    if args.stix:
        bundle = stix_bundle(iocs)
        with open(os.path.join(args.outdir, "stix_bundle.json"), "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)

    print(f"[bold green]Analysis complete![/bold green]")
    print(f"IOCs CSV: {out_csv}")
    print(f"JSON report: {out_json}")
    print(f"HTML report: {out_html}")
    if attachments:
        print(f"Attachments saved under: {os.path.join(args.outdir, 'attachments')}")
    if vt_results:
        print("VirusTotal results included.")
    if urlscan_results:
        print("urlscan.io results included.")
    if args.stix:
        print("STIX bundle emitted.")

if __name__ == "__main__":
    main()
