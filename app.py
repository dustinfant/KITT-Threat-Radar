from flask import Flask, render_template, jsonify, send_file
import json
import os
import csv
import io
import uuid
import datetime
from urllib.parse import urlparse
from apscheduler.schedulers.background import BackgroundScheduler
import feedparser
import yaml
import requests
from bs4 import BeautifulSoup
import tldextract
import re

# -------------------------
# CONFIG
# -------------------------
app = Flask(__name__)

DATA_FILE = "data/feed_normalized.json"
SOURCES_FILE = "sources.yaml"

IOC_FIELDS = [
    "ip",
    "domain",
    "email",
    "md5",
    "sha1",
    "sha256",
    "file_path",
    "service",
    "cve"
]

# -------------------------
# HELPERS
# -------------------------
def load_feed():
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def group_by_category(feed):
    grouped = {}
    sources = set()
    for entry in feed:
        grouped.setdefault(entry.get("category", "Unknown"), []).append(entry)
        sources.add(entry.get("source", "Unknown"))
    return grouped, sorted(sources)

def has_real_iocs(entry):
    return any(entry.get("iocs", {}).get(f) for f in IOC_FIELDS)

def get_article_domain(url):
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""

# -------------------------
# IOC EXTRACTION
# -------------------------
IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
MD5_REGEX = r"\b[a-fA-F0-9]{32}\b"
SHA1_REGEX = r"\b[a-fA-F0-9]{40}\b"
SHA256_REGEX = r"\b[a-fA-F0-9]{64}\b"
EMAIL_REGEX = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}\b"
CVE_REGEX = r"\bCVE-\d{4}-\d{4,7}\b"
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"

def extract_iocs_from_text(text):
    iocs = {
        "ip": re.findall(IP_REGEX, text),
        "domain": list(set([tldextract.extract(d).fqdn for d in re.findall(DOMAIN_REGEX, text) if d])),
        "email": re.findall(EMAIL_REGEX, text),
        "md5": re.findall(MD5_REGEX, text),
        "sha1": re.findall(SHA1_REGEX, text),
        "sha256": re.findall(SHA256_REGEX, text),
        "cve": re.findall(CVE_REGEX, text),
        "file_path": [],
        "service": []
    }
    return iocs

def extract_iocs_from_url(url):
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        text = soup.get_text(separator="\n")
        return extract_iocs_from_text(text)
    except Exception:
        return {k: [] for k in IOC_FIELDS}

# -------------------------
# SOURCES / RSS FETCHER
# -------------------------
def load_sources():
    if not os.path.exists(SOURCES_FILE):
        return []
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        if isinstance(data, dict):
            return data.get("feeds", [])
        elif isinstance(data, list):
            return data
        else:
            return []

def fetch_rss(feed_info):
    feed = feedparser.parse(feed_info["url"])
    normalized = []

    for entry in feed.entries:
        normalized.append({
            "title": entry.get("title", ""),
            "link": entry.get("link", ""),
            "published": entry.get("published", ""),
            "source": feed_info.get("name", "Unknown"),
            "category": feed_info.get("category", "Uncategorized"),
            "iocs": extract_iocs_from_url(entry.get("link", ""))
        })
    return normalized

def update_feed():
    existing = []
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            existing = json.load(f)

    combined = existing.copy()
    sources = load_sources()
    for feed_info in sources:
        combined += fetch_rss(feed_info)

    # Deduplicate
    seen_links = set()
    deduped = []
    for e in combined:
        if e["link"] not in seen_links:
            deduped.append(e)
            seen_links.add(e["link"])

    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(deduped, f, indent=2)

# -------------------------
# ROUTES
# -------------------------
@app.route("/")
def index():
    feed = load_feed()
    grouped, sources = group_by_category(feed)
    fetching = len(feed) == 0  # Banner if feed empty
    return render_template("index.html", grouped=grouped, sources=sources, fetching=fetching, total=len(feed))

@app.route("/api/feed")
def api_feed():
    return jsonify(load_feed())

@app.route("/api/feed/count")
def api_feed_count():
    # Lightweight check the dashboard polls to see if new articles arrived
    return jsonify({"count": len(load_feed())})

# -------------------------
# CSV EXPORT
# -------------------------
@app.route("/export/csv")
def export_csv():
    feed = load_feed()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["title", "source", "link"] + IOC_FIELDS)
    writer.writeheader()

    for entry in feed:
        if not has_real_iocs(entry):
            continue

        article_domain = get_article_domain(entry.get("link", ""))
        row = {
            "title": entry.get("title", ""),
            "source": entry.get("source", ""),
            "link": entry.get("link", "")
        }
        for field in IOC_FIELDS:
            values = entry.get("iocs", {}).get(field, [])
            if field == "domain":
                values = [d for d in values if article_domain not in d.lower()]
            row[field] = "; ".join(values)
        writer.writerow(row)

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="ioc_export.csv"
    )

# -------------------------
# STIX EXPORT
# -------------------------
@app.route("/export/stix")
def export_stix():
    feed = load_feed()
    now = datetime.datetime.utcnow().isoformat() + "Z"
    objects = []

    for entry in feed:
        if not has_real_iocs(entry):
            continue

        article_domain = get_article_domain(entry.get("link", ""))
        for ioc_type, values in entry.get("iocs", {}).items():
            if ioc_type not in IOC_FIELDS:
                continue
            for value in values:
                if ioc_type == "domain" and article_domain in value.lower():
                    continue
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": now,
                    "modified": now,
                    "name": f"{ioc_type.upper()} Indicator",
                    "indicator_types": ["malicious-activity"],
                    "pattern": f"[{ioc_type}:value = '{value}']",
                    "pattern_type": "stix",
                    "valid_from": now
                })

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects
    }

    return send_file(
        io.BytesIO(json.dumps(bundle, indent=2).encode("utf-8")),
        mimetype="application/json",
        as_attachment=True,
        download_name="ioc_export.stix.json"
    )

# -------------------------
# SCHEDULER (non-blocking)
# -------------------------
scheduler = BackgroundScheduler()
scheduler.add_job(update_feed, 'interval', hours=1)  # Hourly updates
scheduler.add_job(update_feed, 'date', run_date=datetime.datetime.now())  # First run in background
scheduler.start()

# -------------------------
# START APP
# -------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5052, debug=False)
