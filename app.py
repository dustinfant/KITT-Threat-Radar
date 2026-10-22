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

from ioc_utils import IOC_FIELDS, clean_iocs, extract_iocs_from_html

# -------------------------
# CONFIG
# -------------------------
app = Flask(__name__)

DATA_FILE = "data/feed_normalized.json"
SOURCES_FILE = "sources.yaml"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/121.0 Safari/537.36"
}

# -------------------------
# HELPERS
# -------------------------
_feed_cache = {"mtime": None, "feed": []}

def load_feed():
    """Load the feed and clean every entry's IOCs (also fixes entries stored before the cleanup existed).
    Cached until the data file changes."""
    if not os.path.exists(DATA_FILE):
        return []
    mtime = os.path.getmtime(DATA_FILE)
    if _feed_cache["mtime"] != mtime:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            feed = json.load(f)
        for entry in feed:
            entry["iocs"] = clean_iocs(entry.get("iocs"), entry.get("link", ""))
        _feed_cache.update(mtime=mtime, feed=feed)
    return _feed_cache["feed"]

def group_by_category(feed):
    grouped = {}
    sources = set()
    for entry in feed:
        grouped.setdefault(entry.get("category", "Unknown"), []).append(entry)
        sources.add(entry.get("source", "Unknown"))
    return grouped, sorted(sources)

def has_real_iocs(entry):
    return any(entry.get("iocs", {}).get(f) for f in IOC_FIELDS)

# -------------------------
# IOC EXTRACTION (logic lives in ioc_utils.py)
# -------------------------
def extract_iocs_from_url(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        return extract_iocs_from_html(r.text, url)
    except Exception:
        return {}

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

def fetch_rss(feed_info, known_links=frozenset()):
    feed = feedparser.parse(feed_info["url"])
    normalized = []

    for entry in feed.entries:
        if entry.get("link", "") in known_links:
            continue  # already stored; don't re-download the article every hour
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
    known_links = {e.get("link") for e in existing}
    sources = load_sources()
    for feed_info in sources:
        try:
            combined += fetch_rss(feed_info, known_links)
        except Exception as exc:
            print(f"[!] Failed source {feed_info.get('name')}: {exc}")

    # Deduplicate, and store cleaned IOCs
    seen_links = set()
    deduped = []
    for e in combined:
        if e["link"] not in seen_links:
            e["iocs"] = clean_iocs(e.get("iocs"), e.get("link", ""))
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

        row = {
            "title": entry.get("title", ""),
            "source": entry.get("source", ""),
            "link": entry.get("link", "")
        }
        for field in IOC_FIELDS:
            row[field] = "; ".join(entry.get("iocs", {}).get(field, []))
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

        for ioc_type, values in entry.get("iocs", {}).items():
            if ioc_type not in IOC_FIELDS:
                continue
            for value in values:
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
