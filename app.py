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

# Articles older than this are hidden, dropped from storage, and never fetched.
# Override with the MAX_AGE_DAYS environment variable (see docker-compose.yml).
MAX_AGE_DAYS = int(os.environ.get("MAX_AGE_DAYS", "30"))

# -------------------------
# HELPERS
# -------------------------
def parse_published(value):
    """Feed date string -> aware datetime, or None if missing, unparseable or bogus (year 0001/1970)."""
    dt = _parse_date_raw(value)
    return dt if dt and dt.year >= 1990 else None

def _parse_date_raw(value):
    if not value:
        return None
    parsed = feedparser.datetimes._parse_date(value)
    if parsed:
        dt = datetime.datetime(*parsed[:6], tzinfo=datetime.timezone.utc)
    else:
        dt = None
        for fmt in ("%b %d, %Y %H:%M:%S%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):  # e.g. CrowdStrike's format
            try:
                dt = datetime.datetime.strptime(value.strip(), fmt)
                break
            except ValueError:
                continue
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt

def cutoff():
    return datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=MAX_AGE_DAYS)

def is_too_old(published):
    dt = _parse_date_raw(published)          # bogus 0001/1970 dates count as old
    return dt is not None and dt < cutoff()   # undated articles are kept

def newest_first(entries):
    epoch = datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
    return sorted(entries, key=lambda e: parse_published(e.get("published")) or epoch, reverse=True)

_feed_cache = {"key": None, "feed": []}

def load_feed():
    """Recent articles, newest first, with cleaned IOCs (also fixes entries stored before the cleanup).
    Cached until the data file changes or the day rolls over."""
    if not os.path.exists(DATA_FILE):
        return []
    key = (os.path.getmtime(DATA_FILE), datetime.date.today())
    if _feed_cache["key"] != key:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            feed = json.load(f)
        feed = [e for e in feed if not is_too_old(e.get("published"))]
        for entry in feed:
            entry["iocs"] = clean_iocs(entry.get("iocs"), entry.get("link", ""))
        _feed_cache.update(key=key, feed=newest_first(feed))
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
        if is_too_old(entry.get("published", "")):
            continue  # some feeds return years of archives
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
    print(f"[*] Fetching {len(sources)} sources", flush=True)
    for feed_info in sources:
        try:
            new = fetch_rss(feed_info, known_links)
            combined += new
            print(f"[+] {feed_info.get('name')}: {len(new)} new", flush=True)
        except Exception as exc:
            print(f"[!] Failed source {feed_info.get('name')}: {exc}", flush=True)
        save_feed(combined)   # save after each source so the dashboard fills in as it goes
    print("[*] Fetch complete", flush=True)

def save_feed(entries):
    """Deduplicate, drop old articles, clean IOCs, sort newest first, and write atomically."""
    seen_links = set()
    deduped = []
    for e in entries:
        if e.get("link") not in seen_links and not is_too_old(e.get("published")):
            e["iocs"] = clean_iocs(e.get("iocs"), e.get("link", ""))
            deduped.append(e)
            seen_links.add(e.get("link"))
    deduped = newest_first(deduped)

    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(deduped, f, indent=2)
    os.replace(tmp, DATA_FILE)   # readers never see a half-written file

# -------------------------
# ROUTES
# -------------------------
@app.route("/")
def index():
    feed = load_feed()
    grouped, sources = group_by_category(feed)
    fetching = len(feed) == 0  # Banner if feed empty
    return render_template("index.html", grouped=grouped, sources=sources, feed_list=feed,
                           fetching=fetching, total=len(feed),
                           latest=feed[0].get("link", "") if feed else "")

@app.route("/api/feed")
def api_feed():
    return jsonify(load_feed())

@app.route("/api/feed/count")
def api_feed_count():
    # Lightweight check the dashboard polls to see if new articles arrived.
    # "latest" (newest article's link) changes even when old articles age out at the same time.
    feed = load_feed()
    return jsonify({"count": len(feed), "latest": feed[0].get("link", "") if feed else ""})

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
