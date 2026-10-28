from flask import Flask, render_template, jsonify, send_file, request
import json
import os
import csv
import io
import uuid
import datetime
import threading
from urllib.parse import urlparse
from apscheduler.schedulers.background import BackgroundScheduler
import feedparser
import yaml
import requests

from ioc_utils import (IOC_FIELDS, clean_iocs, extract_iocs_from_html, ignore_signature,
                       ignore_list, add_ignored_value, remove_ignored_value)

# -------------------------
# CONFIG
# -------------------------
app = Flask(__name__)

DATA_FILE = "data/feed_normalized.json"
STATUS_FILE = "data/status.json"   # per-source health + fetch history
SOURCES_FILE = "sources.yaml"
FETCH_INTERVAL_HOURS = 1
HISTORY_LENGTH = 48                # fetch runs kept in status.json

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
    key = (os.path.getmtime(DATA_FILE), datetime.date.today(), ignore_signature())
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

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

def write_json_atomic(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)   # readers never see a half-written file

def load_status():
    try:
        with open(STATUS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"sources": {}, "history": []}

_ioc_cache = {"key": None, "index": []}

def build_ioc_index():
    """One row per unique indicator: where it appeared, first/last seen. Cached with the feed."""
    feed = load_feed()
    key = _feed_cache["key"]
    if _ioc_cache["key"] == key:
        return _ioc_cache["index"]
    index = {}
    for i, entry in enumerate(feed):
        dt = parse_published(entry.get("published"))
        for ioc_type, values in (entry.get("iocs") or {}).items():
            for value in values:
                row = index.setdefault((ioc_type, value), {
                    "type": ioc_type, "value": value, "articles": [],
                    "sources": set(), "first_seen": None, "last_seen": None})
                row["articles"].append(i)
                row["sources"].add(entry.get("source", "Unknown"))
                if dt:
                    iso = dt.isoformat()
                    if not row["first_seen"] or iso < row["first_seen"]:
                        row["first_seen"] = iso
                    if not row["last_seen"] or iso > row["last_seen"]:
                        row["last_seen"] = iso
    rows = []
    for row in index.values():
        row["sources"] = sorted(row["sources"])
        row["count"] = len(row["articles"])
        rows.append(row)
    rows.sort(key=lambda r: r["last_seen"] or "", reverse=True)   # newest first...
    rows.sort(key=lambda r: r["count"], reverse=True)             # ...within most-reported first
    _ioc_cache.update(key=key, index=rows)
    return rows

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
            "fetched_at": now_iso(),
            "iocs": extract_iocs_from_url(entry.get("link", ""))
        })
    if not normalized and getattr(feed, "bozo", False) and not feed.entries:
        # feedparser doesn't raise on network/parse errors; surface them as failures
        raise RuntimeError(str(getattr(feed, "bozo_exception", "feed could not be read")))
    return normalized

_fetch_lock = threading.Lock()
_fetch_state = {"running": False, "current": None}

def update_feed():
    if not _fetch_lock.acquire(blocking=False):
        print("[~] Fetch already running; skipping", flush=True)
        return
    try:
        _fetch_state["running"] = True
        _run_fetch()
    finally:
        _fetch_state.update(running=False, current=None)
        _fetch_lock.release()

def _run_fetch():
    existing = []
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            existing = json.load(f)

    status = load_status()
    run = {"started": now_iso(), "finished": None, "new": 0, "failed": []}

    combined = existing.copy()
    known_links = {e.get("link") for e in existing}
    sources = load_sources()
    print(f"[*] Fetching {len(sources)} sources", flush=True)
    for feed_info in sources:
        name = feed_info.get("name", "Unknown")
        _fetch_state["current"] = name
        health = status["sources"].setdefault(name, {})
        health.update(category=feed_info.get("category", "Uncategorized"), last_attempt=now_iso())
        try:
            new = fetch_rss(feed_info, known_links)
            combined += new
            run["new"] += len(new)
            health.update(ok=True, last_success=now_iso(), last_new=len(new), error=None)
            print(f"[+] {name}: {len(new)} new", flush=True)
        except Exception as exc:
            run["failed"].append(name)
            health.update(ok=False, error=str(exc)[:200])
            print(f"[!] Failed source {name}: {exc}", flush=True)
        save_feed(combined)   # save after each source so the dashboard fills in as it goes
        write_json_atomic(STATUS_FILE, status)

    # forget sources removed from sources.yaml
    configured = {s.get("name", "Unknown") for s in sources}
    status["sources"] = {k: v for k, v in status["sources"].items() if k in configured}
    run["finished"] = now_iso()
    status["history"] = ([run] + status.get("history", []))[:HISTORY_LENGTH]
    write_json_atomic(STATUS_FILE, status)
    print(f"[*] Fetch complete: {run['new']} new, {len(run['failed'])} failed", flush=True)

def save_feed(entries):
    """Deduplicate, drop old articles, clean IOCs, sort newest first, and write atomically."""
    seen_links = set()
    deduped = []
    for e in entries:
        if e.get("link") not in seen_links and not is_too_old(e.get("published")):
            # stored without the ignore list, so un-ignoring something brings it back
            e["iocs"] = clean_iocs(e.get("iocs"), e.get("link", ""), apply_ignore=False)
            deduped.append(e)
            seen_links.add(e.get("link"))
    write_json_atomic(DATA_FILE, newest_first(deduped))

# -------------------------
# ROUTES
# -------------------------
@app.route("/")
def index():
    # The page is a shell; everything on it is loaded from the /api endpoints below
    return render_template("index.html", max_age_days=MAX_AGE_DAYS)

@app.route("/api/feed")
def api_feed():
    return jsonify(load_feed())

@app.route("/api/status")
def api_status():
    status = load_status()
    sources = load_sources()
    job = scheduler.get_job("hourly")
    health = []
    for s in sources:
        name = s.get("name", "Unknown")
        h = status["sources"].get(name, {})
        health.append({"name": name, "category": s.get("category", "Uncategorized"),
                       "url": s.get("url", ""), "ok": h.get("ok"),
                       "last_success": h.get("last_success"), "last_attempt": h.get("last_attempt"),
                       "last_new": h.get("last_new"), "error": h.get("error")})
    history = status.get("history", [])
    return jsonify({
        "fetching": _fetch_state["running"],
        "fetching_source": _fetch_state["current"],
        "last_fetch": history[0] if history else None,
        "next_fetch": job.next_run_time.isoformat() if getattr(job, "next_run_time", None) else None,
        "interval_hours": FETCH_INTERVAL_HOURS,
        "max_age_days": MAX_AGE_DAYS,
        "sources": health,
        "history": history,
    })

@app.route("/api/stats")
def api_stats():
    feed = load_feed()
    iocs = build_ioc_index()
    day_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=24)
    new_24h = sum(1 for e in feed if (parse_published(e.get("published")) or day_ago) > day_ago)
    by_type = {}
    for row in iocs:
        by_type[row["type"]] = by_type.get(row["type"], 0) + 1
    status = load_status()["sources"]
    configured = load_sources()
    healthy = sum(1 for s in configured if status.get(s.get("name"), {}).get("ok"))
    return jsonify({
        "feeds_configured": len(configured),
        "feeds_healthy": healthy,
        "articles": len(feed),
        "articles_24h": new_24h,
        "articles_with_iocs": sum(1 for e in feed if has_real_iocs(e)),
        "iocs_unique": len(iocs),
        "iocs_by_type": by_type,
    })

@app.route("/api/iocs")
def api_iocs():
    # "articles" are indexes into /api/feed (same order), which the page already has
    return jsonify(build_ioc_index())

@app.route("/api/ignore", methods=["GET"])
def api_ignore_list():
    return jsonify(ignore_list())

@app.route("/api/ignore", methods=["POST", "DELETE"])
def api_ignore_change():
    value = ((request.get_json(silent=True) or {}).get("value") or "").strip()
    try:
        changed = add_ignored_value(value) if request.method == "POST" else remove_ignored_value(value)
    except (ValueError, OSError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "changed": changed, "ignore": ignore_list()})

@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    if _fetch_state["running"]:
        return jsonify({"started": False, "reason": "already running"}), 409
    threading.Thread(target=update_feed, daemon=True).start()
    return jsonify({"started": True}), 202

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
scheduler.add_job(update_feed, 'interval', hours=FETCH_INTERVAL_HOURS, id="hourly")  # Hourly updates
scheduler.add_job(update_feed, 'date', run_date=datetime.datetime.now(), id="startup")  # First run in background
scheduler.start()

# -------------------------
# START APP
# -------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5052, debug=False)
