import ssl
import certifi
ssl._create_default_https_context = lambda: ssl.create_default_context(cafile=certifi.where())

import feedparser
import requests
import time
import json
import os
import re
import yaml
from bs4 import BeautifulSoup, Comment

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ioc_utils import extract_iocs_from_html

OUTPUT_FILE = "data/feed_normalized.json"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/121.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

REQUEST_DELAY = 1.5
MAX_RETRIES = 3
BACKOFF = 3

IOC_PATTERNS = {
    "ip": re.compile(r"\b(?:\d{1,3}(?:\.|\[\.\]|\(dot\))){3}\d{1,3}\b", re.I),
    "registry": re.compile(r"(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s]+"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b"),
    "file_hash": re.compile(r"\b[a-fA-F0-9]{32,64}\b"),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
    "mutex": re.compile(r"Mutex:[^\s]+"),
    "file_path": re.compile(r"[A-Za-z]:\\[^\s<>\"']+"),
    "service": re.compile(r"\bservice\s+(?:name|display name)\s*[:\-]\s*([A-Za-z0-9_\-]+)", re.I),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.I),
}

URL_PATTERN = re.compile(r"https?://", re.I)

def normalize_ioc(value):
    return (
        value.replace("[.]", ".")
             .replace("(dot)", ".")
             .replace("hxxp://", "http://")
             .replace("hxxps://", "https://")
    )

def safe_fetch(url):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.get(url, headers=HEADERS, timeout=15)
            if r.status_code == 429:
                time.sleep(BACKOFF * attempt)
                continue
            r.raise_for_status()
            return r.text
        except requests.RequestException:
            time.sleep(BACKOFF * attempt)
    return None

def extract_iocs(text):
    found = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = set(pattern.findall(text))
        clean = []
        for m in matches:
            if isinstance(m, tuple):
                m = m[0]
            m = normalize_ioc(m)
            if URL_PATTERN.search(m):
                continue
            clean.append(m)
        if clean:
            found[ioc_type] = sorted(clean)
    return found

def clean_summary(html):
    if not html:
        return ""

    soup = BeautifulSoup(html, "html.parser")

    # Remove HTML comments
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        comment.extract()

    # Extract plain text
    text = soup.get_text(separator=" ", strip=True)

    # Remove RSS/Reddit boilerplate
    text = re.sub(r"submitted by.*", "", text, flags=re.I)
    text = re.sub(r"\[link\]|\[comments\]", "", text, flags=re.I)
    text = re.sub(r"r/netsec", "", text, flags=re.I)

    # Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip()

    # Truncate for dashboard
    return text[:600] + "…" if len(text) > 600 else text

def is_reddit_discussion_only(entry):
    title = entry.get("title", "").lower()
    link = entry.get("link", "").lower()
    summary = entry.get("summary", "").lower()

    signals = 0
    if any(x in title for x in ["discussion", "tool thread", "monthly", "weekly", "meta"]):
        signals += 1
    if "reddit.com/r/" in link:
        signals += 1
    if "rules & guidelines" in summary or "submitted by" in summary:
        signals += 1
    return signals >= 2

def load_sources():
    with open("sources.yaml", "r") as f:
        return yaml.safe_load(f)

def fetch_feed(source):
    name = source["name"]
    url = source["url"]
    category = source.get("category", "Unknown")

    print(f"[*] Fetching {name}…")
    feed = feedparser.parse(url)
    results = []

    for entry in feed.entries[:5]:

        if name.lower().startswith("reddit") and is_reddit_discussion_only(entry):
            print(f"[~] Skipping Reddit discussion post: {entry.get('title','')}")
            continue

        link = entry.get("link")
        html = safe_fetch(link)

        # Always clean the feed summary (fix for SecurityWeek and similar)
        summary = clean_summary(entry.get("summary", ""))

        iocs = {}
        if html:
            # Extract IOCs from the article body (shared logic in ioc_utils.py)
            iocs = extract_iocs_from_html(html, link)
            # Replace summary with cleaned full page text
            summary = clean_summary(html)
            time.sleep(REQUEST_DELAY)

        results.append({
            "title": entry.get("title", ""),
            "link": link,
            "summary": summary,
            "published": entry.get("published", ""),
            "source": name,
            "category": category,
            "iocs": iocs
        })

    return results

def main():
    os.makedirs("data", exist_ok=True)
    sources = load_sources()
    all_entries = []

    print("[*] Starting normalized fetch")

    for source in sources:
        try:
            all_entries.extend(fetch_feed(source))
        except Exception as e:
            print(f"[!] Failed source {source['name']}: {e}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_entries, f, indent=2)

    print(f"[+] Wrote {len(all_entries)} entries to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()

