"""
One-off: re-extract IOCs for stored articles that have none.

Needed after the article_text() fix: the hourly sweep skips links it already has,
so entries stored with empty IOCs are never re-scanned on their own.

Run with the app stopped so the two don't write the feed file at the same time:
    docker compose stop
    docker compose run --rm --no-deps kitt python backfill_iocs.py [--source "The Hacker News"]
    docker compose start
"""
import argparse
import json
import os
import time

import requests

from ioc_utils import extract_iocs_from_html

DATA_FILE = "data/feed_normalized.json"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/121.0 Safari/537.36"
}


def save(entries):
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)
    os.replace(tmp, DATA_FILE)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", help="only this source name, e.g. 'The Hacker News'")
    args = ap.parse_args()

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        entries = json.load(f)

    todo = [e for e in entries if not e.get("iocs") and e.get("link")
            and (not args.source or e.get("source") == args.source)]
    print(f"{len(todo)} articles without IOCs to re-scan", flush=True)

    found = failed = 0
    for i, e in enumerate(todo, 1):
        try:
            r = requests.get(e["link"], headers=HEADERS, timeout=15)
            r.raise_for_status()
            iocs = extract_iocs_from_html(r.text, e["link"])
        except Exception as exc:
            failed += 1
            print(f"  [!] {e['link']}: {exc}", flush=True)
            continue
        if iocs:
            e["iocs"] = iocs
            found += 1
            print(f"  [+] {e.get('source')}: {e.get('title', '')[:70]} -> "
                  f"{sum(len(v) for v in iocs.values())} IOCs", flush=True)
        if i % 25 == 0:
            save(entries)
            print(f"  ... {i}/{len(todo)}", flush=True)
        time.sleep(0.5)   # be polite to the publishers

    save(entries)
    print(f"Done: {found} articles gained IOCs, {failed} could not be fetched", flush=True)


if __name__ == "__main__":
    main()
