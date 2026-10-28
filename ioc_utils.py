"""
Shared IOC extraction and cleanup for KITT Threat Radar.

Used by app.py (live fetch + cleanup of stored entries) and fetcher/fetch_normalized.py.
"""
import ipaddress
import json
import os
import re
from urllib.parse import urlparse

import tldextract
import yaml
from bs4 import BeautifulSoup, Comment

IGNORE_FILE = os.environ.get("IOC_IGNORE_FILE", "ioc_ignore.yaml")

# Use the public suffix list bundled with tldextract: no network call, no cache dir needed
_tld = tldextract.TLDExtract(suffix_list_urls=())

IOC_FIELDS = ["ip", "domain", "email", "md5", "sha1", "sha256", "file_path", "service", "cve"]

_DOT = r"(?:\.|\[\.\]|\(dot\))"
IOC_PATTERNS = {
    "ip": re.compile(rf"\b(?:\d{{1,3}}{_DOT}){{3}}\d{{1,3}}\b", re.I),
    "domain": re.compile(rf"\b(?:[a-z0-9](?:[a-z0-9\-]{{0,61}}[a-z0-9])?{_DOT})+[a-z]{{2,}}\b", re.I),
    "email": re.compile(rf"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+{_DOT}[A-Za-z]{{2,}}\b"),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "file_path": re.compile(r"[A-Za-z]:\\[^\s<>\"']+"),
    "service": re.compile(r"\bservice\s+(?:name|display name)\s*[:\-]\s*([A-Za-z0-9_\-]+)", re.I),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
}

# Real TLDs that are far more often file extensions or code in security write-ups
# (update.zip, install.sh, script.py, self.name). Dropped from domains.
FILE_EXTENSION_TLDS = {"zip", "mov", "py", "sh", "pl", "md", "rs", "ps", "so", "name"}

# Page chrome that carries site navigation, not article content
_NOISE_TAGS = ["script", "style", "noscript", "nav", "header", "footer", "aside", "form", "svg", "iframe"]


def refang(value):
    return (value.replace("[.]", ".").replace("(dot)", ".")
                 .replace("hxxp://", "http://").replace("hxxps://", "https://"))


def registered_domain(host):
    """example.com for www.blog.example.com; '' if host has no public suffix."""
    r = _tld(host or "")
    return (getattr(r, "top_domain_under_public_suffix", None) or r.registered_domain or "").lower()


def source_domain(url):
    try:
        return registered_domain(urlparse(url).hostname or "")
    except Exception:
        return ""


def article_text(html):
    """Text of the article body, without site navigation, headers and footers."""
    soup = BeautifulSoup(html, "html.parser")
    for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
        c.extract()
    for tag in soup.find_all(_NOISE_TAGS):
        tag.decompose()
    body = soup.find("article") or soup.find("main") or soup.body or soup
    return body.get_text(separator=" ", strip=True)


# ---------------------------------------------------------------- ignore list
_ignore = {"mtime": None, "domains": set(), "values": set()}


def ignore_signature():
    """Changes whenever the ignore file changes; used as part of cache keys."""
    try:
        return os.path.getmtime(IGNORE_FILE)
    except OSError:
        return None


def load_ignore():
    sig = ignore_signature()
    if sig != _ignore["mtime"]:
        data = {}
        try:
            with open(IGNORE_FILE, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError) as exc:
            print(f"[!] Could not read {IGNORE_FILE}: {exc}", flush=True)
        _ignore.update(
            mtime=sig,
            domains={str(d).strip().lower().lstrip(".") for d in (data.get("domains") or []) if d},
            values={str(v).strip().lower() for v in (data.get("values") or []) if v},
        )
    return _ignore


def _domain_ignored(host, ign):
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in ign["domains"])


def _yaml_line(value):
    return f"  - {json.dumps(value)}"   # a JSON string is a valid YAML scalar


def add_ignored_value(value):
    """Append to the `values:` list at the end of the ignore file, keeping its comments."""
    value = str(value).strip()
    if not value or "\n" in value or len(value) > 512:
        raise ValueError("invalid value")
    if value.lower() in load_ignore()["values"]:
        return False
    text = ""
    if os.path.exists(IGNORE_FILE):
        with open(IGNORE_FILE, "r", encoding="utf-8") as f:
            text = f.read()
    if not re.search(r"^values:", text, re.M):
        text = text.rstrip("\n") + "\n\nvalues:\n"
    text = re.sub(r"^values:\s*\[\]\s*$", "values:", text, flags=re.M)
    text = text.rstrip("\n") + "\n" + _yaml_line(value) + "\n"
    _write(text)
    return True


def remove_ignored_value(value):
    target = str(value).strip().lower()
    with open(IGNORE_FILE, "r", encoding="utf-8") as f:
        lines = f.read().split("\n")
    kept, removed, in_values = [], False, False
    for line in lines:
        if re.match(r"^\S", line):
            in_values = line.startswith("values:")
        m = re.match(r"^\s+-\s+(.*?)\s*(#.*)?$", line) if in_values else None
        if m:
            try:
                item = str(yaml.safe_load(m.group(1))).strip().lower()
            except yaml.YAMLError:
                item = None
            if item == target:
                removed = True
                continue
        kept.append(line)
    if removed:
        _write("\n".join(kept))
    return removed


def _write(text):
    # Write in place (not rename) so a Docker bind-mounted file keeps working
    with open(IGNORE_FILE, "w", encoding="utf-8") as f:
        f.write(text)


def ignore_list():
    ign = load_ignore()
    return {"domains": sorted(ign["domains"]), "values": sorted(ign["values"])}


# ---------------------------------------------------------------- validation
def _valid_domain(d, src, ign):
    labels = d.split(".")
    if labels[-1] in FILE_EXTENSION_TLDS:
        return False
    r = _tld(d)
    if not r.suffix or not r.domain:          # not a real public suffix: httpd.conf, ns.log, 1.sig
        return False
    if src and registered_domain(d) == src:   # the publisher's own site (cloud.google.com -> google.com)
        return False
    if _domain_ignored(d, ign):
        return False
    return True


def _valid_ip(ip):
    try:
        addr = ipaddress.IPv4Address(ip)       # drops 999.1.2.3 and similar version strings
    except ValueError:
        return False
    return addr.is_global                     # drops private, loopback, link-local, reserved, documentation


def clean_iocs(iocs, link="", apply_ignore=True):
    """Filter an IOC dict: drop the article's own domain, filename look-alikes, invalid or
    non-public IPs and (unless apply_ignore=False) anything on the ignore list."""
    src = source_domain(link)
    ign = load_ignore() if apply_ignore else {"domains": set(), "values": set()}
    out = {}
    for field, values in (iocs or {}).items():
        # file_hash duplicated md5/sha1/sha256 in older fetcher output
        if field == "file_hash" or not isinstance(values, list):
            continue
        kept = []
        for v in values:
            v = refang(str(v)).strip()
            if v.lower() in ign["values"]:
                continue
            if field == "domain":
                v = v.lower()
                if not _valid_domain(v, src, ign):
                    continue
            elif field == "email":
                host = v.rsplit("@", 1)[-1]
                if (src and registered_domain(host) == src) or _domain_ignored(host, ign):
                    continue
            elif field == "ip" and not _valid_ip(v):
                continue
            elif field == "file_path" and v.rstrip("\\").count("\\") < 2:
                continue   # "C:\Program" (cut off at a space) or a bare folder isn't useful
            elif field == "cve":
                v = v.upper()
            kept.append(v)
        kept = sorted(set(kept))
        if kept:
            out[field] = kept
    return out


def extract_iocs(text, link=""):
    raw = {}
    for field, pattern in IOC_PATTERNS.items():
        matches = []
        for m in pattern.findall(text):
            m = m[0] if isinstance(m, tuple) else m
            if not re.search(r"https?://", m, re.I):
                matches.append(m)
        raw[field] = matches
    return clean_iocs(raw, link, apply_ignore=False)   # ignore list is applied when displayed


def extract_iocs_from_html(html, link=""):
    return extract_iocs(article_text(html), link)
