"""
Shared IOC extraction and cleanup for KITT Threat Radar.

Used by app.py (live fetch + cleanup of stored entries) and fetcher/fetch_normalized.py.
"""
import ipaddress
import re
from urllib.parse import urlparse

import tldextract
from bs4 import BeautifulSoup, Comment

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


def _valid_domain(d, src):
    labels = d.split(".")
    if labels[-1] in FILE_EXTENSION_TLDS:
        return False
    r = _tld(d)
    if not r.suffix or not r.domain:          # not a real public suffix: httpd.conf, ns.log, 1.sig
        return False
    if src and registered_domain(d) == src:   # the publisher's own site (cloud.google.com -> google.com)
        return False
    return True


def _valid_ip(ip):
    try:
        ipaddress.IPv4Address(ip)              # drops 999.1.2.3 and similar version strings
        return True
    except ValueError:
        return False


def clean_iocs(iocs, link=""):
    """Filter an IOC dict: drop the article's own domain, filename look-alikes and invalid IPs."""
    src = source_domain(link)
    out = {}
    for field, values in (iocs or {}).items():
        # file_hash duplicated md5/sha1/sha256 in older fetcher output
        if field == "file_hash" or not isinstance(values, list):
            continue
        kept = []
        for v in values:
            v = refang(str(v)).strip()
            if field == "domain":
                v = v.lower()
                if not _valid_domain(v, src):
                    continue
            elif field == "email":
                if src and registered_domain(v.rsplit("@", 1)[-1]) == src:
                    continue
            elif field == "ip" and not _valid_ip(v):
                continue
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
    return clean_iocs(raw, link)


def extract_iocs_from_html(html, link=""):
    return extract_iocs(article_text(html), link)
