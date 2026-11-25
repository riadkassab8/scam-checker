"""Layer 2b: domain age through RDAP (registration data, HTTPS, no API key).

Phishing domains are usually days old. This layer asks the registry when the
domain was registered and flags very young ones. Degrades gracefully: any
network problem and the layer reports 'skipped' without blocking the verdict.
"""

import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
TIMEOUT = 6
CACHE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "rdap_cache.json")

_bootstrap = None
_cache = None


def _load_cache():
    global _cache
    if _cache is None:
        try:
            with open(CACHE_PATH, encoding="utf-8") as f:
                _cache = json.load(f)
        except OSError:
            _cache = {}
    return _cache


def _save_cache():
    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(_cache, f)
    except OSError:
        pass


def _fetch(url):
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _server_for(tld):
    global _bootstrap
    if _bootstrap is None:
        _bootstrap = {}
        try:
            data = _fetch(BOOTSTRAP_URL)
            for tlds, servers in data.get("services", []):
                https = [s for s in servers if s.startswith("https://")]
                if https:
                    for t in tlds:
                        _bootstrap[t] = https[0]
        except Exception:
            pass
    return _bootstrap.get(tld)


def registration_date(domain):
    """Return (datetime|None, status). status: ok|unknown|skipped"""
    cache = _load_cache()
    if domain in cache:
        ts = cache[domain]
        return (datetime.fromtimestamp(ts, timezone.utc) if ts else None), "ok"
    tld = domain.rsplit(".", 1)[-1]
    base = _server_for(tld)
    if not base:
        return None, "skipped"
    try:
        data = _fetch(base.rstrip("/") + "/domain/" + domain)
    except Exception:
        return None, "unknown"
    reg = None
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration":
            try:
                reg = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            except (KeyError, ValueError):
                pass
            break
    cache[domain] = reg.timestamp() if reg else None
    _save_cache()
    return reg, "ok"


def _registrable(host):
    try:
        import tldextract
        ext = tldextract.extract(host)
        return ".".join(p for p in (ext.domain, ext.suffix) if p)
    except Exception:
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host


def run(urls, trusted_domains=frozenset()):
    """Return (score, reasons, status). Only checks http(s) links."""
    for url in urls[:3]:
        if not url.lower().startswith(("http://", "https://")):
            continue
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            continue
        if not host:
            continue
        domain = _registrable(host)
        if domain in trusted_domains:
            continue
        reg, status = registration_date(domain)
        if status != "ok" or reg is None:
            continue
        age_days = (datetime.now(timezone.utc) - reg).days
        if age_days < 30:
            return 0.55, [f"الموقع اتسجل من {max(age_days, 1)} يوم بس، ومواقع النصب عادة بتكون جديدة جدا"], "ok"
        if age_days < 180:
            return 0.25, [f"الموقع عمره {age_days} يوم بس، وده حديث نسبيا فخد بالك"], "ok"
        return 0.0, [], "ok"
    return 0.0, [], "skipped"
