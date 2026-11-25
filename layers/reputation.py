"""Layer 2: reputation checks against external services.

All three services need API keys, passed through environment variables:
  VT_API_KEY        - VirusTotal
  GSB_API_KEY       - Google Safe Browsing
  URLSCAN_API_KEY   - urlscan.io (optional; urlscan submissions work without
                      a key for public scans but a key raises limits)

If no key is configured the layer reports itself as skipped and never blocks
the verdict. Network failures degrade gracefully to "unknown".
"""

import json
import os
import urllib.request
import urllib.parse

VT_KEY = os.environ.get("VT_API_KEY")
GSB_KEY = os.environ.get("GSB_API_KEY")
URLSCAN_KEY = os.environ.get("URLSCAN_API_KEY")

TIMEOUT = 8


def _get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _post(url, payload, headers=None):
    data = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def check_virustotal(target_url):
    url_id = urllib.parse.quote(target_url, safe="")
    try:
        data = _get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VT_KEY},
        )
    except Exception:
        # not scanned before -> submit, then report unknown this round
        try:
            _post("https://www.virustotal.com/api/v3/urls",
                  {"url": target_url}, headers={"x-apikey": VT_KEY})
        except Exception:
            pass
        return None
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return stats.get("malicious", 0) + stats.get("suspicious", 0)


def check_safebrowsing(target_url):
    body = json.dumps({
        "client": {"clientId": "scam-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": target_url}],
        },
    }).encode()
    req = urllib.request.Request(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}",
        data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None
    return len(data.get("matches", []))


def run(urls):
    """Return (score, reasons, status). status: 'ok' | 'skipped' | 'partial'."""
    if not (VT_KEY or GSB_KEY):
        return 0.0, [], "skipped"
    reasons = []
    worst = 0.0
    checked = False
    for url in urls[:5]:
        if VT_KEY:
            checked = True
            bad = check_virustotal(url)
            if bad:
                worst = max(worst, 0.95 if bad >= 3 else 0.8)
                reasons.append(f"خدمة VirusTotal فيها {bad} محرك بيعتبر الرابط خطير")
        if GSB_KEY:
            checked = True
            bad = check_safebrowsing(url)
            if bad:
                worst = max(worst, 0.95)
                reasons.append("Google Safe Browsing مصنف الرابط كصفحة احتيال أو ضارة")
    return worst, reasons, "ok" if checked else "skipped"
