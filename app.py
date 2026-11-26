"""Scam checker - Flask app.

Serves one Arabic page. The user pastes a suspicious message or link and gets
a verdict: safe / suspicious / scam, with short reasons.

Run:  python app.py        then open http://127.0.0.1:5000
"""

from flask import Flask, jsonify, redirect, render_template, request, send_from_directory

import json
import os
import urllib.error
import urllib.request

from layers import domainage, model, reputation, rules

app = Flask(__name__)

# verdict thresholds on the combined score
SCAM_AT = 0.65
SUSPICIOUS_AT = 0.30


def combine(*scores):
    """The strongest signal wins; the others add a little on top."""
    scores = sorted(scores, reverse=True)
    total = scores[0]
    for s in scores[1:]:
        total += s * 0.5 * (1 - total)
    return min(total, 1.0)


@app.route("/")
def index():
    return render_template("index.html")


def analyze(text):
    rule_score, rule_reasons, urls, trusted_only = rules.run(text)
    rep_score, rep_reasons, rep_status = reputation.run(urls)
    age_score, age_reasons, age_status = domainage.run(urls, rules.TRUSTED_DOMAINS)
    model_score = model.score(text)

    # A message linking only to known official domains, with no rule hit,
    # gets the model's say damped: legit operator messages look spammy.
    if trusted_only and rule_score == 0.0 and rep_score == 0.0 and age_score == 0.0:
        model_score *= 0.3

    final = combine(rule_score, model_score, rep_score, age_score)

    if final >= SCAM_AT:
        verdict = "scam"
    elif final >= SUSPICIOUS_AT:
        verdict = "suspicious"
    else:
        verdict = "safe"

    reasons = rule_reasons + rep_reasons + age_reasons
    if model_score >= 0.5 and not reasons:
        reasons.append("أسلوب الكلام في الرسالة شبه رسايل نصب معروفة")
    if not reasons:
        reasons.append("ملقتش علامات نصب واضحة في الرسالة")

    return {
        "verdict": verdict,
        "score": round(final, 3),
        "reasons": reasons[:4],
        "urls_found": len(urls),
        "trusted_link": trusted_only,
        "layers": {
            "rules": round(rule_score, 3),
            "model": round(model_score, 3),
            "reputation": rep_status,
            "domain_age": age_status,
        },
    }


@app.route("/sw.js")
def service_worker():
    """Served from the site root so its scope covers the whole site
    (a worker under /static/ could not receive shares for /)."""
    resp = send_from_directory(app.static_folder, "sw.js", mimetype="application/javascript")
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.route("/tips")
def tips():
    return render_template("tips.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/share-target", methods=["POST", "GET"])
def share_target_fallback():
    """Normally the service worker intercepts shares (so images never reach
    the server). This only runs when no worker is active: nothing is read or
    kept, the visitor is just sent to the home page."""
    return redirect("/", code=303)


@app.route("/api/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "empty"}), 400
    if len(text) > 5000:
        return jsonify({"error": "too_long"}), 400
    return jsonify(analyze(text))


@app.route("/api/feedback", methods=["POST"])
def feedback():
    """One-tap verdict feedback. Logged as a JSON line (visible in the
    hosting logs) so misjudged messages can be reviewed and folded back
    into training data. The message text is only logged because the user
    explicitly tapped a feedback button on it."""
    data = request.get_json(silent=True) or {}
    vote = data.get("vote")
    if vote not in ("up", "down"):
        return jsonify({"error": "bad_vote"}), 400
    entry = {
        "type": "feedback",
        "vote": vote,
        "verdict": str(data.get("verdict") or "")[:12],
        "score": round(float(data.get("score") or 0), 3),
        "source": str(data.get("source") or "text")[:8],
        "text": str(data.get("text") or "")[:5000],
    }
    print(json.dumps(entry, ensure_ascii=False), flush=True)
    return jsonify({"ok": True})


OCR_PROMPT = (
    "Extract ALL text from this screenshot verbatim, exactly as written. "
    "Keep Arabic, English, numbers, URLs (http, t.me, etc.) and @handles "
    "character-perfect. Output only the extracted text, no commentary."
)


def _list_model_names(api_key):
    """Ask Google which models this key can actually use; flash first."""
    url = ("https://generativelanguage.googleapis.com/v1beta/models"
           "?pageSize=100&key=" + api_key)
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        names = []
        for m in body.get("models", []):
            methods = m.get("supportedGenerationMethods", [])
            if "generateContent" not in methods:
                continue
            name = (m.get("name") or "").replace("models/", "")
            if name.startswith("gemini") and "image" not in name and "tts" not in name and "audio" not in name and "live" not in name:
                names.append(name)
        names.sort(key=lambda n: ("flash" not in n, "lite" not in n, n))
        return names
    except Exception:
        return []


def _ocr_with_gemini(image_b64, mime):
    """Extract text via a vision model. Needs GEMINI_API_KEY in the env.
    Returns (text, None) on success, (None, "no_key") without a key, or
    (None, short_reason) when the upstream call failed."""
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        return None, "no_key"
    override = os.environ.get("GEMINI_MODEL", "").strip()
    candidates = [override] if override else [
        "gemini-2.5-flash", "gemini-2.5-flash-lite",
        "gemini-2.0-flash", "gemini-2.0-flash-lite",
    ]
    payload = json.dumps({
        "contents": [{"parts": [
            {"text": OCR_PROMPT},
            {"inline_data": {"mime_type": mime, "data": image_b64}},
        ]}],
        "generationConfig": {"temperature": 0, "maxOutputTokens": 1500},
    }).encode("utf-8")
    if not override:
        discovered = _list_model_names(api_key)
        if discovered:
            candidates = candidates + [m for m in discovered
                                       if m not in candidates]
    last_err = "no_model"
    for model_name in candidates:
        url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
               f"{model_name}:generateContent?key={api_key}")
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            return body["candidates"][0]["content"]["parts"][0]["text"].strip(), None
        except urllib.error.HTTPError as e:
            if e.code == 404 and not override:
                continue  # model retired or not enabled for this key; try next
            return None, "upstream_%s" % e.code
        except Exception:
            return None, "upstream_error"
    return None, last_err


@app.route("/api/check-image", methods=["POST"])
def check_image():
    """Image -> verdict. The server reads the text with a vision model and
    runs the same engine. Returns the verdict only, never the extracted text.
    Returns 503 when no vision key is configured so the client can fall back
    to in-browser OCR."""
    data = request.get_json(silent=True) or {}
    image_b64 = data.get("image") or ""
    mime = (data.get("mime") or "image/png").strip()
    if not image_b64:
        return jsonify({"error": "empty"}), 400
    if mime not in ("image/png", "image/jpeg", "image/webp"):
        return jsonify({"error": "bad_type"}), 400
    if len(image_b64) > 12 * 1024 * 1024:
        return jsonify({"error": "too_long"}), 400
    # Privacy gate: until the owner explicitly enables the cloud vision route,
    # the endpoint stays unavailable to plain calls and the UI keeps using
    # on-device OCR. Measurement uses the X-Vision-Preview header.
    if request.headers.get("X-Vision-Preview") != "1":
        return jsonify({"error": "vision_unavailable"}), 503
    text, err = _ocr_with_gemini(image_b64, mime)
    if text is None:
        if err == "no_key":
            return jsonify({"error": "vision_unavailable"}), 503
        # Key exists but the vision call failed: surface a short reason so
        # a bad key or retired model is distinguishable from a missing key.
        return jsonify({"error": "vision_error", "reason": err}), 502
    if len(text) < 3:
        return jsonify({"error": "no_text"}), 422
    return jsonify(analyze(text[:5000]))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
