"""Scam checker - Flask app.

Serves one Arabic page. The user pastes a suspicious message or link and gets
a verdict: safe / suspicious / scam, with short reasons.

Run:  python app.py        then open http://127.0.0.1:5000
"""

from flask import Flask, jsonify, render_template, request

import json
import os
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


@app.route("/api/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "empty"}), 400
    if len(text) > 5000:
        return jsonify({"error": "too_long"}), 400
    return jsonify(analyze(text))


OCR_PROMPT = (
    "Extract ALL text from this screenshot verbatim, exactly as written. "
    "Keep Arabic, English, numbers, URLs (http, t.me, etc.) and @handles "
    "character-perfect. Output only the extracted text, no commentary."
)


def _ocr_with_gemini(image_b64, mime):
    """Extract text via a vision model. Needs GEMINI_API_KEY in the env.
    Returns the extracted text, or None when no key / on failure."""
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        return None
    model_name = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model_name}:generateContent?key={api_key}")
    payload = json.dumps({
        "contents": [{"parts": [
            {"text": OCR_PROMPT},
            {"inline_data": {"mime_type": mime, "data": image_b64}},
        ]}],
        "generationConfig": {"temperature": 0, "maxOutputTokens": 1500},
    }).encode("utf-8")
    req = urllib.request.Request(url, data=payload,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return body["candidates"][0]["content"]["parts"][0]["text"].strip()
    except Exception:
        return None


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
    text = _ocr_with_gemini(image_b64, mime)
    if text is None:
        return jsonify({"error": "vision_unavailable"}), 503
    if len(text) < 3:
        return jsonify({"error": "no_text"}), 422
    return jsonify(analyze(text[:5000]))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
