"""Scam checker - Flask app.

Serves one Arabic page. The user pastes a suspicious message or link and gets
a verdict: safe / suspicious / scam, with short reasons.

Run:  python app.py        then open http://127.0.0.1:5000
"""

from flask import Flask, jsonify, render_template, request

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


@app.route("/api/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "empty"}), 400
    if len(text) > 5000:
        return jsonify({"error": "too_long"}), 400

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

    return jsonify({
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
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
