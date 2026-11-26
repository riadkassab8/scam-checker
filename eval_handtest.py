"""Honest end-to-end eval on the fresh hand-made set (never used in training).

Runs rules + lite model + combine, the same pipeline the site uses, without the
network layers (reputation keys unset, domain age not relevant to these texts).
"""
import csv, sys
sys.path.insert(0, ".")
from layers import rules, model
from app import combine, SCAM_AT, SUSPICIOUS_AT

def verdict(s):
    return "scam" if s >= SCAM_AT else "suspicious" if s >= SUSPICIOUS_AT else "safe"

rows = list(csv.DictReader(open("data/handtest.csv", encoding="utf-8")))
stats = {}
misses, fps = [], []
n_scam = n_legit = 0
warned_scam = 0
for r in rows:
    t, y = r["text"], int(r["label"])
    rs, reasons, _, _ = rules.run(t)
    ms = model.score(t)
    final = combine(rs, ms)
    v = verdict(final)
    if y == 1:
        n_scam += 1
        if final >= SUSPICIOUS_AT: warned_scam += 1
        if v != "scam": misses.append((r["category"], round(final, 2), v, t[:70]))
    else:
        n_legit += 1
        if v != "safe": fps.append((r["category"], round(final, 2), v, t[:70]))

print(f"handmade set: {n_scam} scam + {n_legit} legit")
print(f"scam: explicit-scam {n_scam-len(misses)}/{n_scam} ({(n_scam-len(misses))/n_scam:.1%}), warned (>=suspicious) {warned_scam}/{n_scam} ({warned_scam/n_scam:.1%})")
print(f"legit: correctly safe {n_legit-len(fps)}/{n_legit} ({(n_legit-len(fps))/n_legit:.1%})")
if misses:
    print("\nscams not landing on 'scam':")
    for m in misses: print("  ", m)
if fps:
    print("\nlegit messages flagged:")
    for f in fps: print("  ", f)
