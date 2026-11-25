"""End-to-end evaluation: the whole layered engine (rules + model), not just
the model. Uses the same held-out 20% split as train_model.py.

Reports two readings:
  strict  - only a "scam" verdict counts as a detection
  lenient - "suspicious" counts too (the user still gets warned)
"""

import csv
import os

from sklearn.model_selection import train_test_split

from app import combine, SCAM_AT, SUSPICIOUS_AT
from layers import model, rules
from train_model import is_arabic

HERE = os.path.dirname(os.path.abspath(__file__))


def verdict(text):
    rule_score, _, urls, trusted_only = rules.run(text)
    model_score = model.score(text)
    if trusted_only and rule_score == 0.0:
        model_score *= 0.3
    # reputation and domain-age need network/API keys; held out of the eval
    final = combine(rule_score, model_score, 0.0, 0.0)
    if final >= SCAM_AT:
        return 2
    if final >= SUSPICIOUS_AT:
        return 1
    return 0


def main():
    texts, labels, sources = [], [], []
    with open(os.path.join(HERE, "data", "combined.csv"), encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            texts.append(r["text"])
            labels.append(int(r["label"]))
            sources.append(r["source"])

    _, X_test, _, y_test, _, s_test = train_test_split(
        texts, labels, sources, test_size=0.2, random_state=42, stratify=labels)

    preds = [verdict(t) for t in X_test]

    def metrics(idxs, lenient):
        flagged = lambda p: p >= 1 if lenient else p == 2
        tp = sum(1 for i in idxs if y_test[i] == 1 and flagged(preds[i]))
        fp = sum(1 for i in idxs if y_test[i] == 0 and flagged(preds[i]))
        fn = sum(1 for i in idxs if y_test[i] == 1 and not flagged(preds[i]))
        tn = sum(1 for i in idxs if y_test[i] == 0 and not flagged(preds[i]))
        acc = (tp + tn) / len(idxs)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        return acc, prec, rec

    groups = {
        "overall": list(range(len(X_test))),
        "arabic (real corpora)": [i for i, t in enumerate(X_test) if is_arabic(t) and s_test[i] != "eg_synthetic"],
        "egyptian (synthetic)": [i for i, s in enumerate(s_test) if s == "eg_synthetic"],
        "english (UCI)": [i for i, s in enumerate(s_test) if s == "uci_en"],
        "imc25 multilingual": [i for i, s in enumerate(s_test) if s.startswith("imc25")],
        "mozambique pt": [i for i, s in enumerate(s_test) if s == "moz_pt"],
        "english smishing corpus": [i for i, s in enumerate(s_test) if s == "smishing_en"],
    }

    for name, idxs in groups.items():
        if not idxs:
            continue
        sa, sp, sr = metrics(idxs, lenient=False)
        la, lp, lr = metrics(idxs, lenient=True)
        print(f"{name:<26} n={len(idxs):<5} "
              f"strict:  acc={sa:.4f} prec={sp:.4f} rec={sr:.4f} | "
              f"lenient: acc={la:.4f} prec={lp:.4f} rec={lr:.4f}")


if __name__ == "__main__":
    main()
