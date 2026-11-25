"""Train layer 3 (the text model) and measure it honestly.

- Stratified 80/20 split on data/combined.csv.
- TF-IDF (word unigrams/bigrams + character 3-5 grams) + Logistic Regression.
- Reports overall accuracy, precision, recall, F1 for the scam class, and a
  per-language breakdown (Arabic vs English) so we do not hide where it is weak.
- Saves the fitted pipeline to model.joblib for app.py to load.
"""

import csv
import os

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline, FeatureUnion

HERE = os.path.dirname(os.path.abspath(__file__))


def is_arabic(text):
    return sum("\u0600" <= c <= "\u06ff" for c in text) > max(3, len(text) // 4)


def main():
    texts, labels, sources = [], [], []
    with open(os.path.join(HERE, "data", "combined.csv"), encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            texts.append(r["text"])
            labels.append(int(r["label"]))
            sources.append(r["source"])

    X_train, X_test, y_train, y_test, s_train, s_test = train_test_split(
        texts, labels, sources, test_size=0.2, random_state=42, stratify=labels)

    pipe = Pipeline([
        ("tfidf", FeatureUnion([
            ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
        ])),
        ("clf", LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced")),
    ])
    pipe.fit(X_train, y_train)
    joblib.dump(pipe, os.path.join(HERE, "model.joblib"))

    pred = pipe.predict(X_test)

    print(f"train: {len(X_train)}   test: {len(X_test)}")
    print(f"scam share: {sum(labels) / len(labels):.2%}")
    print()
    print(f"accuracy : {accuracy_score(y_test, pred):.4f}")
    print(f"precision: {precision_score(y_test, pred):.4f}  (of everything flagged scam, how much really was)")
    print(f"recall   : {recall_score(y_test, pred):.4f}  (of all real scams, how much we caught)")
    print(f"f1       : {f1_score(y_test, pred):.4f}")
    tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()
    print(f"confusion: tp={tp} fp={fp} fn={fn} tn={tn}")
    print()

    def report(name, idxs):
        if not idxs:
            return
        yt = [y_test[i] for i in idxs]
        yp = [pred[i] for i in idxs]
        print(f"{name:<28} n={len(idxs):<5} acc={accuracy_score(yt, yp):.4f} "
              f"recall={recall_score(yt, yp, zero_division=0):.4f} "
              f"precision={precision_score(yt, yp, zero_division=0):.4f}")

    ar = [i for i, t in enumerate(X_test) if is_arabic(t)]
    en = [i for i, t in enumerate(X_test) if not is_arabic(t)]
    eg = [i for i, s in enumerate(s_test) if s == "eg_synthetic"]
    ar_real = [i for i in ar if s_test[i] != "eg_synthetic"]
    imc = [i for i, s in enumerate(s_test) if s.startswith("imc25")]
    moz = [i for i, s in enumerate(s_test) if s == "moz_pt"]
    shm = [i for i, s in enumerate(s_test) if s == "smishing_en"]

    print("breakdown on the held-out test set:")
    report("arabic (all)", ar)
    report("arabic (real corpora)", ar_real)
    report("egyptian (synthetic)", eg)
    report("english (UCI)", en)
    report("imc25 multilingual smishing", imc)
    report("mozambique pt", moz)
    report("english smishing corpus", shm)


if __name__ == "__main__":
    main()
