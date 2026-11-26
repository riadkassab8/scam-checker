"""Export the trained sklearn pipeline to a compact pure-Python model (model.json.gz).

Vercel's serverless bundle is tight (250 MB unzipped). Shipping scikit-learn +
scipy + numpy costs ~190 MB and slow cold starts, so the runtime scores the
SAME fitted model with pure Python (layers/model_lite.py). This script is the
bridge: it reads model.joblib and writes the weights/vocabulary to JSON+gzip.
Run it after train_model.py whenever the model is retrained.
"""
import gzip
import json
import os

import joblib

HERE = os.path.dirname(os.path.abspath(__file__))

pipe = joblib.load(os.path.join(HERE, "model.joblib"))
tfidf = pipe.named_steps["tfidf"]
clf = pipe.named_steps["clf"]
tr = dict(tfidf.transformer_list)
word, char = tr["word"], tr["char"]

n_word = len(word.vocabulary_)
n_char = len(char.vocabulary_)
assert clf.coef_.shape[1] == n_word + n_char

word_terms = [None] * n_word
for t, i in word.vocabulary_.items():
    word_terms[i] = t
char_terms = [None] * n_char
for t, i in char.vocabulary_.items():
    char_terms[i] = t

payload = {
    "format": "fahes-tfidf-logreg-1",
    "word": {
        "terms": word_terms,
        "idf": [round(v, 6) for v in word.idf_.tolist()],
        "ngram_range": list(word.ngram_range),
    },
    "char": {
        "terms": char_terms,
        "idf": [round(v, 6) for v in char.idf_.tolist()],
        "ngram_range": list(char.ngram_range),
    },
    "coef": [round(v, 6) for v in clf.coef_[0].tolist()],
    "intercept": clf.intercept_[0],
    "scam_class_index": int(list(clf.classes_).index(1)),
}

out = os.path.join(HERE, "model.json.gz")
with gzip.open(out, "wt", encoding="utf-8") as f:
    json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))
print(f"wrote {out} ({os.path.getsize(out)/1e6:.1f} MB): "
      f"{n_word} word + {n_char} char features")
