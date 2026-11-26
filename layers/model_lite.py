"""Pure-Python scorer for the exported model (model.json.gz).

Reproduces sklearn's TfidfVectorizer (word 1-2 grams + char_wb 3-5 grams,
sublinear tf, idf, L2 norm per vectorizer) + LogisticRegression decision
function exactly, so the deployed service uses the same trained model without
shipping scikit-learn/scipy/numpy (~190 MB) in the serverless bundle.
Verified for output parity against model.joblib on the held-out test set.
"""
import gzip
import json
import math
import os
import re

TOKEN_PATTERN = re.compile(r"(?u)\b\w\w+\b")

_MODEL = None


def _load():
    global _MODEL
    if _MODEL is None:
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "model.json.gz")
        with gzip.open(path, "rt", encoding="utf-8") as f:
            raw = json.load(f)
        _MODEL = {
            "word_terms": {t: i for i, t in enumerate(raw["word"]["terms"])},
            "word_idf": raw["word"]["idf"],
            "word_ngrams": raw["word"]["ngram_range"],
            "char_terms": {t: i for i, t in enumerate(raw["char"]["terms"])},
            "char_idf": raw["char"]["idf"],
            "char_ngrams": raw["char"]["ngram_range"],
            "coef": raw["coef"],
            "intercept": raw["intercept"],
            "scam_class_index": raw["scam_class_index"],
            "n_word": len(raw["word"]["terms"]),
        }
    return _MODEL


def _word_ngrams(tokens, lo, hi):
    out = []
    for n in range(lo, hi + 1):
        for i in range(len(tokens) - n + 1):
            out.append(" ".join(tokens[i:i + n]))
    return out


def _char_wb_ngrams(doc, lo, hi):
    out = []
    for word in doc.split():
        w = " %s " % word
        lw = len(w)
        for n in range(lo, hi + 1):
            for i in range(lw - n + 1):
                out.append(w[i:i + n])
    return out


def _tfidf(ngrams, terms, idf):
    counts = {}
    for g in ngrams:
        idx = terms.get(g)
        if idx is not None:
            counts[idx] = counts.get(idx, 0) + 1
    vec = {}
    norm = 0.0
    for idx, c in counts.items():
        v = (1.0 + math.log(c)) * idf[idx]
        vec[idx] = v
        norm += v * v
    if norm > 0:
        norm = math.sqrt(norm)
        for idx in vec:
            vec[idx] /= norm
    return vec


def scam_probability(text):
    """P(label == scam) for a raw message string, matching model.joblib."""
    m = _load()
    doc = text.lower()
    wlo, whi = m["word_ngrams"]
    clo, chi = m["char_ngrams"]
    wvec = _tfidf(_word_ngrams(TOKEN_PATTERN.findall(doc), wlo, whi),
                  m["word_terms"], m["word_idf"])
    cvec = _tfidf(_char_wb_ngrams(doc, clo, chi), m["char_terms"], m["char_idf"])
    coef, n_word = m["coef"], m["n_word"]
    s = m["intercept"]
    for idx, v in wvec.items():
        s += coef[idx] * v
    for idx, v in cvec.items():
        s += coef[n_word + idx] * v
    p = 1.0 / (1.0 + math.exp(-s))
    # LogisticRegression coef row maps to classes_[1]; classes_ = [0, 1],
    # so p is P(scam) when scam_class_index == 1.
    return p if m["scam_class_index"] == 1 else 1.0 - p
