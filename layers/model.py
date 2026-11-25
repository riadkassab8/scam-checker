"""Layer 3: the text model.

Loads the scikit-learn pipeline saved by train_model.py and returns the
probability that the message is scam/spam. If the model file is missing the
layer reports 0 and marks itself unavailable instead of crashing.
"""

import os

import joblib

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "model.joblib")

_pipeline = None
_tried = False


def _load():
    global _pipeline, _tried
    if not _tried:
        _tried = True
        if os.path.exists(MODEL_PATH):
            _pipeline = joblib.load(MODEL_PATH)
    return _pipeline


def available():
    return _load() is not None


def score(text):
    pipe = _load()
    if pipe is None:
        return 0.0
    return float(pipe.predict_proba([text])[0][1])
