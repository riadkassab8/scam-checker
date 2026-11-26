"""Layer 3: the text model.

Prefers the exported pure-Python model (model.json.gz, scored by
layers/model_lite.py) so the app can deploy without scikit-learn/scipy.
Falls back to the sklearn pipeline (model.joblib) for local training setups.
If neither file exists the layer reports 0 and marks itself unavailable
instead of crashing.
"""

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(ROOT, "model.joblib")
MODEL_JSON = os.path.join(ROOT, "model.json.gz")

USE_LITE = os.path.exists(MODEL_JSON)

_pipeline = None
_tried = False


def _load():
    global _pipeline, _tried
    if not _tried:
        _tried = True
        if not USE_LITE and os.path.exists(MODEL_PATH):
            import joblib
            _pipeline = joblib.load(MODEL_PATH)
    return _pipeline


def available():
    return USE_LITE or _load() is not None


def score(text):
    if USE_LITE:
        from layers import model_lite
        return float(model_lite.scam_probability(text))
    pipe = _load()
    if pipe is None:
        return 0.0
    return float(pipe.predict_proba([text])[0][1])
