# tests/test_ai.py

import pytest

# We want to test ai.classify_record without loading the real DeepSeek model.
# So we temporarily monkeypatch DeepSeek to use a dummy classifier.
import blue_team_ai.ai as ai_module

class DummyModel:
    def classify(self, text):
        # Return a simple label/score based on keywords
        if "fail" in text.lower():
            return {"label": "anomaly", "score": 0.99}
        return {"label": "normal", "score": 0.01}

@pytest.fixture(autouse=True)
def patch_deepseek(monkeypatch):
    """
    Before each test, replace the internal _model with DummyModel().
    """
    monkeypatch.setattr(ai_module, "_model", DummyModel())
    yield

def test_classify_record_anomaly():
    rec = {"message": "Failed password attempt from 1.2.3.4"}
    result = ai_module.classify_record(rec)
    assert result["ai_label"] == "anomaly"
    assert result["ai_score"] == pytest.approx(0.99)

def test_classify_record_normal():
    rec = {"message": "User login succeeded for user1"}
    result = ai_module.classify_record(rec)
    assert result["ai_label"] == "normal"
    assert result["ai_score"] == pytest.approx(0.01)

def test_classify_empty_message():
    rec = {"message": ""}
    result = ai_module.classify_record(rec)
    assert result["ai_label"] == ""
    assert result["ai_score"] == 0.0

def test_classify_missing_message_key():
    rec = {}  # no "message" key
    result = ai_module.classify_record(rec)
    assert result["ai_label"] == ""
    assert result["ai_score"] == 0.0

def test_classify_exception(monkeypatch):
    # Force the model to throw an exception
    class BrokenModel:
        def classify(self, text):
            raise RuntimeError("oops")
    monkeypatch.setattr(ai_module, "_model", BrokenModel())

    rec = {"message": "Any log"}
    result = ai_module.classify_record(rec)
    assert result["ai_label"] == "error"
    assert result["ai_score"] == 0.0
