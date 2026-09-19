"""Tests for blue_team_ai.ai.classify_record.

The OpenRouter client is replaced with a fake, so these run offline and never need an API key.
"""
from types import SimpleNamespace

import pytest

import blue_team_ai.ai as ai_module


class FakeClient:
    """Stands in for openai.OpenAI: returns a canned reply, or raises."""

    def __init__(self, reply=None, error=None):
        self.reply, self.error, self.prompts = reply, error, []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.prompts.append(kwargs["messages"][0]["content"])
        if self.error:
            raise self.error
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=self.reply))])


def use(monkeypatch, client):
    monkeypatch.setattr(ai_module, "client", client)
    monkeypatch.setattr(ai_module, "model_name", "test-model")
    return client


def test_parses_a_well_formed_reply(monkeypatch):
    use(monkeypatch, FakeClient("Label: malicious, Confidence: 0.95"))
    result = ai_module.classify_record({"message": "Failed password for root from 203.0.113.5"})
    assert result == {"ai_label": "malicious", "ai_score": pytest.approx(0.95), "threat_level": -1}


def test_ioc_hits_are_given_to_the_model_as_context(monkeypatch):
    client = use(monkeypatch, FakeClient("Label: malicious, Confidence: 0.9"))
    ai_module.classify_record({
        "message": "connection from 203.0.113.5",
        "ioc_hits": [{"ioc": "203.0.113.5", "type": "ip", "description": "Tor exit node"}],
    })
    assert "203.0.113.5" in client.prompts[0] and "Tor exit node" in client.prompts[0]


def test_off_format_reply_is_discarded_not_guessed(monkeypatch):
    use(monkeypatch, FakeClient("This log looks quite dangerous to me."))
    result = ai_module.classify_record({"message": "something happened"})
    assert result == {"ai_label": "", "ai_score": 0.0, "threat_level": 0}


def test_empty_or_missing_message_never_calls_the_model(monkeypatch):
    client = use(monkeypatch, FakeClient("Label: normal, Confidence: 0.9"))
    assert ai_module.classify_record({"message": ""})["ai_label"] == ""
    assert ai_module.classify_record({})["ai_label"] == ""
    assert client.prompts == []


def test_no_client_configured_returns_the_empty_result(monkeypatch):
    monkeypatch.setattr(ai_module, "client", None)
    assert ai_module.classify_record({"message": "anything"}) == {"ai_label": "", "ai_score": 0.0, "threat_level": 0}


def test_api_failure_with_ioc_hit_falls_back_to_malicious(monkeypatch):
    use(monkeypatch, FakeClient(error=RuntimeError("rate limited")))
    result = ai_module.classify_record({
        "message": "connection accepted",
        "ioc_hits": [{"ioc": "203.0.113.5", "type": "ip", "description": "Tor exit node"}],
    })
    assert result["ai_label"] == "malicious" and result["threat_level"] == -1


def test_api_failure_falls_back_to_keywords(monkeypatch):
    use(monkeypatch, FakeClient(error=RuntimeError("rate limited")))
    assert ai_module.classify_record({"message": "Failed password for admin"})["ai_label"] == "anomalous"
    assert ai_module.classify_record({"message": "Accepted publickey for deploy"})["ai_label"] == "normal"
