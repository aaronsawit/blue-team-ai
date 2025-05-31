#!/usr/bin/env python3
"""
blue_team_ai/ai.py — AI classification (DeepSeek) for log messages.
"""
from typing import Dict, Any
from deepseek import DeepSeek

# Load the lightweight local DeepSeek model once. Adjust model_name if needed.
_model = DeepSeek(model_name="small")

def classify_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Classify a record's "message" field as 'normal' or 'anomaly'.
    Returns a dict with keys:
      - 'ai_label': the predicted label (e.g., "anomaly" or "normal")
      - 'ai_score': the confidence score (float)
    On any failure, returns {'ai_label': 'error', 'ai_score': 0.0}.
    """
    message = record.get("message", "")
    if not message:
        return {"ai_label": "", "ai_score": 0.0}
    try:
        result = _model.classify(message)
        return {
            "ai_label": result.get("label", ""),
            "ai_score": float(result.get("score", 0.0))
        }
    except Exception:
        return {"ai_label": "error", "ai_score": 0.0}
