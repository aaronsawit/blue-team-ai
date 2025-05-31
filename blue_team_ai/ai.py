#!/usr/bin/env python3
"""
blue_team_ai/ai.py — AI classification using DeepSeek via OpenRouter.

This module sends a chat completion request to OpenRouter's DeepSeek model
(deepseek/deepseek-chat). It expects the environment variable DEEPSEEK_API_KEY
to be set (your OpenRouter key). If the key is missing or invalid, or if the
response structure is unexpected, this will fall back to {"ai_label":"", "ai_score":0.0}.
"""

import os
import sys
from typing import Dict, Any

try:
    from openai import OpenAI

    key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    if not key:
        raise ValueError("DEEPSEEK_API_KEY not set")

    client = OpenAI(
        api_key=key,
        base_url="https://openrouter.ai/api/v1"
    )
    model_name = "deepseek/deepseek-chat:free"  # Use ":free" suffix if you're on the free tier

except Exception as e:
    print(f"[OpenRouter Setup Error] {e}", file=sys.stderr)
    client = None
    model_name = None

def classify_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Classify a log record's 'message' using DeepSeek (via OpenRouter).
    Returns a dict with keys:
      - 'ai_label': the predicted label (e.g., 'anomaly' or 'normal')
      - 'ai_score': the confidence score (float)

    If anything goes wrong (missing client, invalid response, etc.), returns
    {'ai_label': '', 'ai_score': 0.0}.
    """
    message = record.get("message", "")
    if not message or client is None:
        return {"ai_label": "", "ai_score": 0.0}

    try:
        prompt = (
            "You are a security log classifier. Answer **only** in the format:"
            "Label: <<normal|anomaly>>, Score: <float>\n\n"
            "Do not add any extra text or explanation.\n\n"
            f"{message}"
        )

        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": "You are a security log classifier."},
                {"role": "user",   "content": prompt}
            ],
            temperature=0.0,
            max_tokens=50
        )

        # The OpenAI client returns a ChatCompletion object, not a dict
        # Access attributes directly, not with .get()
        if not response.choices:
            print(f"[OpenRouter Empty Choices] {response}", file=sys.stderr)
            return {"ai_label": "", "ai_score": 0.0}

        content = response.choices[0].message.content
        if not content:
            print(f"[OpenRouter Empty Content] {response}", file=sys.stderr)
            return {"ai_label": "", "ai_score": 0.0}

        content = content.strip()

        # Expect something like: "Label: Anomaly, Score: 0.92"
        if "Label:" in content and "Score:" in content:
            parts = content.split(",")
            if len(parts) >= 2:
                # Extract label
                label_part = parts[0].split("Label:")[1].strip()
                # Extract score
                try:
                    score_part = parts[1].split("Score:")[1].strip()
                    score = float(score_part)
                except (ValueError, IndexError) as e:
                    print(f"[Score Parse Error] {e} | score_part: '{parts[1] if len(parts) > 1 else 'N/A'}'", file=sys.stderr)
                    score = 0.0
                return {"ai_label": label_part, "ai_score": score}
            else:
                print(f"[Parse Error] Not enough parts after split: {parts}", file=sys.stderr)
                return {"ai_label": content, "ai_score": 0.0}
        else:
            # Unexpected format—dump for debugging
            print(f"[OpenRouter Unexpected Format] content='{content}'", file=sys.stderr)
            return {"ai_label": content, "ai_score": 0.0}

    except Exception as ex:
        print(f"[OpenRouter Classification Error] {ex}", file=sys.stderr)
        return {"ai_label": "error", "ai_score": 0.0}