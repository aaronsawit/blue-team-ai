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
    Now includes IOC context for accurate AI scoring.
    Returns a dict with keys:
      - 'ai_label': the predicted label (e.g., 'anomaly' or 'normal')
      - 'ai_score': the confidence score (float)

    If anything goes wrong (missing client, invalid response, etc.), returns
    {'ai_label': '', 'ai_score': 0.0}.
    """
    message = record.get("message", "")
    ioc_hits = record.get("ioc_hits", [])
    src_ip = record.get("src_ip", "")
    
    if not message or client is None:
        return {"ai_label": "", "ai_score": 0.0}

    try:
        # Build context about IOC hits
        ioc_context = ""
        if ioc_hits:
            ioc_details = []
            for hit in ioc_hits:
                ioc_details.append(f"- {hit['ioc']} ({hit['type']}): {hit['description']}")
            ioc_context = f"\n\nTHREAT INTELLIGENCE MATCHES:\n" + "\n".join(ioc_details)
        
        prompt = (
            "You are a cybersecurity expert. Analyze this log and classify the threat level.\n\n"
            "SCORING SYSTEM:\n"
            "• malicious (-1): Confirmed threats, IOC matches, successful attacks\n"  
            "• anomalous (0): Suspicious activity, failed attempts, unusual patterns\n"
            "• normal (1): Routine operations, successful logins, standard traffic\n\n"
            f"LOG MESSAGE: {message}"
            f"{ioc_context}\n\n"
            "Consider: If there are IOC matches, this is definitely malicious. "
            "Failed logins, blocked connections = anomalous. "
            "Regular operations = normal.\n\n"
            "Response format: Label: <malicious|anomalous|normal>, Score: <0.0-1.0>"
        )

        response = client.chat.completions.create(
            model="deepseek/deepseek-chat:free",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=25,
            temperature=0.0
        )
        
        content = response.choices[0].message.content.strip()
        
        # Parse response: "Label: malicious, Score: 0.95"
        if "Label:" in content and "Score:" in content:
            parts = content.split(",")
            label_part = parts[0].split("Label:")[1].strip()
            score_part = parts[1].split("Score:")[1].strip()
            
            return {
                "ai_label": label_part.lower(),
                "ai_score": float(score_part)
            }
            
    except Exception as e:
        print(f"AI classification error: {e}")
    
    return {"ai_label": "", "ai_score": 0.0}