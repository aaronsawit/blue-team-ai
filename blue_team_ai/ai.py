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
      - 'ai_label': the predicted label (e.g., 'malicious', 'anomalous', or 'normal')
      - 'ai_score': the confidence score (float)
      - 'threat_level': numeric threat level (-1, 0, 1)

    If anything goes wrong (missing client, invalid response, etc.), returns
    {'ai_label': '', 'ai_score': 0.0, 'threat_level': 0}.
    """
    message = record.get("message", "")
    ioc_hits = record.get("ioc_hits", [])
    src_ip = record.get("src_ip", "")
    
    # Define threat levels mapping
    threat_levels = {
        "malicious": -1,
        "anomalous": 0, 
        "normal": 1
    }
    
    if not message or client is None:
        return {"ai_label": "", "ai_score": 0.0, "threat_level": 0}

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
            "Response format: Label: <malicious|anomalous|normal>, Confidence: <0.0-1.0>"
        )

        response = client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=25,
            temperature=0.0
        )
        
        content = response.choices[0].message.content.strip()

        # Parse response: "Label: malicious, Confidence: 0.95"
        if "Label:" in content and "Confidence:" in content:
            parts = content.split(",")
            label_part = parts[0].split("Label:")[1].strip()
            score_part = parts[1].split("Confidence:")[1].strip()
            
            ai_label = label_part.lower()
            ai_score = float(score_part)
            threat_level = threat_levels.get(ai_label, 0)
            
            return {
                "ai_label": ai_label,
                "ai_score": ai_score,
                "threat_level": threat_level
            }
            
    except Exception as e:
        # Handle rate limiting or other API errors
        error_msg = str(e)
        print(f"AI classification error: {error_msg}", file=sys.stderr)
        
        # Fallback: basic keyword-based classification when AI is unavailable
        if ioc_hits:
            result = {"ai_label": "malicious", "ai_score": 0.8, "threat_level": -1}
            print(f"DEBUG: Returning result with IOC fallback: {result}", file=sys.stderr)
            return result
        elif any(word in message.lower() for word in ["attack", "exploit", "malware", "breach"]):
            result = {"ai_label": "malicious", "ai_score": 0.7, "threat_level": -1}
            print(f"DEBUG: Returning result with attack keywords: {result}", file=sys.stderr)
            return result
        elif any(word in message.lower() for word in ["failed", "blocked", "denied", "suspicious"]):
            result = {"ai_label": "anomalous", "ai_score": 0.6, "threat_level": 0}
            print(f"DEBUG: Returning result with anomaly keywords: {result}", file=sys.stderr)
            return result
        else:
            result = {"ai_label": "normal", "ai_score": 0.5, "threat_level": 1}
            print(f"DEBUG: Returning result with normal fallback: {result}", file=sys.stderr)
            return result
    
    result = {"ai_label": "", "ai_score": 0.0, "threat_level": 0}
    print(f"DEBUG: Returning final fallback result: {result}", file=sys.stderr)
    return result