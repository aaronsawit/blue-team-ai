# blue-team-ai

[![tests](https://github.com/aaronsawit/blue-team-ai/actions/workflows/tests.yml/badge.svg)](https://github.com/aaronsawit/blue-team-ai/actions/workflows/tests.yml)

Syslog triage for a blue team: deterministic detection rules decide what is certain, and a language model only gets a vote on what the rules could not settle.

```
syslog line -> parse (RFC 5424) -> detect (rules + IOC match) -> enrich (GeoIP) -> classify (LLM) -> JSON
```

## Why it is built this way

Rules are cheap, explainable and do not hallucinate, so they run first. The model is given the rule hits as context, runs at temperature 0, and must answer in one fixed format (`Label: <malicious|anomalous|normal>, Confidence: <0-1>`). A reply in any other shape is discarded, not guessed at. If the API is down or rate limited, the tool falls back to the rule results and keyword heuristics, so a triage run never fails because a third party did.

## What it detects

| Stage | What it does |
|---|---|
| Parse | RFC 5424 syslog into structured records. Unsupported formats raise a named exception. |
| Rules | SSH brute force by source and time window, suspicious cron entries, IOC hits |
| IOC matching | IPs, domains, URLs and MD5 / SHA1 / SHA256 hashes against a CSV feed |
| Enrich | GeoIP attribution for the source address, plus the matched indicator's description |
| Classify | malicious (-1), anomalous (0) or normal (1), with a confidence score |

## Run it

```bash
git clone https://github.com/aaronsawit/blue-team-ai.git
cd blue-team-ai
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# rules and IOC matching only, no API key needed
python -m blue_team_ai.cli --file blue_team_ai/data/sample_syslog.log --enrich --ioc blue_team_ai/data/iocs.csv

# add GeoIP and the LLM classifier
export OPENROUTER_API_KEY=...
python -m blue_team_ai.cli --file blue_team_ai/data/sample_syslog.log --enrich --ioc blue_team_ai/data/iocs.csv --geoip --ai -v
```

IOC feed format (`blue_team_ai/data/iocs.csv`):

```csv
ioc,type,description
203.0.113.5,ip,Tor exit node
malware.example.com,domain,Phishing site
```

## Tests

```bash
python -m pytest -q
```

36 tests, all offline. The model client is faked, so the classifier's parsing, its refusal of off-format replies and its fallback path are tested without a key or a network.

## Limits

It reads files, not a live stream. GeoIP uses a free public API and is rate limited. The brute-force rule is a simple count per source per window. It is a learning project that I keep honest with tests, not a SIEM.

The same brute-force logic is also written as a Sigma correlation rule in [aaronsawit/detections](https://github.com/aaronsawit/detections).
