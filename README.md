# Blue Team AI Assistant

**Blue Team AI** is a modular Python CLI tool for parsing, enriching, and alerting on syslog logs.

It provides:

* **Parsing** of RFC5424 syslog lines into structured JSON
* **Enrichment** of records with IOC tagging
* **Rule-based detection** for brute-force, suspicious cron, and IOC hits


## Future Addition
* **GeoI IntegrationP** GeoIP enrichment adds geographic context to your parsed logs by looking up each IP address against a local GeoIP database (e.g. MaxMind’s GeoLite2-City .mmdb).
* **AI Summary Integation**  To turn structured alerts into human‐readable summaries or deeper analysis, you can pipe your final JSON (parsed/enriched/alerted) into an LLM.

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/aaronsawit/blue-team-ai.git
cd blue-team-ai

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

### 1. Parse Syslog

Convert RFC5424 logs to JSON:

```bash
python3 -m blue_team_ai.cli \
  --file blue_team_ai/data/sample_syslog.log
```

### 2. Write to Output File

Save parsed JSON to a file:

```bash
python3 -m blue_team_ai.cli \
  --file blue_team_ai/data/sample_syslog.log \
  --output output.json
```

### 3. Enrich Records

Tag IOCs in parsed records:

```bash
python3 -m blue_team_ai.cli \
  --file blue_team_ai/data/sample_syslog.log \
  --enrich \
  --ioc-file blue_team_ai/data/iocs.csv
```

### 4. Apply Alert Rules

Detect anomalies and IOC hits:

```bash
python3 -m blue_team_ai.cli \
  --file blue_team_ai/data/sample_syslog.log \
  --enrich --rules \
  --ioc-file blue_team_ai/data/iocs.csv \
  --output alerts.json
```

#### Available Flags

| Flag           | Description                                               |
| -------------- | --------------------------------------------------------- |
| `-f, --file`   | Path to input syslog file (required)                      |
| `-o, --output` | Path to write JSON output (prints to stdout if omitted)   |
| `-e, --enrich` | Enable IOC enrichment                                     |
| `--ioc-file`   | IOC CSV feed path (default: `blue_team_ai/data/iocs.csv`) |
| `-r, --rules`  | Enable rule-based alert detection                         |

---

## 🧪 Running Tests

Run all unit tests:

```bash
pytest -v
```

---

## 📁 Project Structure For Future Use

```
blue-team-ai/
├── blue_team_ai/
│   ├── cli.py                  # CLI entrypoint (parse → enrich → rules)
│   ├── parsers/parse_logs.py   # RFC5424 parsing logic
│   ├── enrichment.py           # IOC & GeoIP enrichment functions
│   ├── rules.py                # Rule-based detection engine
│   ├── exceptions/             # Custom exception(s)
│   │   └── unsupported_format.py
│   └── data/                   # Sample data files
│       ├── sample_syslog.log   # Example syslog entries
│       ├── iocs.csv            # Threat-intel feed
│       └── GeoLite2-City.mmdb  # GeoIP database (optional)
├── tests/                      # Unit tests
│   ├── test_parse_logs.py
│   ├── test_enrichment.py
│   ├── test_rules.py
│   ├── test_schema.py          # Yet to add
│   └── test_prompt.py          # Yet to add
├── requirements.txt            # Python dependencies
└── README.md                   # Project overview and usage
```

---

## 📝 License

This tool is provided as-is for educational and security research purposes.
