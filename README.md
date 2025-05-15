# Blue Team AI Assistant

**Blue Team AI** is a modular Python tool for parsing syslog logs, built for security analysts and defenders. It converts RFC5424-formatted syslog data into structured JSON, ready for analysis, ingestion, or downstream automation.

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/your-username/blue-team-ai.git
cd blue-team-ai

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate    # Linux/macOS
# or .venv\Scripts\activate   # Windows

# Install in editable mode
pip install -e .
```

---

## 🚀 Usage

### Exit on first malformed line (default behavior)

```bash
python blue_team_ai/cli.py --file data/sample_syslog.log
```

### Write to an output file (exit on first malformed line)

```bash
python blue_team_ai/cli.py --file data/sample_syslog.log --output output.json
```

### Skip malformed lines, logging warnings

```bash
python blue_team_ai/cli.py --file data/sample_syslog.log --output output.json --ignore-errors
```

### Skip malformed lines and print valid JSON to stdout

```bash
python blue_team_ai/cli.py --file data/sample_syslog.log --ignore-errors
```

**Flags:**

* `-f, --file <FILE>`: Path to the input syslog file (required).
* `-o, --output <FILE>`: Optional path for the JSON output file. If omitted, results print to stdout.
* `-i, --ignore-errors`: When set, malformed lines issue a warning and are skipped; otherwise, the first malformed line triggers an error and exit code 1.

---

## 🧪 Running Tests

```bash
python3 -m pytest -q
```

---

## 📁 Project Structure

```
blue-team-ai/
├── blue_team_ai/
│   ├── cli.py                  # Command-line entrypoint
│   ├── parsers/
│   │   └── parse_logs.py       # Syslog parser logic
│   └── exceptions/
│       └── unsupported_format.py
├── tests/
│   └── test_parse_logs.py      # Unit tests for parser
├── pyproject.toml              # Project metadata
└── README.md                   # You're here
```

---

## ✨ Coming Soon

* Auto-detection of RFC3164 vs RFC5424 formats
* Support for log batching & streaming
* Integration with SIEM or log forwarders

---

## 📝 License

MIT © Your Name or Organization
