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
source .venv/bin/activate

# Install in editable mode
pip install -e .
```

---

## 🚀 Usage

### CLI Mode

Parse a syslog file and print structured JSON output:

```bash
python blue_team_ai/cli.py --file data/sample_syslog.log
```

Save output to a file:

```bash
python blue_team_ai/cli.py --file data/sample_syslog.log --output output.json
```

---

## 🧪 Running Tests

Make sure you're in the virtual environment:

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
│   │   └── parse_logs.py       # Syslog parser
│   └── exceptions/
│       └── unsupported_format.py
├── tests/
│   └── test_parse_logs.py      # Unit tests for parser
├── pyproject.toml              # Project metadata
├── README.md                   # You're here
└── .venv/                      # Virtual environment (not committed)
```

---

## ✨ Coming Soon

* Auto-detection of RFC3164 vs RFC5424 formats
* Support for log batching & streaming
* Integration with SIEM or log forwarders

---

## 📝 License

This project is licensed under the MIT License.
