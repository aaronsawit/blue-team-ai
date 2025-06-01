# 🛡️ Blue Team AI - Intelligent Threat Detection System

An AI-powered cybersecurity log analysis tool that combines traditional IOC (Indicator of Compromise) detection with modern AI classification to provide real-time threat intelligence and automated security analysis.

## 🎯 Features

### Core Capabilities
- **RFC5424 Syslog Parsing** - Parse structured syslog data with full field extraction
- **IOC Detection** - Match against custom threat intelligence feeds
- **AI-Powered Classification** - DeepSeek AI analyzes logs with threat context
- **GeoIP Intelligence** - Geographic attribution for IP addresses
- **Multi-IOC Support** - Detect IPs, domains, URLs, and file hashes
- **Real-time Enrichment** - Streaming log analysis and threat scoring

### Threat Intelligence
- **IP Addresses** - Malicious IPs, Tor exit nodes, botnet C2 servers
- **Domains** - Phishing sites, malware distribution, C2 domains  
- **URLs** - Specific malicious endpoints and attack infrastructure
- **File Hashes** - MD5, SHA1, SHA256 malware signatures

### AI Classification System
- **-1 (Malicious)** - Confirmed threats with IOC matches
- **0 (Anomalous)** - Suspicious activity requiring investigation
- **1 (Normal)** - Standard operational baseline activity

## 🚀 Quick Start

### Installation
```bash
git clone https://github.com/aaronsawit/blue-team-ai.git
cd blue-team-ai
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Configuration
1. **Set up OpenRouter API** (for AI classification):
   ```bash
   export OPENROUTER_API_KEY="your_api_key_here"
   ```

2. **Prepare IOC Data** - Create `blue_team_ai/data/iocs.csv`:
   ```csv
   ioc,type,description
   203.0.113.5,ip,Tor exit node
   malware.example.com,domain,Phishing site
   http://evil.example.com/malware.bin,url,Malware download
   5d41402abc4b2a76b9719d911017c592,hash,MD5 malicious payload
   ```

### Usage Examples

#### Basic IOC Detection
```bash
python -m blue_team_ai.cli --file blue_team_ai/data/sample_syslog.log --enrich --ioc blue_team_ai/data/iocs.csv
```

#### Full Analysis with AI and GeoIP
```bash
python -m blue_team_ai.cli --file blue_team_ai/data/sample_syslog.log --enrich --ioc blue_team_ai/data/iocs.csv --geoip --ai -v
```

#### Sample Input Log
```
<34>1 2025-06-01T02:00:00Z host1 sshd 1001 ID99 - Failed password for root from 203.0.113.5 port 22 ssh2
```

#### Sample Output
```json
{
  "message": "Failed password for root from 203.0.113.5 port 22 ssh2",
  "src_ip": "203.0.113.5",
  "ioc_hits": [
    {
      "ioc": "203.0.113.5",
      "type": "ip", 
      "description": "Tor exit node"
    }
  ],
  "geoip": {
    "country": "US",
    "city": "New York"
  },
  "ai_label": "malicious",
  "ai_score": 0.95 #AI Confidence level 
}
```

## 🏗️ Architecture

### Components
- **CLI Module** - Command-line interface and workflow orchestration
- **Parser Module** - RFC5424 syslog parsing (`parsers/parse_logs.py`)
- **Enrichment Engine** - IOC matching and GeoIP integration (`enrichment.py`)
- **Rules Engine** - Detection logic (`rules.py`)
- **Exception Handling** - Custom exceptions for unsupported formats
- **Test Suite** - Comprehensive unit tests for all components

### Data Flow
```
Raw Logs → Parse → IOC Detection → AI Analysis → GeoIP → Enriched Output
```

## 📊 IOC Detection Engine

### Supported IOC Types
| Type | Description | Examples |
|------|-------------|----------|
| IP | IPv4 addresses | `192.0.2.44`, `10.0.0.200` |
| Domain | Domain names | `malware.bad`, `evil-domain.org` |
| URL | Full URLs | `https://phish.example.net/login` |
| Hash | File hashes | MD5, SHA1, SHA256 |

### Pattern Matching
- **Regex-based extraction** for reliable indicator identification
- **Set-based lookup** for O(1) performance on large IOC lists
- **Case-insensitive matching** with normalized comparisons
- **Multiple IOCs per log** support

## 🤖 AI Integration

### Threat Classification
The AI receives enriched context including:
- Original log message
- Matched IOC details and descriptions
- Source IP information
- Threat intelligence context

### Sample AI Prompt
```
You are a cybersecurity expert. Analyze this log and classify the threat level.

LOG MESSAGE: Failed password for root from 203.0.113.5 port 22 ssh2

THREAT INTELLIGENCE MATCHES:
- 203.0.113.5 (ip): Tor exit node

Consider: If there are IOC matches, this is definitely malicious.
Response format: Label: <malicious|anomalous|normal>, Confidence: <0.0-1.0>
```

## 🌍 GeoIP Intelligence

- **Real-time lookups** using ip-api.com
- **Country and city** attribution
- **Private IP handling** - No lookups for RFC1918 addresses
- **Rate limiting respect** with timeout handling

## 📈 Performance

### Benchmarks
- **Parsing**: ~10,000 logs/second
- **IOC Detection**: ~5,000 logs/second  
- **AI Classification**: Limited by API rate limits
- **Memory Usage**: ~50MB for 100k IOCs

### Scalability
- **Streaming processing** for large log files
- **Efficient regex compilation** and caching
- **Set-based IOC lookups** for performance
- **Graceful error handling** for network services

## 🛠️ Development

### Project Structure
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
│       └── iocs.csv            # Threat-intel feed
├── tests/                      # Unit tests
│   ├── test_ai.py
│   ├── test_cli_diagnostic.py
│   ├── test_enrichment.py
│   ├── test_rules.py
│   └── test_parse_logs.py         
├── requirements.txt            # Python dependencies
└── README.md                   # Project overview and usage
```

### Architecture Overview
The system follows a modular pipeline design:
1. **CLI** orchestrates the entire workflow
2. **Parser** extracts structured data from RFC5424 logs
3. **Enrichment** adds IOC matches and GeoIP data
4. **Rules Engine** applies detection logic and scoring
5. **AI Classification** provides context-aware threat analysis

### Processing Pipeline
```
Raw Logs → Parser → Enrichment → Rules Engine → AI Analysis → Output
```

### Adding New IOC Types
1. Update regex patterns in `enrichment.py`
2. Add extraction function for new IOC type
3. Update enrichment logic in the main function
4. Add test cases in `tests/test_enrichment.py`
5. Update IOC CSV with new type examples

### Testing
```bash
# Run all tests
python -m pytest tests/

# Run specific test modules
python -m pytest tests/test_enrichment.py -v
python -m pytest tests/test_rules.py -v

# Test with sample data
python -m blue_team_ai.cli --file blue_team_ai/data/sample_syslog.log --enrich --ioc blue_team_ai/data/iocs.csv -v
```

## 🔧 Configuration

### Environment Variables
- `OPENROUTER_API_KEY` - Required for AI classification
- `GEOIP_TIMEOUT` - GeoIP lookup timeout (default: 2s)
- `LOG_LEVEL` - Logging verbosity (DEBUG, INFO, WARNING, ERROR)

### Command Line Options
```
--file          Input log file (RFC5424 format)
--enrich        Enable IOC enrichment
--ioc           Path to IOC CSV file
--geoip         Enable GeoIP lookups
--ai            Enable AI classification
-v, --verbose   Verbose output
```

## 🚨 Use Cases

### Security Operations Center (SOC)
- **Real-time threat detection** from SIEM exports
- **Alert triage** with AI-powered prioritization
- **Threat hunting** with IOC correlation
- **Incident response** with geographic attribution

### Threat Intelligence
- **IOC validation** against live log data
- **Campaign tracking** across multiple indicators
- **Attribution analysis** with geographic context
- **Feed effectiveness** measurement

### Compliance & Auditing
- **Security event classification** for compliance reporting
- **Log analysis** for audit requirements
- **Threat documentation** with AI explanations
- **Risk assessment** support

## 📋 Requirements

### System Requirements
- Python 3.8+
- 2GB RAM minimum
- Network access for GeoIP and AI services

### Dependencies
- `requests` - HTTP client for API calls
- `openai` - OpenRouter/DeepSeek integration
- `csv` - IOC data parsing
- `re` - Pattern matching
- `pathlib` - File handling

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

### Development Setup
```bash
git clone https://github.com/yourusername/blue-team-ai.git
cd blue-team-ai
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# Run tests to verify setup
python -m pytest tests/
```

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OpenRouter** for free AI API access
- **ip-api.com** for free GeoIP services
- **DeepSeek** for cybersecurity-focused AI models
- **RFC5424** standard for structured logging
