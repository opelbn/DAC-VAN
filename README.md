# DAC-VAN: Detection-As-Code Validation, Automation, and Notation

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

DAC-VAN is a Python-based tool designed to validate, enhance, and test Sigma detection rules against MITRE ATT&CK techniques. It integrates AI-driven analysis (using LLM APIs for logic conversion and variant evaluation), Atomic Red Team (ART) simulations for technique emulation, and log querying via API in SIEM systems like Splunk or Elasticsearch. The pipeline helps cybersecurity researchers and engineers assess the effectiveness of detection rules by identifying logic gaps, evasion variants, and real-world detection performance.

This project is in an early development state and is intended for use in isolated lab environments. **Warning:** Running Atomic Red Team tests or querying production SIEMs can have unintended consequences—use with caution.

## Features

- **Sigma Rule Parsing and Validation:** Parse YAML-based Sigma rules, extract key fields (e.g., MITRE technique, detection logic), and perform structural/semantic validation.
- **Logic Agent:** Uses Grok API to convert Sigma rules into SIEM-specific queries (e.g., Splunk SPL or Elasticsearch DSL). Includes assumptions and validation plans.
- **Variant Agent:** Leverages Grok API to identify common variants of MITRE techniques, assess evasion potential, and recommend rule improvements.
- **Atomic Handler:** Executes Atomic Red Team tests for the associated MITRE technique to simulate attacks and generate test data.
- **SIEM Handlers (Splunk/Elastic):** Queries logs in Splunk or Elasticsearch using generated queries, computes metrics like true positives/false negatives based on ART results.
- **CLI Interface:** Selective execution via flags (e.g., parse-only, full pipeline) with timing metrics and debug logging.
- **Mock Responses:** Fallback to mock data for agents/handlers during errors or CI/testing.
- **Concurrency:** Asynchronous execution for Logic and Variant Agents in full mode.
- **Logging:** Detailed logging with timestamps, console/file output, and CI-friendly redirection.

## Prerequisites

- Python 3.8+
- Access to Grok API (xAI) for Logic and Variant Agents (requires an API key).
- Atomic Red Team installed and configured (path specified in config).
- Splunk or Elasticsearch instance for log querying (credentials in config).
- Virtual environment recommended for dependency isolation.

Dependencies (install via `pip`):
- `requests`
- `pyyaml`
- `elasticsearch`
- `splunk-sdk`
- `atomic-operator` (for Atomic Handler)
- Other libs as imported (e.g., `subprocess`, `logging`, `asyncio`, `json`, `re`, `time`, `os`, `sys`, `argparse`)

## Installation

1. Clone the repository:
git clone https://github.com/your-repo/mcp-pipeline.git
cd mcp-pipeline
text2. Set up a virtual environment:
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
text3. Install dependencies:
pip install requests pyyaml elasticsearch splunk-sdk atomic-operator
text4. Create a `config.json` file in the project root (see Configuration section below).

2. (Optional) For Atomic Red Team:
- Install Atomic Red Team: Follow instructions at [Atomic Red Team GitHub](https://github.com/redcanaryco/atomic-red-team).
- Update `atomic_red_team_path` in `config.json` to point to your ART installation.

## Configuration

Create a `config.json` file in the project root with the following structure:

```json
{
"grok_api_key": "your_grok_api_key_here",
"debug": true,  // Enable debug logging (default: false)
"api_timeout_secs": 30,  // Timeout for API calls
"atomic_red_team_path": "/path/to/atomic-red-team",
"splunk_host": "[splunkhost]",
"splunk_port": 8089,
"splunk_user": "admin",
"splunk_pass": "your_password",
"elastic_url": "http://[splunk_ip]:9200",
"elastic_user": "elastic",
"elastic_pass": "your_password",
"siem_platform": "splunk"  // or "elasticsearch"
}
```

--Current build assumes you're running the pipeline on the same linux host as you've installed Atomic Red Team.  See TODO.
--Grok API Key: Required for Logic and Variant Agents. Obtain from xAI Developer Portal.
--SIEM Credentials: Update for your Splunk or Elasticsearch setup.
--Debug Mode: Enables verbose logging and interactive prompts (e.g., "Proceed? [y/n]").

## Usage
Run the pipeline via client.py with optional flags. The default rule path is rules/rule.yml (relative to repo root).
Basic Command
textpython client.py [rule_path] [flags]
Flags

--parse-only: Run only Sigma parsing and validation.
--logic: Run parsing + Logic Agent (converts rule to SIEM query).
--variant: Run parsing + Variant Agent (identifies evasions and recommendations).
--atomic: Run parsing + Atomic Handler (executes ART tests).
--elastic: Run parsing + Logic Agent + SIEM Handler (queries logs; supports Splunk/Elastic based on config).
--full: Run the full pipeline (default if no flag provided).

Examples:

Parse and validate a rule:
```textpython client.py rules/my_rule.yml --parse-only```

Full pipeline on a custom rule:
```textpython client.py rules/my_rule.yml --full```

Logic conversion only:
```textpython client.py --logic```


Output

Results are logged to console (and validation_output.txt in debug mode).
Includes parsed rule details, agent results, ART test outcomes, SIEM query hits, and timings.
Example log snippet:
```textMCP Pipeline Results:
Title: My Sigma Rule
MITRE Technique: T1059
Detection: {...}
Logic Agent Result: {...}
Variant Agent Result: {...}
Atomic Red Team Result: {...}
Elastic Stack Result: {...}
Timings: {'parsing': '0.123s', 'total': '5.678s'}
```

### Running in CI (e.g., GitHub Actions)

Set GITHUB_ACTIONS env var: Logs redirect to validation_output.txt.
Agents use mock responses to avoid live API calls.
No interactive prompts.

### Debug Mode

Enable in config.json ("debug": true).
Adds verbose logs, raw API responses, and interactive confirmation prompts.
Logs to validation_output.txt for auditing.

### Project Structure

client.py: Main CLI entrypoint and pipeline orchestrator.
sigma_parser.py: Parses and validates Sigma rules.
logic_agent.py: Converts rules to SIEM queries via Grok API.
variant_agent.py: Evaluates technique variants via Grok API.
atomic_handler.py: Runs Atomic Red Team tests.
splunk_handler.py: Queries Splunk logs.
elastic_handler.py: Queries Elasticsearch logs.
config.py: Loads configuration (assumed; not provided in query but implied).
rules/: Directory for Sigma rule YAML files (e.g., rule.yml).
Attached Documents: Example PDFs/DOCs (e.g., IoT security paper, SANS white paper template) for reference or testing attachments.

### Limitations and Warnings

Security Risks: ART tests simulate attacks—run in isolated environments only.
API Dependencies: Requires Grok API access; mock responses used on failure.
SIEM Support: Currently supports Splunk (default) or Elasticsearch; configure via siem_platform.
Timeouts: ART tests have a 30s timeout; may need adjustment for complex techniques.
Elevation: Some ART tests require sudo; detected automatically from YAML.
Mock Data: Used in CI or errors; based on T1059 example.

### Contributing
Contributions welcome! Fork the repo, create a branch, and submit a PR. Focus on:

1) Adding support for more SIEMs.
2) Enhancing prompt engineering for agents.
3) Improving error handling and tests.

### TODO
1) unscrew many things

License
MIT License. See LICENSE for details.
For questions, contact [your-email@example.com].