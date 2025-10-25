# src/dacvan/config.py
import os
import json
import logging

class Config:
    def __init__(self):
        # Set attributes directly in __init__
        self._debug = os.getenv("DEBUG", "false").lower() == "true"
        config_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "config.json")
        self._config = self._load_config(config_path)

    def _load_config(self, config_path):
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
                logging.info(f"Loaded config from {config_path}")
                return config
        except FileNotFoundError:
            logging.error(f"{config_path} not found")
            return {
                "grok_api_key": os.getenv("GROK_API_KEY", ""),
                "debug": os.getenv("DEBUG", "false").lower() == "true",
                "api_timeout_secs": os.getenv("API_TIMEOUT_SECS", 30),
                "atomic_red_team_path": os.getenv("ATOMIC_RED_TEAM_PATH", "/path/to/atomic-red-team"),
                "splunk_host": os.getenv("SPLUNK_HOST", "[splunkhost]"),
                "splunk_port": os.getenv("SPLUNK_PORT", 8089),
                "splunk_user": os.getenv("SPLUNK_USER", "admin"),
                "splunk_pass": os.getenv("SPLUNK_PASS", "your_password"),
                "elastic_url": os.getenv("ELASTIC_URL", "http://[elasticip]:9200"),
                "elastic_user": os.getenv("ELASTIC_USER", "elastic"),
                "elastic_pass": os.getenv("ELASTIC_PASS", "your_password"),
                "siem_platform": os.getenv("SIEM_PLATFORM", "splunk"),
                "index_names": {"elasticsearch": "sysmon-*", "splunk": "linux:process"},
                "field_mappings": {"process.name": "process.name", "command_line": "command_line"},
                "pipeline_context": {"ci_cd": "GitHub Actions runner", "runner_details": "self-hosted on Ubuntu VM"}
            }
        except json.JSONDecodeError as e:
            logging.error(f"Invalid {config_path}: {e}")
            return {
                "grok_api_key": os.getenv("GROK_API_KEY", ""),
                "debug": os.getenv("DEBUG", "false").lower() == "true",
                "api_timeout_secs": os.getenv("API_TIMEOUT_SECS", 30),
                "atomic_red_team_path": os.getenv("ATOMIC_RED_TEAM_PATH", "/path/to/atomic-red-team"),
                "splunk_host": os.getenv("SPLUNK_HOST", "[splunkhost]"),
                "splunk_port": os.getenv("SPLUNK_PORT", 8089),
                "splunk_user": os.getenv("SPLUNK_USER", "admin"),
                "splunk_pass": os.getenv("SPLUNK_PASS", "your_password"),
                "elastic_url": os.getenv("ELASTIC_URL", "http://[elasticip]:9200"),
                "elastic_user": os.getenv("ELASTIC_USER", "elastic"),
                "elastic_pass": os.getenv("ELASTIC_PASS", "your_password"),
                "siem_platform": os.getenv("SIEM_PLATFORM", "splunk"),
                "index_names": {"elasticsearch": "sysmon-*", "splunk": "linux:process"},
                "field_mappings": {"process.name": "process.name", "command_line": "command_line"},
                "pipeline_context": {"ci_cd": "GitHub Actions runner", "runner_details": "self-hosted on Ubuntu VM"}
            }

    @property
    def debug(self):
        return self._debug

    @property
    def grok_api_key(self):
        return self._config.get("grok_api_key", os.getenv("GROK_API_KEY", ""))

    @property
    def api_timeout_secs(self):
        return self._config.get("api_timeout_secs", os.getenv("API_TIMEOUT_SECS", 30))

    @property
    def atomic_red_team_path(self):
        return self._config.get("atomic_red_team_path", os.getenv("ATOMIC_RED_TEAM_PATH", "/path/to/atomic-red-team"))

    @property
    def splunk_host(self):
        return self._config.get("splunk_host", os.getenv("SPLUNK_HOST", "[splunkhost]"))

    @property
    def splunk_port(self):
        return self._config.get("splunk_port", os.getenv("SPLUNK_PORT", 8089))

    @property
    def splunk_user(self):
        return self._config.get("splunk_user", os.getenv("SPLUNK_USER", "admin"))

    @property
    def splunk_pass(self):
        return self._config.get("splunk_pass", os.getenv("SPLUNK_PASS", "your_password"))

    @property
    def elastic_url(self):
        return self._config.get("elastic_url", os.getenv("ELASTIC_URL", "http://[elasticip]:9200"))

    @property
    def elastic_user(self):
        return self._config.get("elastic_user", os.getenv("ELASTIC_USER", "elastic"))

    @property
    def elastic_pass(self):
        return self._config.get("elastic_pass", os.getenv("ELASTIC_PASS", "your_password"))

    @property
    def siem_platform(self):
        return self._config.get("siem_platform", os.getenv("SIEM_PLATFORM", "splunk"))

    @property
    def index_names(self):
        return self._config.get("index_names", {"elasticsearch": "sysmon-*", "splunk": "linux:process"})

    @property
    def field_mappings(self):
        return self._config.get("field_mappings", {"process.name": "process.name", "command_line": "command_line"})

    @property
    def pipeline_context(self):
        return self._config.get("pipeline_context", {"ci_cd": "GitHub Actions runner", "runner_details": "self-hosted on Ubuntu VM"})