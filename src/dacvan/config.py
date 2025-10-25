import os
import logging
from dotenv import load_dotenv

load_dotenv()

class Config:
    def __init__(self):
        # Paths
        self.atomic_red_team_path = os.path.expanduser("~/AtomicRedTeam")
        self.sysmon_config_path = "/etc/sysmon/config.xml"  # For Sysmon on Ubuntu VM

        # Elastic settings (kept for potential hybrid testing or reversion)
        self.elastic_url = os.getenv('ELASTIC_URL', "http://localhost:9200")
        self.elastic_user = os.getenv('ELASTIC_USER', "elastic")
        self.elastic_pass = os.getenv('ELASTIC_PASS', "")

        # Splunk settings (primary for current setup)
        self.splunk_host = os.getenv("SPLUNK_HOST", "192.168.182.1")
        self.splunk_port = os.getenv("SPLUNK_PORT", "8089")
        self.splunk_user = os.getenv("SPLUNK_USER", "admin")
        self.splunk_pass = os.getenv("SPLUNK_PASS", "").strip("'\"")  # Strip quotes/whitespace

        # API Keys (e.g., for Logic Agent)
        self.grok_api_key = os.getenv('GROK_API_KEY', '')

        # Debug mode
        self.debug = os.getenv('DEBUG', 'False').lower() == 'true'

        # Timeouts (in seconds)
        self.api_timeout_secs = 60  # For API calls like Splunk searches

        # Validate config
        self.validate_config()

    def validate_config(self):
        if not self.grok_api_key:
            logging.warning("GROK_API_KEY not set; using mocks for LLM calls")
        if not all([self.splunk_pass, self.splunk_host, self.splunk_user, self.splunk_port]):
            logging.error("Splunk credentials incomplete; connection will fail—check .env for SPLUNK_HOST, SPLUNK_PORT, SPLUNK_USER, SPLUNK_PASS")
        else:
            logging.debug(f"Splunk config loaded: host={self.splunk_host}, port={self.splunk_port}, user={self.splunk_user}")