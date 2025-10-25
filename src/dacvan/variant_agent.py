# variant_agent.py (updated mock to match T1543.002)
import requests
import json
import logging
import os

class VariantAgent:
    def __init__(self, config, debug=False):
        self.config = config
        self.debug = debug
        self.api_url = "https://api.x.ai/v1/chat/completions"
        self.api_key = config.grok_api_key

    def evaluate_variants(self, rule_json):
        if self.debug:
            logging.debug("Starting Variant Agent evaluation")
        
        if os.getenv("GITHUB_ACTIONS"):
            logging.info("Running in CI: Using mock response for Variant Agent")
            return self._mock_response()

        try:
            if self.debug:
                proceed = input("Proceed to Variant Agent LLM query? [y/n]: ")
                if proceed.lower() != "y":
                    logging.debug("Skipped Variant Agent LLM query")
                    return self._mock_response()
            
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
            payload = {
                "model": "grok-beta",
                "messages": [{"role": "user", "content": self._build_prompt(rule_json)}],
                "temperature": 0.7,
                "max_tokens": 1024,
                "stream": False
            }
            response = requests.post(self.api_url, json=payload, headers=headers, timeout=10)
            response.raise_for_status()
            result = response.json()["choices"][0]["message"]["content"]
            result_json = json.loads(result)
            
            logging.info("Variant Agent evaluation completed")
            return result_json
        
        except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
            logging.warning(f"Variant Agent API error: {e}, using mock response")
            return self._mock_response()
        except Exception as e:
            logging.error(f"Variant Agent error: {e}, using mock response")
            return self._mock_response()

    def _build_prompt(self, rule_json):
        return f"""
You are a cybersecurity expert with deep knowledge of MITRE ATT&CK techniques. I have a Sigma rule targeting MITRE ATT&CK technique {rule_json["mitre_technique"]} (e.g., T1543.002 Create or Modify System Process). The rule is:

```yaml
{json.dumps(rule_json, indent=2)}
Please provide a structured JSON response addressing:

Variants: List at least 3 common variants of the technique (e.g., alternative tools, obfuscation methods).
Evasion Potential: For each variant, assess whether it could evade the rule. Explain why.
Detection Recommendations: Suggest rule modifications to cover each variant.
Response Format:
{{
  "variants": [
    {{
      "name": "Variant name",
      "description": "How the variant works",
      "evasion_potential": "High/Medium/Low",
      "evasion_reason": "Why it evades the rule",
      "detection_recommendation": "How to modify the rule",
      "atomic_yaml": "Corresponding Atomic Red Team YAML"
    }}
  ]
}}
"""

    def _mock_response(self):
        """Return a mock LLM response for T1543.002."""
        return {
            "variants": [
                {
                    "name": "Obfuscated Systemd Service Creation",
                    "description": "Creates a systemd service with obfuscated file paths using environment variables.",
                    "evasion_potential": "High",
                    "evasion_reason": "Rule checks for literal paths '/etc/systemd/' or '.service', misses variable-based paths.",
                    "detection_recommendation": "Add regex to match environment variable expansions in file_path.",
                    "atomic_yaml": """attack_technique: T1543.002
atomic_tests:
- name: Obfuscated Systemd Service
  description: Create a service with an obfuscated path.
  supported_platforms: [linux]
  executor:
    name: bash
    command: |
      SERVICE_PATH=$HOME/.hidden/systemd; mkdir -p $SERVICE_PATH; echo "[Unit]\nDescription=Obfuscated Service\n[Service]\nExecStart=/bin/bash -c 'echo test'\n[Install]\nWantedBy=multi-user.target" > $SERVICE_PATH/test.service; systemctl link $SERVICE_PATH/test.service
"""
                },
                {
                    "name": "Alternative Service Manager",
                    "description": "Uses a non-systemd service manager like OpenRC to create a service.",
                    "evasion_potential": "Medium",
                    "evasion_reason": "Rule targets process.name='systemd', misses other service managers.",
                    "detection_recommendation": "Include process.name='rc-service' or other managers in detection.",
                    "atomic_yaml": """attack_technique: T1543.002
atomic_tests:
- name: OpenRC Service Creation
  description: Create a service using OpenRC.
  supported_platforms: [linux]
  executor:
    name: bash
    command: |
      echo '#!/bin/sh\nsleep 3600' > /etc/init.d/testsvc; chmod +x /etc/init.d/testsvc; rc-update add testsvc default
"""
                },
                {
                    "name": "Dynamic Service File Modification",
                    "description": "Modifies an existing .service file dynamically via script.",
                    "evasion_potential": "High",
                    "evasion_reason": "Rule focuses on creation, misses modifications to existing services.",
                    "detection_recommendation": "Add file modification events for .service files in logsource.",
                    "atomic_yaml": """attack_technique: T1543.002
atomic_tests:
- name: Modify Systemd Service
  description: Modify an existing systemd service file.
  supported_platforms: [linux]
  executor:
    name: bash
    command: |
      echo "ExecStart=/bin/bash -c 'malicious'" >> /etc/systemd/system/existing.service; systemctl daemon-reload
"""
                }
            ]
        }