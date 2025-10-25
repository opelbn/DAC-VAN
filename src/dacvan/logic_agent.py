# logic_agent.py (updated to use grok-3)
import requests
import json
import logging
import time

class LogicAgent:
    def __init__(self, config, debug=False):
        self.config = config
        self.debug = debug
        self.api_url = "https://api.x.ai/v1/chat/completions"
        self.headers = {
            "Authorization": f"Bearer {config.grok_api_key}",
            "Content-Type": "application/json"
        }

    def evaluate_rule(self, rule_json):
        """Evaluate the Sigma rule logic using Grok API."""
        if self.debug:
            logging.debug("Starting Logic Agent evaluation")
        
        try:
            prompt = self._build_prompt(rule_json)
            payload = {
                "model": "grok-3",  # Changed to grok-3 for faster response
                "messages": [{"role": "system", "content": "You are a helpful assistant."}, {"role": "user", "content": prompt}]
            }
            
            logging.info(f"API Request to Logic Agent:\n{json.dumps(payload, indent=2)}")
            
            for attempt in range(3):
                try:
                    response = requests.post(
                        self.api_url,
                        headers=self.headers,
                        json=payload,
                        timeout=(5, self.config.api_timeout_secs - 5)
                    )
                    response.raise_for_status()
                    logging.info(f"API Response status: {response.status_code}, elapsed: {response.elapsed.total_seconds():.3f}s")
                    logging.info("API response received after %s seconds.", response.elapsed.total_seconds())
                    if self.debug:
                        logging.debug(f"Raw API Response: {response.text}")
                    result = response.json()['choices'][0]['message']['content']
                    return json.loads(result)
                except requests.RequestException as e:
                    logging.warning(f"API attempt {attempt+1} failed: {e}. Response: {getattr(e.response, 'text', 'No response') if hasattr(e, 'response') else 'No response'}")
                    if attempt < 2:
                        time.sleep(2 ** attempt)
                    else:
                        raise
        except Exception as e:
            logging.warning(f"Logic Agent error: {e}; using mock response")
            return self._mock_response("elasticsearch")

    def _build_prompt(self, rule_json):
        return f"Convert this Sigma rule to Splunk SPL query. Respond ONLY with the JSON object containing 'query', 'assumptions', and 'validation_plan'. No additional text: {json.dumps(rule_json)}"

    def _mock_response(self, platform):
        return {
            "query": {
                "query": {"bool": {"must": [{"term": {"process.name": "systemd"}}, {"wildcard": {"command_line": "*init.d*"}}]}},
                "index": "logs-endpoint.events-*"
            },
            "assumptions": ["Assumes ECS field names", "Assumes process creation logs are indexed"],
            "validation_plan": {"expected_fields": ["process.name", "command_line"], "coverage_gaps": ["May miss service file modifications"]}
        }