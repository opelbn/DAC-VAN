# src/dacvan/siem_handler.py
import logging
from elasticsearch import Elasticsearch
import splunklib.client as client
import splunklib.results as results
import json
from typing import Dict, Any, Optional

class SIEMHandler:
    _platform_handlers = {
        "elasticsearch": {
            "connect": lambda config: Elasticsearch(config.elastic_url, basic_auth=(config.elastic_user, config.elastic_pass)),
            "query": lambda client, query, index, field_mappings: client.search(index=index, body={"query": query})["hits"]["total"]["value"],
            "metrics": lambda hits, art_results: {
                "true_positives": 1 if any(test["status"] == "Success" for test in art_results.get("tests", [])) and hits > 0 else 0,
                "false_negatives": 1 if any(test["status"] == "Success" for test in art_results.get("tests", [])) and hits == 0 else 0,
                "false_positives": 1 if not any(test["status"] == "Success" for test in art_results.get("tests", [])) and hits > 0 else 0
            }
        },
        "splunk": {
            "connect": lambda config: client.connect(host=config.splunk_host, port=config.splunk_port, username=config.splunk_user, password=config.splunk_pass, verify=False),
            "query": lambda client, query, index, field_mappings: self._execute_splunk_query(client, query, index, field_mappings),
            "metrics": lambda hits, art_results: {"true_positives": hits if hits > 0 else 0, "false_negatives": 0, "false_positives": 0}
        }
    }

    def __init__(self, config, debug=False):
        self.config = config
        self.debug = debug
        self.siem_platform = config.siem_platform
        self.index_names = config.index_names
        self.field_mappings = config.field_mappings or {}
        self.pipeline_context = config.pipeline_context
        self._client = None
        self._initialize_connection()

    def _initialize_connection(self):
        handler = self._platform_handlers.get(self.siem_platform)
        if not handler:
            logging.error(f"Unsupported SIEM platform: {self.siem_platform}")
            return
        try:
            self._client = handler["connect"](self.config)
            logging.info(f"Connected to {self.siem_platform} successfully")
        except Exception as e:
            logging.error(f"Connection error for {self.siem_platform}: {e}")
            self._client = None

    def _execute_splunk_query(self, client, query, index, field_mappings):
        kwargs = {"earliest_time": "-24h", "latest_time": "now", "exec_mode": "normal"}
        job = client.jobs.create(query, **kwargs)
        while not job.is_ready():
            pass
        reader = results.ResultsReader(job.results())
        hits = 0
        for _ in reader:
            hits += 1
        return hits

    def _discover_field_mappings(self):
        if self.siem_platform == "splunk" and self._client:
            fields = []
            search_query = f'search index="{self.index_names.get("splunk", "linux:process")}" sourcetype="sysmon:linux" | fieldsummary'
            kwargs = {"earliest_time": "-24h", "latest_time": "now", "exec_mode": "normal"}
            job = self._client.jobs.create(search_query, **kwargs)
            while not job.is_ready():
                pass
            reader = results.ResultsReader(job.results())
            for result in reader:
                if result.get("field") not in ["_time", "_raw"]:
                    fields.append(result.get("field"))
            return {k: k for k in fields}  # Default mapping, can be refined
        elif self.siem_platform == "elasticsearch" and self._client:
            mappings = self._client.indices.get_mapping()
            fields = []
            for index in mappings:
                for prop in mappings[index]["mappings"].get("properties", {}):
                    fields.append(prop)
            return {k: k for k in fields}  # Default mapping
        return self.field_mappings

    def query_logs(self, rule_json, logic_result, art_results=None):
        if self.debug:
            logging.debug(f"Querying {self.siem_platform} logs")
        
        technique = rule_json["mitre_technique"]
        try:
            if self.debug:
                proceed = input(f"Proceed to {self.siem_platform} query? [y/n]: ")
                if proceed.lower() != "y":
                    logging.debug(f"Skipped {self.siem_platform} query")
                    return self._mock_response()
            
            if not self._client:
                raise ValueError(f"No connection to {self.siem_platform}")

            field_mappings = self._discover_field_mappings()
            query = logic_result.get("query", {})
            index = self.index_names.get(self.siem_platform, "default")
            hits = self._platform_handlers[self.siem_platform]["query"](self._client, query, index, field_mappings)

            metrics = self._platform_handlers[self.siem_platform]["metrics"](hits, art_results)
            
            logging.info(f"{self.siem_platform} query completed for {technique}")
            return {
                "query": query,
                "index": index,
                "hits": hits,
                **metrics,
                "events": []  # Simplified, adjust based on need
            }
        except Exception as e:
            logging.warning(f"{self.siem_platform} Handler error: {e}, using mock response")
            return self._mock_response()

    def _mock_response(self):
        """Return a mock response based on SIEM platform."""
        return {
            "query": "",
            "index": self.index_names.get(self.siem_platform, "default"),
            "hits": 0,
            "true_positives": 0,
            "false_negatives": 0,
            "false_positives": 0,
            "events": []
        }

    @classmethod
    def register_platform(cls, platform: str, connect_func, query_func, metrics_func):
        """Register a new SIEM platform dynamically."""
        cls._platform_handlers[platform] = {
            "connect": connect_func,
            "query": query_func,
            "metrics": metrics_func
        }