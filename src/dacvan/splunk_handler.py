# splunk_handler.py (updated for sysmon:linux and fields)
import logging
import splunklib.client as client
import splunklib.results as results
import json

class SplunkHandler:
    def __init__(self, config, debug=False):
        self.config = config
        self.debug = debug
        self.splunk_host = config.splunk_host
        self.splunk_port = config.splunk_port
        self.splunk_user = config.splunk_user
        self.splunk_pass = config.splunk_pass
        self.splunk_url = f"https://{self.splunk_host}:{self.splunk_port}"
        self.service = None
        self.connect()

    def connect(self):
        try:
            logging.debug(f"Attempting Splunk connection to {self.splunk_url} with user {self.splunk_user}")
            self.service = client.connect(
                host=self.splunk_host,
                port=self.splunk_port,
                username=self.splunk_user,
                password=self.splunk_pass,
                verify=False
            )
            logging.info("Connected to Splunk successfully")
        except Exception as e:
            logging.error(f"Splunk connection error: {e}")
            self.service = None

    def get_field_mappings(self, sourcetype="sysmon:linux"):
        try:
            if not self.service:
                raise ValueError("No connection to Splunk")
            
            search_query = f'search index="sysmon" sourcetype="{sourcetype}" | fieldsummary'
            kwargs = {"earliest_time": "-24h", "latest_time": "now", "exec_mode": "normal"}  # Extended range
            job = self.service.jobs.create(search_query, **kwargs)
            while not job.is_ready():
                pass
            
            fields = []
            reader = results.ResultsReader(job.results())
            for result in reader:
                if result.get("field") not in ["_time", "_raw"]:
                    fields.append(result.get("field"))
            
            logging.debug(f"Fields for sourcetype={sourcetype}: {fields}")
            return fields
        except Exception as e:
            logging.warning(f"Failed to fetch field mappings: {e}")
            return []

    def query_logs(self, rule_json, logic_result, atomic_result=None):
        if self.debug:
            logging.debug("Querying Splunk logs")

        spl_search = logic_result.get("query", 'sourcetype="sysmon:linux"')  # Default value outside try
        try:
            if not self.service:
                raise ValueError("No connection to Splunk")

            fields = self.get_field_mappings(sourcetype="sysmon:linux")
            field_map = {
                "process_name": next((f for f in ["Image", "process_name"] if f in fields), "ProcessId"),
                "command_line": next((f for f in ["CommandLine", "process_exec"] if f in fields), "CommandLine"),
                "file_path": next((f for f in ["TargetFilename", "file_path"] if f in fields), None)
            }
            logging.debug(f"Field mappings: {field_map}")

            if isinstance(spl_search, dict):
                index = logic_result.get("index", "sysmon")
                query_dict = spl_search.get("query", {})
                spl_search = f'search index={index} {json.dumps(query_dict)}'
            else:
                for sigma_field, splunk_field in field_map.items():
                    if splunk_field:  # Only replace if field exists
                        spl_search = spl_search.replace(sigma_field, splunk_field)
                spl_search = f'search index="sysmon" sourcetype="sysmon:linux" {spl_search}'

            logging.debug(f"Executing SPL query: {spl_search}")

            kwargs = {"earliest_time": "-24h", "latest_time": "now", "exec_mode": "normal"}
            job = self.service.jobs.create(spl_search, **kwargs)
            while not job.is_ready():
                pass

            reader = results.ResultsReader(job.results())
            hits = 0
            events = []
            for result in reader:
                hits += 1
                events.append(dict(result))

            if hits == 0 and not field_map["file_path"]:
                logging.warning(f"No events or file_path fields returned; available fields: {fields}. Ensure Sysmon logs FileCreate events.")
            elif hits == 0:
                logging.warning(f"No events returned; available fields: {fields}. Check event data.")

            return {
                "query": spl_search,
                "index": "sysmon",
                "hits": hits,
                "true_positives": hits if hits > 0 else 0,
                "false_negatives": 0,
                "events": events
            }
        except Exception as e:
            logging.warning(f"Splunk Handler error: {e}, using mock response")
            return {
                "query": spl_search,  # Now defined
                "index": "sysmon",
                "hits": 0,
                "true_positives": 0,
                "false_negatives": 0,
                "events": []
            }