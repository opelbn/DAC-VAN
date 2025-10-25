import logging
from elasticsearch import Elasticsearch

class ElasticHandler:
    def __init__(self, config, debug=False):
        self.config = config
        self.debug = debug

    def query_logs(self, rule_json, logic_result, art_results):
        """Run Elastic Stack query and compute TP/FN/FP based on ART results."""
        if self.debug:
            logging.debug("Starting Elastic Handler evaluation")
        
        technique = rule_json["mitre_technique"]
        try:
            if self.debug:
                proceed = input("Proceed to Elastic Stack query? [y/n]: ")
                if proceed.lower() != "y":
                    logging.debug("Skipped Elastic Stack query")
                    return self._mock_response()
            
            # Get the query from logic_result
            query = logic_result.get("query", {}).get("query", {})
            index = logic_result.get("query", {}).get("index", "logs-endpoint.events-*")
            
            # Run the query with authentication
            client = Elasticsearch(
                self.config.elastic_url,
                basic_auth=(self.config.elastic_user, self.config.elastic_pass)
            )
            response = client.search(index=index, body={"query": query})
            hits = response["hits"]["total"]["value"]
            
            # Compute TP/FN/FP based on ART
            successful_art = any(test["status"] == "Success" for test in art_results.get("tests", []))
            tp = 1 if successful_art and hits > 0 else 0
            fn = 1 if successful_art and hits == 0 else 0
            fp = 1 if not successful_art and hits > 0 else 0
            
            logging.info(f"Elastic Stack query completed for {technique}")
            return {
                "query": query,
                "index": index,
                "hits": hits,
                "true_positives": tp,
                "false_negatives": fn,
                "false_positives": fp
            }
        
        except Exception as e:
            logging.warning(f"Elastic Stack unavailable: {e}, using mock response")
            return self._mock_response()

    def _mock_response(self):
        """Return a mock Elastic Stack response."""
        return {
            "query": "",
            "index": "",
            "hits": 0,
            "true_positives": 0,
            "false_negatives": 0,
            "false_positives": 0
        }