# client.py (with live Logic and Splunk, mocked Variant and Atomic)
from dacvan.sigma_parser import SigmaParser
from dacvan.logic_agent import LogicAgent
from dacvan.variant_agent import VariantAgent
from dacvan.atomic_handler import AtomicHandler
from dacvan.splunk_handler import SplunkHandler
from dacvan.config import Config
import logging
import os
import sys
import json
import argparse
import time
import io

def setup_logging(debug=False):
    level = logging.DEBUG if debug else logging.INFO
    log_format = "%(asctime)s %(levelname)s: %(message)s"

    # Base config
    logging.basicConfig(level=level, format=log_format)

    # Add console handler for interactive runs
    try:
        is_tty = os.isatty(sys.stdin.fileno())  # Check if interactive
    except (io.UnsupportedOperation, ValueError):
        is_tty = False  # Assume non-interactive if fileno fails (e.g., pytest)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(logging.Formatter(log_format))
    logging.getLogger().addHandler(console_handler)

    # Optional file handler for debug mode
    if debug:
        file_handler = logging.FileHandler("validation_output.txt")
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(log_format))
        logging.getLogger().addHandler(file_handler)
        logging.debug("Debug mode enabled; logging to validation_output.txt")

    # CI-specific: Redirect to file if non-tty and GITHUB_ACTIONS
    if not is_tty and 'GITHUB_ACTIONS' in os.environ:
        logging.getLogger().removeHandler(console_handler)
        logging.basicConfig(filename="validation_output.txt", level=level, format=log_format, force=True)
        logging.info("CI mode detected; logging to validation_output.txt")
    logging.info("Logging initialized")

class MCPClient:
    def __init__(self):
        self.config = Config()
        self.debug = self.config.debug
        setup_logging(self.debug)
        self.siem_config = self._load_siem_config()
        self.parser = SigmaParser(self.debug)
        self.logic_agent = LogicAgent(self.config, self.debug)
        self.variant_agent = VariantAgent(self.config, self.debug)
        self.atomic_handler = AtomicHandler(self.config, self.debug)
        self.splunk_handler = SplunkHandler(self.config, self.debug)
        logging.info("MCPClient initialized with debug=%s", self.debug)

    def _load_siem_config(self):
        try:
            config_path = os.path.join(os.path.dirname(__file__), "config.json")
            with open(config_path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            logging.error("config.json not found")
            return {"siem_platform": "elasticsearch"}
        except json.JSONDecodeError as e:
            logging.error(f"Invalid config.json: {e}")
            return {"siem_platform": "elasticsearch"}

    def run_pipeline(self, rule_path, args):
        if self.debug:
            logging.info("WARNING: Do not run this tool in production environments unless you fully understand the risks. Tests should be conducted in an isolated lab.")
        
        total_start = time.perf_counter()
        timings = {}
        
        rule_json = None
        parsing_start = time.perf_counter()
        try:
            if self.debug and os.isatty(sys.stdin.fileno()) and 'GITHUB_ACTIONS' not in os.environ:
                proceed = input("Proceed to Sigma rule parsing? [y/n]: ")
                if proceed.lower() != "y":
                    logging.debug("Skipped Sigma rule parsing")
                    timings['total'] = time.perf_counter() - total_start
                    logging.info(f"Timings: { {k: f'{v:.3f}s' for k, v in timings.items()} }")
                    return None
            parsing_io_start = time.perf_counter()
            base_path = os.getenv("GITHUB_WORKSPACE", os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
            if not os.path.isabs(rule_path):
                rule_path = os.path.join(base_path, rule_path)
            if args.parse_only:
                validity = self.parser.parse_rule(rule_path, validate_only=True)
                logging.info(f"Sigma rule validity: {'Valid' if validity['valid'] else f'Invalid: {validity['reason']}' }")
                if validity['details']['errors'] or validity['details']['warnings']:
                    logging.info(f"Details: {validity['details']}")
                timings['parsing'] = time.perf_counter() - parsing_io_start
                timings['total'] = time.perf_counter() - total_start
                logging.info(f"Timings: { {k: f'{v:.3f}s' for k, v in timings.items()} }")
                return validity
            else:
                rule_json = self.parser.parse_rule(rule_path)
                rule_json["file_path"] = rule_path
        except Exception as e:
            timings['parsing'] = time.perf_counter() - parsing_io_start if 'parsing_io_start' in locals() else time.perf_counter() - parsing_start
            timings['total'] = time.perf_counter() - total_start
            logging.error(f"Failed to parse rule: {e} [Halted: Yes]")
            logging.info(f"Timings: { {k: f'{v:.3f}s' for k, v in timings.items()} }")
            return None
        
        timings['parsing'] = time.perf_counter() - parsing_io_start
        logging.info("Parsing done. Proceeding to agents/handlers.")
        
        logic_result = None
        variant_result = None
        if args.full:
            agents_start = time.perf_counter()
            logging.info("Starting parallel agents (synchronous)")
            logic_result = self._run_logic(rule_json)
            variant_result = self.variant_agent._mock_response()
            logging.info("Parallel agents complete. Logic: %s, Variant: %s", logic_result, variant_result)
            timings['agents_parallel'] = time.perf_counter() - agents_start
        else:
            if args.logic or args.elastic:
                logic_start = time.perf_counter()
                logging.info("Entering Logic branch. Calling _run_logic.")
                logic_result = self._run_logic(rule_json)
                logging.info("Logic done. Result: %s", logic_result)
                timings['logic'] = time.perf_counter() - logic_start
            if args.variant:
                variant_start = time.perf_counter()
                variant_result = self.variant_agent._mock_response()
                timings['variant'] = time.perf_counter() - variant_start
        
        atomic_result = None
        if args.atomic or args.full:
            atomic_start = time.perf_counter()
            atomic_result = self.atomic_handler.run_tests(rule_json)
            timings['atomic'] = time.perf_counter() - atomic_start
        
        elastic_result = None
        if args.elastic or args.full:
            if logic_result is None:
                logic_start = time.perf_counter()
                logic_result = self._run_logic(rule_json)
                timings['logic'] = (timings.get('logic', 0) + time.perf_counter() - logic_start) if 'logic' in timings else time.perf_counter() - logic_start
            elastic_start = time.perf_counter()
            elastic_result = self.splunk_handler.query_logs(rule_json, logic_result)
            timings['elastic'] = time.perf_counter() - elastic_start
        
        if elastic_result:
            rule_json = self.parser.update_metrics(
                rule_json,
                elastic_result["true_positives"],
                elastic_result["false_negatives"]
            )
        
        logging.info("Pipeline complete. Logging results now.")
        logging.info("MCP Pipeline Results:")
        logging.info(f"Title: {rule_json['title']}")
        logging.info(f"MITRE Technique: {rule_json['mitre_technique']}")
        logging.info(f"Detection: {rule_json['detection']}")
        if elastic_result:
            logging.info(f"Metrics: {rule_json['metrics']}")
        if logic_result:
            logging.info(f"Logic Agent Result: {logic_result}")
        if variant_result:
            logging.info(f"Variant Agent Result: {variant_result}")
        if atomic_result:
            logging.info(f"Atomic Red Team Result: {atomic_result}")
        if elastic_result:
            logging.info(f"Elastic Stack Result: {elastic_result}")
        
        timings['total'] = time.perf_counter() - total_start
        logging.info(f"Timings: { {k: f'{v:.3f}s' for k, v in timings.items()} }")
        
        return rule_json

    def _run_logic(self, rule_json):
        return self.logic_agent.evaluate_rule(rule_json)

    def _run_variant(self, rule_json):
        return self.variant_agent._mock_response()

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="MCP Pipeline CLI for selective workflows")
        group = parser.add_mutually_exclusive_group()
        group.add_argument('--parse-only', action='store_true', help="Run only Sigma rule parsing and validity check")
        group.add_argument('--logic', action='store_true', help="Run parsing + Logic Agent")
        group.add_argument('--variant', action='store_true', help="Run parsing + Variant Agent")
        group.add_argument('--atomic', action='store_true', help="Run parsing + Atomic Handler")
        group.add_argument('--elastic', action='store_true', help="Run parsing + Logic Agent + Elastic Handler")
        group.add_argument('--full', action='store_true', help="Run full pipeline (default)")
        parser.add_argument('rule_path', nargs='?', default="rules/rule.yml", help="Path to the Sigma rule YAML")

        args = parser.parse_args()
        if not (args.parse_only or args.logic or args.variant or args.atomic or args.elastic or args.full):
            args.full = True

        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        rule_path = args.rule_path if os.path.isabs(args.rule_path) else os.path.join(base_path, args.rule_path)
        client = MCPClient()
        client.run_pipeline(rule_path, args)
    except Exception as e:
        logging.error(f"Main block failed: {e}")
        raise