import yaml
import logging
import os
import re  # For potential advanced checks, e.g., condition parsing

class SigmaParser:
    def __init__(self, debug=False):
        self.debug = debug

    def parse_rule(self, rule_path, validate_only=False):
        try:
            with open(rule_path, 'r') as f:
                rule_yaml = yaml.safe_load(f)
        
        # Extract key fields (with guards for None)
            tags = rule_yaml.get('tags', []) or []
            mitre_technique = next((tag.replace('attack.', '') for tag in tags if tag.startswith('attack.')), '')
            rule_json = {
                'title': rule_yaml.get('title', ''),
                'mitre_technique': mitre_technique,
                'detection': rule_yaml.get('detection', {}) or {},
                'logsource': rule_yaml.get('logsource', {}) or {}
            }
        
            if validate_only:
                return self._validate_rule(rule_json, rule_yaml)
        
            return rule_json
        except yaml.YAMLError as e:
            if validate_only:
                return {"valid": False, "reason": str(e), "details": {"errors": [str(e)], "warnings": []}}
            raise Exception(f"Sigma rule YAML invalid: {str(e)}")
        except FileNotFoundError as e:
            if validate_only:
                return {"valid": False, "reason": str(e), "details": {"errors": [str(e)], "warnings": []}}
            raise Exception(f"Rule file not found: {str(e)}")
        except Exception as e:
            if validate_only:
                return {"valid": False, "reason": str(e), "details": {"errors": [str(e)], "warnings": []}}
            raise Exception(f"Failed to parse rule: {str(e)}")

    def _validate_rule(self, rule_json, raw_yaml):
        """Perform full validation on the parsed rule."""
        details = {"errors": [], "warnings": []}
        
        # Structural checks
        if not rule_json.get('title'):
            details["errors"].append("Missing 'title' field")
        
        detection = rule_json.get('detection')
        if not detection:
            details["errors"].append("Missing 'detection' field")
        else:
            # Semantic checks if detection exists
            condition = detection.get('condition')
            if condition is None:
                details["errors"].append("Missing 'condition' in detection")
            else:
                selections = [k for k in detection if k != 'condition']
                for sel in selections:
                    if sel not in str(condition):  # str() to handle None safely
                        details["warnings"].append(f"Selection '{sel}' not referenced in condition")
                # Optional: Basic condition syntax check (e.g., no empty parens)
                if re.search(r'\(\s*\)', str(condition)):
                    details["warnings"].append("Empty parentheses in condition")
        
        if not rule_json.get('mitre_technique'):
            details["warnings"].append("Missing or invalid 'tags' with MITRE technique (e.g., 'attack.t1543.002')")
        
        if not rule_json.get('logsource'):
            details["warnings"].append("Missing 'logsource' field")
        
        valid = len(details["errors"]) == 0
        reason = "; ".join(details["errors"]) if details["errors"] else None
        return {"valid": valid, "reason": reason, "details": details}

    def update_metrics(self, rule_json, true_positives, false_negatives):
        """Update the rule metrics with TP/FN from Elastic results."""
        if 'metrics' not in rule_json:
            rule_json['metrics'] = {}
        rule_json['metrics']['true_positives'] = true_positives
        rule_json['metrics']['false_negatives'] = false_negatives
        return rule_json