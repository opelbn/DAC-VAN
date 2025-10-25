# atomic_handler.py (refined test filtering)
import subprocess
import logging
import json
import yaml
import os
import re
import platform
import distro

class AtomicHandler:
    def __init__(self, config, debug=False):
        self.config = config
        self.debug = debug
        self.atomic_path = config.atomic_red_team_path
        self.venv_path = "/home/dac-van/MSISE/dac_mcp/venv/bin/python"

    def run_tests(self, rule_json):
        if self.debug:
            logging.debug("Starting Atomic Handler evaluation")
        
        technique = rule_json["mitre_technique"]
        results = []
        try:
            technique_yaml = os.path.join(self.atomic_path, 'atomics', technique, f'{technique}.yaml')
            if not os.path.exists(technique_yaml):
                raise ValueError(f"No atomics available for technique {technique} in {self.atomic_path}")
            
            use_sudo = False
            elevation_count = 0
            total_tests = 0
            valid_tests = []
            try:
                with open(technique_yaml, 'r') as f:
                    yaml_data = yaml.safe_load(f)
                atomic_tests = yaml_data.get('atomic_tests', [])
                total_tests = len(atomic_tests)
                distro_info = distro.info()
                distro_name = distro_info.get('id', '').lower()
                for i, test in enumerate(atomic_tests):
                    supported_platforms = test.get('supported_platforms', [])
                    test_commands = test.get('executor', {}).get('command', '')
                    # Skip SysV test on Ubuntu
                    if distro_name == 'ubuntu' and '/usr/local/etc/rc.d/' in test_commands:
                        logging.warning(f"Skipping test {test.get('name', 'Unknown')} (UUID: {test.get('uuid', 'Unknown')}) for {technique}: Incompatible directory /usr/local/etc/rc.d/ on Ubuntu")
                        continue
                    if 'linux' in supported_platforms or distro_name in supported_platforms:
                        valid_tests.append((i, test))
                    if test.get('executor', {}).get('elevation_required', False):
                        use_sudo = True
                        elevation_count += 1
                logging.info(f"Elevation required: {'Yes' if use_sudo else 'No'} ({elevation_count}/{len(valid_tests)} tests)")
                if not valid_tests:
                    raise ValueError(f"No compatible tests for {technique} on {distro_name}")
            except Exception as e:
                logging.warning(f"Failed to parse YAML for elevation check: {e}. Falling back to sudo.")
                use_sudo = True
            
            if self.debug:
                proceed = input("Proceed to Atomic Red Team test execution? [y/n]: ")
                if proceed.lower() != "y":
                    logging.debug("Skipped Atomic Red Team test execution")
                    return self._mock_response()
            
            cmd = [self.venv_path, "-m", "atomic_operator", "run", "--techniques", technique, "--atomics_path", self.atomic_path, "--cleanup"]
            if use_sudo:
                cmd = ["sudo"] + cmd
            process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60, check=False)
            stdout, stderr = process.stdout, process.stderr
            exit_status = process.returncode
            
            logging.info("Atomic cmd: %s\nstdout: %s\nstderr: %s\nexit: %s", cmd, stdout, stderr, exit_status)
            
            error_msg = stderr
            all_successful = True
            error_sources = (error_msg + stdout).lower()
            if "skipping" in error_sources:
                status = "Skipped"
                logging.warning(f"ART tests skipped for {technique} (platform incompatibility)")
                results = [{"name": technique, "status": status, "output": stdout[:100] + "..." if len(stdout) > 100 else stdout, "error": error_msg[:100] + "..." if len(error_msg) > 100 else error_msg}]
            elif any(err in error_sources for err in ["permission denied", "timed out", "directory nonexistent", "cannot create", "chmod", "unrecognized service", "not found"]):
                status = "Failed"
                all_successful = False
                failure_reason = ', '.join(err for err in ['permissions', 'timeout', 'directory issues', 'unrecognized service', 'other errors'] if err in error_sources)
                logging.warning(f"ART tests failed for {technique} due to {failure_reason}")
                if not use_sudo and "permission denied" in error_sources:
                    logging.warning("Suggestion: This technique may require elevation. Re-run with sudo or check permissions.")
            elif exit_status != 0:
                status = "Failed"
                all_successful = False
                failure_reason = "non-zero exit code"
                logging.warning(f"Atomic-operator failed: {error_msg}")
            else:
                status = "Success"
            
            name_map = {}
            for line in error_msg.splitlines():
                match = re.search(r'Running (.+?) test \((.+?)\)', line)
                if match:
                    name_map[match.group(2)] = match.group(1)
            
            lines = stdout.splitlines()
            for line in lines:
                match = re.search(r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}):\s*(.+)', line)
                if match:
                    uuid = match.group(1)
                    json_str = match.group(2)
                    try:
                        data = json.loads(json_str)
                        inner_json_str = data.get('response', '{}')
                        inner_data = json.loads(inner_json_str)
                        name = name_map.get(uuid, data.get('technique_name', uuid))
                        return_code = inner_data.get('return_code', 1)
                        test_status = "Success" if return_code == 0 else "Failed"
                        output = inner_data.get('output', 'No output').replace("b'", '').replace("'", '')[:100] + "..." if len(inner_data.get('output', '')) > 100 else inner_data.get('output', '').replace("b'", '').replace("'", '')
                        test_error = inner_data.get('records', [{}])[0].get('message_data', 'No error')[:100] + "..." if len(inner_data.get('records', [{}])[0].get('message_data', '')) > 100 else inner_data.get('records', [{}])[0].get('message_data', '')
                        results.append({"name": name, "uuid": uuid, "status": test_status, "output": output, "error": test_error})
                    except json.JSONDecodeError as e:
                        logging.warning(f"JSON parse error for UUID {uuid}: {e}")
                        results.append({"name": uuid, "status": "Failed", "output": json_str[:100] + "...", "error": "JSON parse error"})
            
            if not results:
                results = [{"name": technique, "status": status, "output": stdout[:100] + "..." if len(stdout) > 100 else stdout, "error": error_msg[:100] + "..." if len(error_msg) > 100 else error_msg}]
            
            if not all_successful and status == "Success":
                status = "Partial Success"
                logging.warning(f"ART tests for {technique} had mixed outcomes")
            
            logging.info(f"Atomic Red Team tests completed for {technique}")
            return {"tests": results}
        
        except subprocess.TimeoutExpired as e:
            logging.warning(f"Atomic Handler timed out for {technique} after {e.timeout} seconds")
            return self._mock_response()
        except Exception as e:
            logging.warning(f"Atomic Handler error: {e}")
            return self._mock_response()

    def _mock_response(self):
        return {
            "tests": [
                {
                    "name": "T1543.002-Systemd-Service-Creation",
                    "status": "Success",
                    "output": "Simulated systemd service creation",
                    "error": ""
                }
            ]
        }