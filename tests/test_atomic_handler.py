# tests/test_atomic_handler.py
import pytest
from dacvan.atomic_handler import AtomicHandler
from dacvan.config import Config

@pytest.fixture
def handler():
    config = Config()
    return AtomicHandler(config, debug=True)

def test_run_tests_debug_skip_flow(mocker, handler):
    """Test run_tests flow with debug skip (no execution)."""
    mocker.patch("builtins.input", return_value="n")  # Simulate "no" input
    mocker.patch("os.path.exists", return_value=True)
    rule_json = {"mitre_technique": "t1059"}
    result = handler.run_tests(rule_json)
    assert result == handler._mock_response()

def test_run_tests_file_not_found_flow(mocker, handler):
    """Test run_tests flow with missing atomic file (triggers mock)."""
    mocker.patch("os.path.exists", return_value=False)
    rule_json = {"mitre_technique": "t1059"}
    result = handler.run_tests(rule_json)
    assert result == handler._mock_response()