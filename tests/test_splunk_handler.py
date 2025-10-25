# tests/test_splunk_handler.py
import pytest
from dacvan.splunk_handler import SplunkHandler
from dacvan.config import Config
import splunklib.client as client

@pytest.fixture
def handler(mocker):
    config = Config()
    mocker.patch.object(client, "connect", side_effect=Exception("Connection Error"))
    return SplunkHandler(config, debug=True)

def test_connect_error_flow(handler):
    """Test connection error flow (triggers mock response)."""
    assert handler.service is None  # Connection failed

def test_query_logs_no_connection_flow(handler):
    """Test query_logs flow with no connection (triggers mock response)."""
    rule_json = {}
    logic_result = {"query": "mock_spl"}
    result = handler.query_logs(rule_json, logic_result)
    assert result["hits"] == 0
    assert result["events"] == []