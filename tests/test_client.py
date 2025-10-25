# tests/test_client.py
import pytest
import asyncio
from dacvan.client import MCPClient
from dacvan.siem_handler import SIEMHandler
import argparse
import json

@pytest.fixture(params=["elasticsearch", "splunk"])
def client_with_siem(mocker, request):
    mocker.patch("asyncio.run", lambda coro: coro)
    mock_parse_rule = mocker.patch("dacvan.sigma_parser.SigmaParser.parse_rule", return_value={"title": "Test", "mitre_technique": "t1059", "detection": {}, "logsource": {}})
    mocker.patch("builtins.open", mocker.mock_open(read_data=json.dumps({
        "siem_platform": request.param,
        "index_names": {"elasticsearch": "sysmon-*", "splunk": "linux:process"},
        "field_mappings": {"process.name": "process.name", "command_line": "command_line"},
        "pipeline_context": {"ci_cd": "GitHub Actions runner", "runner_details": "self-hosted on Ubuntu VM"},
        "grok_api_key": "mock_key",
        "debug": True,
        "api_timeout_secs": 30,
        "atomic_red_team_path": "/mock/path",
        "splunk_host": "localhost",
        "splunk_port": 8089,
        "splunk_user": "admin",
        "splunk_pass": "changeme",
        "elastic_url": "http://localhost:9200",
        "elastic_user": "elastic",
        "elastic_pass": "changeme"
    })))
    mocker.patch("os.path.join", return_value="/fake/path/to/fake.yml")
    client_instance = MCPClient()
    mocker.patch.object(client_instance.parser, "parse_rule", mock_parse_rule)
    return client_instance

@pytest.mark.asyncio
async def test_run_pipeline_with_siem(mocker, client_with_siem):
    mocker.patch("builtins.input", return_value="n")
    args = argparse.Namespace(parse_only=True, logic=False, variant=False, atomic=False, elastic=False, full=False, rule_path="fake.yml")
    result = await client.run_pipeline("fake.yml", args)
    assert result is not None
    assert result["valid"]

def test_register_new_platform(mocker):
    """Test registering a new SIEM platform."""
    mock_config = mocker.Mock()
    mock_config.siem_platform = "new_siem"
    mocker.patch("dacvan.config.Config", return_value=mock_config)
    handler = SIEMHandler(mock_config, debug=False)
    def mock_connect(config): return mocker.Mock()
    def mock_query(client, query, index, field_mappings): return 1
    def mock_metrics(hits, art_results): return {"true_positives": hits, "false_negatives": 0, "false_positives": 0}
    SIEMHandler.register_platform("new_siem", mock_connect, mock_query, mock_metrics)
    assert handler._platform_handlers.get("new_siem") is not None

@pytest.fixture
def client(mocker):
    mocker.patch("asyncio.run", lambda coro: coro)
    mock_parse_rule = mocker.patch("dacvan.sigma_parser.SigmaParser.parse_rule", return_value={"title": "Test", "mitre_technique": "t1059", "detection": {}, "logsource": {}})
    mocker.patch("builtins.open", mocker.mock_open())  # Mock file open
    mocker.patch("os.path.join", return_value="/fake/path/to/fake.yml")  # Mock path resolution
    client_instance = MCPClient()
    mocker.patch.object(client_instance.parser, "parse_rule", mock_parse_rule)  # Mock instance method
    return client_instance

@pytest.mark.asyncio
async def test_run_pipeline_parse_only_flow(mocker, client):
    """Test parse_only flow with mocked parsing."""
    mocker.patch("builtins.input", return_value="n")  # Skip in debug
    args = argparse.Namespace(parse_only=True, logic=False, variant=False, atomic=False, elastic=False, full=False, rule_path="fake.yml")
    result = await client.run_pipeline("fake.yml", args)
    assert result is not None
    assert result["valid"]

@pytest.mark.asyncio
async def test_run_pipeline_full_flow(mocker, client):
    """Test full pipeline flow with all mocks (no real calls)."""
    mocker.patch("dacvan.logic_agent.LogicAgent.evaluate_rule", side_effect=Exception("Mock Logic Error"))
    mocker.patch("dacvan.variant_agent.VariantAgent.evaluate_variants", side_effect=Exception("Mock Variant Error"))
    mocker.patch("dacvan.atomic_handler.AtomicHandler.run_tests", side_effect=Exception("Mock Atomic Error"))
    mocker.patch("dacvan.splunk_handler.SplunkHandler.query_logs", side_effect=Exception("Mock Splunk Error"))
    mocker.patch("builtins.input", return_value="n")  # Skip in debug
    args = argparse.Namespace(full=True, parse_only=False, logic=False, variant=False, atomic=False, elastic=False, rule_path="fake.yml")
    try:
        result = await client.run_pipeline("fake.yml", args)
        assert result is not None  # This might fail due to exception
    except Exception as e:
        assert str(e) == "Mock Logic Error"  # Expect the mock exception

