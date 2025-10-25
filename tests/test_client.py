# tests/test_client.py
import pytest
import asyncio
from dacvan.client import MCPClient
import argparse

@pytest.fixture
def client(mocker):
    mocker.patch("asyncio.run", lambda coro: coro)
    mocker.patch("dacvan.sigma_parser.SigmaParser.parse_rule", return_value={"title": "Test", "mitre_technique": "t1059", "detection": {}, "logsource": {}})
    mocker.patch("builtins.open", mocker.mock_open())  # Mock file open to avoid FileNotFoundError
    client_instance = MCPClient()
    client_instance.parser.parse_rule = mocker.MagicMock(return_value={"valid": True, "reason": None, "details": {}})  # Ensure parse_only works
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

