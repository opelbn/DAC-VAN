# tests/test_logic_agent.py
import pytest
from dacvan.logic_agent import LogicAgent
from dacvan.config import Config

@pytest.fixture
def agent():
    config = Config()
    return LogicAgent(config, debug=True)

def test_build_prompt_flow(agent):
    """Test prompt construction flow (no API call)."""
    rule_json = {"title": "Test", "mitre_technique": "t1059"}
    prompt = agent._build_prompt(rule_json)
    assert "Convert this Sigma rule to Splunk SPL query" in prompt
    assert '"title": "Test"' in prompt

def test_evaluate_rule_error_flow(mocker, agent):
    """Test evaluate_rule flow with mocked API failure (triggers mock response)."""
    mocker.patch("requests.post", side_effect=Exception("API Error"))
    rule_json = {"mitre_technique": "t1059"}
    result = agent.evaluate_rule(rule_json)
    assert "query" in result  # Verifies mock response structure
    assert result == agent._mock_response("elasticsearch")