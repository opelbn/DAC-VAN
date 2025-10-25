# tests/test_variant_agent.py
import pytest
import os
from dacvan.variant_agent import VariantAgent
from dacvan.config import Config

@pytest.fixture
def agent():
    config = Config()
    return VariantAgent(config, debug=True)

def test_evaluate_variants_ci_flow(mocker, agent):
    """Test evaluate_variants flow with CI mock (no API call)."""
    mocker.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"})
    rule_json = {"mitre_technique": "t1059"}
    result = agent.evaluate_variants(rule_json)
    assert "variants" in result
    assert len(result["variants"]) == 3  # Matches _mock_response

def test_evaluate_variants_debug_skip_flow(mocker, agent):
    """Test evaluate_variants flow with debug skip (no API call)."""
    mocker.patch("builtins.input", return_value="n")  # Simulate "no" input
    rule_json = {"mitre_technique": "t1059"}
    result = agent.evaluate_variants(rule_json)
    assert result == agent._mock_response()