# tests/test_sigma_parser.py
import pytest
from dacvan.sigma_parser import SigmaParser

@pytest.fixture
def parser():
    return SigmaParser(debug=True)

def test_parse_rule_success(mocker, parser):
    """Test successful parsing flow with mocked file content."""
    mock_open = mocker.mock_open(read_data="""
title: Test Rule
tags: [attack.t1059]
detection: {condition: 'test'}
logsource: {category: 'process_creation'}
""")
    mocker.patch("builtins.open", mock_open)
    rule_json = parser.parse_rule("fake_path.yml")
    assert rule_json["title"] == "Test Rule"
    assert rule_json["mitre_technique"] == "t1059"

def test_parse_rule_validate_only_invalid(mocker, parser):
    """Test validate_only flow with invalid YAML (mocked error)."""
    mock_open = mocker.mock_open(read_data="invalid: yaml")  # Simulate invalid YAML content
    mocker.patch("builtins.open", mock_open)
    mocker.patch("yaml.safe_load", side_effect=ValueError("Invalid YAML"))
    validity = parser.parse_rule("fake_path.yml", validate_only=True)
    assert not validity["valid"]
    assert "Invalid YAML" in validity["reason"]  # Match the raw exception

def test_update_metrics_flow(parser):
    """Test metrics update flow with mock values."""
    rule_json = {"metrics": {}}
    updated = parser.update_metrics(rule_json, true_positives=1, false_negatives=0)
    assert updated["metrics"]["true_positives"] == 1
    assert updated["metrics"]["false_negatives"] == 0