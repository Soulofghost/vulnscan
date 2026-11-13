import pytest
from app.engine.cvss import calculate_cvss_v31, parse_vector_string

def test_canonical_critical_vector_log4j():
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
    metrics = {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "C", "C": "H", "I": "H", "A": "H"
    }
    result = calculate_cvss_v31(metrics)
    assert result["base_score"] == 10.0
    assert result["severity"] == "CRITICAL"
    assert result["scope_changed"] is True

def test_canonical_high_vector_heartbleed():
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    metrics = {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "N", "A": "N"
    }
    result = calculate_cvss_v31(metrics)
    assert result["base_score"] == 7.5
    assert result["severity"] == "HIGH"
    assert result["scope_changed"] is False

def test_low_severity_vector():
    metrics = {
        "AV": "P", "AC": "H", "PR": "H", "UI": "R",
        "S": "U", "C": "L", "I": "N", "A": "N"
    }
    result = calculate_cvss_v31(metrics)
    assert result["base_score"] < 4.0
    assert result["severity"] in ["LOW", "NONE"]

def test_parse_vector_string():
    vec = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N"
    parsed = parse_vector_string(vec)
    assert parsed["AV"] == "N"
    assert parsed["AC"] == "H"
    assert parsed["PR"] == "L"
    assert parsed["UI"] == "R"
    assert parsed["S"] == "C"
    assert parsed["C"] == "L"
    assert parsed["I"] == "L"
    assert parsed["A"] == "N"
