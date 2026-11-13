import os
import pytest
from fastapi.testclient import TestClient

os.environ["VULNSCAN_DB"] = "test_vulnscan_api.db"

from app.database import init_db
from app.main import app

@pytest.fixture(scope="module", autouse=True)
def setup_test_db():
    if os.path.exists("test_vulnscan_api.db"):
        os.remove("test_vulnscan_api.db")
    init_db()
    yield
    if os.path.exists("test_vulnscan_api.db"):
        try:
            os.remove("test_vulnscan_api.db")
        except Exception:
            pass

client = TestClient(app)

def test_health_check():
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "FIRST CVSS" in data["cvss_standard"]

def test_list_and_create_assets():
    res = client.get("/api/v1/assets")
    assert res.status_code == 200
    assets = res.json()
    assert len(assets) >= 2

    # Register new asset
    payload = {
        "name": "internal-payment-svc",
        "ip_address": "10.0.3.88",
        "environment": "PROD",
        "criticality": "CRITICAL",
        "open_ports": "8080,6379"
    }
    create_res = client.post("/api/v1/assets", json=payload)
    assert create_res.status_code == 201
    created = create_res.json()
    assert created["name"] == "internal-payment-svc"
    assert created["open_ports"] == "8080,6379"

def test_scan_asset_and_findings_lifecycle():
    # Scan ast-gateway which has ports 80,443,8080
    scan_res = client.post("/api/v1/assets/ast-gateway/scan")
    assert scan_res.status_code == 200
    data = scan_res.json()
    assert data["findings_detected"] >= 2
    findings = data["findings"]
    first_finding = findings[0]
    finding_id = first_finding["id"]

    # Verify findings listing
    list_res = client.get("/api/v1/findings")
    assert list_res.status_code == 200
    assert len(list_res.json()) >= data["findings_detected"]

    # Update finding status: PATCH_APPLIED -> VERIFIED
    patch_res = client.patch(f"/api/v1/findings/{finding_id}/status", json={"status": "PATCH_APPLIED"})
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "PATCH_APPLIED"

    verify_res = client.patch(f"/api/v1/findings/{finding_id}/status", json={"status": "VERIFIED"})
    assert verify_res.status_code == 200
    assert verify_res.json()["status"] == "VERIFIED"

def test_cvss_calculator_api():
    req = {
        "av": "N", "ac": "L", "pr": "N", "ui": "N",
        "s": "U", "c": "H", "i": "H", "a": "H"
    }
    calc_res = client.post("/api/v1/cvss/calculate", json=req)
    assert calc_res.status_code == 200
    calc_data = calc_res.json()
    assert calc_data["base_score"] == 9.8
    assert calc_data["severity"] == "CRITICAL"

def test_executive_summary_posture():
    res = client.get("/api/v1/findings/summary/posture")
    assert res.status_code == 200
    summary = res.json()
    assert summary["total_assets"] >= 3
    assert "overall_posture_score" in summary
    assert 0 <= summary["overall_posture_score"] <= 100
