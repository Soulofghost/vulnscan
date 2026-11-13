from pydantic import BaseModel, Field
from typing import Optional, List

class AssetCreate(BaseModel):
    name: str = Field(..., example="prod-web-01")
    ip_address: str = Field(..., example="10.0.1.50")
    environment: str = Field("PROD", example="PROD")
    criticality: str = Field("HIGH", example="HIGH")
    open_ports: str = Field("80,443", example="80,443,8080")

class AssetResponse(BaseModel):
    id: str
    name: str
    ip_address: str
    environment: str
    criticality: str
    open_ports: str
    last_scanned: Optional[str] = None
    created_at: str

class FindingResponse(BaseModel):
    id: str
    asset_id: str
    asset_ip: str
    cve_id: str
    title: str
    service: str
    port: int
    cvss_vector: str
    base_score: float
    severity: str
    impact_score: float
    exploitability_score: float
    description: str
    remediation: str
    status: str
    created_at: str

class FindingStatusUpdate(BaseModel):
    status: str = Field(..., example="PATCH_APPLIED")

class CVSSCalculateRequest(BaseModel):
    vector: Optional[str] = None
    av: Optional[str] = "N"
    ac: Optional[str] = "L"
    pr: Optional[str] = "N"
    ui: Optional[str] = "N"
    s: Optional[str] = "U"
    c: Optional[str] = "H"
    i: Optional[str] = "H"
    a: Optional[str] = "H"

class CVSSCalculateResponse(BaseModel):
    vector: str
    base_score: float
    severity: str
    impact_score: float
    exploitability_score: float
    scope_changed: bool

class ScanAssetRequest(BaseModel):
    asset_id: str

class ScanResultResponse(BaseModel):
    asset_id: str
    asset_name: str
    findings_detected: int
    findings: List[FindingResponse]

class ExecutiveSummaryResponse(BaseModel):
    total_assets: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    unremediated_count: int
    remediated_count: int
    overall_posture_score: float
