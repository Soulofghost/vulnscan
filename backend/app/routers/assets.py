import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from typing import List
from app.database import get_db_connection
from app.schemas import AssetCreate, AssetResponse, ScanResultResponse, FindingResponse
from app.engine.scanner import scan_target_asset

router = APIRouter(prefix="/assets", tags=["Assets"])

@router.get("", response_model=List[AssetResponse])
def get_assets():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM assets ORDER BY created_at DESC")
        rows = cursor.fetchall()
        return [
            AssetResponse(
                id=r["id"],
                name=r["name"],
                ip_address=r["ip_address"],
                environment=r["environment"],
                criticality=r["criticality"],
                open_ports=r["open_ports"],
                last_scanned=r["last_scanned"],
                created_at=r["created_at"]
            )
            for r in rows
        ]

@router.post("", response_model=AssetResponse, status_code=201)
def create_asset(req: AssetCreate):
    asset_id = "ast-" + str(uuid.uuid4())[:8]
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO assets (id, name, ip_address, environment, criticality, open_ports)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (asset_id, req.name.strip(), req.ip_address.strip(), req.environment.upper(), req.criticality.upper(), req.open_ports.strip()))
        conn.commit()

        cursor.execute("SELECT * FROM assets WHERE id = ?", (asset_id,))
        r = cursor.fetchone()
        return AssetResponse(
            id=r["id"],
            name=r["name"],
            ip_address=r["ip_address"],
            environment=r["environment"],
            criticality=r["criticality"],
            open_ports=r["open_ports"],
            last_scanned=r["last_scanned"],
            created_at=r["created_at"]
        )

@router.post("/{asset_id}/scan", response_model=ScanResultResponse)
def scan_asset(asset_id: str):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM assets WHERE id = ?", (asset_id,))
        asset_row = cursor.fetchone()
        if not asset_row:
            raise HTTPException(status_code=404, detail="Asset not found.")

        asset_dict = dict(asset_row)
        findings = scan_target_asset(asset_dict)

        # Clear previous findings for this asset to simulate a fresh scan pass
        cursor.execute("DELETE FROM findings WHERE asset_id = ?", (asset_id,))

        # Insert new findings
        for f in findings:
            cursor.execute("""
                INSERT INTO findings (
                    id, asset_id, asset_ip, cve_id, title, service, port,
                    cvss_vector, base_score, severity, impact_score, exploitability_score,
                    description, remediation, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f["id"], f["asset_id"], f["asset_ip"], f["cve_id"], f["title"], f["service"], f["port"],
                f["cvss_vector"], f["base_score"], f["severity"], f["impact_score"], f["exploitability_score"],
                f["description"], f["remediation"], f["status"]
            ))

        now_str = datetime.now(timezone.utc).isoformat()
        cursor.execute("UPDATE assets SET last_scanned = ? WHERE id = ?", (now_str, asset_id))
        conn.commit()

        # Query inserted findings
        cursor.execute("SELECT * FROM findings WHERE asset_id = ? ORDER BY base_score DESC", (asset_id,))
        saved = cursor.fetchall()
        finding_responses = [
            FindingResponse(
                id=r["id"],
                asset_id=r["asset_id"],
                asset_ip=r["asset_ip"],
                cve_id=r["cve_id"],
                title=r["title"],
                service=r["service"],
                port=r["port"],
                cvss_vector=r["cvss_vector"],
                base_score=r["base_score"],
                severity=r["severity"],
                impact_score=r["impact_score"],
                exploitability_score=r["exploitability_score"],
                description=r["description"],
                remediation=r["remediation"],
                status=r["status"],
                created_at=r["created_at"]
            )
            for r in saved
        ]

        return ScanResultResponse(
            asset_id=asset_dict["id"],
            asset_name=asset_dict["name"],
            findings_detected=len(finding_responses),
            findings=finding_responses
        )
