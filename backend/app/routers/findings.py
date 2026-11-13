from fastapi import APIRouter, HTTPException
from typing import List, Optional
from app.database import get_db_connection
from app.schemas import FindingResponse, FindingStatusUpdate, ExecutiveSummaryResponse

router = APIRouter(prefix="/findings", tags=["Findings"])

@router.get("", response_model=List[FindingResponse])
def get_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    asset_id: Optional[str] = None
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM findings WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        if status:
            query += " AND status = ?"
            params.append(status.upper())
        if asset_id:
            query += " AND asset_id = ?"
            params.append(asset_id)

        query += " ORDER BY base_score DESC, created_at DESC"
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

        return [
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
            for r in rows
        ]

@router.patch("/{finding_id}/status", response_model=FindingResponse)
def update_finding_status(finding_id: str, req: FindingStatusUpdate):
    valid = ["UNREMEDIATED", "PATCH_APPLIED", "VERIFIED"]
    stat = req.status.upper()
    if stat not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid}")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE findings SET status = ? WHERE id = ?", (stat, finding_id))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Finding not found.")
        conn.commit()

        cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        r = cursor.fetchone()
        return FindingResponse(
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

@router.get("/summary/posture", response_model=ExecutiveSummaryResponse)
def get_executive_summary():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        total_assets = cursor.execute("SELECT count(*) FROM assets").fetchone()[0]
        total_findings = cursor.execute("SELECT count(*) FROM findings").fetchone()[0]
        crit = cursor.execute("SELECT count(*) FROM findings WHERE severity = 'CRITICAL'").fetchone()[0]
        high = cursor.execute("SELECT count(*) FROM findings WHERE severity = 'HIGH'").fetchone()[0]
        med = cursor.execute("SELECT count(*) FROM findings WHERE severity = 'MEDIUM'").fetchone()[0]
        low = cursor.execute("SELECT count(*) FROM findings WHERE severity = 'LOW'").fetchone()[0]
        unremediated = cursor.execute("SELECT count(*) FROM findings WHERE status = 'UNREMEDIATED'").fetchone()[0]
        remediated = cursor.execute("SELECT count(*) FROM findings WHERE status IN ('PATCH_APPLIED', 'VERIFIED')").fetchone()[0]

        # Posture score (0 to 100, where 100 is pristine)
        penalty = (crit * 25.0) + (high * 10.0) + (med * 4.0) + (low * 1.0)
        mitigation_bonus = remediated * 15.0
        calculated_score = max(0.0, min(100.0, 100.0 - penalty + mitigation_bonus))

        return ExecutiveSummaryResponse(
            total_assets=total_assets,
            total_findings=total_findings,
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            unremediated_count=unremediated,
            remediated_count=remediated,
            overall_posture_score=round(calculated_score, 1)
        )
