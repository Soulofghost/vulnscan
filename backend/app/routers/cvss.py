from fastapi import APIRouter
from app.schemas import CVSSCalculateRequest, CVSSCalculateResponse
from app.engine.cvss import calculate_cvss_v31, parse_vector_string

router = APIRouter(prefix="/cvss", tags=["CVSS Calculator"])

@router.post("/calculate", response_model=CVSSCalculateResponse)
def calculate_score(req: CVSSCalculateRequest):
    if req.vector and req.vector.startswith("CVSS:3.1"):
        metrics = parse_vector_string(req.vector)
    else:
        metrics = {
            "AV": req.av,
            "AC": req.ac,
            "PR": req.pr,
            "UI": req.ui,
            "S": req.s,
            "C": req.c,
            "I": req.i,
            "A": req.a
        }

    res = calculate_cvss_v31(metrics)
    return CVSSCalculateResponse(
        vector=res["vector"],
        base_score=res["base_score"],
        severity=res["severity"],
        impact_score=res["impact_score"],
        exploitability_score=res["exploitability_score"],
        scope_changed=res["scope_changed"]
    )
