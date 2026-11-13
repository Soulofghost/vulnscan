import math
import re
from typing import Dict, Any, Tuple

# CVSS v3.1 Metric Constants
AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
IMPACT_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}

def cvss_roundup(val: float) -> float:
    int_val = round(val * 100000)
    if int_val % 10000 == 0:
        return int_val / 100000.0
    return math.ceil(int_val / 10000.0) / 10.0

def parse_vector_string(vector: str) -> Dict[str, str]:
    metrics = {}
    parts = vector.strip().split("/")
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k.upper()] = v.upper()
    return metrics

def calculate_cvss_v31(metrics: Dict[str, str]) -> Dict[str, Any]:
    """
    Calculates CVSS v3.1 Base Score, Impact, Exploitability, and Severity Tier
    based on the official FIRST specification.
    """
    av = metrics.get("AV", "N")
    ac = metrics.get("AC", "L")
    pr = metrics.get("PR", "N")
    ui = metrics.get("UI", "N")
    scope = metrics.get("S", "U")
    c = metrics.get("C", "H")
    i = metrics.get("I", "H")
    a = metrics.get("A", "H")

    # Weights
    av_val = AV_WEIGHTS.get(av, 0.85)
    ac_val = AC_WEIGHTS.get(ac, 0.77)
    ui_val = UI_WEIGHTS.get(ui, 0.85)
    c_val = IMPACT_WEIGHTS.get(c, 0.56)
    i_val = IMPACT_WEIGHTS.get(i, 0.56)
    a_val = IMPACT_WEIGHTS.get(a, 0.56)

    is_scope_changed = (scope == "C")
    if is_scope_changed:
        pr_val = PR_WEIGHTS_CHANGED.get(pr, 0.85)
    else:
        pr_val = PR_WEIGHTS_UNCHANGED.get(pr, 0.85)

    # Sub-scores
    iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))
    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    if not is_scope_changed:
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)

    if impact <= 0:
        base_score = 0.0
    else:
        if not is_scope_changed:
            base_score = cvss_roundup(min(impact + exploitability, 10.0))
        else:
            base_score = cvss_roundup(min(1.08 * (impact + exploitability), 10.0))

    base_score = round(base_score, 1)

    # Severity Rating
    if base_score == 0.0:
        severity = "NONE"
    elif 0.1 <= base_score <= 3.9:
        severity = "LOW"
    elif 4.0 <= base_score <= 6.9:
        severity = "MEDIUM"
    elif 7.0 <= base_score <= 8.9:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    vector_str = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c}/I:{i}/A:{a}"

    return {
        "vector": vector_str,
        "base_score": base_score,
        "severity": severity,
        "impact_score": round(impact, 2),
        "exploitability_score": round(exploitability, 2),
        "scope_changed": is_scope_changed
    }
