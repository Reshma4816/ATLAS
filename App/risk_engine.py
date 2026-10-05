"""
Pure Python Risk Engine (0 LLM Tokens)
Calculates deterministic risk scores based on weighted parameters,
threat intelligence, business context, and pentest verification status.
"""

from typing import Dict, Any, List

WEIGHT_CVSS = 0.35
WEIGHT_EPSS = 0.20
WEIGHT_KEV = 0.20
WEIGHT_CRITICALITY = 0.15
WEIGHT_EXPOSURE = 0.10


def calculate_risk_score(
    cvss_base: float,
    epss_score: float,
    is_cisa_kev: bool,
    asset_criticality: float,
    exposure_level: float,
    is_pentest_validated: bool = False
) -> float:
    normalized_epss = epss_score * 10.0
    kev_score = 10.0 if is_cisa_kev else 0.0

    raw_score = (
        (cvss_base * WEIGHT_CVSS) +
        (normalized_epss * WEIGHT_EPSS) +
        (kev_score * WEIGHT_KEV) +
        (asset_criticality * WEIGHT_CRITICALITY) +
        (exposure_level * WEIGHT_EXPOSURE)
    )

    # Apply a 10% risk multiplier if the pentest agent actively verified/exploited the issue
    if is_pentest_validated:
        raw_score *= 1.10

    return round(min(max(raw_score, 0.0), 10.0), 2)


def get_risk_severity(score: float) -> str:
    """Categorizes the numerical score into a standard risk severity band."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def rank_vulnerabilities(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Ranks vulnerabilities based on base score, threat intel,
    business context, and pentest agent verification output.
    """
    for item in findings:
        # Resolve fields with fallback key compatibility
        cvss = float(item.get("cvss", item.get("base_score", 0.0)))
        epss = float(item.get("epss", item.get("epssScore", 0.0)))
        cisa_kev = bool(item.get("cisa_kev", item.get("inCisaKev", False)))
        criticality = float(item.get("asset_criticality", 5.0))
        exposure = float(item.get("exposure_level", 5.0))
        
        # Check if pentest_agent verified or exploited this vulnerability
        is_validated = bool(
            item.get("verified", False) or 
            item.get("validated", False) or 
            item.get("exploited", False)
        )

        calculated_score = calculate_risk_score(
            cvss_base=cvss,
            epss_score=epss,
            is_cisa_kev=cisa_kev,
            asset_criticality=criticality,
            exposure_level=exposure,
            is_pentest_validated=is_validated
        )

        item["calculated_risk_score"] = calculated_score
        item["severity"] = get_risk_severity(calculated_score)

    return sorted(findings, key=lambda x: x["calculated_risk_score"], reverse=True)