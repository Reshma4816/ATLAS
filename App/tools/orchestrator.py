import re
from App.tools.scanner import run_nmap_discovery
from App.tools.openvas import run_openvas_scan
from App.tools.openscap import run_openscap_audit
from App.tools.owasp import run_owasp_zap_scan
from App.tools.threat_intel import ThreatIntelModule

# Instantiate a module-level singleton to avoid NameError when imported globally
ti_module = ThreatIntelModule()


def run_pipeline_orchestration(target: str) -> dict:
    """
    Triggers and groups vulnerability engines systematically.
    """
    results = {
        "nmap": "Executing...",
        "openvas": "Skipped",
        "openscap": "Skipped",
        "owasp_zap": "Skipped",
    }

    # 1. Run Nmap-equivalent Discovery Scan (pure-Python, first step)
    try:
        nmap_results = run_nmap_discovery(target)
    except Exception as exc:
        results["nmap"] = f"Discovery scan failed with an unexpected error: {exc}"
        return results

    results["nmap"] = nmap_results.get("raw_output", "No output returned.")

    # If discovery fails completely, stop execution to prevent invalid target checks
    if not nmap_results.get("success"):
        return results

    # Carry structured port data forward
    open_ports = nmap_results.get("structured_data", [])
    results["discovered_ports"] = open_ports

    # 2. Run OpenVAS Network Vulnerability Scan
    try:
        results["openvas"] = run_openvas_scan(target)
    except Exception as exc:
        results["openvas"] = f"OpenVAS scan failed: {exc}"

    # 3. Run OpenSCAP Compliance Audit Scan
    try:
        results["openscap"] = run_openscap_audit(target)
    except Exception as exc:
        results["openscap"] = f"OpenSCAP audit failed: {exc}"

    # 4. Run OWASP ZAP only if discovery detected an open web port
    if nmap_results.get("is_web_exposed"):
        https_ports = {443, 8443}
        scheme = "https" if any(p.get("port") in https_ports for p in open_ports) else "http"
        target_web_url = f"{scheme}://{target}"

        try:
            results["owasp_zap"] = run_owasp_zap_scan(target_web_url)
        except Exception as exc:
            results["owasp_zap"] = f"OWASP ZAP scan failed: {exc}"
    else:
        results["owasp_zap"] = "Bypassed (No web ports detected by discovery scan)."

    # 5. Threat Intelligence Processing Stage
    try:
        # Normalize logs to string format safely
        raw_openvas = str(results.get('openvas', ''))
        raw_openscap = str(results.get('openscap', ''))
        raw_zap = str(results.get('owasp_zap', ''))
        combined_logs = f"{raw_openvas} {raw_openscap} {raw_zap}"

        # Extract unique CVE IDs using regex
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        detected_cves = list(set(re.findall(cve_pattern, combined_logs, re.IGNORECASE)))

        # Enrich using calculate_threat_score (matching threat_intel.py method name)
        enriched_list = []
        for cve in detected_cves:
            intel = ti_module.calculate_threat_score(base_cvss=7.5, cve_id=cve.upper())
            enriched_list.append(intel)

        # Sort findings by threat adjusted score
        enriched_list.sort(key=lambda x: x.get("threatAdjustedScore", 0.0), reverse=True)

        results["threat_intel"] = {
            "status": "Success",
            "total_cves_analyzed": len(detected_cves),
            "enriched_findings": enriched_list
        }
    except Exception as exc:
        results["threat_intel"] = {"status": "Failed", "error": str(exc)}

    return results