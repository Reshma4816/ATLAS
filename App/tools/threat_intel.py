# App/tools/threat_intel.py
import requests
import logging

logging.basicConfig(level=logging.INFO)

class ThreatIntelModule:
    def __init__(self):
        self.cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.epss_api_url = "https://api.first.org/data/v1/epss"
        self._kev_catalog = None

    @property
    def kev_catalog(self) -> set:
        """Lazy load and cache CISA KEV catalog."""
        if self._kev_catalog is None:
            try:
                res = requests.get(self.cisa_kev_url, timeout=5)
                if res.status_code == 200:
                    vulns = res.json().get("vulnerabilities", [])
                    self._kev_catalog = {item["cveID"] for item in vulns if "cveID" in item}
                else:
                    self._kev_catalog = set()
            except Exception as exc:
                logging.warning(f"CISA KEV fetch failed: {exc}")
                self._kev_catalog = set()
        return self._kev_catalog

    def get_epss_score(self, cve_id: str) -> float:
        """Fetch live EPSS score from FIRST.org API."""
        if not cve_id or not cve_id.startswith("CVE-"):
            return 0.0
        try:
            res = requests.get(f"{self.epss_api_url}?cve={cve_id}", timeout=5)
            if res.status_code == 200:
                data = res.json().get("data", [])
                if data:
                    return float(data[0].get("epss", 0.0))
        except Exception as exc:
            logging.warning(f"EPSS lookup failed for {cve_id}: {exc}")
        return 0.0

    def calculate_threat_score(self, base_cvss: float, cve_id: str = None) -> dict:
        """
        Enriches an EXISTING finding score.
        Formula: 40% Base CVSS + 40% EPSS Probability + 20% CISA KEV Presence
        """
        # If no CVE exists (e.g. general web configuration issue), no active threat intel applies
        if not cve_id or not cve_id.startswith("CVE-"):
            return {
                "cveId": None,
                "inCisaKev": False,
                "epssScore": 0.0,
                "threatAdjustedScore": base_cvss  # Score remains unchanged
            }

        in_kev = cve_id in self.kev_catalog
        epss = self.get_epss_score(cve_id)
        kev_score = 10.0 if in_kev else 0.0

        # Weighted calculation
        threat_score = round((0.4 * base_cvss) + (0.4 * epss * 10) + (0.2 * kev_score), 2)

        return {
            "cveId": cve_id,
            "inCisaKev": in_kev,
            "epssScore": epss,
            "threatAdjustedScore": threat_score
        }