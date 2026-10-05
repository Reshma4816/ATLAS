"""
AI Orchestrator Agent State Machine
Coordinates pipeline phases, tool orchestration, Pentest Agent validation/exploitation,
business context risk ranking, and Ollama synthesis output.

Flow:
  1. scan_and_validate(target)
       -> scans, validates findings (drops false positives), returns ONLY a
          categorized count summary + validated_findings. Nothing else runs
          here — no exploitation, no risk scoring, no synthesis. This is the
          state the UI shows while awaiting the user's pentest decision.

  2a. exploit_mode(target, validated_findings)      [user clicked "Request Approval" -> approved]
        -> runs Pentest Agent exploitation to discover/confirm NEW vulnerabilities,
           merges + dedupes them into the validated set, THEN runs risk scoring
           and Ollama synthesis (executive summary, remediation plan, attack
           graph, attack path).

  2b. skip_pentest_and_finalize(target, validated_findings)   [user clicked "Continue Without Pentest"]
        -> skips exploitation entirely. Goes straight to risk scoring and
           Ollama synthesis using only the Stage 1 validated findings.

Response contracts for scan_and_validate / exploit_mode / skip_pentest_and_finalize
match what the frontend renders — do not rename their keys without also
updating App/main.py and the frontend's orchestrationApi.ts.

ID HANDLING — IMPORTANT
------------------------
run_agent_validation() and run_agent_exploitation() are themselves backed by
an LLM (Ollama) that free-generates JSON, including each finding's "id"
field. Small local models routinely reuse the same id (e.g. "VULN-001") for
every item in a list, or omit it, or leave it null. exploit_mode() merges
findings into a dict keyed by id specifically to dedupe re-confirmed
findings — but if incoming ids collide with each other (rather than with a
*real* existing finding), that same dict write silently collapses multiple
distinct findings down to one. _dedupe_id() and _mint_new_id() below exist
to make sure an id is only ever reused when it actually refers to something
we already tracked; anything else gets a guaranteed-unique id instead of
being trusted at face value.
"""

import json
from typing import Any, Dict, List, Set
import ollama

# --- REAL MODULE IMPORTS ---
from App.business_context import get_asset_context
from App.risk_engine import rank_vulnerabilities
from App.tools.orchestrator import run_pipeline_orchestration

# Imported separate pentest agent entry points
from pentest_agent.pentest_agent import run_agent_validation, run_agent_exploitation


SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _severity_from_score(score: float) -> str:
    """Maps a CVSS-style 0-10 score to the uppercase severity buckets the UI expects."""
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "INFO"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def _empty_category_counts() -> Dict[str, int]:
    return {level: 0 for level in SEVERITY_LEVELS}


def _dedupe_id(candidate: str, seen_ids: Set[str]) -> str:
    """
    Returns an id guaranteed not to already be in seen_ids, adding it to
    seen_ids before returning. If candidate is already taken, appends a
    numeric suffix until it finds a free one. This is what stops an
    LLM-generated id (which may be blank, null, or reused across every item)
    from silently overwriting a previous finding in an id-keyed dict.
    """
    candidate = candidate or "FINDING"
    if candidate not in seen_ids:
        seen_ids.add(candidate)
        return candidate
    n = 2
    while f"{candidate}-{n}" in seen_ids:
        n += 1
    deduped = f"{candidate}-{n}"
    seen_ids.add(deduped)
    return deduped


class AIOrchestratorAgent:
    def __init__(self, model_name: str = "llama3.1"):
        self.model_name = model_name

    # =========================================================================
    # STAGE 1: SCAN -> PENTEST VALIDATION -> FALSE POSITIVE REMOVAL ->
    #          BUSINESS CONTEXT -> CATEGORIZED SUMMARY. STOPS HERE.
    # =========================================================================
    def scan_and_validate(self, target: str = "127.0.0.1") -> Dict[str, Any]:
        """
        Executes the discovery/scan pipeline, validates raw findings via the
        Pentest Agent (validation mode), drops anything flagged as a false
        positive, enriches survivors with business context, and returns the
        categorized count summary. This is a terminal state for Stage 1 —
        no exploitation, risk scoring, or synthesis happens here. The caller
        (frontend) waits for the user's pentest decision before Stage 2 runs.
        """
        # STEP 1: Execute Scanner Pipeline via Orchestrator
        print(f"\n=== [PHASE 1] EXECUTING DISCOVERY SCAN PIPELINE ON {target} ===")
        orch_results = run_pipeline_orchestration(target)

        raw_findings: List[Dict[str, Any]] = []
        intel_data = orch_results.get("threat_intel", {})

        if intel_data.get("status") == "Success":
            for idx, item in enumerate(intel_data.get("enriched_findings", []), start=1):
                cvss = item.get("threatAdjustedScore", item.get("base_cvss", 7.5))
                raw_findings.append({
                    "id": f"VULN-{idx:03d}",
                    "cve_id": item.get("cve_id", "N/A"),
                    "host": target,
                    "title": f"Vulnerability {item.get('cve_id', '')}".strip(),
                    "cvss": cvss,
                    "inCisaKev": item.get("inCisaKev", False),
                    "epssScore": item.get("epssScore", 0.0),
                })

        # Fallback to open ports if no specific CVEs were parsed
        if not raw_findings and "discovered_ports" in orch_results:
            for p in orch_results.get("discovered_ports", []):
                raw_findings.append({
                    "id": f"PORT-{p.get('port', '0')}",
                    "cve_id": "INFO-PORT-OPEN",
                    "host": target,
                    "title": f"Open Port Discovered: {p.get('port')} ({p.get('service', 'unknown')})",
                    "cvss": 3.0,
                })

        # STEP 2: Execute Pentest Agent in Validation Mode (false-positive removal)
        print(f"\n=== [PHASE 2] VALIDATING RAW FINDINGS VIA PENTEST AGENT ===")
        val_res = run_agent_validation(target, raw_findings)
        verified_list = val_res.get("validated_findings", [])

        # Tracks every id we've already assigned in THIS call so an LLM that
        # returns the same "id" (or no id) for multiple items can never
        # collide — each finding always ends up with a unique id here.
        seen_ids: Set[str] = set()

        validated_findings: List[Dict[str, Any]] = []
        if verified_list:
            for v_item in verified_list:
                # Drop anything the agent explicitly marked as not verified —
                # this is the false-positive filter.
                if v_item.get("verified", True) is False:
                    continue
                # Prefer the validator's id when it gave one, but never trust
                # it blindly — dedupe against everything assigned so far.
                candidate_id = v_item.get("id") or f"VULN-{len(validated_findings) + 1:03d}"
                fid = _dedupe_id(str(candidate_id), seen_ids)
                validated_findings.append({
                    "id": fid,
                    "title": v_item.get("vulnerability", "Discovered Vulnerability"),
                    "host": target,
                    "cvss": v_item.get("cvss", 7.5),
                    "cve_id": v_item.get("cve_id", "N/A"),
                    "validated": True,
                    "details": v_item.get("evidence", "Validated via validation script"),
                })
        else:
            # Validator returned no structured list — carry raw findings over,
            # tagged as validated so the UI still has something to show, with
            # the validator's raw response preserved for audit purposes.
            # Raw findings already have deterministic unique ids, but we still
            # run them through _dedupe_id for safety/consistency.
            for r_item in raw_findings:
                fid = _dedupe_id(str(r_item.get("id", "")), seen_ids)
                validated_findings.append({
                    **r_item,
                    "id": fid,
                    "validated": True,
                    "details": f"Carried over from scan (validator returned no structured findings): {json.dumps(val_res)[:200]}",
                })

        # STEP 3: Business Context Enrichment (kept — informs severity/category
        # display and is needed later by Stage 2, but does NOT rank or score).
        print(f"\n=== [PHASE 3] ENRICHING VALIDATED FINDINGS WITH BUSINESS CONTEXT ===")
        for finding in validated_findings:
            finding.update(get_asset_context(target))

        # Build the exact Stage 1 output contract expected by the frontend.
        # Category counts only — no ranking, no risk score, no synthesis.
        category_counts = _empty_category_counts()
        contract_findings: List[Dict[str, Any]] = []
        for finding in validated_findings:
            severity = _severity_from_score(finding.get("cvss", 0))
            category_counts[severity] += 1
            contract_findings.append({
                "id": finding.get("id"),
                "title": finding.get("title", "Untitled Finding"),
                "severity": severity,
                "validated": finding.get("validated", True),
                "details": finding.get("details", ""),
                # Internal fields the UI doesn't read directly but Stage 2
                # needs to dedupe/rescore — harmless extras alongside the contract.
                "cvss": finding.get("cvss"),
                "cve_id": finding.get("cve_id"),
                "host": finding.get("host"),
                "business_criticality": finding.get("business_criticality"),
                "data_sensitivity": finding.get("data_sensitivity"),
            })

        return {
            "status": "VALIDATED",
            "target": target,
            "summary": {
                "total_validated_vulnerabilities": len(contract_findings),
                "category_counts": category_counts,
            },
            "validated_findings": contract_findings,
        }

    # Backwards-compatible alias for any existing callers.
    def run_validation_phase(self, target: str = "127.0.0.1") -> Dict[str, Any]:
        return self.scan_and_validate(target)

    # =========================================================================
    # STAGE 2a: "Request Approval" -> approved
    #   PENTEST EXPLOITATION (find NEW vulns) -> DEDUPE -> RISK SCORE -> SYNTHESIS
    # =========================================================================
    def exploit_mode(self, target: str, validated_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Runs the Pentest Agent in exploitation mode against the Stage 1
        validated findings to discover/confirm NEW vulnerabilities, merges +
        dedupes them by finding id, THEN runs risk scoring and calls Ollama
        to synthesize the executive summary, remediation plan, attack graph,
        and attack path.
        """
        print(f"\n=== [PHASE 4] EXECUTING PENTEST ASSESSMENT/EXPLOITATION ON {target} ===")
        exp_res = run_agent_exploitation(target, validated_findings)
        exploited_list = exp_res.get("validated_findings", [])

        # Index Stage 1 findings by id so exploitation results merge/dedupe
        # cleanly. Stage 1 ids are already unique (see _dedupe_id above), but
        # we re-run them through here too in case validated_findings came
        # from an older/uncleaned source.
        seen_ids: Set[str] = set()
        findings_by_id: Dict[str, Dict[str, Any]] = {}
        for f in validated_findings:
            fid = _dedupe_id(str(f.get("id") or f"VULN-{len(findings_by_id) + 1:03d}"), seen_ids)
            entry = dict(f)
            entry["id"] = fid
            findings_by_id[fid] = entry

        newly_discovered = 0
        for exp_item in exploited_list:
            reported_id = exp_item.get("id")
            # Only reuse an incoming id when it actually refers to a finding
            # we already know about — that's a genuine "confirmed" match.
            # Anything else (missing, blank, or colliding with another new
            # item) gets a freshly minted unique id instead of overwriting
            # whatever else already holds that key.
            if reported_id and reported_id in findings_by_id:
                fid = reported_id
                existing = findings_by_id.get(fid)
            else:
                fid = _dedupe_id(str(reported_id or f"EXPLOIT-{len(findings_by_id) + 1:03d}"), seen_ids)
                existing = None
                newly_discovered += 1

            merged = {
                **(existing or {}),
                "id": fid,
                "cve_id": (existing or {}).get("cve_id", fid),
                "host": target,
                "title": exp_item.get("vulnerability", (existing or {}).get("title", "Exploited Vulnerability")),
                # Exploitation confirms real-world impact — floor the score at 8.5
                # but never downgrade a finding that already scored higher.
                "cvss": max(float((existing or {}).get("cvss") or 0), 8.5),
                "exploited": True,
                "details": exp_item.get("evidence", (existing or {}).get("details", "Canary probe successful")),
            }
            merged.update(get_asset_context(target))
            findings_by_id[fid] = merged  # overwrite = dedupe by id (safe: fid is guaranteed unique/known here)

        deduped_findings = list(findings_by_id.values())

        print(f"\n=== [PHASE 5] RISK SCORING ({newly_discovered} new finding(s) from exploitation) ===")
        final_ranked = rank_vulnerabilities(deduped_findings)

        # Recompute severity + category counts post-exploitation
        category_counts = _empty_category_counts()
        for f in final_ranked:
            severity = _severity_from_score(f.get("cvss", 0))
            f["severity"] = severity
            category_counts[severity] += 1

        print("\n=== [PHASE 6] GENERATING ATTACK GRAPH & REMEDIATION SYNTHESIS ===")
        synthesis = self._call_ollama_synthesis(target, final_ranked)

        return {
            "status": "COMPLETED",
            "target": target,
            "summary": {
                "total_validated_vulnerabilities": len(final_ranked),
                "category_counts": category_counts,
            },
            "final_ranked_findings": final_ranked,
            "agent_exploitation_data": exp_res,
            "synthesis": synthesis,
        }

    # Backwards-compatible alias for any existing callers.
    def run_assessment_phase(self, target: str, initial_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return self.exploit_mode(target, initial_findings)

    # =========================================================================
    # STAGE 2b: "Continue Without Pentest"
    #   NO EXPLOITATION -> RISK SCORE -> SYNTHESIS, straight from Stage 1 findings
    # =========================================================================
    def skip_pentest_and_finalize(self, target: str, validated_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Used when the user declines active pentesting. Skips exploitation
        entirely and goes straight to risk scoring + Ollama synthesis using
        only the Stage 1 validated findings.
        """
        print(f"\n=== [PHASE 4] SKIPPED — PENTEST EXPLOITATION NOT REQUESTED ===")
        print(f"\n=== [PHASE 5] RISK SCORING ON {len(validated_findings)} VALIDATED FINDING(S) ===")

        # No id-keyed merge happens on this path (it's a straight list ->
        # rank_vulnerabilities), so this branch was never susceptible to the
        # id-collision collapse — kept as-is aside from a defensive id
        # dedupe pass for consistency with Stage 2a's output.
        seen_ids: Set[str] = set()
        deduped_input: List[Dict[str, Any]] = []
        for f in validated_findings:
            entry = dict(f)
            entry["id"] = _dedupe_id(str(entry.get("id") or f"VULN-{len(deduped_input) + 1:03d}"), seen_ids)
            deduped_input.append(entry)

        final_ranked = rank_vulnerabilities(deduped_input)

        category_counts = _empty_category_counts()
        for f in final_ranked:
            severity = _severity_from_score(f.get("cvss", 0))
            f["severity"] = severity
            category_counts[severity] += 1

        print("\n=== [PHASE 6] GENERATING ATTACK GRAPH & REMEDIATION SYNTHESIS ===")
        synthesis = self._call_ollama_synthesis(target, final_ranked)

        return {
            "status": "COMPLETED_WITHOUT_PENTEST",
            "target": target,
            "summary": {
                "total_validated_vulnerabilities": len(final_ranked),
                "category_counts": category_counts,
            },
            "final_ranked_findings": final_ranked,
            "synthesis": synthesis,
        }

    # =========================================================================
    # LOCAL CLI PIPELINE
    # =========================================================================
    def run_pipeline(self, target: str = "127.0.0.1") -> Dict[str, Any]:
        stage1 = self.scan_and_validate(target)

        print("\n=== [STAGE 1 SUMMARY] ===")
        print(json.dumps(stage1["summary"], indent=2))

        print("\n=== [APPROVAL GATE] ===")
        user_choice = input("Do you want to run the Pentesting Agent in ASSESSMENT/EXPLOITATION mode? (y/N): ").strip().lower()

        if user_choice == "y":
            return self.exploit_mode(target, stage1["validated_findings"])
        else:
            print("\n[INFO] Skipping Pentest Exploitation phase.")
            return self.skip_pentest_and_finalize(target, stage1["validated_findings"])

    def _call_ollama_synthesis(self, target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        prompt = f"""
You are the ATLAS Security Orchestrator. Analyze the provided target and its actual findings to generate a tailored security report.

Target Host: {target}
Actual Findings:
{json.dumps(findings, indent=2)}

INSTRUCTIONS:
1. Base all remediation steps directly on the vulnerabilities present in 'Actual Findings'.
2. Do NOT invent unrelated vulnerabilities (e.g., do NOT mention Log4j or XSS unless present in findings).
3. Build the attack graph and path according to the severity and impact of the actual findings.

CRITICAL: Output MUST be valid JSON matching this exact structure:
{{
  "executive_summary": "Summary describing the actual risk posture based on findings.",
  "remediation_plan": [
    "Specific step based on finding 1",
    "Specific step based on finding 2"
  ],
  "attackGraph": {{
    "nodes": [
      {{"id": "node-attacker", "label": "External Attacker", "type": "actor"}},
      {{"id": "node-target", "label": "{target}", "type": "asset"}}
    ],
    "edges": [
      {{"source": "node-attacker", "target": "node-target", "label": "Actual impact (e.g. Missing Security Headers / Information Disclosure)"}}
    ]
  }},
  "attackPath": [
    {{"step": "1", "action": "Reconnaissance & Header Analysis", "target": "{target}"}},
    {{"step": "2", "action": "Exploit missing browser defenses", "target": "Client Browser"}}
  ]
}}
"""
        try:
            res = ollama.chat(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                format="json"
            )
            return json.loads(res["message"]["content"])
        except Exception as e:
            return {"error": f"Synthesis formatting error: {str(e)}"}


if __name__ == "__main__":
    agent = AIOrchestratorAgent()
    result = agent.run_pipeline("http://127.0.0.1:5000")

    print("\n==========================================")
    print("           FINAL SYNTHESIS REPORT          ")
    print("==========================================")
    print(json.dumps(result.get("synthesis"), indent=2))