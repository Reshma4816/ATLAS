import type { Vulnerability, Severity } from '../types';

// Point this at your FastAPI server. Override via Vite env var if you deploy
// the API somewhere other than localhost:8000.
const API_BASE_URL =
  (import.meta as any).env?.VITE_ATLAS_API_URL ?? 'http://127.0.0.1:8000';

export class OrchestrationApiError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'OrchestrationApiError';
    this.status = status;
  }
}

// ---- Raw backend response shapes ----

export type BackendSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface CategoryCounts {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  INFO: number;
}

export interface FindingsSummary {
  total_validated_vulnerabilities: number;
  category_counts: CategoryCounts;
}

// Contract fields (id/title/severity/validated/details) are guaranteed by the
// backend. Everything else is carried along for Stage 2 dedup/rescoring and
// isn't guaranteed to be present.
export interface RawFinding {
  id: string;
  title: string;
  severity: BackendSeverity;
  validated: boolean;
  details: string;
  cvss?: number;
  cve_id?: string;
  host?: string;
  exploited?: boolean;
  business_criticality?: string;
  data_sensitivity?: string;
  [key: string]: unknown;
}

export interface ScanPhaseResponse {
  status: string;
  target: string;
  summary: FindingsSummary;
  validated_findings: RawFinding[];
}

export interface AttackGraphNode {
  id: string;
  label: string;
  type: string;
}

export interface AttackGraphEdge {
  source: string;
  target: string;
  label: string;
}

export interface AttackPathStep {
  step: string;
  action: string;
  target: string;
}

export interface Synthesis {
  executive_summary?: string;
  remediation_plan?: string[];
  attackGraph?: { nodes: AttackGraphNode[]; edges: AttackGraphEdge[] };
  attackPath?: AttackPathStep[];
  error?: string;
}

// Shared by both Stage 2 outcomes — /assess (exploit_mode) and
// /finalize (skip_pentest_and_finalize) return the same shape, differing
// only in `status` ("COMPLETED" vs "COMPLETED_WITHOUT_PENTEST") and the
// optional exploitation payload.
export interface Stage2PhaseResponse {
  status: string;
  target: string;
  summary: FindingsSummary;
  final_ranked_findings: RawFinding[];
  agent_exploitation_data?: unknown;
  synthesis: Synthesis;
}

// Backwards-compatible alias (previous name used only for the assess call).
export type AssessPhaseResponse = Stage2PhaseResponse;

// ---- API calls ----

async function postJson<T>(path: string, body: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch (err) {
    // Network failure: server down, CORS blocked, no connectivity, etc.
    throw new OrchestrationApiError(
      `Could not reach ATLAS API at ${API_BASE_URL}${path}. Is the backend running?`
    );
  }

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const errBody = await res.json();
      detail = errBody.detail ?? detail;
    } catch {
      /* response wasn't JSON, fall back to statusText */
    }
    throw new OrchestrationApiError(detail, res.status);
  }

  try {
    return (await res.json()) as T;
  } catch {
    throw new OrchestrationApiError('ATLAS API returned an invalid response body.');
  }
}

/** Stage 1 — Scan & Validate (Phases 1–3): POST /api/orchestration/scan
 *  Terminal on its own — does NOT trigger Stage 2. The caller must wait
 *  for the user's pentest decision before calling runAssessPhase or
 *  runFinalizePhase. */
export function runScanPhase(target: string): Promise<ScanPhaseResponse> {
  return postJson<ScanPhaseResponse>('/api/orchestration/scan', { target });
}

/** Stage 2a ("Request Approval" -> approved) — Exploitation, risk scoring,
 *  and synthesis: POST /api/orchestration/assess. Only call this after the
 *  user has explicitly chosen to run active pentesting. */
export function runAssessPhase(
  target: string,
  validated_findings: RawFinding[]
): Promise<Stage2PhaseResponse> {
  return postJson<Stage2PhaseResponse>('/api/orchestration/assess', {
    target,
    validated_findings,
  });
}

/** Stage 2b ("Continue Without Pentest") — Risk scoring and synthesis with
 *  no exploitation: POST /api/orchestration/finalize. Only call this after
 *  the user has explicitly chosen to skip active pentesting. */
export function runFinalizePhase(
  target: string,
  validated_findings: RawFinding[]
): Promise<Stage2PhaseResponse> {
  return postJson<Stage2PhaseResponse>('/api/orchestration/finalize', {
    target,
    validated_findings,
  });
}

// ---- Mapping: backend RawFinding[] + Synthesis -> frontend Vulnerability[] ----

// Backend severity is uppercase (CRITICAL/HIGH/MEDIUM/LOW/INFO); the frontend's
// Severity type is title case (Critical/High/Medium/Low/Info).
function severityFromBackend(severity: BackendSeverity): Severity {
  const map: Record<BackendSeverity, Severity> = {
    CRITICAL: 'Critical',
    HIGH: 'High',
    MEDIUM: 'Medium',
    LOW: 'Low',
    INFO: 'Info',
  };
  return map[severity] ?? 'Info';
}

/**
 * Converts raw backend findings (which vary in shape depending on whether they
 * came from CVE enrichment, open-port discovery, or pentest exploitation) into
 * the strongly-typed Vulnerability[] the existing UI components expect.
 * Synthesis data (attack graph / attack path / remediation plan) is used to
 * enrich matching findings where possible, and as a fallback otherwise.
 */
export function mapFindingsToVulnerabilities(
  findings: RawFinding[],
  synthesis?: Synthesis
): Vulnerability[] {
  const remediationSteps = synthesis?.remediation_plan ?? [];
  const globalAttackPath =
    synthesis?.attackPath?.map((s) => ({ step: s.step, detail: `${s.action} → ${s.target}` })) ?? [];

  return findings.map((f, idx) => {
    const isExploited = Boolean(f.exploited);

    const vuln: Vulnerability = {
      id: f.id ?? `VULN-${String(idx + 1).padStart(3, '0')}`,
      title: f.title,
      severity: severityFromBackend(f.severity),
      cvss: f.cvss ?? 0,
      confidence: f.validated || isExploited ? 95 : 70,
      cwe: f.cve_id ?? 'CWE-Unknown',
      affected: f.host ?? 'Unknown asset',
      description: f.details || `${f.title} identified on ${f.host ?? 'target'}.`,
      businessImpact: isExploited
        ? 'Confirmed exploitable during active pentest — direct business impact validated.'
        : f.business_criticality
        ? `Affects an asset flagged as ${f.business_criticality} business criticality.`
        : 'Impact pending validation.',
      threatIntel: f.data_sensitivity
        ? `Asset handles ${f.data_sensitivity} data — treat threat correlation accordingly.`
        : 'No active exploitation intelligence found.',
      remediation:
        remediationSteps[idx] ?? remediationSteps[0] ?? 'Review finding and apply standard remediation guidance.',
      attackPath:
        globalAttackPath.length > 0
          ? globalAttackPath
          : [{ step: '1', detail: f.details || `Finding observed on ${f.host ?? 'target'}` }],
    };

    return vuln;
  });
}