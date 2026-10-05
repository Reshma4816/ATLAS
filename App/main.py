import os
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Import the main agent state machine
from App.agent import AIOrchestratorAgent

app = FastAPI(
    title="ATLAS Security Orchestrator API",
    description="Multi-agent security vulnerability analysis and validation platform.",
    version="1.0.0"
)

# Enable CORS for React frontend or external clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production as needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# PYDANTIC REQUEST & RESPONSE MODELS
# ==========================================

class ScanRequest(BaseModel):
    target: str = Field(..., example="http://127.0.0.1:5000", description="Target URL or IP address to scan")


class AssessmentRequest(BaseModel):
    target: str = Field(..., example="http://127.0.0.1:5000", description="Target URL or IP address")
    # NOTE: this must be the `validated_findings` array returned by
    # POST /api/orchestration/scan — not a renamed/reshaped copy — since
    # exploit_mode() dedupes and rescopes exploitation results against these
    # exact finding ids.
    validated_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="The validated_findings array returned by Stage 1 (scan_and_validate)"
    )


class StatusResponse(BaseModel):
    status: str
    message: str


# ==========================================
# API ROUTE HANDLERS
# ==========================================

@app.get("/", response_model=StatusResponse)
async def root() -> Dict[str, str]:
    """Health check endpoint."""
    return {"status": "online", "message": "ATLAS Security Orchestrator API is operational."}


@app.post("/api/orchestration/scan", response_model=Dict[str, Any])
async def run_scan_phase(req: ScanRequest) -> Dict[str, Any]:
    """
    STAGE 1: Executes the scanner pipeline, validates raw findings via the
    Pentest Agent (dropping false positives), applies business context, and
    returns the categorized summary + validated_findings contract the
    frontend renders while awaiting pentest approval.
    """
    try:
        agent = AIOrchestratorAgent()
        result = agent.scan_and_validate(req.target)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Scan & validate phase failed: {str(e)}"
        )


@app.post("/api/orchestration/assess", response_model=Dict[str, Any])
async def run_assess_phase(req: AssessmentRequest) -> Dict[str, Any]:
    """
    STAGE 2a ("Request Approval" -> approved): Runs the Pentest Agent in
    exploitation mode using non-destructive canary probes against the Stage 1
    validated findings to discover NEW vulnerabilities, dedupes results by
    finding id, THEN recalculates risk scores and generates the Ollama
    synthesis (executive summary, remediation plan, attack graph, attack path).
    """
    try:
        agent = AIOrchestratorAgent()
        result = agent.exploit_mode(req.target, req.validated_findings)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Exploit mode phase failed: {str(e)}"
        )


@app.post("/api/orchestration/finalize", response_model=Dict[str, Any])
async def run_finalize_phase(req: AssessmentRequest) -> Dict[str, Any]:
    """
    STAGE 2b ("Continue Without Pentest"): Skips exploitation entirely and
    goes straight to risk scoring + Ollama synthesis using only the Stage 1
    validated findings.
    """
    try:
        agent = AIOrchestratorAgent()
        result = agent.skip_pentest_and_finalize(req.target, req.validated_findings)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Finalize (skip-pentest) phase failed: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("App.main:app", host="127.0.0.1", port=8000, reload=True)