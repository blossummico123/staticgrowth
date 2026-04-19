"""
AI Sentinel — Cloud API Service
FastAPI wrapper around the vulnerability prioritization engine.
"""

import io
import json
import os
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Add parent dir so we can import the prioritizer
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from prioritize_vulnerabilities import (
    collect_all_findings,
    parse_fickling_safety_results,
    parse_modelscan_json,
    parse_osv_scanner_json,
    parse_picklescan_txt,
    parse_semgrep_json,
    prioritize_with_openai,
)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AI Sentinel",
    description=(
        "AI-powered vulnerability prioritization for ML model artifacts. "
        "Upload scan results from open-source tools (Fickling, ModelScan, "
        "Semgrep, OSV-Scanner, etc.) and get AI-prioritized findings."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    scanner: str = ""
    scanner_severity: str = ""
    title: str = ""
    description: str = ""
    category: str = ""
    file: Optional[str] = None
    line: Optional[int] = None
    indicators: dict = Field(default_factory=dict)


class PrioritizeRequest(BaseModel):
    findings: list[Finding] = Field(
        ..., description="Array of vulnerability findings from scanners"
    )
    model: str = Field(default="gpt-4o", description="OpenAI model to use")


class ScanResultsRequest(BaseModel):
    scanner: str = Field(
        ..., description="Scanner name: fickling, semgrep, modelscan, picklescan, osv-scanner"
    )
    results: dict | list | str = Field(
        ..., description="Raw scanner output (JSON object/array or text)"
    )
    model: str = Field(default="gpt-4o", description="OpenAI model to use")


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str
    openai_configured: bool


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/api/v1/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
        openai_configured=bool(OPENAI_API_KEY),
    )


@app.post("/api/v1/prioritize")
async def prioritize(request: PrioritizeRequest):
    """
    Accept pre-parsed findings and prioritize them with AI.

    Send an array of findings (from any scanner) and get back
    AI-prioritized vulnerabilities ranked by criticality.
    """
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY not configured")

    if not request.findings:
        return {
            "metadata": {"total_findings": 0},
            "prioritized_vulnerabilities": [],
        }

    # Convert Pydantic models to dicts for the prioritizer
    findings = []
    for f in request.findings:
        entry = f.model_dump(exclude_none=True)
        entry["_hash"] = f"{f.scanner}:{f.title}"[:12]
        findings.append(entry)

    result = prioritize_with_openai(
        findings, model=request.model, api_key=OPENAI_API_KEY
    )
    return result


@app.post("/api/v1/scan-results")
async def ingest_scan_results(request: ScanResultsRequest):
    """
    Accept raw scanner output, parse it, and prioritize.

    Supported scanners: fickling, semgrep, modelscan, picklescan, osv-scanner
    """
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY not configured")

    scanner = request.scanner.lower().replace("-", "").replace("_", "")
    findings = []

    # Write raw results to temp file for parsers that expect files
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tmp:
        if isinstance(request.results, str):
            tmp.write(request.results)
        else:
            json.dump(request.results, tmp)
        tmp_path = tmp.name

    try:
        if scanner in ("fickling", "safetyresults"):
            findings = parse_fickling_safety_results(tmp_path)
        elif scanner == "semgrep":
            findings = parse_semgrep_json(tmp_path)
        elif scanner == "modelscan":
            findings = parse_modelscan_json(tmp_path)
        elif scanner in ("picklescan",):
            findings = parse_picklescan_txt(tmp_path)
        elif scanner in ("osvscanner", "osv"):
            findings = parse_osv_scanner_json(tmp_path)
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown scanner: {request.scanner}. Supported: fickling, semgrep, modelscan, picklescan, osv-scanner",
            )
    finally:
        os.unlink(tmp_path)

    if not findings:
        return {
            "metadata": {"total_findings": 0, "scanner": request.scanner},
            "prioritized_vulnerabilities": [],
        }

    result = prioritize_with_openai(
        findings, model=request.model, api_key=OPENAI_API_KEY
    )
    return result


@app.post("/api/v1/upload-and-scan")
async def upload_and_scan(
    file: UploadFile = File(..., description="Scanner output file (JSON or text)"),
    scanner: str = "auto",
    model: str = "gpt-4o",
):
    """
    Upload a scanner results file, auto-detect format, parse, and prioritize.
    """
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY not configured")

    content = await file.read()
    filename = file.filename or "upload.json"

    # Write to temp
    with tempfile.NamedTemporaryFile(
        delete=False, suffix=os.path.splitext(filename)[1]
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        findings = []

        # Auto-detect scanner from filename or content
        if scanner == "auto":
            fname_lower = filename.lower()
            if "safety_results" in fname_lower or "fickling" in fname_lower:
                scanner = "fickling"
            elif "semgrep" in fname_lower:
                scanner = "semgrep"
            elif "modelscan" in fname_lower:
                scanner = "modelscan"
            elif "picklescan" in fname_lower:
                scanner = "picklescan"
            elif "osv" in fname_lower:
                scanner = "osv-scanner"
            else:
                # Try all parsers
                findings.extend(parse_fickling_safety_results(tmp_path))
                findings.extend(parse_semgrep_json(tmp_path))
                findings.extend(parse_modelscan_json(tmp_path))
                findings.extend(parse_osv_scanner_json(tmp_path))
                scanner = "auto-detected"

        if not findings:
            s = scanner.lower().replace("-", "").replace("_", "")
            if s in ("fickling", "safetyresults"):
                findings = parse_fickling_safety_results(tmp_path)
            elif s == "semgrep":
                findings = parse_semgrep_json(tmp_path)
            elif s == "modelscan":
                findings = parse_modelscan_json(tmp_path)
            elif s == "picklescan":
                findings = parse_picklescan_txt(tmp_path)
            elif s in ("osvscanner", "osv"):
                findings = parse_osv_scanner_json(tmp_path)

    finally:
        os.unlink(tmp_path)

    if not findings:
        return {
            "metadata": {
                "total_findings": 0,
                "scanner": scanner,
                "filename": filename,
            },
            "prioritized_vulnerabilities": [],
        }

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        h = f.get("_hash", "")
        if h not in seen:
            seen.add(h)
            unique.append(f)

    result = prioritize_with_openai(unique, model=model, api_key=OPENAI_API_KEY)
    result["metadata"]["filename"] = filename
    result["metadata"]["scanner"] = scanner
    return result


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
