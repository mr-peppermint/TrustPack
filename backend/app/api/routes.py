import asyncio
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel

from app.api import frontend_adapter
from app.config import settings
from app.models.request import AnalyzeRequest
from app.models.response import AnalyzeResponse
from app.services import orchestrator, report_generator
from app.utils.errors import AnalysisTimeoutError
from app.utils.logging import get_logger

router = APIRouter()
logger = get_logger(__name__)

_semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_ANALYSES)


async def _run_analysis(request: AnalyzeRequest) -> Dict[str, Any]:
    # TrustPackError subclasses intentionally propagate to the app-level exception handler in
    # main.py, which renders the consistent {"error": {"code", "message"}} shape.
    budget = settings.ANALYSIS_TIMEOUT_SECONDS + (settings.AI_TIMEOUT + 2 if settings.AI_ENABLED else 0)
    async with _semaphore:
        try:
            return await asyncio.wait_for(
                orchestrator.analyze_package(
                    request.package_name, request.version,
                    ecosystem=request.ecosystem, repository_url=request.repository_url,
                ),
                timeout=budget,
            )
        except asyncio.TimeoutError:
            raise AnalysisTimeoutError("Analysis exceeded the time budget")


def _history_item(report: Dict[str, Any]) -> Dict[str, Any]:
    package = report.get("package") or {}
    risk = report.get("risk") or {}
    return {
        "id": report["report_id"],
        "created_at": report.get("created_at"),
        "package": {"name": package.get("name"), "version": package.get("version"), "ecosystem": package.get("ecosystem", "npm")},
        "repository": (report.get("source") or {}).get("repository"),
        "verdict": risk.get("verdict"),
        "risk_level": risk.get("level"),
        "risk_score": risk.get("score"),
        "confidence": risk.get("confidence"),
        "analysis_complete": report.get("analysis_complete"),
    }


# ----------------------------------------------------------------------------- health

@router.get("/health")
@router.get("/api/health")
async def health() -> dict:
    return {"status": "ok"}


# ----------------------------------------------------------------------------- canonical API

@router.post("/api/analyze", response_model=AnalyzeResponse)
@router.post("/analyze", response_model=AnalyzeResponse, include_in_schema=False)  # original path, kept for compatibility
async def analyze(request: AnalyzeRequest) -> dict:
    return await _run_analysis(request)


@router.get("/api/analysis/{analysis_id}", response_model=AnalyzeResponse)
@router.get("/report/{analysis_id}", response_model=AnalyzeResponse, include_in_schema=False)
async def get_analysis(analysis_id: str) -> dict:
    return report_generator.get_report(analysis_id)


@router.get("/api/history")
async def history(limit: int = Query(50, ge=1, le=500)) -> List[Dict[str, Any]]:
    return [_history_item(r) for r in report_generator.list_reports(limit)]


# ----------------------------------------------------------------------------- React frontend contract
# src/services/analysisService.ts defaults: POST /analyses -> {id}, GET /analyses/{id}, GET /analyses.
# Set VITE_USE_MOCK=false and VITE_API_BASE_URL=http://localhost:8000 to use these.

class FrontendAnalysisRequest(BaseModel):
    ecosystem: str
    name: str
    version: str
    repoUrl: Optional[str] = ""


@router.post("/analyses", include_in_schema=True)
async def frontend_start(body: FrontendAnalysisRequest) -> Dict[str, str]:
    request = AnalyzeRequest(
        package_name=body.name, version=body.version, ecosystem=body.ecosystem, repository_url=body.repoUrl or None,
    )
    report = await _run_analysis(request)
    return {"id": report["report_id"]}


@router.get("/analyses")
async def frontend_history(limit: int = Query(100, ge=1, le=500)) -> List[Dict[str, Any]]:
    return [frontend_adapter.to_summary(r) for r in report_generator.list_reports(limit)]


@router.get("/analyses/{analysis_id}")
async def frontend_result(analysis_id: str) -> Dict[str, Any]:
    return frontend_adapter.to_result(report_generator.get_report(analysis_id))
