import asyncio

from fastapi import APIRouter

from app.config import settings
from app.models.request import AnalyzeRequest
from app.models.response import AnalyzeResponse
from app.services import orchestrator, report_generator
from app.utils.errors import AnalysisTimeoutError
from app.utils.logging import get_logger

router = APIRouter()
logger = get_logger(__name__)

_semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_ANALYSES)


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest) -> dict:
    # TrustPackError subclasses intentionally propagate to the app-level
    # exception handler in main.py, which renders the consistent
    # {"error": {"code", "message"}} shape.
    async with _semaphore:
        try:
            report = await asyncio.wait_for(
                orchestrator.analyze_package(request.package_name, request.version),
                timeout=settings.ANALYSIS_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            raise AnalysisTimeoutError("Analysis exceeded the time budget")
    return report


@router.get("/report/{report_id}", response_model=AnalyzeResponse)
async def get_report(report_id: str) -> dict:
    return report_generator.get_report(report_id)
