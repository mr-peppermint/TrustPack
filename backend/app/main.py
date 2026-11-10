from contextlib import asynccontextmanager, closing
from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router
from app.config import settings
from app.startup_progress import startup
from app.utils.errors import TrustPackError
from app.utils.logging import configure_logging, get_logger

configure_logging(settings.LOG_LEVEL)
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Run boot phases while the server starts, reporting progress to the frontend.

    The frontend polls /api/startup-progress while the backend appears offline or
    is still booting, and shows a determinate startup progress bar until the
    backend reports ready.
    """
    startup.advance("loading-config", 20, "Loading configuration…")
    startup.advance("connecting-database", 50, "Opening history database…")
    try:
        from app.services.report_store import _connect, check_durable_history, durable_history_enabled

        with closing(_connect()) as _conn:  # ensure the schema exists before clients connect
            pass
        if durable_history_enabled():
            if check_durable_history():
                logger.info("Durable report history is enabled through Supabase")
            else:
                logger.error("Supabase history is configured but its table is not reachable; run backend/supabase/schema.sql and verify credentials")
        else:
            logger.warning("Durable report history is disabled; SQLite history can be lost when the host filesystem resets")
    except Exception:  # pragma: no cover - warm-up must never block startup
        logger.warning("History database warm-up skipped")
    startup.advance("warming-cache", 80, "Warming analysis cache…")
    startup.mark_ready()
    yield


app = FastAPI(
    title="TrustPack API",
    description=(
        "Analyzes whether a published npm package corresponds to its claimed "
        "source repository and surfaces evidence-based, explainable risk findings."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    # Vite moves to 5174, 5175, ... when 5173 is busy, so any local dev port is accepted.
    allow_origin_regex=r"^http://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.exception_handler(TrustPackError)
async def trustpack_error_handler(request: Request, exc: TrustPackError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.http_status,
        content={"error": {"code": exc.code, "message": exc.message}},
        headers=exc.headers or None,
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    safe_errors = [{k: v for k, v in err.items() if k != "ctx"} for err in exc.errors()]
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "validation_error",
                "message": "Invalid request payload",
                "details": jsonable_encoder(safe_errors),
            }
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception")
    return JSONResponse(
        status_code=500,
        content={"error": {"code": "internal_error", "message": "An unexpected error occurred"}},
    )


app.include_router(router)
