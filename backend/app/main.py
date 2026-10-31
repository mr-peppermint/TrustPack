from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router
from app.config import settings
from app.utils.errors import TrustPackError
from app.utils.logging import configure_logging, get_logger

configure_logging(settings.LOG_LEVEL)
logger = get_logger(__name__)

app = FastAPI(
    title="TrustPack API",
    description=(
        "Analyzes whether a published npm package corresponds to its claimed "
        "source repository and surfaces evidence-based, explainable risk findings."
    ),
    version="1.0.0",
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
