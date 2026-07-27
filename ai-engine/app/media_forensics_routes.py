from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    Header,
    Response,
)
from starlette.concurrency import run_in_threadpool

from app.media_analysis_service import (
    get_media_analysis_service,
)
from app.media_forensics_runtime import get_media_runtime
from app.media_forensics_schemas import (
    MediaAnalysisRequest,
    MediaAnalysisResponse,
)
from app.security import (
    REQUEST_ID_HEADER,
    require_service_token,
)


logger = logging.getLogger("ddh.media_forensics")

router = APIRouter(
    prefix="/v1/media-forensics",
    tags=[
        "Multi-Modal Media Forensics",
    ],
    dependencies=[
        Depends(require_service_token),
    ],
)

media_analysis_service = get_media_analysis_service()
media_runtime = get_media_runtime()


@router.get(
    "/health",
)
async def media_forensics_health() -> dict[str, object]:
    runtime_health = media_runtime.health().to_dict()

    return {
        "status": runtime_health.get(
            "status",
            "UNKNOWN",
        ),
        "service": "DDH Multi-Modal Media Forensics",
        "supported_job_types": [
            "DEEPFAKE_IMAGE_DETECTION",
            "DEEPFAKE_VIDEO_DETECTION",
            "DEEPFAKE_AUDIO_DETECTION",
            "IMAGE_FORENSICS",
            "VIDEO_FORENSICS",
            "AUDIO_FORENSICS",
            "OCR_EXTRACTION",
        ],
        "runtime": runtime_health,
        "timestamp": datetime.now(timezone.utc),
    }


@router.post(
    "/analyze",
    response_model=MediaAnalysisResponse,
    response_model_exclude_none=True,
)
async def analyze_media(
    engine_request: MediaAnalysisRequest,
    response: Response,
    request_id_header: Annotated[
        str | None,
        Header(
            alias=REQUEST_ID_HEADER,
            convert_underscores=False,
        ),
    ] = None,
) -> MediaAnalysisResponse:
    response.headers[
        REQUEST_ID_HEADER
    ] = str(engine_request.request_id)

    validation_error = _validate_request_id_header(
        engine_request,
        request_id_header,
    )
    if validation_error is not None:
        return validation_error

    logger.info(
        "Multi-modal media analysis started",
        extra={
            "request_id": str(
                engine_request.request_id
            ),
            "organization_id": str(
                engine_request.organization_id
            ),
            "analysis_job_id": str(
                engine_request.analysis_job_id
            ),
            "job_type": engine_request.job_type,
            "media_type": engine_request.media_type,
        },
    )

    analysis_response = await run_in_threadpool(
        media_analysis_service.analyze,
        engine_request,
    )

    log_method = (
        logger.info
        if analysis_response.success
        else logger.warning
    )
    log_method(
        (
            "Multi-modal media analysis completed"
            if analysis_response.success
            else "Multi-modal media analysis failed"
        ),
        extra={
            "request_id": str(
                engine_request.request_id
            ),
            "organization_id": str(
                engine_request.organization_id
            ),
            "analysis_job_id": str(
                engine_request.analysis_job_id
            ),
            "job_type": engine_request.job_type,
            "runtime": analysis_response.runtime,
            "processing_duration_ms": (
                analysis_response.processing_duration_ms
            ),
            "error_code": analysis_response.error_code,
        },
    )

    return analysis_response


def _validate_request_id_header(
    engine_request: MediaAnalysisRequest,
    request_id_header: str | None,
) -> MediaAnalysisResponse | None:
    if not request_id_header:
        return _request_failure(
            engine_request,
            error_code="REQUEST_ID_HEADER_REQUIRED",
            error_message=(
                "X-Request-ID header is required"
            ),
        )

    try:
        header_request_id = UUID(
            request_id_header.strip()
        )
    except ValueError:
        return _request_failure(
            engine_request,
            error_code="INVALID_REQUEST_ID_HEADER",
            error_message=(
                "X-Request-ID header must contain "
                "a valid UUID"
            ),
        )

    if header_request_id != engine_request.request_id:
        return _request_failure(
            engine_request,
            error_code="REQUEST_ID_MISMATCH",
            error_message=(
                "X-Request-ID header does not match "
                "the request body"
            ),
        )

    return None


def _request_failure(
    engine_request: MediaAnalysisRequest,
    *,
    error_code: str,
    error_message: str,
) -> MediaAnalysisResponse:
    return MediaAnalysisResponse(
        request_id=engine_request.request_id,
        analysis_job_id=engine_request.analysis_job_id,
        organization_id=engine_request.organization_id,
        success=False,
        runtime=None,
        deepfake_assessment=None,
        forensics_assessment=None,
        ocr_assessment=None,
        processing_duration_ms=0,
        warnings=[],
        error_code=error_code,
        error_message=error_message,
        processed_at=datetime.now(timezone.utc),
    )