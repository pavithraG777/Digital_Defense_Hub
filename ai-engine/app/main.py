from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import (
    Depends,
    FastAPI,
    Header,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.schemas import (
    RiskEngineRequest,
    RiskEngineResponse,
)
from app.scoring import IncidentRiskScorer
from app.security import (
    REQUEST_ID_HEADER,
    require_service_token,
)


logger = logging.getLogger("ddh.ai_risk")

settings = get_settings()

risk_scorer = IncidentRiskScorer(
    model_name=settings.model_name,
    model_version=settings.model_version,
)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Offline ransomware and incident risk scoring "
        "service for Digital Defense Hub."
    ),
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.middleware("http")
async def enforce_maximum_request_size(
    request: Request,
    call_next,
) -> Response:
    content_length_value = request.headers.get(
        "content-length"
    )

    if content_length_value:
        try:
            content_length = int(
                content_length_value
            )
        except ValueError:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "detail": (
                        "Invalid Content-Length header"
                    ),
                },
            )

        if content_length < 0:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "detail": (
                        "Invalid Content-Length header"
                    ),
                },
            )

        if (
            content_length
            > settings.maximum_request_bytes
        ):
            return JSONResponse(
                status_code=(
                    status.HTTP_413_CONTENT_TOO_LARGE
                ),
                content={
                    "detail": (
                        "Request body exceeds maximum "
                        "allowed size"
                    ),
                },
            )

    response = await call_next(request)

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "Cache-Control"
    ] = "no-store"

    return response


@app.get(
    "/health",
    dependencies=[
        Depends(require_service_token),
    ],
)
async def health_check() -> dict[str, object]:
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "model_name": settings.model_name,
        "model_version": settings.model_version,
        "policy_version": settings.policy_version,
        "timestamp": datetime.now(
            timezone.utc
        ),
    }


@app.post(
    "/v1/risk/incident",
    response_model=RiskEngineResponse,
    response_model_exclude_none=True,
    dependencies=[
        Depends(require_service_token),
    ],
)
async def assess_incident_risk(
    engine_request: RiskEngineRequest,
    response: Response,
    request_id_header: Annotated[
        str | None,
        Header(
            alias=REQUEST_ID_HEADER,
            convert_underscores=False,
        ),
    ] = None,
) -> RiskEngineResponse:
    response.headers[
        REQUEST_ID_HEADER
    ] = str(engine_request.request_id)

    if not request_id_header:
        return RiskEngineResponse(
            request_id=engine_request.request_id,
            success=False,
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
        return RiskEngineResponse(
            request_id=engine_request.request_id,
            success=False,
            error_code="INVALID_REQUEST_ID_HEADER",
            error_message=(
                "X-Request-ID header must contain "
                "a valid UUID"
            ),
        )

    if (
        header_request_id
        != engine_request.request_id
    ):
        return RiskEngineResponse(
            request_id=engine_request.request_id,
            success=False,
            error_code="REQUEST_ID_MISMATCH",
            error_message=(
                "X-Request-ID header does not match "
                "the request body"
            ),
        )

    try:
        assessment = risk_scorer.assess(
            engine_request.features
        )
    except (
        ArithmeticError,
        ValueError,
    ) as error:
        logger.warning(
            "Incident risk assessment rejected",
            extra={
                "request_id": str(
                    engine_request.request_id
                ),
                "organization_id": str(
                    engine_request.organization_id
                ),
                "incident_id": str(
                    engine_request.incident_id
                ),
                "error": str(error),
            },
        )

        return RiskEngineResponse(
            request_id=engine_request.request_id,
            success=False,
            error_code="RISK_ASSESSMENT_FAILED",
            error_message=(
                "Unable to calculate incident risk"
            ),
        )

    logger.info(
        "Incident risk assessment completed",
        extra={
            "request_id": str(
                engine_request.request_id
            ),
            "organization_id": str(
                engine_request.organization_id
            ),
            "incident_id": str(
                engine_request.incident_id
            ),
            "overall_risk_score": (
                assessment.overall_risk_score
            ),
            "risk_level": assessment.risk_level,
        },
    )

    return RiskEngineResponse(
        request_id=engine_request.request_id,
        success=True,
        assessment=assessment,
    )