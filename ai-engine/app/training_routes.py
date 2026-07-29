from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Response
from starlette.concurrency import run_in_threadpool

from app.config import get_settings
from app.image_training_service import TrainingInputError, train_image_classifier
from app.security import REQUEST_ID_HEADER, require_service_token
from app.training_schemas import ImageTrainingRequest, ImageTrainingResponse

logger = logging.getLogger("ddh.model_training")
router = APIRouter(prefix="/v1/model-training", dependencies=[Depends(require_service_token)])

@router.post("/image-classification", response_model=ImageTrainingResponse, response_model_exclude_none=True)
async def train_image_classification(engine_request: ImageTrainingRequest, response: Response, request_id_header: Annotated[str | None, Header(alias=REQUEST_ID_HEADER, convert_underscores=False)] = None) -> ImageTrainingResponse:
    response.headers[REQUEST_ID_HEADER] = str(engine_request.request_id)
    if not request_id_header:
        return _failure(engine_request, "REQUEST_ID_HEADER_REQUIRED", "X-Request-ID header is required")
    try:
        if UUID(request_id_header.strip()) != engine_request.request_id:
            return _failure(engine_request, "REQUEST_ID_MISMATCH", "X-Request-ID header does not match request body")
    except ValueError:
        return _failure(engine_request, "INVALID_REQUEST_ID_HEADER", "X-Request-ID header must contain a valid UUID")
    try:
        result = await run_in_threadpool(train_image_classifier, engine_request, get_settings())
    except TrainingInputError as error:
        return _failure(engine_request, "INVALID_TRAINING_DATASET", str(error))
    except Exception:
        logger.exception("Image model training failed", extra={"training_job_id": str(engine_request.training_job_id)})
        return _failure(engine_request, "MODEL_TRAINING_FAILED", "Image model training failed")
    return ImageTrainingResponse(request_id=engine_request.request_id, training_job_id=engine_request.training_job_id, organization_id=engine_request.organization_id, success=True, artifact_path=result.artifact_path, artifact_sha256=result.artifact_sha256, artifact_format="PTH", training_record_count=result.training_record_count, validation_record_count=result.validation_record_count, metrics=result.metrics)

def _failure(request: ImageTrainingRequest, code: str, message: str) -> ImageTrainingResponse:
    return ImageTrainingResponse(request_id=request.request_id, training_job_id=request.training_job_id, organization_id=request.organization_id, success=False, error_code=code, error_message=message, processed_at=datetime.now(timezone.utc))
