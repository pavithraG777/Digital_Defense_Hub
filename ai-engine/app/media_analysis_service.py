from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

from app.config import get_settings
from app.media_audio_analyzer import AudioAnalyzer
from app.media_forensics_runtime import (
    MediaRuntimeError,
    get_media_runtime,
)
from app.media_forensics_schemas import (
    MediaAnalysisRequest,
    MediaAnalysisResponse,
)
from app.media_image_analyzer import ImageAnalyzer
from app.media_ocr_analyzer import OCRAnalyzer
from app.media_video_analyzer import VideoAnalyzer


class MediaAnalysisService:
    """Orchestrates one validated offline media-analysis job."""

    _JOB_MEDIA_TYPES: dict[str, set[str]] = {
        "DEEPFAKE_IMAGE_DETECTION": {"IMAGE"},
        "DEEPFAKE_VIDEO_DETECTION": {"VIDEO"},
        "DEEPFAKE_AUDIO_DETECTION": {"AUDIO"},
        "IMAGE_FORENSICS": {"IMAGE"},
        "VIDEO_FORENSICS": {"VIDEO"},
        "AUDIO_FORENSICS": {"AUDIO"},
        "OCR_EXTRACTION": {
            "IMAGE",
            "VIDEO",
            "DOCUMENT",
        },
    }

    def __init__(
        self,
        *,
        image_analyzer: ImageAnalyzer | None = None,
        video_analyzer: VideoAnalyzer | None = None,
        audio_analyzer: AudioAnalyzer | None = None,
        ocr_analyzer: OCRAnalyzer | None = None,
    ) -> None:
        settings = get_settings()
        allow_fallback = bool(
            getattr(
                settings,
                "media_allow_heuristic_fallback",
                getattr(
                    settings,
                    "media_heuristic_fallback",
                    True,
                ),
            )
        )

        self._runtime = get_media_runtime()
        self._runtime.initialize()
        self._image_analyzer = (
            image_analyzer
            or ImageAnalyzer(
                allow_heuristic_fallback=allow_fallback,
            )
        )
        self._video_analyzer = (
            video_analyzer
            or VideoAnalyzer(
                allow_heuristic_fallback=allow_fallback,
            )
        )
        self._audio_analyzer = (
            audio_analyzer
            or AudioAnalyzer(
                allow_heuristic_fallback=allow_fallback,
            )
        )
        self._ocr_analyzer = (
            ocr_analyzer or OCRAnalyzer()
        )

    def analyze(
        self,
        request: MediaAnalysisRequest,
    ) -> MediaAnalysisResponse:
        started = perf_counter()

        try:
            self._validate_request_compatibility(request)
            source_path = self._resolve_and_verify_source(
                request
            )
            workspace_paths = (
                self._runtime.prepare_job_workspace(
                    request.organization_id,
                    request.analysis_job_id,
                )
            )
            workspace = self._resolve_workspace_root(
                workspace_paths
            )
            visualization_directory = self._workspace_path(
                workspace_paths,
                (
                    "visualizations",
                    "visualization",
                    "outputs",
                ),
                workspace / "visualizations",
            )
            output_directory = self._workspace_path(
                workspace_paths,
                (
                    "outputs",
                    "output",
                    "results",
                ),
                workspace / "outputs",
            )
            visualization_directory.mkdir(
                parents=True,
                exist_ok=True,
            )
            output_directory.mkdir(
                parents=True,
                exist_ok=True,
            )

            (
                runtime,
                warnings,
                deepfake_assessment,
                forensics_assessment,
                ocr_assessment,
            ) = self._dispatch(
                request=request,
                source_path=source_path,
                workspace=workspace,
                visualization_directory=(
                    visualization_directory
                ),
                output_directory=output_directory,
            )

            return MediaAnalysisResponse(
                request_id=request.request_id,
                analysis_job_id=request.analysis_job_id,
                organization_id=request.organization_id,
                success=True,
                runtime=self._normalize_runtime(runtime),
                deepfake_assessment=deepfake_assessment,
                forensics_assessment=(
                    forensics_assessment
                ),
                ocr_assessment=ocr_assessment,
                processing_duration_ms=self._duration_ms(
                    started
                ),
                warnings=self._unique(warnings),
                error_code=None,
                error_message=None,
                processed_at=datetime.now(timezone.utc),
            )
        except Exception as error:
            return MediaAnalysisResponse(
                request_id=request.request_id,
                analysis_job_id=request.analysis_job_id,
                organization_id=request.organization_id,
                success=False,
                runtime=None,
                deepfake_assessment=None,
                forensics_assessment=None,
                ocr_assessment=None,
                processing_duration_ms=self._duration_ms(
                    started
                ),
                warnings=[],
                error_code=self._error_code(error),
                error_message=self._safe_error_message(error),
                processed_at=datetime.now(timezone.utc),
            )

    def _dispatch(
        self,
        *,
        request: MediaAnalysisRequest,
        source_path: Path,
        workspace: Path,
        visualization_directory: Path,
        output_directory: Path,
    ) -> tuple[
        str,
        list[str],
        Any,
        Any,
        Any,
    ]:
        parameters = request.parameters or {}
        create_visualization = bool(
            parameters.get(
                "create_visualization",
                True,
            )
        )
        visualization_path = (
            visualization_directory
            / f"{request.analysis_job_id}.jpg"
            if create_visualization
            else None
        )

        if request.job_type == "DEEPFAKE_IMAGE_DETECTION":
            assessment, runtime, warnings = (
                self._image_analyzer.analyze_deepfake(
                    source_path,
                    model=request.model,
                    visualization_path=(
                        visualization_path
                    ),
                )
            )
            return (
                runtime,
                warnings,
                assessment,
                None,
                None,
            )

        if request.job_type == "IMAGE_FORENSICS":
            assessment, runtime, warnings = (
                self._image_analyzer.analyze_forensics(
                    source_path,
                    visualization_path=(
                        visualization_path
                    ),
                )
            )
            return (
                runtime,
                warnings,
                None,
                assessment,
                None,
            )

        if request.job_type == "DEEPFAKE_VIDEO_DETECTION":
            assessment, runtime, warnings = (
                self._video_analyzer.analyze_deepfake(
                    source_path,
                    workspace,
                    model=request.model,
                    visualization_path=(
                        visualization_path
                    ),
                )
            )
            return (
                runtime,
                warnings,
                assessment,
                None,
                None,
            )

        if request.job_type == "VIDEO_FORENSICS":
            assessment, runtime, warnings = (
                self._video_analyzer.analyze_forensics(
                    source_path,
                    workspace,
                    visualization_path=(
                        visualization_path
                    ),
                )
            )
            return (
                runtime,
                warnings,
                None,
                assessment,
                None,
            )

        if request.job_type == "DEEPFAKE_AUDIO_DETECTION":
            assessment, runtime, warnings = (
                self._audio_analyzer.analyze_deepfake(
                    source_path,
                    workspace,
                    model=request.model,
                    visualization_path=(
                        visualization_path
                    ),
                )
            )
            return (
                runtime,
                warnings,
                assessment,
                None,
                None,
            )

        if request.job_type == "AUDIO_FORENSICS":
            assessment, runtime, warnings = (
                self._audio_analyzer.analyze_forensics(
                    source_path,
                    workspace,
                    visualization_path=(
                        visualization_path
                    ),
                )
            )
            return (
                runtime,
                warnings,
                None,
                assessment,
                None,
            )

        if request.job_type == "OCR_EXTRACTION":
            assessment, runtime, warnings = (
                self._ocr_analyzer.analyze(
                    source_path,
                    request.media_type,
                    workspace,
                    output_file_path=(
                        output_directory
                        / "ocr-extracted-text.txt"
                    ),
                )
            )
            return (
                runtime,
                warnings,
                None,
                None,
                assessment,
            )

        raise MediaRuntimeError(
            f"unsupported analysis job type: {request.job_type}"
        )

    def _validate_request_compatibility(
        self,
        request: MediaAnalysisRequest,
    ) -> None:
        expected_types = self._JOB_MEDIA_TYPES.get(
            request.job_type
        )
        if expected_types is None:
            raise MediaRuntimeError(
                "unsupported media analysis job type"
            )
        if request.media_type not in expected_types:
            raise MediaRuntimeError(
                f"{request.job_type} does not support "
                f"{request.media_type} media"
            )
        if (
            request.execution_device == "CUDA"
            and not self._cuda_available()
        ):
            raise MediaRuntimeError(
                "CUDA execution was requested but CUDA is "
                "unavailable"
            )

    def _resolve_and_verify_source(
        self,
        request: MediaAnalysisRequest,
    ) -> Path:
        source_path = self._runtime.resolve_source_file(
            request.source_file_path
        )
        if not source_path.is_file():
            raise MediaRuntimeError(
                "analysis source file is unavailable"
            )

        actual_size = source_path.stat().st_size
        if actual_size != request.file_size_bytes:
            raise MediaRuntimeError(
                "analysis source file size does not match "
                "the request"
            )
        self._runtime.verify_file_hash(
            source_path,
            request.file_hash,
        )
        return source_path

    @staticmethod
    def _resolve_workspace_root(
        workspace_paths: dict[str, Path],
    ) -> Path:
        for key in (
            "root",
            "workspace",
            "job",
            "job_root",
        ):
            candidate = workspace_paths.get(key)
            if candidate is not None:
                candidate.mkdir(
                    parents=True,
                    exist_ok=True,
                )
                return candidate.resolve()

        if not workspace_paths:
            raise MediaRuntimeError(
                "media analysis workspace was not prepared"
            )
        candidate = next(iter(workspace_paths.values()))
        candidate.mkdir(parents=True, exist_ok=True)
        return candidate.resolve()

    @staticmethod
    def _workspace_path(
        workspace_paths: dict[str, Path],
        keys: tuple[str, ...],
        fallback: Path,
    ) -> Path:
        for key in keys:
            candidate = workspace_paths.get(key)
            if candidate is not None:
                return candidate.resolve()
        return fallback.resolve()

    def _cuda_available(self) -> bool:
        health = self._runtime.health()
        if isinstance(health, dict):
            return bool(
                health.get("cuda_available", False)
            )
        return bool(
            getattr(health, "cuda_available", False)
        )

    @staticmethod
    def _normalize_runtime(runtime: str) -> str:
        normalized = str(runtime).strip().upper()
        mapping = {
            "PYTORCH": "PYTORCH",
            "TORCH": "PYTORCH",
            "ONNX": "ONNX_RUNTIME",
            "ONNX_RUNTIME": "ONNX_RUNTIME",
            "OPENCV": "OPENCV",
            "TESSERACT": "TESSERACT",
            "HYBRID": "HYBRID",
            "HEURISTIC_FALLBACK": "HEURISTIC_FALLBACK",
            "CLASSICAL_IMAGE_FORENSICS": "OPENCV",
            "CLASSICAL_VIDEO_FORENSICS": "OPENCV",
            "CLASSICAL_AUDIO_FORENSICS": "HYBRID",
        }
        result = mapping.get(normalized)
        if result is None:
            raise MediaRuntimeError(
                f"unsupported analysis runtime: {runtime}"
            )
        return result

    @staticmethod
    def _duration_ms(started: float) -> int:
        return max(
            0,
            int(round((perf_counter() - started) * 1000)),
        )

    @staticmethod
    def _error_code(error: Exception) -> str:
        message = str(error).lower()
        if "hash" in message:
            return "SOURCE_INTEGRITY_VALIDATION_FAILED"
        if "size does not match" in message:
            return "SOURCE_SIZE_VALIDATION_FAILED"
        if "cuda" in message:
            return "EXECUTION_DEVICE_UNAVAILABLE"
        if "model" in message:
            return "MODEL_EXECUTION_FAILED"
        if (
            "unsupported" in message
            or "does not support" in message
        ):
            return "UNSUPPORTED_ANALYSIS_REQUEST"
        if isinstance(error, MediaRuntimeError):
            return "MEDIA_RUNTIME_ERROR"
        return "MEDIA_ANALYSIS_FAILED"

    @staticmethod
    def _safe_error_message(error: Exception) -> str:
        message = str(error).strip()
        if not message:
            return "Offline media analysis failed"
        return message[:1000]

    @staticmethod
    def _unique(values: list[str]) -> list[str]:
        return list(dict.fromkeys(values))


_media_analysis_service: MediaAnalysisService | None = None


def get_media_analysis_service() -> MediaAnalysisService:
    global _media_analysis_service

    if _media_analysis_service is None:
        _media_analysis_service = MediaAnalysisService()

    return _media_analysis_service