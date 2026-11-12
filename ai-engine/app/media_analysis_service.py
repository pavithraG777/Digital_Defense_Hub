from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

from app.config import get_settings
from app.advanced_forensics import enrich_advanced_forensics
from app.media_audio_analyzer import AudioAnalyzer
from app.media_forensics_runtime import (
    MediaRuntimeError,
    get_media_runtime,
)
from app.media_forensics_schemas import (
    DeepfakeAssessment,
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
        "AI_GENERATED_IMAGE_DETECTION": {"IMAGE"},
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

            warnings.extend(
                enrich_advanced_forensics(
                    file_hash=request.file_hash,
                    media_type=request.media_type,
                    deepfake=deepfake_assessment,
                    forensics=forensics_assessment,
                    ocr=ocr_assessment,
                )
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

        if request.job_type in {
            "DEEPFAKE_IMAGE_DETECTION",
            "AI_GENERATED_IMAGE_DETECTION",
        }:
            ensemble_models = request.models or ([request.model] if request.model else [])
            if len(ensemble_models) <= 1:
                assessment, runtime, warnings = self._image_analyzer.analyze_deepfake(
                    source_path,
                    model=ensemble_models[0] if ensemble_models else None,
                    visualization_path=visualization_path,
                )
            else:
                results = [
                    self._image_analyzer.analyze_deepfake(
                        source_path,
                        model=model,
                        visualization_path=visualization_path if index == 0 else None,
                    )
                    for index, model in enumerate(ensemble_models)
                ]
                assessment = self._combine_image_ensemble(
                    [value[0] for value in results], ensemble_models
                )
                runtime = "ENSEMBLE[" + ",".join(value[1] for value in results) + "]"
                warnings = [warning for value in results for warning in value[2]]
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

    @staticmethod
    def _combine_image_ensemble(assessments, models) -> DeepfakeAssessment:
        severity = {
            "AUTHENTIC": 0,
            "LIKELY_AUTHENTIC": 1,
            "SUSPICIOUS": 2,
            "LIKELY_DEEPFAKE": 3,
            "DEEPFAKE": 4,
        }
        def face_applicable(assessment) -> bool:
            features = assessment.feature_data or {}
            width, height = features.get("width"), features.get("height")
            faces = features.get("faces")
            if not (assessment.faces_detected or 0):
                return False
            if not isinstance(width, (int, float)) or not isinstance(height, (int, float)) or not isinstance(faces, list):
                return True  # Legacy results have no bounding boxes.
            image_area = width * height
            if image_area <= 0:
                return False
            return any(
                isinstance(face, dict)
                and isinstance(face.get("width"), (int, float))
                and isinstance(face.get("height"), (int, float))
                and face["width"] * face["height"] / image_area >= 0.02
                for face in faces
            )

        applied = [
            str(model.configuration.get("ensemble_role", "")).upper() != "FACE_SWAP"
            or face_applicable(assessment)
            for assessment, model in zip(assessments, models)
        ]
        applicable_indices = [
            index
            for index, is_applied in enumerate(applied)
            if is_applied
        ] or list(range(len(assessments)))
        selected_index = max(
            applicable_indices,
            key=lambda index: (
                severity[assessments[index].detection_result],
                assessments[index].deepfake_probability,
            ),
        )
        selected = assessments[selected_index]
        components = []
        signals = []
        for index, (assessment, model) in enumerate(zip(assessments, models)):
            role = str(
                model.configuration.get(
                    "ensemble_role", model.model_name
                )
            )
            components.append(
                {
                    "role": role,
                    "applied": applied[index],
                    "verdict": assessment.detection_result,
                    "deepfake_probability": assessment.deepfake_probability,
                    "confidence_score": assessment.confidence_score,
                    "threshold": model.confidence_threshold,
                }
            )
            if applied[index]:
                signals.extend(assessment.signals)
        feature_data = dict(selected.feature_data)
        feature_data["ensemble_components"] = components
        positive = {"LIKELY_DEEPFAKE", "DEEPFAKE"}
        negative = {"AUTHENTIC", "LIKELY_AUTHENTIC"}
        verdicts = {assessments[index].detection_result for index in applicable_indices}
        disagreement = bool(verdicts & positive and verdicts & negative)
        feature_data["ensemble_disagreement"] = disagreement
        if disagreement:
            return selected.model_copy(
                update={
                    "detection_result": "SUSPICIOUS",
                    "confidence_score": min(selected.confidence_score, 60.0),
                    "signals": signals,
                    "feature_data": feature_data,
                    "detection_summary": (
                        "Specialized image detectors disagree; human review is required. "
                        "The displayed probability is the highest-risk component, "
                        "not an ensemble consensus."
                    ),
                }
            )
        return selected.model_copy(
            update={
                "signals": signals,
                "feature_data": feature_data,
                "detection_summary": (
                    f"Ensemble verdict {selected.detection_result} was selected "
                    f"from {len(applicable_indices)} applicable specialized image detectors."
                ),
            }
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
        if normalized.startswith("ENSEMBLE[") and normalized.endswith("]"):
            components = {
                value.strip()
                for value in normalized[9:-1].split(",")
                if value.strip()
            }
            if components == {"PYTORCH"}:
                return "PYTORCH"
            if components == {"ONNX_RUNTIME"}:
                return "ONNX_RUNTIME"
            if "HEURISTIC_FALLBACK" in components:
                return "HEURISTIC_FALLBACK"
            return "HYBRID"
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
