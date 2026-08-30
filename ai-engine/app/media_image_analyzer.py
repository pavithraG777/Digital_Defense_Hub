from __future__ import annotations

from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Mapping

import cv2
import numpy as np

from app.media_forensics_runtime import MediaRuntimeError
from app.media_forensics_schemas import (
    AnalysisSignal,
    DeepfakeAssessment,
    MediaForensicsAssessment,
    ModelExecutionSpecification,
    SuspiciousRegion,
)
from app.media_image_features import (
    ImageFeatureExtractor,
    ImageFeatureSet,
)
from app.media_model_runner import MediaModelRunner


class ImageAnalyzer:
    """Runs offline image deepfake and classical forensic analysis."""

    def __init__(
        self,
        feature_extractor: ImageFeatureExtractor | None = None,
        model_runner: MediaModelRunner | None = None,
        allow_heuristic_fallback: bool = True,
    ) -> None:
        self._feature_extractor = (
            feature_extractor or ImageFeatureExtractor()
        )
        # Keep one runner for the lifetime of the analyzer. MediaModelRunner
        # owns the verified PyTorch/ONNX model caches; constructing it inside
        # analyze_deepfake() made every request reload the model from disk.
        self._model_runner = model_runner or MediaModelRunner()
        self._allow_heuristic_fallback = (
            allow_heuristic_fallback
        )

    def analyze_deepfake(
        self,
        file_path: Path,
        *,
        model: ModelExecutionSpecification | None = None,
        visualization_path: Path | None = None,
    ) -> tuple[DeepfakeAssessment, str, list[str]]:
        image, features = self._feature_extractor.extract(
            file_path,
        )

        warnings: list[str] = []
        signals = self._build_signals(features)
        heuristic_probability = self._heuristic_probability(
            signals,
        )

        model_payload: dict[str, Any] | None = None
        model_runtime = "HEURISTIC_FALLBACK"
        model_probability: float | None = None
        model_confidence: float | None = None

        if model is not None:
            try:
                inference_result = self._model_runner.run_image(
                    model,
                    image,
                )
                model_payload = self._object_to_dict(
                    inference_result,
                )
                model_probability = self._extract_percentage(
                    model_payload,
                    (
                        "deepfake_probability",
                        "fake_probability",
                        "manipulation_probability",
                    ),
                )
                model_confidence = self._extract_percentage(
                    model_payload,
                    (
                        "confidence_score",
                        "confidence",
                    ),
                )
                model_runtime = self._resolve_model_runtime(
                    model,
                    model_payload,
                )

                if model_probability is None:
                    raise MediaRuntimeError(
                        "model result did not contain a "
                        "deepfake probability"
                    )

                signals.append(
                    AnalysisSignal(
                        code="MODEL_DEEPFAKE_PROBABILITY",
                        name="Offline model assessment",
                        category="MODEL_INFERENCE",
                        description=(
                            "Verified offline model inference "
                            "indicates possible synthetic or "
                            "manipulated image content."
                        ),
                        score=model_probability,
                        confidence=(
                            model_confidence
                            if model_confidence is not None
                            else 70.0
                        ),
                        detected=model_probability >= 50.0,
                    )
                )
            except Exception as error:
                if not self._allow_heuristic_fallback:
                    raise MediaRuntimeError(
                        "offline image model inference failed"
                    ) from error

                warnings.append(
                    "Offline image model inference failed; "
                    "the result uses HEURISTIC_FALLBACK and "
                    "must not be interpreted as a trained-model "
                    "prediction."
                )
                model_payload = {
                    "error": str(error),
                }
                model_runtime = "HEURISTIC_FALLBACK"

        if model is None:
            warnings.append(
                "No verified image deepfake model was supplied; "
                "the result uses HEURISTIC_FALLBACK and is not "
                "a trained-model prediction."
            )

        if model_probability is not None:
            deepfake_probability = self._clamp(
                (model_probability * 0.75)
                + (heuristic_probability * 0.25)
            )
            confidence_score = self._clamp(
                (
                    (
                        model_confidence
                        if model_confidence is not None
                        else 70.0
                    )
                    * 0.80
                )
                + (self._evidence_confidence(signals) * 0.20)
            )
        else:
            deepfake_probability = heuristic_probability
            confidence_score = min(
                65.0,
                self._evidence_confidence(signals),
            )

        authenticity_probability = self._clamp(
            100.0 - deepfake_probability,
        )
        detection_result = self._deepfake_result(
            deepfake_probability,
        )

        suspicious_regions = self._convert_regions(
            features,
        )
        manipulated_faces = self._manipulated_face_count(
            features,
        )
        facial_artifact_detected = (
            manipulated_faces > 0
            or self._signal_detected(
                signals,
                "FACIAL_ARTIFACT",
            )
        )

        saved_visualization = self._save_visualization(
            image=image,
            features=features,
            suspicious_regions=suspicious_regions,
            destination=visualization_path,
            warnings=warnings,
        )

        feature_data = self._feature_payload(features)
        feature_data["analysis_runtime"] = model_runtime
        feature_data["heuristic_probability"] = round(
            heuristic_probability,
            4,
        )
        if model_payload is not None:
            feature_data["model_inference"] = model_payload

        assessment = DeepfakeAssessment(
            media_type="IMAGE",
            detection_result=detection_result,
            deepfake_probability=round(
                deepfake_probability,
                4,
            ),
            authenticity_probability=round(
                authenticity_probability,
                4,
            ),
            confidence_score=round(
                confidence_score,
                4,
            ),
            faces_detected=len(features.faces),
            manipulated_faces_detected=manipulated_faces,
            total_frames_analyzed=None,
            suspicious_frames=None,
            audio_duration_seconds=None,
            lip_sync_anomaly_detected=False,
            facial_artifact_detected=(
                facial_artifact_detected
            ),
            audio_manipulation_detected=False,
            metadata_inconsistency_detected=(
                bool(features.metadata_editing_trace)
            ),
            detection_summary=self._deepfake_summary(
                detection_result,
                deepfake_probability,
                model_runtime,
            ),
            signals=signals,
            feature_data=feature_data,
            suspicious_regions=suspicious_regions,
            visualization_file_path=saved_visualization,
        )

        return assessment, model_runtime, warnings

    def analyze_forensics(
        self,
        file_path: Path,
        *,
        visualization_path: Path | None = None,
    ) -> tuple[
        MediaForensicsAssessment,
        str,
        list[str],
    ]:
        image, features = self._feature_extractor.extract(
            file_path,
        )
        warnings: list[str] = []
        signals = self._build_signals(features)
        manipulation_score = self._forensic_score(signals)
        forensic_result = self._forensic_result(
            manipulation_score,
        )

        editing_trace = bool(
            features.metadata_editing_trace
        )
        compression_anomaly = self._signal_detected(
            signals,
            "COMPRESSION_ANOMALY",
        )
        copy_move = self._signal_detected(
            signals,
            "COPY_MOVE_PATTERN",
        )
        noise_inconsistency = self._signal_detected(
            signals,
            "NOISE_INCONSISTENCY",
        )
        ela_inconsistency = self._signal_detected(
            signals,
            "ELA_INCONSISTENCY",
        )
        splicing_detected = (
            ela_inconsistency and noise_inconsistency
        )

        suspicious_locations = self._convert_regions(
            features,
        )
        saved_visualization = self._save_visualization(
            image=image,
            features=features,
            suspicious_regions=suspicious_locations,
            destination=visualization_path,
            warnings=warnings,
        )

        findings = self._forensic_findings(
            signals,
            features,
        )
        confidence_score = self._forensic_confidence(
            signals,
            manipulation_score,
        )

        feature_data = self._feature_payload(features)
        feature_data["analysis_runtime"] = (
            "CLASSICAL_IMAGE_FORENSICS"
        )
        feature_data["manipulation_score"] = round(
            manipulation_score,
            4,
        )

        assessment = MediaForensicsAssessment(
            media_type="IMAGE",
            forensic_result=forensic_result,
            confidence_score=round(
                confidence_score,
                4,
            ),
            editing_trace_detected=editing_trace,
            compression_anomaly_detected=(
                compression_anomaly
            ),
            copy_move_detected=copy_move,
            splicing_detected=splicing_detected,
            frame_duplication_detected=False,
            frame_deletion_detected=False,
            audio_discontinuity_detected=False,
            noise_inconsistency_detected=(
                noise_inconsistency
            ),
            timestamp_anomaly_detected=False,
            analysis_summary=self._forensic_summary(
                forensic_result,
                manipulation_score,
            ),
            findings=findings,
            signals=signals,
            suspicious_locations=suspicious_locations,
            forensic_feature_data=feature_data,
            visualization_file_path=saved_visualization,
        )

        return (
            assessment,
            "CLASSICAL_IMAGE_FORENSICS",
            warnings,
        )

    def _build_signals(
        self,
        features: ImageFeatureSet,
    ) -> list[AnalysisSignal]:
        face_score = self._face_artifact_score(features)
        ela_score = self._clamp(
            (features.ela_mean_difference * 4.0)
            + (features.ela_percentile_99 * 1.2)
        )
        noise_score = self._clamp(
            (features.noise_patch_variation * 4.0)
            + (features.noise_standard_deviation * 1.5)
        )
        copy_move_score = self._clamp(
            features.copy_move_match_count * 5.0,
        )
        blockiness_score = self._ratio_score(
            features.jpeg_blockiness_ratio,
            multiplier=160.0,
        )
        frequency_score = self._ratio_score(
            features.high_frequency_ratio,
            multiplier=130.0,
        )
        channel_score = self._clamp(
            (
                max(
                    0.0,
                    0.92
                    - features.minimum_channel_correlation,
                )
                * 120.0
            )
            + min(
                35.0,
                features.color_channel_difference * 0.35,
            )
        )
        metadata_score = (
            90.0
            if features.metadata_editing_trace
            else 0.0
        )

        return [
            self._signal(
                code="FACIAL_ARTIFACT",
                name="Facial artifact pattern",
                category="FACIAL_FORENSICS",
                description=(
                    "Face regions show asymmetry, noise, or "
                    "frequency characteristics associated with "
                    "possible manipulation."
                ),
                score=face_score,
                threshold=55.0,
                confidence=(
                    78.0 if features.faces else 25.0
                ),
            ),
            self._signal(
                code="ELA_INCONSISTENCY",
                name="Error-level inconsistency",
                category="COMPRESSION_FORENSICS",
                description=(
                    "JPEG recompression differences are uneven "
                    "across image regions."
                ),
                score=ela_score,
                threshold=55.0,
                confidence=70.0,
            ),
            self._signal(
                code="NOISE_INCONSISTENCY",
                name="Noise inconsistency",
                category="PIXEL_FORENSICS",
                description=(
                    "Local noise residuals vary unusually between "
                    "image regions."
                ),
                score=noise_score,
                threshold=55.0,
                confidence=72.0,
            ),
            self._signal(
                code="COPY_MOVE_PATTERN",
                name="Copy-move feature matches",
                category="STRUCTURAL_FORENSICS",
                description=(
                    "Repeated local feature patterns may indicate "
                    "copied or cloned image content."
                ),
                score=copy_move_score,
                threshold=50.0,
                confidence=75.0,
            ),
            self._signal(
                code="COMPRESSION_ANOMALY",
                name="JPEG block anomaly",
                category="COMPRESSION_FORENSICS",
                description=(
                    "Block-boundary characteristics are inconsistent "
                    "with uniform image compression."
                ),
                score=blockiness_score,
                threshold=55.0,
                confidence=65.0,
            ),
            self._signal(
                code="FREQUENCY_ANOMALY",
                name="High-frequency anomaly",
                category="FREQUENCY_FORENSICS",
                description=(
                    "Frequency-domain energy distribution contains "
                    "possible synthetic or editing artifacts."
                ),
                score=frequency_score,
                threshold=60.0,
                confidence=62.0,
            ),
            self._signal(
                code="COLOR_CHANNEL_INCONSISTENCY",
                name="Color-channel inconsistency",
                category="COLOR_FORENSICS",
                description=(
                    "Color-channel relationships differ from normal "
                    "photographic correlation patterns."
                ),
                score=channel_score,
                threshold=60.0,
                confidence=60.0,
            ),
            self._signal(
                code="METADATA_EDITING_TRACE",
                name="Metadata editing trace",
                category="METADATA_FORENSICS",
                description=(
                    "Image metadata identifies editing or processing "
                    "software."
                ),
                score=metadata_score,
                threshold=50.0,
                confidence=85.0,
            ),
        ]

    @staticmethod
    def _signal(
        *,
        code: str,
        name: str,
        category: str,
        description: str,
        score: float,
        threshold: float,
        confidence: float,
    ) -> AnalysisSignal:
        normalized_score = ImageAnalyzer._clamp(score)
        return AnalysisSignal(
            code=code,
            name=name,
            category=category,
            description=description,
            score=round(normalized_score, 4),
            confidence=round(
                ImageAnalyzer._clamp(confidence),
                4,
            ),
            detected=normalized_score >= threshold,
        )

    def _heuristic_probability(
        self,
        signals: list[AnalysisSignal],
    ) -> float:
        weights = {
            "FACIAL_ARTIFACT": 0.25,
            "ELA_INCONSISTENCY": 0.18,
            "NOISE_INCONSISTENCY": 0.16,
            "COPY_MOVE_PATTERN": 0.13,
            "COMPRESSION_ANOMALY": 0.08,
            "FREQUENCY_ANOMALY": 0.08,
            "COLOR_CHANNEL_INCONSISTENCY": 0.05,
            "METADATA_EDITING_TRACE": 0.07,
        }
        score = sum(
            signal.score * weights.get(signal.code, 0.0)
            for signal in signals
        )
        detected_count = sum(
            1 for signal in signals if signal.detected
        )
        if detected_count >= 4:
            score += 8.0
        elif detected_count >= 2:
            score += 4.0
        return self._clamp(score)

    def _forensic_score(
        self,
        signals: list[AnalysisSignal],
    ) -> float:
        weights = {
            "ELA_INCONSISTENCY": 0.22,
            "NOISE_INCONSISTENCY": 0.18,
            "COPY_MOVE_PATTERN": 0.20,
            "METADATA_EDITING_TRACE": 0.15,
            "COMPRESSION_ANOMALY": 0.10,
            "FREQUENCY_ANOMALY": 0.08,
            "COLOR_CHANNEL_INCONSISTENCY": 0.07,
        }
        score = sum(
            signal.score * weights.get(signal.code, 0.0)
            for signal in signals
        )
        detected_count = sum(
            1
            for signal in signals
            if signal.detected
            and signal.code in weights
        )
        if detected_count >= 4:
            score += 10.0
        elif detected_count >= 2:
            score += 5.0
        return self._clamp(score)

    def _face_artifact_score(
        self,
        features: ImageFeatureSet,
    ) -> float:
        if not features.faces:
            return 0.0
        return max(
            self._face_score(face)
            for face in features.faces
        )

    def _manipulated_face_count(
        self,
        features: ImageFeatureSet,
    ) -> int:
        return sum(
            1
            for face in features.faces
            if self._face_score(face) >= 55.0
        )

    def _face_score(self, face: Any) -> float:
        payload = self._object_to_dict(face)
        direct_score = self._first_number(
            payload,
            (
                "artifact_score",
                "suspicion_score",
                "manipulation_score",
            ),
        )
        if direct_score is not None:
            return self._normalize_percentage(direct_score)

        component_values = [
            self._normalize_percentage(value)
            for key, value in payload.items()
            if isinstance(value, (int, float))
            and any(
                token in key.lower()
                for token in (
                    "asymmetry",
                    "noise",
                    "frequency",
                    "artifact",
                )
            )
        ]
        if not component_values:
            return 0.0
        return self._clamp(
            sum(component_values) / len(component_values)
        )

    def _convert_regions(
        self,
        features: ImageFeatureSet,
    ) -> list[SuspiciousRegion]:
        converted: list[SuspiciousRegion] = []
        for region in features.suspicious_regions:
            payload = self._object_to_dict(region)
            score = self._normalize_percentage(
                self._first_number(
                    payload,
                    (
                        "score",
                        "suspicion_score",
                        "anomaly_score",
                    ),
                )
                or 0.0
            )
            bounding_box = self._bounding_box(payload)
            converted.append(
                SuspiciousRegion(
                    region_type=str(
                        payload.get(
                            "region_type",
                            payload.get(
                                "type",
                                "IMAGE_ANOMALY",
                            ),
                        )
                    ),
                    frame_number=None,
                    page_number=None,
                    timestamp_seconds=None,
                    bounding_box=bounding_box,
                    score=round(score, 4),
                    description=str(
                        payload.get(
                            "description",
                            "Suspicious image region detected.",
                        )
                    ),
                )
            )

        return converted

    def _save_visualization(
        self,
        *,
        image: np.ndarray,
        features: ImageFeatureSet,
        suspicious_regions: list[SuspiciousRegion],
        destination: Path | None,
        warnings: list[str],
    ) -> str | None:
        if destination is None:
            return None

        try:
            destination = destination.resolve()
            destination.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            visualization = image.copy()

            for region in suspicious_regions:
                if region.bounding_box is None:
                    continue
                x, y, width, height = region.bounding_box
                start = (max(0, int(x)), max(0, int(y)))
                end = (
                    max(0, int(x + width)),
                    max(0, int(y + height)),
                )
                cv2.rectangle(
                    visualization,
                    start,
                    end,
                    (0, 0, 255),
                    2,
                )

            for face in features.faces:
                payload = self._object_to_dict(face)
                bounding_box = self._bounding_box(payload)
                if bounding_box is None:
                    continue
                x, y, width, height = bounding_box
                cv2.rectangle(
                    visualization,
                    (int(x), int(y)),
                    (int(x + width), int(y + height)),
                    (0, 165, 255),
                    2,
                )

            extension = destination.suffix.lower()
            if extension not in {".jpg", ".jpeg", ".png"}:
                destination = destination.with_suffix(".jpg")
                extension = ".jpg"

            encoded, buffer = cv2.imencode(
                extension,
                visualization,
            )
            if not encoded:
                raise MediaRuntimeError(
                    "unable to encode image visualization"
                )
            buffer.tofile(str(destination))
            return str(destination)
        except Exception as error:
            warnings.append(
                "Unable to create image forensic "
                f"visualization: {error}"
            )
            return None

    def _forensic_findings(
        self,
        signals: list[AnalysisSignal],
        features: ImageFeatureSet,
    ) -> list[str]:
        findings = [
            signal.description
            for signal in signals
            if signal.detected
        ]
        if features.metadata_software:
            findings.append(
                "Metadata software value: "
                f"{features.metadata_software}"
            )
        if not findings:
            findings.append(
                "No strong classical image manipulation "
                "indicator was detected."
            )
        return findings

    def _forensic_confidence(
        self,
        signals: list[AnalysisSignal],
        score: float,
    ) -> float:
        detected = [
            signal
            for signal in signals
            if signal.detected
        ]
        if not detected:
            return self._clamp(
                55.0 + ((50.0 - min(score, 50.0)) * 0.4)
            )
        average_confidence = sum(
            signal.confidence for signal in detected
        ) / len(detected)
        return self._clamp(
            average_confidence
            + min(15.0, len(detected) * 2.5)
        )

    def _evidence_confidence(
        self,
        signals: list[AnalysisSignal],
    ) -> float:
        detected = [
            signal
            for signal in signals
            if signal.detected
        ]
        if not detected:
            return 45.0
        return self._clamp(
            (
                sum(signal.confidence for signal in detected)
                / len(detected)
            )
            + min(12.0, len(detected) * 2.0)
        )

    @staticmethod
    def _deepfake_result(
        probability: float,
    ) -> str:
        if probability >= 85.0:
            return "DEEPFAKE"
        if probability >= 70.0:
            return "LIKELY_DEEPFAKE"
        if probability >= 50.0:
            return "SUSPICIOUS"
        if probability >= 30.0:
            return "LIKELY_AUTHENTIC"
        return "AUTHENTIC"

    @staticmethod
    def _forensic_result(score: float) -> str:
        if score >= 75.0:
            return "MANIPULATED"
        if score >= 45.0:
            return "SUSPICIOUS"
        return "AUTHENTIC"

    @staticmethod
    def _deepfake_summary(
        result: str,
        probability: float,
        runtime: str,
    ) -> str:
        if runtime == "HEURISTIC_FALLBACK":
            return (
                f"Image classified as {result} with a "
                f"{probability:.2f}% heuristic indicator score. "
                "No trained-model conclusion is claimed."
            )
        return (
            f"Image classified as {result} with a "
            f"{probability:.2f}% combined offline model and "
            "forensic indicator score."
        )

    @staticmethod
    def _forensic_summary(
        result: str,
        score: float,
    ) -> str:
        return (
            f"Classical image forensic result is {result} "
            f"with a {score:.2f}% manipulation indicator score."
        )

    @staticmethod
    def _signal_detected(
        signals: list[AnalysisSignal],
        code: str,
    ) -> bool:
        return any(
            signal.code == code and signal.detected
            for signal in signals
        )

    @staticmethod
    def _feature_payload(
        features: ImageFeatureSet,
    ) -> dict[str, Any]:
        return ImageAnalyzer._object_to_dict(features)

    @staticmethod
    def _object_to_dict(value: Any) -> dict[str, Any]:
        if value is None:
            return {}
        to_dict = getattr(value, "to_dict", None)
        if callable(to_dict):
            result = to_dict()
            if isinstance(result, Mapping):
                return dict(result)
        model_dump = getattr(value, "model_dump", None)
        if callable(model_dump):
            result = model_dump(mode="json")
            if isinstance(result, Mapping):
                return dict(result)
        if is_dataclass(value):
            result = asdict(value)
            if isinstance(result, Mapping):
                return dict(result)
        if hasattr(value, "__dict__"):
            return dict(vars(value))
        return {}

    @staticmethod
    def _extract_percentage(
        payload: Mapping[str, Any],
        names: tuple[str, ...],
    ) -> float | None:
        value = ImageAnalyzer._first_number(
            payload,
            names,
        )
        if value is not None:
            return ImageAnalyzer._normalize_percentage(value)

        probabilities = payload.get("probabilities")
        if isinstance(probabilities, (list, tuple)):
            numeric = [
                float(item)
                for item in probabilities
                if isinstance(item, (int, float))
            ]
            if numeric:
                return ImageAnalyzer._normalize_percentage(
                    numeric[-1]
                )
        return None

    @staticmethod
    def _first_number(
        payload: Mapping[str, Any],
        names: tuple[str, ...],
    ) -> float | None:
        for name in names:
            value = payload.get(name)
            if isinstance(value, (int, float)):
                return float(value)
        return None

    @staticmethod
    def _resolve_model_runtime(
        model: ModelExecutionSpecification,
        payload: Mapping[str, Any],
    ) -> str:
        candidates = [
            payload.get("runtime"),
            payload.get("execution_runtime"),
            getattr(model, "runtime", None),
            getattr(model, "model_format", None),
            getattr(model, "framework", None),
        ]
        for candidate in candidates:
            normalized = str(candidate or "").upper()
            if "ONNX" in normalized:
                return "ONNX"
            if (
                "PYTORCH" in normalized
                or "TORCH" in normalized
                or "PTH" in normalized
            ):
                return "PYTORCH"
        return "PYTORCH"

    @staticmethod
    def _bounding_box(
        payload: Mapping[str, Any],
    ) -> tuple[float, float, float, float] | None:
        existing = payload.get("bounding_box")
        if (
            isinstance(existing, (list, tuple))
            and len(existing) == 4
            and all(
                isinstance(value, (int, float))
                for value in existing
            )
        ):
            return tuple(float(value) for value in existing)

        coordinate_sets = (
            ("x", "y", "width", "height"),
            ("left", "top", "width", "height"),
        )
        for names in coordinate_sets:
            values = [payload.get(name) for name in names]
            if all(
                isinstance(value, (int, float))
                for value in values
            ):
                return tuple(float(value) for value in values)
        return None

    @staticmethod
    def _ratio_score(
        value: float,
        *,
        multiplier: float,
    ) -> float:
        numeric = max(0.0, float(value))
        if numeric <= 1.0:
            return ImageAnalyzer._clamp(
                numeric * multiplier
            )
        return ImageAnalyzer._clamp(numeric)

    @staticmethod
    def _normalize_percentage(value: float) -> float:
        numeric = float(value)
        if 0.0 <= numeric <= 1.0:
            numeric *= 100.0
        return ImageAnalyzer._clamp(numeric)

    @staticmethod
    def _clamp(value: float) -> float:
        return max(0.0, min(100.0, float(value)))
