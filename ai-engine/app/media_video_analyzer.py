from __future__ import annotations

from dataclasses import asdict, is_dataclass
from pathlib import Path
from statistics import fmean
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
from app.media_model_runner import MediaModelRunner
from app.media_video_features import (
    VideoFeatureExtractor,
    VideoFeatureSet,
    VideoFrameFeature,
)


class VideoAnalyzer:
    """Runs bounded offline video deepfake and forensic analysis."""

    def __init__(
        self,
        feature_extractor: VideoFeatureExtractor | None = None,
        model_runner: MediaModelRunner | None = None,
        *,
        maximum_model_frames: int = 16,
        allow_heuristic_fallback: bool = True,
    ) -> None:
        if (
            maximum_model_frames < 2
            or maximum_model_frames > 128
        ):
            raise ValueError(
                "maximum_model_frames must be between 2 and 128"
            )

        self._feature_extractor = (
            feature_extractor or VideoFeatureExtractor()
        )
        self._model_runner = model_runner
        self._maximum_model_frames = maximum_model_frames
        self._allow_heuristic_fallback = (
            allow_heuristic_fallback
        )

    def analyze_deepfake(
        self,
        file_path: Path,
        workspace_path: Path,
        *,
        model: ModelExecutionSpecification | None = None,
        visualization_path: Path | None = None,
    ) -> tuple[DeepfakeAssessment, str, list[str]]:
        features = self._feature_extractor.extract(
            file_path,
            workspace_path,
        )
        warnings: list[str] = []
        signals = self._deepfake_signals(features)
        heuristic_probability = (
            self._video_heuristic_probability(
                features,
                signals,
            )
        )

        model_payload: dict[str, Any] | None = None
        model_probability: float | None = None
        model_confidence: float | None = None
        runtime = "HEURISTIC_FALLBACK"

        if model is not None:
            try:
                tensor = self._build_model_tensor(
                    features,
                    model,
                )
                runner = (
                    self._model_runner
                    or MediaModelRunner()
                )
                inference_result = runner.run_tensor(
                    model,
                    tensor,
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
                if model_probability is None:
                    raise MediaRuntimeError(
                        "video model result did not contain a "
                        "deepfake probability"
                    )
                runtime = self._resolve_model_runtime(
                    model,
                    model_payload,
                )
                signals.append(
                    self._signal(
                        code="VIDEO_MODEL_DEEPFAKE_PROBABILITY",
                        name="Offline video model assessment",
                        category="MODEL_INFERENCE",
                        description=(
                            "The verified offline video model found "
                            "possible synthetic or manipulated "
                            "temporal content."
                        ),
                        score=model_probability,
                        confidence=(
                            model_confidence
                            if model_confidence is not None
                            else 70.0
                        ),
                        threshold=50.0,
                    )
                )
            except Exception as error:
                if not self._allow_heuristic_fallback:
                    raise MediaRuntimeError(
                        "offline video model inference failed"
                    ) from error

                model_payload = {"error": str(error)}
                warnings.append(
                    "Offline video model inference failed; "
                    "HEURISTIC_FALLBACK was used and the result "
                    "must not be treated as a trained-model "
                    "prediction."
                )
                runtime = "HEURISTIC_FALLBACK"
        else:
            warnings.append(
                "No verified video deepfake model was supplied; "
                "HEURISTIC_FALLBACK was used and the result is "
                "not a trained-model prediction."
            )

        if model_probability is not None:
            probability = self._clamp(
                (model_probability * 0.80)
                + (heuristic_probability * 0.20)
            )
            confidence = self._clamp(
                (
                    (
                        model_confidence
                        if model_confidence is not None
                        else 70.0
                    )
                    * 0.80
                )
                + (
                    self._signal_confidence(signals)
                    * 0.20
                )
            )
        else:
            probability = heuristic_probability
            confidence = min(
                62.0,
                self._signal_confidence(signals),
            )

        result = self._deepfake_result(probability)
        suspicious_regions = self._video_regions(features)
        visualization = self._save_contact_sheet(
            features=features,
            destination=visualization_path,
            warnings=warnings,
        )

        frame_scores = [
            {
                "frame_number": frame.frame_number,
                "timestamp_seconds": frame.timestamp_seconds,
                "score": round(
                    self._frame_suspicion_score(frame),
                    4,
                ),
                "is_suspicious": frame.is_suspicious,
            }
            for frame in features.frames
        ]
        feature_data = features.to_dict()
        feature_data["analysis_runtime"] = runtime
        feature_data["heuristic_probability"] = round(
            heuristic_probability,
            4,
        )
        feature_data["frame_scores"] = frame_scores
        if model_payload is not None:
            feature_data["model_inference"] = model_payload

        manipulated_faces = sum(
            self._manipulated_faces(frame)
            for frame in features.frames
        )
        faces_detected = sum(
            len(frame.image_features.faces)
            for frame in features.frames
        )

        assessment = DeepfakeAssessment(
            media_type="VIDEO",
            detection_result=result,
            deepfake_probability=round(probability, 4),
            authenticity_probability=round(
                self._clamp(100.0 - probability),
                4,
            ),
            confidence_score=round(confidence, 4),
            faces_detected=faces_detected,
            manipulated_faces_detected=manipulated_faces,
            total_frames_analyzed=(
                features.sampled_frame_count
            ),
            suspicious_frames=(
                features.suspicious_frame_count
            ),
            audio_duration_seconds=None,
            lip_sync_anomaly_detected=False,
            facial_artifact_detected=(
                manipulated_faces > 0
            ),
            audio_manipulation_detected=False,
            metadata_inconsistency_detected=False,
            detection_summary=self._deepfake_summary(
                result,
                probability,
                runtime,
                features.sampled_frame_count,
            ),
            signals=signals,
            feature_data=feature_data,
            suspicious_regions=suspicious_regions,
            visualization_file_path=visualization,
        )

        return assessment, runtime, self._unique(warnings)

    def analyze_forensics(
        self,
        file_path: Path,
        workspace_path: Path,
        *,
        visualization_path: Path | None = None,
    ) -> tuple[
        MediaForensicsAssessment,
        str,
        list[str],
    ]:
        features = self._feature_extractor.extract(
            file_path,
            workspace_path,
        )
        warnings: list[str] = []
        signals = self._forensic_signals(features)
        score = self._forensic_score(features, signals)
        result = self._forensic_result(score)

        frame_duplication = self._significant_count(
            features.duplicate_transition_count,
            features.sampled_frame_count,
            ratio=0.05,
            minimum=2,
        )
        frame_deletion = self._significant_count(
            features.timestamp_anomaly_count,
            features.sampled_frame_count,
            ratio=0.03,
            minimum=1,
        )
        compression_anomaly = self._signal_detected(
            signals,
            "VIDEO_COMPRESSION_ANOMALY",
        )
        noise_inconsistency = self._signal_detected(
            signals,
            "VIDEO_NOISE_INCONSISTENCY",
        )
        splicing = (
            self._signal_detected(
                signals,
                "ABRUPT_SUSPICIOUS_TRANSITION",
            )
            and features.suspicious_frame_count > 0
        )

        suspicious_locations = self._video_regions(features)
        visualization = self._save_contact_sheet(
            features=features,
            destination=visualization_path,
            warnings=warnings,
        )
        findings = [
            signal.description
            for signal in signals
            if signal.detected
        ]
        if not findings:
            findings.append(
                "No strong sampled-frame or temporal manipulation "
                "indicator was detected."
            )

        feature_data = features.to_dict()
        feature_data["analysis_runtime"] = (
            "CLASSICAL_VIDEO_FORENSICS"
        )
        feature_data["manipulation_score"] = round(
            score,
            4,
        )

        assessment = MediaForensicsAssessment(
            media_type="VIDEO",
            forensic_result=result,
            confidence_score=round(
                self._signal_confidence(signals),
                4,
            ),
            editing_trace_detected=False,
            compression_anomaly_detected=(
                compression_anomaly
            ),
            copy_move_detected=self._any_frame_copy_move(
                features
            ),
            splicing_detected=splicing,
            frame_duplication_detected=frame_duplication,
            frame_deletion_detected=frame_deletion,
            audio_discontinuity_detected=False,
            noise_inconsistency_detected=(
                noise_inconsistency
            ),
            timestamp_anomaly_detected=frame_deletion,
            analysis_summary=(
                f"Video forensic result is {result} with a "
                f"{score:.2f}% manipulation indicator score "
                f"across {features.sampled_frame_count} sampled "
                "frames."
            ),
            findings=findings,
            signals=signals,
            suspicious_locations=suspicious_locations,
            forensic_feature_data=feature_data,
            visualization_file_path=visualization,
        )

        return (
            assessment,
            "CLASSICAL_VIDEO_FORENSICS",
            self._unique(warnings),
        )

    def _deepfake_signals(
        self,
        features: VideoFeatureSet,
    ) -> list[AnalysisSignal]:
        sampled = max(1, features.sampled_frame_count)
        suspicious_ratio = (
            features.suspicious_frame_count / sampled
        )
        facial_ratio = self._facial_artifact_ratio(features)
        temporal_score = self._clamp(
            (
                features.abrupt_transition_count
                / max(1, sampled - 1)
            )
            * 180.0
        )

        return [
            self._signal(
                code="SUSPICIOUS_FRAME_RATIO",
                name="Suspicious sampled frames",
                category="FRAME_FORENSICS",
                description=(
                    "Multiple sampled frames contain pixel, noise, "
                    "compression, or copy-move anomalies."
                ),
                score=suspicious_ratio * 100.0,
                confidence=72.0,
                threshold=25.0,
            ),
            self._signal(
                code="PERSISTENT_FACIAL_ARTIFACT",
                name="Persistent facial artifacts",
                category="FACIAL_FORENSICS",
                description=(
                    "Facial artifact indicators persist across "
                    "multiple sampled video frames."
                ),
                score=facial_ratio * 100.0,
                confidence=75.0,
                threshold=20.0,
            ),
            self._signal(
                code="TEMPORAL_VISUAL_ANOMALY",
                name="Temporal visual anomaly",
                category="TEMPORAL_FORENSICS",
                description=(
                    "Abrupt visual changes overlap with suspicious "
                    "sampled-frame evidence."
                ),
                score=temporal_score,
                confidence=64.0,
                threshold=45.0,
            ),
        ]

    def _forensic_signals(
        self,
        features: VideoFeatureSet,
    ) -> list[AnalysisSignal]:
        sampled = max(1, features.sampled_frame_count)
        transitions = max(1, sampled - 1)
        average_ela = fmean(
            frame.image_features.ela_percentile_99
            for frame in features.frames
        )
        average_noise = fmean(
            frame.image_features.noise_patch_variation
            for frame in features.frames
        )
        suspicious_abrupt = sum(
            1
            for frame in features.frames
            if frame.abrupt_transition and frame.is_suspicious
        )

        return [
            self._signal(
                code="FRAME_DUPLICATION_PATTERN",
                name="Repeated frame pattern",
                category="TEMPORAL_FORENSICS",
                description=(
                    "Repeated perceptual frame hashes may indicate "
                    "frame duplication or frozen content."
                ),
                score=(
                    features.duplicate_transition_count
                    / transitions
                    * 150.0
                ),
                confidence=72.0,
                threshold=35.0,
            ),
            self._signal(
                code="ABRUPT_SUSPICIOUS_TRANSITION",
                name="Abrupt suspicious transitions",
                category="TEMPORAL_FORENSICS",
                description=(
                    "Abrupt scene transitions coincide with sampled "
                    "frames containing forensic anomalies."
                ),
                score=(
                    suspicious_abrupt
                    / transitions
                    * 220.0
                ),
                confidence=68.0,
                threshold=35.0,
            ),
            self._signal(
                code="VIDEO_TIMESTAMP_ANOMALY",
                name="Frame timestamp anomaly",
                category="TIMELINE_FORENSICS",
                description=(
                    "Observed frame timestamps differ from the "
                    "declared frame-rate timeline."
                ),
                score=(
                    features.timestamp_anomaly_count
                    / sampled
                    * 180.0
                ),
                confidence=70.0,
                threshold=30.0,
            ),
            self._signal(
                code="VIDEO_COMPRESSION_ANOMALY",
                name="Cross-frame compression anomaly",
                category="COMPRESSION_FORENSICS",
                description=(
                    "Sampled frames contain elevated and inconsistent "
                    "error-level compression evidence."
                ),
                score=average_ela * 2.0,
                confidence=65.0,
                threshold=55.0,
            ),
            self._signal(
                code="VIDEO_NOISE_INCONSISTENCY",
                name="Cross-frame noise inconsistency",
                category="PIXEL_FORENSICS",
                description=(
                    "Local noise residual variation is elevated "
                    "across sampled frames."
                ),
                score=average_noise * 5.0,
                confidence=68.0,
                threshold=55.0,
            ),
        ]

    def _video_heuristic_probability(
        self,
        features: VideoFeatureSet,
        signals: list[AnalysisSignal],
    ) -> float:
        suspicious_ratio = (
            features.suspicious_frame_count
            / max(1, features.sampled_frame_count)
        )
        frame_scores = [
            self._frame_suspicion_score(frame)
            for frame in features.frames
        ]
        peak_frame_score = (
            max(frame_scores) if frame_scores else 0.0
        )
        mean_frame_score = (
            fmean(frame_scores) if frame_scores else 0.0
        )
        temporal_signal = next(
            (
                signal.score
                for signal in signals
                if signal.code == "TEMPORAL_VISUAL_ANOMALY"
            ),
            0.0,
        )
        return self._clamp(
            (suspicious_ratio * 100.0 * 0.35)
            + (peak_frame_score * 0.25)
            + (mean_frame_score * 0.25)
            + (temporal_signal * 0.15)
        )

    def _forensic_score(
        self,
        features: VideoFeatureSet,
        signals: list[AnalysisSignal],
    ) -> float:
        weights = {
            "FRAME_DUPLICATION_PATTERN": 0.20,
            "ABRUPT_SUSPICIOUS_TRANSITION": 0.25,
            "VIDEO_TIMESTAMP_ANOMALY": 0.20,
            "VIDEO_COMPRESSION_ANOMALY": 0.18,
            "VIDEO_NOISE_INCONSISTENCY": 0.17,
        }
        score = sum(
            signal.score * weights.get(signal.code, 0.0)
            for signal in signals
        )
        suspicious_ratio = (
            features.suspicious_frame_count
            / max(1, features.sampled_frame_count)
        )
        return self._clamp(
            score + (suspicious_ratio * 15.0)
        )

    def _build_model_tensor(
        self,
        features: VideoFeatureSet,
        model: ModelExecutionSpecification,
    ) -> np.ndarray:
        selected = self._select_model_frames(features)
        if len(selected) < 2:
            raise MediaRuntimeError(
                "at least two decoded frames are required "
                "for video model inference"
            )

        input_width = int(
            self._model_option(
                model,
                "input_width",
                224,
            )
        )
        input_height = int(
            self._model_option(
                model,
                "input_height",
                224,
            )
        )
        if (
            input_width < 32
            or input_width > 2048
            or input_height < 32
            or input_height > 2048
        ):
            raise MediaRuntimeError(
                "invalid video model input dimensions"
            )

        tensors: list[np.ndarray] = []
        for frame in selected:
            image = self._read_image(
                Path(frame.extracted_file_path)
            )
            rgb = cv2.cvtColor(
                image,
                cv2.COLOR_BGR2RGB,
            )
            resized = cv2.resize(
                rgb,
                (input_width, input_height),
                interpolation=cv2.INTER_AREA,
            )
            normalized = (
                resized.astype(np.float32) / 255.0
            )
            tensors.append(
                np.transpose(normalized, (2, 0, 1))
            )

        temporal_tensor = np.stack(tensors, axis=0)
        layout = str(
            self._model_option(
                model,
                "input_layout",
                "NCTHW",
            )
        ).upper()
        if layout == "NTCHW":
            return np.expand_dims(
                temporal_tensor,
                axis=0,
            ).astype(np.float32)
        if layout == "NCTHW":
            return np.expand_dims(
                np.transpose(
                    temporal_tensor,
                    (1, 0, 2, 3),
                ),
                axis=0,
            ).astype(np.float32)
        raise MediaRuntimeError(
            "video model input_layout must be NCTHW or NTCHW"
        )

    def _select_model_frames(
        self,
        features: VideoFeatureSet,
    ) -> list[VideoFrameFeature]:
        frames = list(features.frames)
        if len(frames) <= self._maximum_model_frames:
            return frames

        positions = np.linspace(
            0,
            len(frames) - 1,
            num=self._maximum_model_frames,
        )
        selected_indices = {
            int(round(position))
            for position in positions
        }
        suspicious_indices = [
            index
            for index, frame in enumerate(frames)
            if frame.is_suspicious
        ]
        for index in suspicious_indices:
            if len(selected_indices) >= self._maximum_model_frames:
                break
            selected_indices.add(index)

        ordered = sorted(selected_indices)
        if len(ordered) > self._maximum_model_frames:
            ordered = ordered[: self._maximum_model_frames]
        return [frames[index] for index in ordered]

    def _video_regions(
        self,
        features: VideoFeatureSet,
    ) -> list[SuspiciousRegion]:
        regions: list[SuspiciousRegion] = []
        for frame in features.frames:
            if not frame.is_suspicious:
                continue
            source_regions = (
                frame.image_features.suspicious_regions
            )
            if not source_regions:
                regions.append(
                    SuspiciousRegion(
                        region_type="SUSPICIOUS_FRAME",
                        frame_number=frame.frame_number,
                        page_number=None,
                        timestamp_seconds=(
                            frame.timestamp_seconds
                        ),
                        bounding_box=None,
                        score=round(
                            self._frame_suspicion_score(
                                frame
                            ),
                            4,
                        ),
                        description=(
                            "Sampled video frame contains multiple "
                            "forensic anomaly indicators."
                        ),
                    )
                )
                continue

            for source_region in source_regions[:10]:
                payload = self._object_to_dict(
                    source_region
                )
                regions.append(
                    SuspiciousRegion(
                        region_type=str(
                            payload.get(
                                "region_type",
                                payload.get(
                                    "type",
                                    "FRAME_REGION_ANOMALY",
                                ),
                            )
                        ),
                        frame_number=frame.frame_number,
                        page_number=None,
                        timestamp_seconds=(
                            frame.timestamp_seconds
                        ),
                        bounding_box=self._bounding_box(
                            payload
                        ),
                        score=round(
                            self._normalize_percentage(
                                self._first_number(
                                    payload,
                                    (
                                        "score",
                                        "suspicion_score",
                                        "anomaly_score",
                                    ),
                                )
                                or self._frame_suspicion_score(
                                    frame
                                )
                            ),
                            4,
                        ),
                        description=str(
                            payload.get(
                                "description",
                                "Suspicious region in sampled "
                                "video frame.",
                            )
                        ),
                    )
                )
        return regions

    def _save_contact_sheet(
        self,
        *,
        features: VideoFeatureSet,
        destination: Path | None,
        warnings: list[str],
    ) -> str | None:
        if destination is None:
            return None

        try:
            ranked = sorted(
                features.frames,
                key=self._frame_suspicion_score,
                reverse=True,
            )[:12]
            if not ranked:
                return None

            tile_width = 320
            tile_height = 200
            columns = min(4, len(ranked))
            rows = (
                len(ranked) + columns - 1
            ) // columns
            sheet = np.zeros(
                (
                    rows * tile_height,
                    columns * tile_width,
                    3,
                ),
                dtype=np.uint8,
            )

            for index, frame in enumerate(ranked):
                image = self._read_image(
                    Path(frame.extracted_file_path)
                )
                resized = cv2.resize(
                    image,
                    (tile_width, tile_height - 20),
                    interpolation=cv2.INTER_AREA,
                )
                row = index // columns
                column = index % columns
                top = row * tile_height
                left = column * tile_width
                sheet[
                    top : top + tile_height - 20,
                    left : left + tile_width,
                ] = resized
                label = (
                    f"F:{frame.frame_number} "
                    f"T:{frame.timestamp_seconds:.2f}s "
                    f"S:{self._frame_suspicion_score(frame):.1f}"
                )
                cv2.putText(
                    sheet,
                    label,
                    (left + 5, top + tile_height - 5),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.42,
                    (0, 255, 255),
                    1,
                    cv2.LINE_AA,
                )

            resolved = destination.resolve()
            if resolved.suffix.lower() not in {
                ".jpg",
                ".jpeg",
                ".png",
            }:
                resolved = resolved.with_suffix(".jpg")
            resolved.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            extension = resolved.suffix.lower()
            encoded, buffer = cv2.imencode(
                extension,
                sheet,
            )
            if not encoded:
                raise MediaRuntimeError(
                    "unable to encode video contact sheet"
                )
            buffer.tofile(str(resolved))
            return str(resolved)
        except Exception as error:
            warnings.append(
                "Unable to create video forensic contact sheet: "
                f"{error}"
            )
            return None

    def _frame_suspicion_score(
        self,
        frame: VideoFrameFeature,
    ) -> float:
        image = frame.image_features
        region_score = min(
            100.0,
            len(image.suspicious_regions) * 20.0,
        )
        copy_move_score = min(
            100.0,
            image.copy_move_match_count * 5.0,
        )
        ela_score = min(
            100.0,
            image.ela_percentile_99 * 2.0,
        )
        noise_score = min(
            100.0,
            image.noise_patch_variation * 5.0,
        )
        temporal_bonus = (
            15.0 if frame.abrupt_transition else 0.0
        )
        return self._clamp(
            (region_score * 0.25)
            + (copy_move_score * 0.20)
            + (ela_score * 0.25)
            + (noise_score * 0.20)
            + temporal_bonus
        )

    def _facial_artifact_ratio(
        self,
        features: VideoFeatureSet,
    ) -> float:
        facial_frames = [
            frame
            for frame in features.frames
            if frame.image_features.faces
        ]
        if not facial_frames:
            return 0.0
        suspicious = sum(
            1
            for frame in facial_frames
            if self._manipulated_faces(frame) > 0
        )
        return suspicious / len(facial_frames)

    def _manipulated_faces(
        self,
        frame: VideoFrameFeature,
    ) -> int:
        count = 0
        for face in frame.image_features.faces:
            payload = self._object_to_dict(face)
            value = self._first_number(
                payload,
                (
                    "artifact_score",
                    "suspicion_score",
                    "manipulation_score",
                ),
            )
            if (
                value is not None
                and self._normalize_percentage(value) >= 55.0
            ):
                count += 1
        return count

    @staticmethod
    def _any_frame_copy_move(
        features: VideoFeatureSet,
    ) -> bool:
        return any(
            frame.image_features.copy_move_match_count >= 10
            for frame in features.frames
        )

    @staticmethod
    def _read_image(path: Path) -> np.ndarray:
        try:
            encoded = np.fromfile(
                str(path),
                dtype=np.uint8,
            )
            image = cv2.imdecode(
                encoded,
                cv2.IMREAD_COLOR,
            )
        except (OSError, ValueError, cv2.error) as error:
            raise MediaRuntimeError(
                "unable to load sampled video frame"
            ) from error
        if image is None or image.size == 0:
            raise MediaRuntimeError(
                "sampled video frame is empty"
            )
        return image

    @staticmethod
    def _model_option(
        model: ModelExecutionSpecification,
        key: str,
        default: Any,
    ) -> Any:
        direct = getattr(model, key, None)
        if direct is not None:
            return direct
        configuration = getattr(
            model,
            "configuration",
            None,
        )
        if isinstance(configuration, Mapping):
            return configuration.get(key, default)
        return default

    @staticmethod
    def _signal(
        *,
        code: str,
        name: str,
        category: str,
        description: str,
        score: float,
        confidence: float,
        threshold: float,
    ) -> AnalysisSignal:
        normalized = VideoAnalyzer._clamp(score)
        return AnalysisSignal(
            code=code,
            name=name,
            category=category,
            description=description,
            score=round(normalized, 4),
            confidence=round(
                VideoAnalyzer._clamp(confidence),
                4,
            ),
            detected=normalized >= threshold,
        )

    @staticmethod
    def _signal_confidence(
        signals: list[AnalysisSignal],
    ) -> float:
        detected = [
            signal
            for signal in signals
            if signal.detected
        ]
        if not detected:
            return 52.0
        return VideoAnalyzer._clamp(
            fmean(
                signal.confidence for signal in detected
            )
            + min(12.0, len(detected) * 2.0)
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
    def _significant_count(
        count: int,
        total: int,
        *,
        ratio: float,
        minimum: int,
    ) -> bool:
        threshold = max(
            minimum,
            int(np.ceil(max(1, total) * ratio)),
        )
        return count >= threshold

    @staticmethod
    def _deepfake_result(probability: float) -> str:
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
        frames: int,
    ) -> str:
        if runtime == "HEURISTIC_FALLBACK":
            return (
                f"Video classified as {result} with a "
                f"{probability:.2f}% heuristic indicator score "
                f"across {frames} sampled frames. No trained-model "
                "conclusion is claimed."
            )
        return (
            f"Video classified as {result} with a "
            f"{probability:.2f}% combined offline model and "
            f"forensic score across {frames} sampled frames."
        )

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
        value = VideoAnalyzer._first_number(
            payload,
            names,
        )
        if value is not None:
            return VideoAnalyzer._normalize_percentage(
                value
            )
        probabilities = payload.get("probabilities")
        if isinstance(probabilities, (list, tuple)):
            numeric = [
                float(item)
                for item in probabilities
                if isinstance(item, (int, float))
            ]
            if numeric:
                return VideoAnalyzer._normalize_percentage(
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

        for names in (
            ("x", "y", "width", "height"),
            ("left", "top", "width", "height"),
        ):
            values = [payload.get(name) for name in names]
            if all(
                isinstance(value, (int, float))
                for value in values
            ):
                return tuple(float(value) for value in values)
        return None

    @staticmethod
    def _normalize_percentage(value: float) -> float:
        numeric = float(value)
        if 0.0 <= numeric <= 1.0:
            numeric *= 100.0
        return VideoAnalyzer._clamp(numeric)

    @staticmethod
    def _unique(values: list[str]) -> list[str]:
        return list(dict.fromkeys(values))

    @staticmethod
    def _clamp(value: float) -> float:
        return max(0.0, min(100.0, float(value)))