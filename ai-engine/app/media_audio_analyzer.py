from __future__ import annotations

from dataclasses import asdict, is_dataclass
from pathlib import Path
from statistics import fmean
from typing import Any, Mapping

import cv2
import numpy as np
import torch
import torchaudio

from app.media_audio_features import (
    AudioFeatureExtractor,
    AudioFeatureSet,
    AudioSegmentFeature,
)
from app.media_forensics_runtime import MediaRuntimeError
from app.media_forensics_schemas import (
    AnalysisSignal,
    DeepfakeAssessment,
    MediaForensicsAssessment,
    ModelExecutionSpecification,
    SuspiciousRegion,
)
from app.media_model_runner import MediaModelRunner


class AudioAnalyzer:
    """Runs offline synthetic-audio and classical audio forensics."""

    def __init__(
        self,
        feature_extractor: AudioFeatureExtractor | None = None,
        model_runner: MediaModelRunner | None = None,
        *,
        maximum_model_segments: int = 12,
        allow_heuristic_fallback: bool = True,
    ) -> None:
        if (
            maximum_model_segments < 1
            or maximum_model_segments > 128
        ):
            raise ValueError(
                "maximum_model_segments must be between 1 and 128"
            )

        self._feature_extractor = (
            feature_extractor or AudioFeatureExtractor()
        )
        self._model_runner = model_runner
        self._maximum_model_segments = (
            maximum_model_segments
        )
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
        waveform, features = self._feature_extractor.extract(
            file_path,
            workspace_path,
        )
        signals = self._deepfake_signals(features)
        warnings: list[str] = []
        heuristic_probability = self._heuristic_probability(
            features,
            signals,
        )

        model_results: list[dict[str, Any]] = []
        model_probabilities: list[float] = []
        model_confidences: list[float] = []
        runtime = "HEURISTIC_FALLBACK"

        if model is not None:
            try:
                runner = (
                    self._model_runner
                    or MediaModelRunner()
                )
                tensors = self._build_model_inputs(
                    waveform=waveform,
                    sample_rate=features.sample_rate,
                    model=model,
                )
                for index, tensor in enumerate(tensors):
                    inference = runner.run_tensor(
                        model,
                        tensor,
                    )
                    payload = self._object_to_dict(
                        inference
                    )
                    probability = self._extract_percentage(
                        payload,
                        (
                            "deepfake_probability",
                            "fake_probability",
                            "synthetic_probability",
                            "manipulation_probability",
                        ),
                    )
                    if probability is None:
                        raise MediaRuntimeError(
                            "audio model result did not contain "
                            "a synthetic-audio probability"
                        )
                    confidence = self._extract_percentage(
                        payload,
                        (
                            "confidence_score",
                            "confidence",
                        ),
                    )
                    payload["segment_index"] = index
                    model_results.append(payload)
                    model_probabilities.append(probability)
                    if confidence is not None:
                        model_confidences.append(confidence)

                runtime = self._resolve_model_runtime(
                    model,
                    model_results[0],
                )
                aggregate_probability = (
                    self._aggregate_model_probabilities(
                        model_probabilities
                    )
                )
                aggregate_confidence = (
                    fmean(model_confidences)
                    if model_confidences
                    else 70.0
                )
                signals.append(
                    self._signal(
                        code="AUDIO_MODEL_SYNTHETIC_PROBABILITY",
                        name="Offline synthetic-audio model",
                        category="MODEL_INFERENCE",
                        description=(
                            "The verified offline audio model found "
                            "possible synthesized or voice-converted "
                            "audio characteristics."
                        ),
                        score=aggregate_probability,
                        confidence=aggregate_confidence,
                        threshold=50.0,
                    )
                )
            except Exception as error:
                if not self._allow_heuristic_fallback:
                    raise MediaRuntimeError(
                        "offline audio model inference failed"
                    ) from error

                warnings.append(
                    "Offline audio model inference failed; "
                    "HEURISTIC_FALLBACK was used and the result "
                    "must not be treated as a trained-model "
                    "prediction."
                )
                model_results = [{"error": str(error)}]
                model_probabilities = []
                model_confidences = []
                runtime = "HEURISTIC_FALLBACK"
        else:
            warnings.append(
                "No verified synthetic-audio model was supplied; "
                "HEURISTIC_FALLBACK was used and the result is "
                "not a trained-model prediction."
            )

        if model_probabilities:
            aggregate_probability = (
                self._aggregate_model_probabilities(
                    model_probabilities
                )
            )
            probability = self._clamp(
                (aggregate_probability * 0.80)
                + (heuristic_probability * 0.20)
            )
            confidence = self._clamp(
                (
                    (
                        fmean(model_confidences)
                        if model_confidences
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
        suspicious_regions = self._audio_regions(features)
        visualization = self._save_visualization(
            waveform=waveform,
            sample_rate=features.sample_rate,
            destination=visualization_path,
            warnings=warnings,
        )

        feature_data = features.to_dict()
        feature_data["analysis_runtime"] = runtime
        feature_data["heuristic_probability"] = round(
            heuristic_probability,
            4,
        )
        if model_results:
            feature_data["model_segment_inferences"] = (
                model_results
            )

        assessment = DeepfakeAssessment(
            media_type="AUDIO",
            detection_result=result,
            deepfake_probability=round(probability, 4),
            authenticity_probability=round(
                self._clamp(100.0 - probability),
                4,
            ),
            confidence_score=round(confidence, 4),
            faces_detected=None,
            manipulated_faces_detected=None,
            total_frames_analyzed=None,
            suspicious_frames=None,
            audio_duration_seconds=round(
                features.duration_seconds,
                6,
            ),
            lip_sync_anomaly_detected=False,
            facial_artifact_detected=False,
            audio_manipulation_detected=(
                probability >= 50.0
            ),
            metadata_inconsistency_detected=False,
            detection_summary=self._deepfake_summary(
                result,
                probability,
                runtime,
                features.duration_seconds,
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
        waveform, features = self._feature_extractor.extract(
            file_path,
            workspace_path,
        )
        warnings: list[str] = []
        signals = self._forensic_signals(features)
        score = self._forensic_score(features, signals)
        result = self._forensic_result(score)

        discontinuity = self._signal_detected(
            signals,
            "AUDIO_DISCONTINUITY",
        )
        repeated = self._signal_detected(
            signals,
            "REPEATED_AUDIO_SEGMENT",
        )
        noise_inconsistency = self._signal_detected(
            signals,
            "SPECTRAL_NOISE_INCONSISTENCY",
        )
        clipping = self._signal_detected(
            signals,
            "AUDIO_CLIPPING",
        )
        suspicious_locations = self._audio_regions(features)
        visualization = self._save_visualization(
            waveform=waveform,
            sample_rate=features.sample_rate,
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
                "No strong classical audio manipulation "
                "indicator was detected."
            )

        feature_data = features.to_dict()
        feature_data["analysis_runtime"] = (
            "CLASSICAL_AUDIO_FORENSICS"
        )
        feature_data["manipulation_score"] = round(
            score,
            4,
        )

        assessment = MediaForensicsAssessment(
            media_type="AUDIO",
            forensic_result=result,
            confidence_score=round(
                self._signal_confidence(signals),
                4,
            ),
            editing_trace_detected=False,
            compression_anomaly_detected=clipping,
            copy_move_detected=repeated,
            splicing_detected=discontinuity,
            frame_duplication_detected=False,
            frame_deletion_detected=False,
            audio_discontinuity_detected=discontinuity,
            noise_inconsistency_detected=(
                noise_inconsistency
            ),
            timestamp_anomaly_detected=False,
            analysis_summary=(
                f"Audio forensic result is {result} with a "
                f"{score:.2f}% manipulation indicator score "
                f"across {features.duration_seconds:.2f} seconds."
            ),
            findings=findings,
            signals=signals,
            suspicious_locations=suspicious_locations,
            forensic_feature_data=feature_data,
            visualization_file_path=visualization,
        )

        return (
            assessment,
            "CLASSICAL_AUDIO_FORENSICS",
            self._unique(warnings),
        )

    def _deepfake_signals(
        self,
        features: AudioFeatureSet,
    ) -> list[AnalysisSignal]:
        pitch_stability_score = 0.0
        if (
            features.pitch_standard_deviation_hz
            is not None
            and features.voiced_segment_ratio >= 0.25
        ):
            pitch_stability_score = self._clamp(
                (
                    12.0
                    - features.pitch_standard_deviation_hz
                )
                * 8.0
            )

        spectral_stability_score = self._clamp(
            (
                0.08
                - features.spectral_flatness_standard_deviation
            )
            * 1000.0
        )
        suspicious_ratio = (
            features.suspicious_segment_count
            / max(1, len(features.segments))
        )
        repeated_ratio = (
            features.repeated_segment_count
            / max(1, len(features.segments))
        )

        return [
            self._signal(
                code="UNNATURAL_PITCH_STABILITY",
                name="Unnatural pitch stability",
                category="VOICE_FORENSICS",
                description=(
                    "Voiced segments exhibit unusually stable pitch "
                    "that may be associated with synthesized speech."
                ),
                score=pitch_stability_score,
                confidence=62.0,
                threshold=55.0,
            ),
            self._signal(
                code="UNNATURAL_SPECTRAL_STABILITY",
                name="Unnatural spectral stability",
                category="SPECTRAL_FORENSICS",
                description=(
                    "Spectral-flatness variation is unusually low "
                    "across the analyzed audio."
                ),
                score=spectral_stability_score,
                confidence=60.0,
                threshold=55.0,
            ),
            self._signal(
                code="SUSPICIOUS_AUDIO_SEGMENT_RATIO",
                name="Suspicious audio segments",
                category="SEGMENT_FORENSICS",
                description=(
                    "Multiple audio segments contain combined "
                    "spectral, repetition, or amplitude anomalies."
                ),
                score=suspicious_ratio * 100.0,
                confidence=70.0,
                threshold=25.0,
            ),
            self._signal(
                code="SYNTHETIC_REPETITION_PATTERN",
                name="Repeated spectral pattern",
                category="VOICE_FORENSICS",
                description=(
                    "Repeated segment-level spectral fingerprints "
                    "may indicate generated or looped audio."
                ),
                score=repeated_ratio * 120.0,
                confidence=68.0,
                threshold=35.0,
            ),
        ]

    def _forensic_signals(
        self,
        features: AudioFeatureSet,
    ) -> list[AnalysisSignal]:
        segment_count = max(1, len(features.segments))
        discontinuity_score = self._clamp(
            features.discontinuity_count
            / max(1.0, features.duration_seconds)
            * 45.0
        )
        energy_jump_score = self._clamp(
            features.energy_jump_count
            / max(1.0, features.duration_seconds)
            * 30.0
        )
        repetition_score = self._clamp(
            features.repeated_segment_count
            / segment_count
            * 140.0
        )
        noise_score = self._clamp(
            (
                features.spectral_flatness_standard_deviation
                * 700.0
            )
            + (
                features
                .spectral_centroid_standard_deviation_hz
                / 60.0
            )
        )
        clipping_score = self._clamp(
            features.clipping_ratio * 5000.0
        )

        return [
            self._signal(
                code="AUDIO_DISCONTINUITY",
                name="Audio waveform discontinuity",
                category="WAVEFORM_FORENSICS",
                description=(
                    "Abrupt sample or energy discontinuities may "
                    "indicate cutting, joining, or splicing."
                ),
                score=max(
                    discontinuity_score,
                    energy_jump_score,
                ),
                confidence=75.0,
                threshold=50.0,
            ),
            self._signal(
                code="REPEATED_AUDIO_SEGMENT",
                name="Repeated audio segments",
                category="STRUCTURAL_FORENSICS",
                description=(
                    "Identical segment-level spectral fingerprints "
                    "indicate possible repetition or looping."
                ),
                score=repetition_score,
                confidence=74.0,
                threshold=40.0,
            ),
            self._signal(
                code="SPECTRAL_NOISE_INCONSISTENCY",
                name="Spectral noise inconsistency",
                category="SPECTRAL_FORENSICS",
                description=(
                    "Spectral centroid and flatness variation suggest "
                    "inconsistent noise characteristics."
                ),
                score=noise_score,
                confidence=68.0,
                threshold=55.0,
            ),
            self._signal(
                code="AUDIO_CLIPPING",
                name="Audio clipping",
                category="AMPLITUDE_FORENSICS",
                description=(
                    "A material portion of samples reaches the "
                    "digital amplitude limit."
                ),
                score=clipping_score,
                confidence=78.0,
                threshold=50.0,
            ),
        ]

    def _heuristic_probability(
        self,
        features: AudioFeatureSet,
        signals: list[AnalysisSignal],
    ) -> float:
        weights = {
            "UNNATURAL_PITCH_STABILITY": 0.30,
            "UNNATURAL_SPECTRAL_STABILITY": 0.25,
            "SUSPICIOUS_AUDIO_SEGMENT_RATIO": 0.25,
            "SYNTHETIC_REPETITION_PATTERN": 0.20,
        }
        score = sum(
            signal.score * weights.get(signal.code, 0.0)
            for signal in signals
        )
        if (
            features.voiced_segment_ratio < 0.10
            and features.silence_ratio > 0.80
        ):
            score *= 0.50
        return self._clamp(score)

    def _forensic_score(
        self,
        features: AudioFeatureSet,
        signals: list[AnalysisSignal],
    ) -> float:
        weights = {
            "AUDIO_DISCONTINUITY": 0.35,
            "REPEATED_AUDIO_SEGMENT": 0.25,
            "SPECTRAL_NOISE_INCONSISTENCY": 0.25,
            "AUDIO_CLIPPING": 0.15,
        }
        score = sum(
            signal.score * weights.get(signal.code, 0.0)
            for signal in signals
        )
        suspicious_ratio = (
            features.suspicious_segment_count
            / max(1, len(features.segments))
        )
        return self._clamp(
            score + (suspicious_ratio * 12.0)
        )

    def _build_model_inputs(
        self,
        *,
        waveform: np.ndarray,
        sample_rate: int,
        model: ModelExecutionSpecification,
    ) -> list[np.ndarray]:
        window_seconds = float(
            self._model_option(
                model,
                "window_seconds",
                4.0,
            )
        )
        if window_seconds <= 0 or window_seconds > 60:
            raise MediaRuntimeError(
                "audio model window_seconds must be between "
                "zero and 60"
            )
        window_samples = max(
            1,
            int(round(sample_rate * window_seconds)),
        )
        segments = self._sample_waveform_windows(
            waveform,
            window_samples,
        )
        representation = str(
            self._model_option(
                model,
                "input_representation",
                "LOG_MEL_SPECTROGRAM",
            )
        ).upper()

        if representation in {"WAVEFORM", "RAW_WAVEFORM"}:
            layout = str(
                self._model_option(
                    model,
                    "input_layout",
                    "NCT",
                )
            ).upper()
            tensors: list[np.ndarray] = []
            for segment in segments:
                normalized = self._normalize_waveform(segment)
                if layout == "NT":
                    tensor = normalized[None, :]
                elif layout == "NCT":
                    tensor = normalized[None, None, :]
                else:
                    raise MediaRuntimeError(
                        "waveform input_layout must be NT or NCT"
                    )
                tensors.append(tensor.astype(np.float32))
            return tensors

        if representation not in {
            "MEL_SPECTROGRAM",
            "LOG_MEL_SPECTROGRAM",
        }:
            raise MediaRuntimeError(
                "unsupported audio model input representation"
            )

        n_fft = int(
            self._model_option(model, "n_fft", 400)
        )
        hop_length = int(
            self._model_option(model, "hop_length", 160)
        )
        n_mels = int(
            self._model_option(model, "n_mels", 64)
        )
        if (
            n_fft < 128
            or n_fft > 8192
            or hop_length < 1
            or n_mels < 8
            or n_mels > 512
        ):
            raise MediaRuntimeError(
                "invalid audio spectrogram configuration"
            )

        mel_transform = torchaudio.transforms.MelSpectrogram(
            sample_rate=sample_rate,
            n_fft=n_fft,
            hop_length=hop_length,
            n_mels=n_mels,
            power=2.0,
        )
        amplitude_to_db = (
            torchaudio.transforms.AmplitudeToDB(
                stype="power",
                top_db=80.0,
            )
        )
        tensors = []
        for segment in segments:
            waveform_tensor = torch.from_numpy(
                self._normalize_waveform(segment)
            )
            mel = mel_transform(waveform_tensor)
            if representation == "LOG_MEL_SPECTROGRAM":
                mel = amplitude_to_db(mel)
            mel = (
                mel - torch.mean(mel)
            ) / (torch.std(mel) + 1e-6)
            tensors.append(
                mel.unsqueeze(0)
                .unsqueeze(0)
                .numpy()
                .astype(np.float32)
            )
        return tensors

    def _sample_waveform_windows(
        self,
        waveform: np.ndarray,
        window_samples: int,
    ) -> list[np.ndarray]:
        if waveform.size <= window_samples:
            return [
                np.pad(
                    waveform,
                    (0, window_samples - waveform.size),
                ).astype(np.float32)
            ]

        maximum_start = waveform.size - window_samples
        count = min(
            self._maximum_model_segments,
            max(
                1,
                int(np.ceil(waveform.size / window_samples)),
            ),
        )
        starts = sorted(
            {
                int(round(value))
                for value in np.linspace(
                    0,
                    maximum_start,
                    num=count,
                )
            }
        )
        return [
            waveform[
                start : start + window_samples
            ].astype(np.float32)
            for start in starts
        ]

    def _audio_regions(
        self,
        features: AudioFeatureSet,
    ) -> list[SuspiciousRegion]:
        return [
            SuspiciousRegion(
                region_type="AUDIO_SEGMENT_ANOMALY",
                frame_number=None,
                page_number=None,
                timestamp_seconds=segment.start_seconds,
                bounding_box=None,
                score=round(
                    self._segment_score(segment),
                    4,
                ),
                description=(
                    "Audio segment contains combined spectral, "
                    "amplitude, or repetition anomalies."
                ),
            )
            for segment in features.segments
            if segment.is_suspicious
        ]

    def _save_visualization(
        self,
        *,
        waveform: np.ndarray,
        sample_rate: int,
        destination: Path | None,
        warnings: list[str],
    ) -> str | None:
        if destination is None:
            return None

        try:
            width = 1200
            waveform_height = 260
            spectrogram_height = 420
            canvas = np.zeros(
                (
                    waveform_height + spectrogram_height,
                    width,
                    3,
                ),
                dtype=np.uint8,
            )

            positions = np.linspace(
                0,
                waveform.size - 1,
                num=width,
            ).astype(np.int64)
            sampled = waveform[positions]
            center = waveform_height // 2
            scale = (waveform_height // 2) - 10
            y_values = (
                center - (sampled * scale)
            ).astype(np.int32)
            points = np.column_stack(
                (
                    np.arange(width, dtype=np.int32),
                    np.clip(
                        y_values,
                        0,
                        waveform_height - 1,
                    ),
                )
            )
            cv2.polylines(
                canvas,
                [points],
                False,
                (0, 255, 0),
                1,
                cv2.LINE_AA,
            )
            cv2.line(
                canvas,
                (0, center),
                (width - 1, center),
                (80, 80, 80),
                1,
            )

            spectrogram = self._visual_spectrogram(
                waveform,
                sample_rate,
            )
            spectrogram = cv2.resize(
                spectrogram,
                (width, spectrogram_height),
                interpolation=cv2.INTER_AREA,
            )
            canvas[
                waveform_height:,
                :,
            ] = spectrogram

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
            encoded, buffer = cv2.imencode(
                resolved.suffix.lower(),
                canvas,
            )
            if not encoded:
                raise MediaRuntimeError(
                    "unable to encode audio visualization"
                )
            buffer.tofile(str(resolved))
            return str(resolved)
        except Exception as error:
            warnings.append(
                "Unable to create waveform/spectrogram "
                f"visualization: {error}"
            )
            return None

    @staticmethod
    def _visual_spectrogram(
        waveform: np.ndarray,
        sample_rate: int,
    ) -> np.ndarray:
        maximum_samples = sample_rate * 300
        if waveform.size > maximum_samples:
            positions = np.linspace(
                0,
                waveform.size - 1,
                num=maximum_samples,
            ).astype(np.int64)
            waveform = waveform[positions]

        n_fft = 512
        hop = 256
        if waveform.size < n_fft:
            waveform = np.pad(
                waveform,
                (0, n_fft - waveform.size),
            )
        frame_count = (
            1 + (waveform.size - n_fft) // hop
        )
        shape = (frame_count, n_fft)
        strides = (
            waveform.strides[0] * hop,
            waveform.strides[0],
        )
        frames = np.lib.stride_tricks.as_strided(
            waveform,
            shape=shape,
            strides=strides,
            writeable=False,
        )
        spectrum = np.abs(
            np.fft.rfft(
                frames * np.hanning(n_fft),
                axis=1,
            )
        )
        decibels = 20.0 * np.log10(spectrum + 1e-8)
        decibels -= np.max(decibels)
        normalized = np.clip(
            (decibels + 80.0) / 80.0 * 255.0,
            0.0,
            255.0,
        ).astype(np.uint8)
        grayscale = np.flipud(normalized.T)
        return cv2.applyColorMap(
            grayscale,
            cv2.COLORMAP_INFERNO,
        )

    @staticmethod
    def _segment_score(
        segment: AudioSegmentFeature,
    ) -> float:
        return AudioAnalyzer._clamp(
            (60.0 if segment.is_repeated else 0.0)
            + (segment.spectral_flatness * 35.0)
            + min(20.0, segment.zero_crossing_rate * 50.0)
            + (
                20.0
                if segment.peak_amplitude >= 0.999
                else 0.0
            )
        )

    @staticmethod
    def _aggregate_model_probabilities(
        probabilities: list[float],
    ) -> float:
        return AudioAnalyzer._clamp(
            (fmean(probabilities) * 0.65)
            + (max(probabilities) * 0.35)
        )

    @staticmethod
    def _normalize_waveform(
        waveform: np.ndarray,
    ) -> np.ndarray:
        centered = waveform.astype(np.float32)
        centered = centered - np.mean(centered)
        peak = float(np.max(np.abs(centered)))
        if peak > 1e-6:
            centered = centered / peak
        return centered.astype(np.float32)

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
        normalized = AudioAnalyzer._clamp(score)
        return AnalysisSignal(
            code=code,
            name=name,
            category=category,
            description=description,
            score=round(normalized, 4),
            confidence=round(
                AudioAnalyzer._clamp(confidence),
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
        return AudioAnalyzer._clamp(
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
        duration: float,
    ) -> str:
        if runtime == "HEURISTIC_FALLBACK":
            return (
                f"Audio classified as {result} with a "
                f"{probability:.2f}% heuristic indicator score "
                f"across {duration:.2f} seconds. No trained-model "
                "conclusion is claimed."
            )
        return (
            f"Audio classified as {result} with a "
            f"{probability:.2f}% combined offline model and "
            f"forensic score across {duration:.2f} seconds."
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
        value = AudioAnalyzer._first_number(
            payload,
            names,
        )
        if value is not None:
            return AudioAnalyzer._normalize_percentage(
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
                return AudioAnalyzer._normalize_percentage(
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
    def _normalize_percentage(value: float) -> float:
        numeric = float(value)
        if 0.0 <= numeric <= 1.0:
            numeric *= 100.0
        return AudioAnalyzer._clamp(numeric)

    @staticmethod
    def _unique(values: list[str]) -> list[str]:
        return list(dict.fromkeys(values))

    @staticmethod
    def _clamp(value: float) -> float:
        return max(0.0, min(100.0, float(value)))