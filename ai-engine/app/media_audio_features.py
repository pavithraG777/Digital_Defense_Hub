from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from statistics import fmean
from typing import Any

import numpy as np
import soundfile as sf

from app.config import get_settings
from app.media_forensics_runtime import MediaRuntimeError


@dataclass(frozen=True)
class AudioSegmentFeature:
    segment_index: int
    start_seconds: float
    end_seconds: float
    rms_energy: float
    peak_amplitude: float
    zero_crossing_rate: float
    spectral_centroid_hz: float
    spectral_bandwidth_hz: float
    spectral_rolloff_hz: float
    spectral_flatness: float
    pitch_hz: float | None
    voiced: bool
    fingerprint: str
    is_repeated: bool
    is_suspicious: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "segment_index": self.segment_index,
            "start_seconds": self.start_seconds,
            "end_seconds": self.end_seconds,
            "rms_energy": self.rms_energy,
            "peak_amplitude": self.peak_amplitude,
            "zero_crossing_rate": self.zero_crossing_rate,
            "spectral_centroid_hz": (
                self.spectral_centroid_hz
            ),
            "spectral_bandwidth_hz": (
                self.spectral_bandwidth_hz
            ),
            "spectral_rolloff_hz": self.spectral_rolloff_hz,
            "spectral_flatness": self.spectral_flatness,
            "pitch_hz": self.pitch_hz,
            "voiced": self.voiced,
            "fingerprint": self.fingerprint,
            "is_repeated": self.is_repeated,
            "is_suspicious": self.is_suspicious,
        }


@dataclass(frozen=True)
class AudioFeatureSet:
    sample_rate: int
    channel_count: int
    duration_seconds: float
    sample_count: int
    analyzed_duration_seconds: float
    rms_energy: float
    peak_amplitude: float
    dynamic_range_db: float
    clipping_ratio: float
    silence_ratio: float
    zero_crossing_rate: float
    spectral_centroid_mean_hz: float
    spectral_centroid_standard_deviation_hz: float
    spectral_bandwidth_mean_hz: float
    spectral_bandwidth_standard_deviation_hz: float
    spectral_rolloff_mean_hz: float
    spectral_flatness_mean: float
    spectral_flatness_standard_deviation: float
    pitch_mean_hz: float | None
    pitch_standard_deviation_hz: float | None
    voiced_segment_ratio: float
    discontinuity_count: int
    energy_jump_count: int
    repeated_segment_count: int
    suspicious_segment_count: int
    converted_audio_path: str
    segments: tuple[AudioSegmentFeature, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_rate": self.sample_rate,
            "channel_count": self.channel_count,
            "duration_seconds": self.duration_seconds,
            "sample_count": self.sample_count,
            "analyzed_duration_seconds": (
                self.analyzed_duration_seconds
            ),
            "rms_energy": self.rms_energy,
            "peak_amplitude": self.peak_amplitude,
            "dynamic_range_db": self.dynamic_range_db,
            "clipping_ratio": self.clipping_ratio,
            "silence_ratio": self.silence_ratio,
            "zero_crossing_rate": self.zero_crossing_rate,
            "spectral_centroid_mean_hz": (
                self.spectral_centroid_mean_hz
            ),
            "spectral_centroid_standard_deviation_hz": (
                self.spectral_centroid_standard_deviation_hz
            ),
            "spectral_bandwidth_mean_hz": (
                self.spectral_bandwidth_mean_hz
            ),
            "spectral_bandwidth_standard_deviation_hz": (
                self.spectral_bandwidth_standard_deviation_hz
            ),
            "spectral_rolloff_mean_hz": (
                self.spectral_rolloff_mean_hz
            ),
            "spectral_flatness_mean": (
                self.spectral_flatness_mean
            ),
            "spectral_flatness_standard_deviation": (
                self.spectral_flatness_standard_deviation
            ),
            "pitch_mean_hz": self.pitch_mean_hz,
            "pitch_standard_deviation_hz": (
                self.pitch_standard_deviation_hz
            ),
            "voiced_segment_ratio": self.voiced_segment_ratio,
            "discontinuity_count": self.discontinuity_count,
            "energy_jump_count": self.energy_jump_count,
            "repeated_segment_count": (
                self.repeated_segment_count
            ),
            "suspicious_segment_count": (
                self.suspicious_segment_count
            ),
            "converted_audio_path": self.converted_audio_path,
            "segments": [
                segment.to_dict()
                for segment in self.segments
            ],
        }


class AudioFeatureExtractor:
    """Creates bounded offline audio forensic features."""

    def __init__(
        self,
        *,
        target_sample_rate: int = 16000,
        maximum_duration_seconds: float = 600.0,
        segment_duration_seconds: float = 2.0,
        analysis_timeout_seconds: float = 300.0,
        ffmpeg_executable: Path | None = None,
    ) -> None:
        if target_sample_rate < 8000:
            raise ValueError(
                "target_sample_rate must be at least 8000"
            )
        if (
            maximum_duration_seconds <= 0
            or maximum_duration_seconds > 3600
        ):
            raise ValueError(
                "maximum_duration_seconds must be between "
                "zero and 3600"
            )
        if (
            segment_duration_seconds < 0.25
            or segment_duration_seconds > 30
        ):
            raise ValueError(
                "segment_duration_seconds must be between "
                "0.25 and 30"
            )
        if analysis_timeout_seconds <= 0:
            raise ValueError(
                "analysis_timeout_seconds must be greater "
                "than zero"
            )

        settings = get_settings()
        configured_ffmpeg = Path(
            str(settings.ffmpeg_executable)
        )

        self._target_sample_rate = target_sample_rate
        self._maximum_duration_seconds = (
            maximum_duration_seconds
        )
        self._segment_duration_seconds = (
            segment_duration_seconds
        )
        self._analysis_timeout_seconds = (
            analysis_timeout_seconds
        )
        self._ffmpeg_executable = (
            ffmpeg_executable or configured_ffmpeg
        ).resolve()

        if not self._ffmpeg_executable.is_file():
            raise MediaRuntimeError(
                "FFmpeg executable is unavailable: "
                f"{self._ffmpeg_executable}"
            )

    def extract(
        self,
        file_path: Path,
        workspace_path: Path,
    ) -> tuple[np.ndarray, AudioFeatureSet]:
        source_path = file_path.resolve()
        if not source_path.is_file():
            raise MediaRuntimeError(
                f"media file does not exist: {source_path}"
            )

        workspace = workspace_path.resolve()
        workspace.mkdir(parents=True, exist_ok=True)
        converted_path = workspace / "analysis-audio.wav"

        self._convert_to_bounded_pcm(
            source_path,
            converted_path,
        )
        waveform, sample_rate = self._load_audio(
            converted_path
        )

        if waveform.size == 0:
            raise MediaRuntimeError(
                "decoded audio stream is empty"
            )

        feature_set = self._extract_features(
            waveform=waveform,
            sample_rate=sample_rate,
            converted_path=converted_path,
        )
        return waveform, feature_set

    def _convert_to_bounded_pcm(
        self,
        source_path: Path,
        destination_path: Path,
    ) -> None:
        command = [
            str(self._ffmpeg_executable),
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-protocol_whitelist",
            "file,pipe",
            "-y",
            "-i",
            str(source_path),
            "-map",
            "0:a:0",
            "-vn",
            "-t",
            f"{self._maximum_duration_seconds:.3f}",
            "-ac",
            "1",
            "-ar",
            str(self._target_sample_rate),
            "-c:a",
            "pcm_s16le",
            str(destination_path),
        ]
        creation_flags = (
            getattr(subprocess, "CREATE_NO_WINDOW", 0)
            if os.name == "nt"
            else 0
        )

        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self._analysis_timeout_seconds,
                creationflags=creation_flags,
                shell=False,
            )
        except subprocess.TimeoutExpired as error:
            raise MediaRuntimeError(
                "FFmpeg audio extraction timed out"
            ) from error
        except OSError as error:
            raise MediaRuntimeError(
                "FFmpeg audio extraction could not start"
            ) from error

        if result.returncode != 0:
            error_message = (
                result.stderr.strip()
                or "unknown FFmpeg decoding error"
            )
            raise MediaRuntimeError(
                "unable to decode the first audio stream: "
                f"{error_message[-1000:]}"
            )
        if (
            not destination_path.is_file()
            or destination_path.stat().st_size <= 44
        ):
            raise MediaRuntimeError(
                "FFmpeg did not produce usable PCM audio"
            )

    @staticmethod
    def _load_audio(
        audio_path: Path,
    ) -> tuple[np.ndarray, int]:
        try:
            waveform, sample_rate = sf.read(
                str(audio_path),
                dtype="float32",
                always_2d=True,
            )
        except (OSError, RuntimeError, ValueError) as error:
            raise MediaRuntimeError(
                "unable to read decoded PCM audio"
            ) from error

        if waveform.ndim != 2:
            raise MediaRuntimeError(
                "decoded audio has an unsupported shape"
            )
        mono = np.mean(
            waveform,
            axis=1,
            dtype=np.float32,
        )
        mono = np.nan_to_num(
            mono,
            nan=0.0,
            posinf=1.0,
            neginf=-1.0,
        )
        mono = np.clip(
            mono,
            -1.0,
            1.0,
        ).astype(np.float32)
        return mono, int(sample_rate)

    def _extract_features(
        self,
        *,
        waveform: np.ndarray,
        sample_rate: int,
        converted_path: Path,
    ) -> AudioFeatureSet:
        frames = self._frame_waveform(
            waveform,
            sample_rate,
        )
        window = np.hanning(frames.shape[1]).astype(
            np.float32
        )
        windowed = frames * window
        spectrum = np.abs(
            np.fft.rfft(windowed, axis=1)
        ).astype(np.float64)
        frequencies = np.fft.rfftfreq(
            frames.shape[1],
            d=1.0 / sample_rate,
        )
        spectral_power = np.square(spectrum)
        spectral_sum = np.sum(
            spectrum,
            axis=1,
        ) + 1e-12

        rms_values = np.sqrt(
            np.mean(np.square(frames), axis=1)
            + 1e-12
        )
        zero_crossing_values = np.mean(
            np.not_equal(
                np.signbit(frames[:, 1:]),
                np.signbit(frames[:, :-1]),
            ),
            axis=1,
        )
        centroid_values = (
            np.sum(
                spectrum * frequencies,
                axis=1,
            )
            / spectral_sum
        )
        bandwidth_values = np.sqrt(
            np.sum(
                spectrum
                * np.square(
                    frequencies[None, :]
                    - centroid_values[:, None]
                ),
                axis=1,
            )
            / spectral_sum
        )
        flatness_values = (
            np.exp(
                np.mean(
                    np.log(spectral_power + 1e-12),
                    axis=1,
                )
            )
            / (
                np.mean(
                    spectral_power + 1e-12,
                    axis=1,
                )
                + 1e-12
            )
        )
        rolloff_values = self._spectral_rolloff(
            spectrum,
            frequencies,
        )

        segment_features = self._segment_features(
            waveform,
            sample_rate,
        )
        pitch_values = [
            segment.pitch_hz
            for segment in segment_features
            if segment.pitch_hz is not None
        ]
        frame_rms_db = 20.0 * np.log10(
            rms_values + 1e-9
        )
        energy_differences = np.abs(
            np.diff(frame_rms_db)
        )
        energy_jump_count = int(
            np.sum(energy_differences >= 18.0)
        )
        derivative = np.abs(np.diff(waveform))
        discontinuity_threshold = max(
            0.35,
            float(np.percentile(derivative, 99.9))
            * 1.5,
        )
        discontinuity_count = int(
            np.sum(derivative >= discontinuity_threshold)
        )

        absolute_waveform = np.abs(waveform)
        rms_energy = float(
            np.sqrt(
                np.mean(np.square(waveform)) + 1e-12
            )
        )
        peak_amplitude = float(
            np.max(absolute_waveform)
        )
        non_silent = absolute_waveform[
            absolute_waveform >= 1e-4
        ]
        noise_floor = (
            float(np.percentile(non_silent, 10))
            if non_silent.size
            else 1e-9
        )
        dynamic_range_db = 20.0 * np.log10(
            (peak_amplitude + 1e-9)
            / (noise_floor + 1e-9)
        )

        repeated_segment_count = sum(
            1
            for segment in segment_features
            if segment.is_repeated
        )
        suspicious_segment_count = sum(
            1
            for segment in segment_features
            if segment.is_suspicious
        )
        duration_seconds = waveform.size / sample_rate

        return AudioFeatureSet(
            sample_rate=sample_rate,
            channel_count=1,
            duration_seconds=round(
                duration_seconds,
                6,
            ),
            sample_count=int(waveform.size),
            analyzed_duration_seconds=round(
                duration_seconds,
                6,
            ),
            rms_energy=round(rms_energy, 8),
            peak_amplitude=round(
                peak_amplitude,
                8,
            ),
            dynamic_range_db=round(
                max(0.0, dynamic_range_db),
                6,
            ),
            clipping_ratio=round(
                float(
                    np.mean(absolute_waveform >= 0.999)
                ),
                8,
            ),
            silence_ratio=round(
                float(
                    np.mean(absolute_waveform <= 0.001)
                ),
                8,
            ),
            zero_crossing_rate=round(
                float(fmean(zero_crossing_values)),
                8,
            ),
            spectral_centroid_mean_hz=round(
                float(fmean(centroid_values)),
                6,
            ),
            spectral_centroid_standard_deviation_hz=round(
                float(np.std(centroid_values)),
                6,
            ),
            spectral_bandwidth_mean_hz=round(
                float(fmean(bandwidth_values)),
                6,
            ),
            spectral_bandwidth_standard_deviation_hz=round(
                float(np.std(bandwidth_values)),
                6,
            ),
            spectral_rolloff_mean_hz=round(
                float(fmean(rolloff_values)),
                6,
            ),
            spectral_flatness_mean=round(
                float(fmean(flatness_values)),
                8,
            ),
            spectral_flatness_standard_deviation=round(
                float(np.std(flatness_values)),
                8,
            ),
            pitch_mean_hz=(
                round(float(fmean(pitch_values)), 6)
                if pitch_values
                else None
            ),
            pitch_standard_deviation_hz=(
                round(float(np.std(pitch_values)), 6)
                if pitch_values
                else None
            ),
            voiced_segment_ratio=round(
                (
                    len(pitch_values)
                    / max(1, len(segment_features))
                ),
                8,
            ),
            discontinuity_count=discontinuity_count,
            energy_jump_count=energy_jump_count,
            repeated_segment_count=(
                repeated_segment_count
            ),
            suspicious_segment_count=(
                suspicious_segment_count
            ),
            converted_audio_path=str(converted_path),
            segments=tuple(segment_features),
        )

    def _segment_features(
        self,
        waveform: np.ndarray,
        sample_rate: int,
    ) -> list[AudioSegmentFeature]:
        segment_size = max(
            1,
            int(
                round(
                    sample_rate
                    * self._segment_duration_seconds
                )
            ),
        )
        raw_segments: list[dict[str, Any]] = []

        for segment_index, start in enumerate(
            range(0, waveform.size, segment_size)
        ):
            segment = waveform[
                start : start + segment_size
            ]
            if segment.size < sample_rate // 4:
                continue

            (
                centroid,
                bandwidth,
                rolloff,
                flatness,
            ) = self._single_spectrum_features(
                segment,
                sample_rate,
            )
            pitch = self._estimate_pitch(
                segment,
                sample_rate,
            )
            rms = float(
                np.sqrt(
                    np.mean(np.square(segment)) + 1e-12
                )
            )
            peak = float(np.max(np.abs(segment)))
            zero_crossing = float(
                np.mean(
                    np.not_equal(
                        np.signbit(segment[1:]),
                        np.signbit(segment[:-1]),
                    )
                )
            )
            fingerprint = self._audio_fingerprint(
                segment,
                sample_rate,
            )

            raw_segments.append(
                {
                    "segment_index": segment_index,
                    "start_seconds": start / sample_rate,
                    "end_seconds": (
                        start + segment.size
                    )
                    / sample_rate,
                    "rms_energy": rms,
                    "peak_amplitude": peak,
                    "zero_crossing_rate": zero_crossing,
                    "spectral_centroid_hz": centroid,
                    "spectral_bandwidth_hz": bandwidth,
                    "spectral_rolloff_hz": rolloff,
                    "spectral_flatness": flatness,
                    "pitch_hz": pitch,
                    "voiced": pitch is not None,
                    "fingerprint": fingerprint,
                }
            )

        fingerprint_counts: dict[str, int] = {}
        for segment in raw_segments:
            fingerprint = str(segment["fingerprint"])
            fingerprint_counts[fingerprint] = (
                fingerprint_counts.get(fingerprint, 0) + 1
            )

        results: list[AudioSegmentFeature] = []
        for segment in raw_segments:
            repeated = (
                fingerprint_counts[
                    str(segment["fingerprint"])
                ]
                > 1
            )
            suspicious = self._is_suspicious_segment(
                rms=float(segment["rms_energy"]),
                flatness=float(
                    segment["spectral_flatness"]
                ),
                zero_crossing=float(
                    segment["zero_crossing_rate"]
                ),
                repeated=repeated,
            )
            results.append(
                AudioSegmentFeature(
                    segment_index=int(
                        segment["segment_index"]
                    ),
                    start_seconds=round(
                        float(segment["start_seconds"]),
                        6,
                    ),
                    end_seconds=round(
                        float(segment["end_seconds"]),
                        6,
                    ),
                    rms_energy=round(
                        float(segment["rms_energy"]),
                        8,
                    ),
                    peak_amplitude=round(
                        float(segment["peak_amplitude"]),
                        8,
                    ),
                    zero_crossing_rate=round(
                        float(
                            segment["zero_crossing_rate"]
                        ),
                        8,
                    ),
                    spectral_centroid_hz=round(
                        float(
                            segment[
                                "spectral_centroid_hz"
                            ]
                        ),
                        6,
                    ),
                    spectral_bandwidth_hz=round(
                        float(
                            segment[
                                "spectral_bandwidth_hz"
                            ]
                        ),
                        6,
                    ),
                    spectral_rolloff_hz=round(
                        float(
                            segment[
                                "spectral_rolloff_hz"
                            ]
                        ),
                        6,
                    ),
                    spectral_flatness=round(
                        float(
                            segment["spectral_flatness"]
                        ),
                        8,
                    ),
                    pitch_hz=(
                        round(
                            float(segment["pitch_hz"]),
                            6,
                        )
                        if segment["pitch_hz"] is not None
                        else None
                    ),
                    voiced=bool(segment["voiced"]),
                    fingerprint=str(
                        segment["fingerprint"]
                    ),
                    is_repeated=repeated,
                    is_suspicious=suspicious,
                )
            )
        return results

    @staticmethod
    def _frame_waveform(
        waveform: np.ndarray,
        sample_rate: int,
    ) -> np.ndarray:
        frame_size = max(
            256,
            int(round(sample_rate * 0.025)),
        )
        hop_size = max(
            128,
            int(round(sample_rate * 0.010)),
        )
        if waveform.size < frame_size:
            waveform = np.pad(
                waveform,
                (0, frame_size - waveform.size),
            )

        frame_count = (
            1
            + (waveform.size - frame_size) // hop_size
        )
        shape = (frame_count, frame_size)
        strides = (
            waveform.strides[0] * hop_size,
            waveform.strides[0],
        )
        return np.lib.stride_tricks.as_strided(
            waveform,
            shape=shape,
            strides=strides,
            writeable=False,
        ).copy()

    @staticmethod
    def _spectral_rolloff(
        spectrum: np.ndarray,
        frequencies: np.ndarray,
    ) -> np.ndarray:
        cumulative = np.cumsum(spectrum, axis=1)
        thresholds = cumulative[:, -1] * 0.85
        indices = np.argmax(
            cumulative >= thresholds[:, None],
            axis=1,
        )
        return frequencies[indices]

    @staticmethod
    def _single_spectrum_features(
        segment: np.ndarray,
        sample_rate: int,
    ) -> tuple[float, float, float, float]:
        maximum_fft_size = 32768
        if segment.size > maximum_fft_size:
            positions = np.linspace(
                0,
                segment.size - 1,
                num=maximum_fft_size,
            ).astype(np.int64)
            segment = segment[positions]

        windowed = segment * np.hanning(segment.size)
        spectrum = np.abs(np.fft.rfft(windowed))
        frequencies = np.fft.rfftfreq(
            segment.size,
            d=1.0 / sample_rate,
        )
        total = float(np.sum(spectrum)) + 1e-12
        centroid = float(
            np.sum(spectrum * frequencies) / total
        )
        bandwidth = float(
            np.sqrt(
                np.sum(
                    spectrum
                    * np.square(frequencies - centroid)
                )
                / total
            )
        )
        cumulative = np.cumsum(spectrum)
        rolloff_index = int(
            np.searchsorted(
                cumulative,
                cumulative[-1] * 0.85,
            )
        )
        rolloff_index = min(
            rolloff_index,
            frequencies.size - 1,
        )
        power = np.square(spectrum) + 1e-12
        flatness = float(
            np.exp(np.mean(np.log(power)))
            / np.mean(power)
        )
        return (
            centroid,
            bandwidth,
            float(frequencies[rolloff_index]),
            flatness,
        )

    @staticmethod
    def _estimate_pitch(
        segment: np.ndarray,
        sample_rate: int,
    ) -> float | None:
        if (
            segment.size < sample_rate // 10
            or float(np.sqrt(np.mean(np.square(segment))))
            < 0.005
        ):
            return None

        maximum_samples = min(
            segment.size,
            sample_rate,
        )
        centered = segment[:maximum_samples]
        centered = centered - np.mean(centered)
        fft_size = 1 << (
            (2 * maximum_samples - 1).bit_length()
        )
        frequency_domain = np.fft.rfft(
            centered,
            n=fft_size,
        )
        correlation = np.fft.irfft(
            frequency_domain
            * np.conjugate(frequency_domain),
            n=fft_size,
        )[:maximum_samples]
        minimum_lag = max(1, sample_rate // 400)
        maximum_lag = min(
            correlation.size - 1,
            sample_rate // 70,
        )
        if maximum_lag <= minimum_lag:
            return None

        search = correlation[
            minimum_lag : maximum_lag + 1
        ]
        peak_offset = int(np.argmax(search))
        peak_lag = minimum_lag + peak_offset
        normalized_peak = (
            correlation[peak_lag]
            / (correlation[0] + 1e-12)
        )
        if normalized_peak < 0.20:
            return None
        return float(sample_rate / peak_lag)

    @staticmethod
    def _audio_fingerprint(
        segment: np.ndarray,
        sample_rate: int,
    ) -> str:
        target_size = min(segment.size, sample_rate * 2)
        if segment.size != target_size:
            positions = np.linspace(
                0,
                segment.size - 1,
                num=target_size,
            ).astype(np.int64)
            normalized = segment[positions]
        else:
            normalized = segment

        spectrum = np.abs(
            np.fft.rfft(
                normalized * np.hanning(normalized.size)
            )
        )
        bands = np.array_split(spectrum, 32)
        signature = np.asarray(
            [
                np.log1p(float(np.mean(band)))
                for band in bands
            ],
            dtype=np.float32,
        )
        maximum = float(np.max(signature))
        if maximum > 0:
            signature /= maximum
        quantized = np.rint(signature * 255.0).astype(
            np.uint8
        )
        return hashlib.sha256(
            quantized.tobytes()
        ).hexdigest()

    @staticmethod
    def _is_suspicious_segment(
        *,
        rms: float,
        flatness: float,
        zero_crossing: float,
        repeated: bool,
    ) -> bool:
        indicators = (
            repeated,
            flatness >= 0.65,
            zero_crossing >= 0.35,
            rms >= 0.85,
        )
        return sum(bool(value) for value in indicators) >= 2