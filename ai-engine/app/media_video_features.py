from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from statistics import fmean
from typing import Any

import cv2
import numpy as np

from app.media_forensics_runtime import MediaRuntimeError
from app.media_image_features import (
    ImageFeatureExtractor,
    ImageFeatureSet,
)


@dataclass(frozen=True)
class VideoFrameFeature:
    frame_number: int
    timestamp_seconds: float
    extracted_file_path: str
    perceptual_hash: str
    mean_luma: float
    interframe_difference: float | None
    histogram_correlation: float | None
    duplicate_of_previous: bool
    abrupt_transition: bool
    timestamp_anomaly: bool
    is_suspicious: bool
    image_features: ImageFeatureSet

    def to_dict(self) -> dict[str, Any]:
        return {
            "frame_number": self.frame_number,
            "timestamp_seconds": self.timestamp_seconds,
            "extracted_file_path": self.extracted_file_path,
            "perceptual_hash": self.perceptual_hash,
            "mean_luma": self.mean_luma,
            "interframe_difference": (
                self.interframe_difference
            ),
            "histogram_correlation": (
                self.histogram_correlation
            ),
            "duplicate_of_previous": (
                self.duplicate_of_previous
            ),
            "abrupt_transition": self.abrupt_transition,
            "timestamp_anomaly": self.timestamp_anomaly,
            "is_suspicious": self.is_suspicious,
            "image_features": self.image_features.to_dict(),
        }


@dataclass(frozen=True)
class VideoFeatureSet:
    width: int
    height: int
    frames_per_second: float
    declared_frame_count: int
    duration_seconds: float
    codec: str | None
    sampled_frame_count: int
    decode_failure_count: int
    duplicate_transition_count: int
    abrupt_transition_count: int
    timestamp_anomaly_count: int
    suspicious_frame_count: int
    frames_with_faces: int
    face_presence_ratio: float
    mean_interframe_difference: float
    maximum_interframe_difference: float
    mean_histogram_correlation: float
    frames: tuple[VideoFrameFeature, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "width": self.width,
            "height": self.height,
            "frames_per_second": self.frames_per_second,
            "declared_frame_count": (
                self.declared_frame_count
            ),
            "duration_seconds": self.duration_seconds,
            "codec": self.codec,
            "sampled_frame_count": self.sampled_frame_count,
            "decode_failure_count": self.decode_failure_count,
            "duplicate_transition_count": (
                self.duplicate_transition_count
            ),
            "abrupt_transition_count": (
                self.abrupt_transition_count
            ),
            "timestamp_anomaly_count": (
                self.timestamp_anomaly_count
            ),
            "suspicious_frame_count": (
                self.suspicious_frame_count
            ),
            "frames_with_faces": self.frames_with_faces,
            "face_presence_ratio": self.face_presence_ratio,
            "mean_interframe_difference": (
                self.mean_interframe_difference
            ),
            "maximum_interframe_difference": (
                self.maximum_interframe_difference
            ),
            "mean_histogram_correlation": (
                self.mean_histogram_correlation
            ),
            "frames": [
                frame.to_dict()
                for frame in self.frames
            ],
        }


class VideoFeatureExtractor:
    """Extracts bounded, reproducible video forensic features."""

    def __init__(
        self,
        image_feature_extractor: (
            ImageFeatureExtractor | None
        ) = None,
        *,
        maximum_frames: int = 120,
        frame_interval_seconds: float = 1.0,
        maximum_frame_dimension: int = 1280,
    ) -> None:
        if maximum_frames < 1 or maximum_frames > 1000:
            raise ValueError(
                "maximum_frames must be between 1 and 1000"
            )
        if frame_interval_seconds <= 0:
            raise ValueError(
                "frame_interval_seconds must be greater than zero"
            )
        if (
            maximum_frame_dimension < 320
            or maximum_frame_dimension > 4096
        ):
            raise ValueError(
                "maximum_frame_dimension must be between "
                "320 and 4096"
            )

        self._image_feature_extractor = (
            image_feature_extractor
            or ImageFeatureExtractor()
        )
        self._maximum_frames = maximum_frames
        self._frame_interval_seconds = (
            frame_interval_seconds
        )
        self._maximum_frame_dimension = (
            maximum_frame_dimension
        )

    def extract(
        self,
        file_path: Path,
        workspace_path: Path,
    ) -> VideoFeatureSet:
        source_path = file_path.resolve()
        if not source_path.is_file():
            raise MediaRuntimeError(
                f"video file does not exist: {source_path}"
            )

        frame_directory = (
            workspace_path.resolve() / "sampled-frames"
        )
        frame_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        capture = cv2.VideoCapture(str(source_path))
        if not capture.isOpened():
            raise MediaRuntimeError(
                "OpenCV could not open the video file"
            )

        try:
            width = max(
                0,
                int(capture.get(cv2.CAP_PROP_FRAME_WIDTH)),
            )
            height = max(
                0,
                int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT)),
            )
            frames_per_second = float(
                capture.get(cv2.CAP_PROP_FPS)
            )
            if (
                not np.isfinite(frames_per_second)
                or frames_per_second <= 0
            ):
                frames_per_second = 25.0

            declared_frame_count = max(
                0,
                int(capture.get(cv2.CAP_PROP_FRAME_COUNT)),
            )
            duration_seconds = (
                declared_frame_count / frames_per_second
                if declared_frame_count > 0
                else 0.0
            )
            codec = self._decode_fourcc(
                int(capture.get(cv2.CAP_PROP_FOURCC))
            )
            sample_indices = self._sample_indices(
                declared_frame_count,
                frames_per_second,
            )

            (
                frame_features,
                decode_failure_count,
            ) = self._extract_indexed_frames(
                capture=capture,
                sample_indices=sample_indices,
                frames_per_second=frames_per_second,
                frame_directory=frame_directory,
            )

            if not frame_features:
                (
                    frame_features,
                    decode_failure_count,
                ) = self._extract_sequential_frames(
                    capture=capture,
                    frames_per_second=frames_per_second,
                    frame_directory=frame_directory,
                )

            if not frame_features:
                raise MediaRuntimeError(
                    "no decodable video frames were found"
                )

            return self._build_feature_set(
                width=width,
                height=height,
                frames_per_second=frames_per_second,
                declared_frame_count=declared_frame_count,
                duration_seconds=duration_seconds,
                codec=codec,
                frames=frame_features,
                decode_failure_count=(
                    decode_failure_count
                ),
            )
        finally:
            capture.release()

    def _extract_indexed_frames(
        self,
        *,
        capture: cv2.VideoCapture,
        sample_indices: list[int],
        frames_per_second: float,
        frame_directory: Path,
    ) -> tuple[list[VideoFrameFeature], int]:
        frames: list[VideoFrameFeature] = []
        decode_failure_count = 0
        previous_gray: np.ndarray | None = None
        previous_histogram: np.ndarray | None = None
        previous_hash: str | None = None

        for frame_number in sample_indices:
            if not capture.set(
                cv2.CAP_PROP_POS_FRAMES,
                float(frame_number),
            ):
                decode_failure_count += 1
                continue

            decoded, image = capture.read()
            if not decoded or image is None or image.size == 0:
                decode_failure_count += 1
                continue

            observed_timestamp = max(
                0.0,
                float(
                    capture.get(cv2.CAP_PROP_POS_MSEC)
                )
                / 1000.0,
            )
            expected_timestamp = (
                frame_number / frames_per_second
            )

            (
                frame_feature,
                previous_gray,
                previous_histogram,
                previous_hash,
            ) = self._process_frame(
                frame_number=frame_number,
                expected_timestamp=expected_timestamp,
                observed_timestamp=observed_timestamp,
                image=image,
                frame_directory=frame_directory,
                previous_gray=previous_gray,
                previous_histogram=previous_histogram,
                previous_hash=previous_hash,
            )
            frames.append(frame_feature)

        return frames, decode_failure_count

    def _extract_sequential_frames(
        self,
        *,
        capture: cv2.VideoCapture,
        frames_per_second: float,
        frame_directory: Path,
    ) -> tuple[list[VideoFrameFeature], int]:
        capture.set(cv2.CAP_PROP_POS_FRAMES, 0.0)
        frame_step = max(
            1,
            int(
                round(
                    frames_per_second
                    * self._frame_interval_seconds
                )
            ),
        )
        frames: list[VideoFrameFeature] = []
        decode_failure_count = 0
        current_frame = 0
        previous_gray: np.ndarray | None = None
        previous_histogram: np.ndarray | None = None
        previous_hash: str | None = None

        while len(frames) < self._maximum_frames:
            decoded, image = capture.read()
            if not decoded:
                break
            if image is None or image.size == 0:
                decode_failure_count += 1
                current_frame += 1
                continue

            if current_frame % frame_step != 0:
                current_frame += 1
                continue

            expected_timestamp = (
                current_frame / frames_per_second
            )
            observed_timestamp = max(
                0.0,
                float(
                    capture.get(cv2.CAP_PROP_POS_MSEC)
                )
                / 1000.0,
            )

            (
                frame_feature,
                previous_gray,
                previous_histogram,
                previous_hash,
            ) = self._process_frame(
                frame_number=current_frame,
                expected_timestamp=expected_timestamp,
                observed_timestamp=observed_timestamp,
                image=image,
                frame_directory=frame_directory,
                previous_gray=previous_gray,
                previous_histogram=previous_histogram,
                previous_hash=previous_hash,
            )
            frames.append(frame_feature)
            current_frame += 1

        return frames, decode_failure_count

    def _process_frame(
        self,
        *,
        frame_number: int,
        expected_timestamp: float,
        observed_timestamp: float,
        image: np.ndarray,
        frame_directory: Path,
        previous_gray: np.ndarray | None,
        previous_histogram: np.ndarray | None,
        previous_hash: str | None,
    ) -> tuple[
        VideoFrameFeature,
        np.ndarray,
        np.ndarray,
        str,
    ]:
        normalized_image = self._resize_frame(image)
        frame_path = (
            frame_directory
            / f"frame_{frame_number:010d}.png"
        )
        self._write_lossless_frame(
            frame_path,
            normalized_image,
        )

        _, image_features = (
            self._image_feature_extractor.extract(
                frame_path,
            )
        )
        gray = cv2.cvtColor(
            normalized_image,
            cv2.COLOR_BGR2GRAY,
        )
        comparison_gray = cv2.resize(
            gray,
            (320, 180),
            interpolation=cv2.INTER_AREA,
        )
        histogram = cv2.calcHist(
            [gray],
            [0],
            None,
            [64],
            [0, 256],
        )
        cv2.normalize(
            histogram,
            histogram,
            alpha=0.0,
            beta=1.0,
            norm_type=cv2.NORM_MINMAX,
        )
        perceptual_hash = self._average_hash(gray)

        difference: float | None = None
        histogram_correlation: float | None = None
        duplicate = False
        abrupt_transition = False

        if previous_gray is not None:
            difference = float(
                np.mean(
                    cv2.absdiff(
                        comparison_gray,
                        previous_gray,
                    )
                )
            )
        if previous_histogram is not None:
            histogram_correlation = float(
                cv2.compareHist(
                    previous_histogram,
                    histogram,
                    cv2.HISTCMP_CORREL,
                )
            )
        if (
            difference is not None
            and previous_hash is not None
        ):
            duplicate = (
                difference <= 2.5
                or self._hash_distance(
                    perceptual_hash,
                    previous_hash,
                )
                <= 4
            )
        if (
            difference is not None
            and histogram_correlation is not None
        ):
            abrupt_transition = (
                difference >= 35.0
                and histogram_correlation < 0.35
            )

        timestamp_anomaly = (
            abs(observed_timestamp - expected_timestamp)
            > max(
                0.25,
                self._frame_interval_seconds * 0.5,
            )
        )
        is_suspicious = self._is_suspicious_frame(
            image_features
        )

        frame_feature = VideoFrameFeature(
            frame_number=frame_number,
            timestamp_seconds=round(
                (
                    observed_timestamp
                    if observed_timestamp > 0
                    else expected_timestamp
                ),
                6,
            ),
            extracted_file_path=str(frame_path),
            perceptual_hash=perceptual_hash,
            mean_luma=round(float(np.mean(gray)), 4),
            interframe_difference=(
                round(difference, 4)
                if difference is not None
                else None
            ),
            histogram_correlation=(
                round(histogram_correlation, 6)
                if histogram_correlation is not None
                else None
            ),
            duplicate_of_previous=duplicate,
            abrupt_transition=abrupt_transition,
            timestamp_anomaly=timestamp_anomaly,
            is_suspicious=is_suspicious,
            image_features=image_features,
        )

        return (
            frame_feature,
            comparison_gray,
            histogram,
            perceptual_hash,
        )

    def _sample_indices(
        self,
        frame_count: int,
        frames_per_second: float,
    ) -> list[int]:
        if frame_count <= 0:
            return []

        frame_step = max(
            1,
            int(
                round(
                    frames_per_second
                    * self._frame_interval_seconds
                )
            ),
        )
        indices = list(
            range(
                0,
                frame_count,
                frame_step,
            )
        )
        if not indices:
            indices = [0]

        last_frame = frame_count - 1
        if indices[-1] != last_frame:
            indices.append(last_frame)

        if len(indices) > self._maximum_frames:
            indices = sorted(
                {
                    int(value)
                    for value in np.linspace(
                        0,
                        last_frame,
                        num=self._maximum_frames,
                    )
                }
            )
        return indices

    def _resize_frame(
        self,
        image: np.ndarray,
    ) -> np.ndarray:
        height, width = image.shape[:2]
        maximum_dimension = max(height, width)
        if maximum_dimension <= self._maximum_frame_dimension:
            return image

        scale = (
            self._maximum_frame_dimension
            / maximum_dimension
        )
        target_width = max(1, int(round(width * scale)))
        target_height = max(1, int(round(height * scale)))
        return cv2.resize(
            image,
            (target_width, target_height),
            interpolation=cv2.INTER_AREA,
        )

    @staticmethod
    def _write_lossless_frame(
        destination: Path,
        image: np.ndarray,
    ) -> None:
        encoded, buffer = cv2.imencode(
            ".png",
            image,
            [cv2.IMWRITE_PNG_COMPRESSION, 3],
        )
        if not encoded:
            raise MediaRuntimeError(
                "unable to encode sampled video frame"
            )
        try:
            buffer.tofile(str(destination))
        except OSError as error:
            raise MediaRuntimeError(
                "unable to persist sampled video frame"
            ) from error

    @staticmethod
    def _average_hash(gray: np.ndarray) -> str:
        resized = cv2.resize(
            gray,
            (8, 8),
            interpolation=cv2.INTER_AREA,
        )
        bits = resized >= float(np.mean(resized))
        bit_string = "".join(
            "1" if value else "0"
            for value in bits.flatten()
        )
        return f"{int(bit_string, 2):016x}"

    @staticmethod
    def _hash_distance(
        first_hash: str,
        second_hash: str,
    ) -> int:
        return (
            int(first_hash, 16)
            ^ int(second_hash, 16)
        ).bit_count()

    @staticmethod
    def _is_suspicious_frame(
        features: ImageFeatureSet,
    ) -> bool:
        indicators = (
            len(features.suspicious_regions) > 0,
            features.copy_move_match_count >= 10,
            features.ela_percentile_99 >= 35.0,
            features.noise_patch_variation >= 12.0,
            bool(features.metadata_editing_trace),
        )
        return sum(bool(value) for value in indicators) >= 2

    @staticmethod
    def _decode_fourcc(value: int) -> str | None:
        if value <= 0:
            return None
        codec = "".join(
            chr((value >> (8 * index)) & 0xFF)
            for index in range(4)
        ).strip("\x00 ")
        return codec or None

    @staticmethod
    def _build_feature_set(
        *,
        width: int,
        height: int,
        frames_per_second: float,
        declared_frame_count: int,
        duration_seconds: float,
        codec: str | None,
        frames: list[VideoFrameFeature],
        decode_failure_count: int,
    ) -> VideoFeatureSet:
        differences = [
            frame.interframe_difference
            for frame in frames
            if frame.interframe_difference is not None
        ]
        correlations = [
            frame.histogram_correlation
            for frame in frames
            if frame.histogram_correlation is not None
        ]
        frames_with_faces = sum(
            1
            for frame in frames
            if frame.image_features.faces
        )
        sampled_count = len(frames)

        return VideoFeatureSet(
            width=width,
            height=height,
            frames_per_second=round(
                frames_per_second,
                6,
            ),
            declared_frame_count=declared_frame_count,
            duration_seconds=round(
                duration_seconds,
                6,
            ),
            codec=codec,
            sampled_frame_count=sampled_count,
            decode_failure_count=decode_failure_count,
            duplicate_transition_count=sum(
                1
                for frame in frames
                if frame.duplicate_of_previous
            ),
            abrupt_transition_count=sum(
                1
                for frame in frames
                if frame.abrupt_transition
            ),
            timestamp_anomaly_count=sum(
                1
                for frame in frames
                if frame.timestamp_anomaly
            ),
            suspicious_frame_count=sum(
                1
                for frame in frames
                if frame.is_suspicious
            ),
            frames_with_faces=frames_with_faces,
            face_presence_ratio=round(
                (
                    frames_with_faces / sampled_count
                    if sampled_count
                    else 0.0
                ),
                6,
            ),
            mean_interframe_difference=round(
                fmean(differences)
                if differences
                else 0.0,
                6,
            ),
            maximum_interframe_difference=round(
                max(differences)
                if differences
                else 0.0,
                6,
            ),
            mean_histogram_correlation=round(
                fmean(correlations)
                if correlations
                else 0.0,
                6,
            ),
            frames=tuple(frames),
        )