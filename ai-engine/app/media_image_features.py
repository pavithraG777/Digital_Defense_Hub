from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import cv2
import numpy as np
from PIL import ExifTags, Image

from app.media_forensics_runtime import (
    MediaRuntimeError,
    get_media_runtime,
)

@dataclass(frozen=True)
class FaceFeature:
    x: int
    y: int
    width: int
    height: int

    blur_variance: float
    edge_density: float
    symmetry_error: float
    noise_standard_deviation: float
    color_channel_difference: float
    high_frequency_ratio: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SuspiciousImageRegion:
    x: int
    y: int
    width: int
    height: int
    score: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ImageFeatureSet:
    width: int
    height: int
    channels: int

    blur_variance: float
    edge_density: float
    grayscale_entropy: float

    minimum_channel_correlation: float
    color_channel_difference: float

    noise_mean: float
    noise_standard_deviation: float
    noise_patch_variation: float

    jpeg_blockiness_ratio: float

    ela_mean_difference: float
    ela_percentile_99: float

    high_frequency_ratio: float

    copy_move_match_count: int

    metadata_editing_trace: bool
    metadata_software: str | None
    metadata: dict[str, Any]

    faces: list[FaceFeature]
    suspicious_regions: list[
        SuspiciousImageRegion
    ]

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "faces": [
                face.to_dict()
                for face in self.faces
            ],
            "suspicious_regions": [
                region.to_dict()
                for region in self.suspicious_regions
            ],
        }


class ImageFeatureExtractor:
    def __init__(self) -> None:
        cascade_path = (
            get_media_runtime().model_root
            / "opencv"
            / "haarcascades"
            / "haarcascade_frontalface_default.xml"
        )

        if not cascade_path.is_file():
            raise MediaRuntimeError(
                "OpenCV face detector model is missing: "
                f"{cascade_path}"
            )

        self._face_detector = cv2.CascadeClassifier(
            str(cascade_path),
        )

        if self._face_detector.empty():
            raise MediaRuntimeError(
                "OpenCV face detector could not be initialized"
            )

    def load_image(
        self,
        file_path: Path,
    ) -> np.ndarray:
        try:
            encoded_data = np.fromfile(
                str(file_path),
                dtype=np.uint8,
            )

            image = cv2.imdecode(
                encoded_data,
                cv2.IMREAD_COLOR,
            )
        except (
            OSError,
            ValueError,
            cv2.error,
        ) as error:
            raise MediaRuntimeError(
                "unable to load image"
            ) from error

        if image is None or image.size == 0:
            raise MediaRuntimeError(
                "unable to decode image"
            )

        return image

    def extract(
        self,
        file_path: Path,
    ) -> tuple[
        np.ndarray,
        ImageFeatureSet,
    ]:
        image = self.load_image(
            file_path,
        )

        grayscale = cv2.cvtColor(
            image,
            cv2.COLOR_BGR2GRAY,
        )

        height, width = grayscale.shape
        channels = (
            image.shape[2]
            if image.ndim == 3
            else 1
        )

        edges = cv2.Canny(
            grayscale,
            100,
            200,
        )

        blur_variance = float(
            cv2.Laplacian(
                grayscale,
                cv2.CV_64F,
            ).var()
        )
        edge_density = float(
            np.count_nonzero(edges) /
            max(
                1,
                edges.size,
            )
        )

        grayscale_entropy = self._entropy(
            grayscale,
        )

        (
            minimum_channel_correlation,
            color_channel_difference,
        ) = self._color_features(
            image,
        )

        residual = cv2.absdiff(
            grayscale,
            cv2.GaussianBlur(
                grayscale,
                (
                    5,
                    5,
                ),
                0,
            ),
        )

        noise_mean = float(
            np.mean(residual)
        )
        noise_standard_deviation = float(
            np.std(residual)
        )

        (
            noise_patch_variation,
            suspicious_regions,
        ) = self._noise_patch_features(
            residual,
        )

        jpeg_blockiness_ratio = (
            self._jpeg_blockiness(
                grayscale,
            )
        )

        (
            ela_mean_difference,
            ela_percentile_99,
        ) = self._error_level_features(
            image,
        )

        high_frequency_ratio = (
            self._high_frequency_ratio(
                grayscale,
            )
        )

        copy_move_match_count = (
            self._copy_move_matches(
                grayscale,
            )
        )

        (
            metadata_editing_trace,
            metadata_software,
            metadata,
        ) = self._metadata_features(
            file_path,
        )

        detected_faces = (
            self._face_detector.detectMultiScale(
                grayscale,
                scaleFactor=1.1,
                minNeighbors=5,
                minSize=(
                    40,
                    40,
                ),
            )
        )

        faces = [
            self._extract_face_feature(
                image,
                grayscale,
                int(x),
                int(y),
                int(face_width),
                int(face_height),
            )
            for (
                x,
                y,
                face_width,
                face_height,
            ) in detected_faces
        ]

        feature_set = ImageFeatureSet(
            width=width,
            height=height,
            channels=channels,
            blur_variance=round(
                blur_variance,
                6,
            ),
            edge_density=round(
                edge_density,
                6,
            ),
            grayscale_entropy=round(
                grayscale_entropy,
                6,
            ),
            minimum_channel_correlation=round(
                minimum_channel_correlation,
                6,
            ),
            color_channel_difference=round(
                color_channel_difference,
                6,
            ),
            noise_mean=round(
                noise_mean,
                6,
            ),
            noise_standard_deviation=round(
                noise_standard_deviation,
                6,
            ),
            noise_patch_variation=round(
                noise_patch_variation,
                6,
            ),
            jpeg_blockiness_ratio=round(
                jpeg_blockiness_ratio,
                6,
            ),
            ela_mean_difference=round(
                ela_mean_difference,
                6,
            ),
            ela_percentile_99=round(
                ela_percentile_99,
                6,
            ),
            high_frequency_ratio=round(
                high_frequency_ratio,
                6,
            ),
            copy_move_match_count=(
                copy_move_match_count
            ),
            metadata_editing_trace=(
                metadata_editing_trace
            ),
            metadata_software=(
                metadata_software
            ),
            metadata=metadata,
            faces=faces,
            suspicious_regions=(
                suspicious_regions
            ),
        )

        return image, feature_set

    def _extract_face_feature(
        self,
        image: np.ndarray,
        grayscale: np.ndarray,
        x: int,
        y: int,
        width: int,
        height: int,
    ) -> FaceFeature:
        face_gray = grayscale[
            y:y + height,
            x:x + width,
        ]
        face_color = image[
            y:y + height,
            x:x + width,
        ]

        face_edges = cv2.Canny(
            face_gray,
            100,
            200,
        )

        face_blur_variance = float(
            cv2.Laplacian(
                face_gray,
                cv2.CV_64F,
            ).var()
        )
        face_edge_density = float(
            np.count_nonzero(face_edges) /
            max(
                1,
                face_edges.size,
            )
        )

        symmetry_error = (
            self._symmetry_error(
                face_gray,
            )
        )

        face_residual = cv2.absdiff(
            face_gray,
            cv2.GaussianBlur(
                face_gray,
                (
                    5,
                    5,
                ),
                0,
            ),
        )

        (
            _,
            face_color_difference,
        ) = self._color_features(
            face_color,
        )

        return FaceFeature(
            x=x,
            y=y,
            width=width,
            height=height,
            blur_variance=round(
                face_blur_variance,
                6,
            ),
            edge_density=round(
                face_edge_density,
                6,
            ),
            symmetry_error=round(
                symmetry_error,
                6,
            ),
            noise_standard_deviation=round(
                float(
                    np.std(
                        face_residual
                    )
                ),
                6,
            ),
            color_channel_difference=round(
                face_color_difference,
                6,
            ),
            high_frequency_ratio=round(
                self._high_frequency_ratio(
                    face_gray,
                ),
                6,
            ),
        )

    @staticmethod
    def _entropy(
        grayscale: np.ndarray,
    ) -> float:
        histogram = cv2.calcHist(
            [grayscale],
            [0],
            None,
            [256],
            [
                0,
                256,
            ],
        ).flatten()

        histogram_sum = float(
            np.sum(histogram)
        )

        if histogram_sum <= 0:
            return 0.0

        probabilities = (
            histogram /
            histogram_sum
        )
        probabilities = probabilities[
            probabilities > 0
        ]

        return float(
            -np.sum(
                probabilities *
                np.log2(
                    probabilities
                )
            )
        )

    @staticmethod
    def _color_features(
        image: np.ndarray,
    ) -> tuple[
        float,
        float,
    ]:
        if (
            image.ndim != 3
            or image.shape[2] < 3
        ):
            return 1.0, 0.0

        channels = cv2.split(
            image,
        )

        flattened_channels = [
            channel.astype(
                np.float64,
            ).flatten()
            for channel in channels[:3]
        ]

        correlations: list[float] = []

        for first_index in range(3):
            for second_index in range(
                first_index + 1,
                3,
            ):
                first_channel = (
                    flattened_channels[
                        first_index
                    ]
                )
                second_channel = (
                    flattened_channels[
                        second_index
                    ]
                )

                if (
                    np.std(first_channel) == 0
                    or np.std(
                        second_channel
                    ) == 0
                ):
                    correlation = 1.0
                else:
                    correlation = float(
                        np.corrcoef(
                            first_channel,
                            second_channel,
                        )[0, 1]
                    )

                if not math.isfinite(
                    correlation
                ):
                    correlation = 1.0

                correlations.append(
                    correlation,
                )

        channel_means = [
            float(
                np.mean(channel)
            )
            for channel in channels[:3]
        ]

        color_difference = float(
            max(channel_means) -
            min(channel_means)
        )

        return (
            min(correlations),
            color_difference,
        )

    @staticmethod
    def _symmetry_error(
        grayscale: np.ndarray,
    ) -> float:
        width = grayscale.shape[1]
        half_width = width // 2

        if half_width == 0:
            return 0.0

        left_side = grayscale[
            :,
            :half_width,
        ]
        right_side = grayscale[
            :,
            width - half_width:,
        ]
        right_side = cv2.flip(
            right_side,
            1,
        )

        difference = cv2.absdiff(
            left_side,
            right_side,
        )

        return float(
            np.mean(difference) /
            255.0
        )

    @staticmethod
    def _jpeg_blockiness(
        grayscale: np.ndarray,
    ) -> float:
        height, width = grayscale.shape

        horizontal_boundaries = np.arange(
            8,
            height,
            8,
        )
        vertical_boundaries = np.arange(
            8,
            width,
            8,
        )

        boundary_values: list[float] = []

        if horizontal_boundaries.size > 0:
            boundary_values.append(
                float(
                    np.mean(
                        np.abs(
                            grayscale[
                                horizontal_boundaries,
                                :,
                            ].astype(
                                np.float32
                            ) -
                            grayscale[
                                horizontal_boundaries - 1,
                                :,
                            ].astype(
                                np.float32
                            )
                        )
                    )
                )
            )

        if vertical_boundaries.size > 0:
            boundary_values.append(
                float(
                    np.mean(
                        np.abs(
                            grayscale[
                                :,
                                vertical_boundaries,
                            ].astype(
                                np.float32
                            ) -
                            grayscale[
                                :,
                                vertical_boundaries - 1,
                            ].astype(
                                np.float32
                            )
                        )
                    )
                )
            )

        if not boundary_values:
            return 1.0

        horizontal_difference = float(
            np.mean(
                np.abs(
                    np.diff(
                        grayscale.astype(
                            np.float32
                        ),
                        axis=0,
                    )
                )
            )
        )
        vertical_difference = float(
            np.mean(
                np.abs(
                    np.diff(
                        grayscale.astype(
                            np.float32
                        ),
                        axis=1,
                    )
                )
            )
        )

        general_difference = max(
            0.000001,
            (
                horizontal_difference +
                vertical_difference
            ) / 2,
        )

        return float(
            np.mean(
                boundary_values
            ) /
            general_difference
        )

    @staticmethod
    def _error_level_features(
        image: np.ndarray,
    ) -> tuple[
        float,
        float,
    ]:
        encode_success, encoded_image = (
            cv2.imencode(
                ".jpg",
                image,
                [
                    cv2.IMWRITE_JPEG_QUALITY,
                    90,
                ],
            )
        )

        if not encode_success:
            return 0.0, 0.0

        recompressed_image = cv2.imdecode(
            encoded_image,
            cv2.IMREAD_COLOR,
        )

        if recompressed_image is None:
            return 0.0, 0.0

        difference = cv2.absdiff(
            image,
            recompressed_image,
        ).astype(
            np.float32
        )

        return (
            float(
                np.mean(difference)
            ),
            float(
                np.percentile(
                    difference,
                    99,
                )
            ),
        )

    @staticmethod
    def _high_frequency_ratio(
        grayscale: np.ndarray,
    ) -> float:
        frequency_data = np.fft.fftshift(
            np.fft.fft2(
                grayscale.astype(
                    np.float32
                )
            )
        )
        magnitude = np.abs(
            frequency_data,
        )

        height, width = magnitude.shape
        center_y = height // 2
        center_x = width // 2

        low_frequency_height = max(
            1,
            height // 8,
        )
        low_frequency_width = max(
            1,
            width // 8,
        )

        low_frequency_mask = np.zeros(
            magnitude.shape,
            dtype=bool,
        )
        low_frequency_mask[
            center_y - low_frequency_height:
            center_y + low_frequency_height + 1,
            center_x - low_frequency_width:
            center_x + low_frequency_width + 1,
        ] = True

        total_energy = float(
            np.sum(magnitude)
        )

        if total_energy <= 0:
            return 0.0

        high_frequency_energy = float(
            np.sum(
                magnitude[
                    ~low_frequency_mask
                ]
            )
        )

        return (
            high_frequency_energy /
            total_energy
        )

    @staticmethod
    def _noise_patch_features(
        residual: np.ndarray,
    ) -> tuple[
        float,
        list[SuspiciousImageRegion],
    ]:
        height, width = residual.shape

        row_edges = np.linspace(
            0,
            height,
            5,
            dtype=int,
        )
        column_edges = np.linspace(
            0,
            width,
            5,
            dtype=int,
        )

        patches: list[
            tuple[
                int,
                int,
                int,
                int,
                float,
            ]
        ] = []

        for row_index in range(4):
            for column_index in range(4):
                y1 = int(
                    row_edges[
                        row_index
                    ]
                )
                y2 = int(
                    row_edges[
                        row_index + 1
                    ]
                )
                x1 = int(
                    column_edges[
                        column_index
                    ]
                )
                x2 = int(
                    column_edges[
                        column_index + 1
                    ]
                )

                patch = residual[
                    y1:y2,
                    x1:x2,
                ]

                if patch.size == 0:
                    continue

                patches.append(
                    (
                        x1,
                        y1,
                        x2 - x1,
                        y2 - y1,
                        float(
                            np.std(patch)
                        ),
                    )
                )

        if not patches:
            return 0.0, []

        patch_values = np.asarray(
            [
                patch[4]
                for patch in patches
            ],
            dtype=np.float64,
        )

        patch_mean = float(
            np.mean(patch_values)
        )
        patch_standard_deviation = float(
            np.std(patch_values)
        )

        variation = (
            patch_standard_deviation /
            max(
                patch_mean,
                0.000001,
            )
        )

        suspicious_regions: list[
            SuspiciousImageRegion
        ] = []

        threshold = (
            patch_mean +
            patch_standard_deviation
        )

        for (
            x,
            y,
            patch_width,
            patch_height,
            patch_value,
        ) in patches:
            if (
                patch_standard_deviation > 0
                and patch_value > threshold
            ):
                score = min(
                    100.0,
                    (
                        (
                            patch_value -
                            patch_mean
                        ) /
                        patch_standard_deviation
                    ) * 35,
                )

                suspicious_regions.append(
                    SuspiciousImageRegion(
                        x=x,
                        y=y,
                        width=patch_width,
                        height=patch_height,
                        score=round(
                            score,
                            4,
                        ),
                        reason=(
                            "Local noise pattern "
                            "differs from surrounding "
                            "regions"
                        ),
                    )
                )

        return (
            variation,
            suspicious_regions,
        )

    @staticmethod
    def _copy_move_matches(
        grayscale: np.ndarray,
    ) -> int:
        detector = cv2.ORB_create(
            nfeatures=1000,
        )

        keypoints, descriptors = (
            detector.detectAndCompute(
                grayscale,
                None,
            )
        )

        if (
            descriptors is None
            or len(keypoints) < 4
        ):
            return 0

        matcher = cv2.BFMatcher(
            cv2.NORM_HAMMING,
            crossCheck=False,
        )

        try:
            matches = matcher.knnMatch(
                descriptors,
                descriptors,
                k=3,
            )
        except cv2.error:
            return 0

        suspicious_matches = 0

        for match_group in matches:
            selected_match = next(
                (
                    match
                    for match in match_group
                    if (
                        match.queryIdx !=
                        match.trainIdx
                    )
                ),
                None,
            )

            if selected_match is None:
                continue

            if selected_match.distance > 32:
                continue

            query_point = np.asarray(
                keypoints[
                    selected_match.queryIdx
                ].pt,
                dtype=np.float32,
            )
            train_point = np.asarray(
                keypoints[
                    selected_match.trainIdx
                ].pt,
                dtype=np.float32,
            )

            spatial_distance = float(
                np.linalg.norm(
                    query_point -
                    train_point
                )
            )

            if spatial_distance >= 30:
                suspicious_matches += 1

        return suspicious_matches

    @staticmethod
    def _metadata_features(
        file_path: Path,
    ) -> tuple[
        bool,
        str | None,
        dict[str, Any],
    ]:
        metadata: dict[str, Any] = {}
        software_value: str | None = None

        try:
            with Image.open(
                file_path,
            ) as image:
                exif_data = image.getexif()

                for tag_id, raw_value in (
                    exif_data.items()
                ):
                    tag_name = ExifTags.TAGS.get(
                        tag_id,
                        str(tag_id),
                    )

                    if tag_name not in {
                        "Software",
                        "Make",
                        "Model",
                        "DateTime",
                        "DateTimeOriginal",
                        "DateTimeDigitized",
                    }:
                        continue

                    value = str(
                        raw_value,
                    )[:500]

                    metadata[
                        tag_name
                    ] = value

                    if tag_name == "Software":
                        software_value = value

        except (
            OSError,
            ValueError,
        ):
            metadata = {}

        editing_keywords = {
            "photoshop",
            "gimp",
            "lightroom",
            "snapseed",
            "canva",
            "affinity",
            "pixlr",
        }

        normalized_software = (
            software_value.lower()
            if software_value
            else ""
        )

        editing_trace = any(
            keyword in normalized_software
            for keyword in editing_keywords
        )

        return (
            editing_trace,
            software_value,
            metadata,
        )