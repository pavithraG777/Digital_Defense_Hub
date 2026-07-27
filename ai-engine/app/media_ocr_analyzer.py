from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from statistics import fmean
from typing import Any

import cv2
import fitz
import numpy as np
import pytesseract
from pytesseract import Output

from app.config import get_settings
from app.media_forensics_runtime import MediaRuntimeError
from app.media_forensics_schemas import OCRAssessment


@dataclass(frozen=True)
class OCRUnitResult:
    unit_type: str
    unit_number: int
    timestamp_seconds: float | None
    extraction_method: str
    text: str
    confidence_score: float | None
    word_count: int
    bounding_boxes: tuple[dict[str, Any], ...]
    preprocessing_variant: str
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "unit_type": self.unit_type,
            "unit_number": self.unit_number,
            "timestamp_seconds": self.timestamp_seconds,
            "extraction_method": self.extraction_method,
            "text": self.text,
            "confidence_score": self.confidence_score,
            "word_count": self.word_count,
            "bounding_box_count": len(
                self.bounding_boxes
            ),
            "preprocessing_variant": (
                self.preprocessing_variant
            ),
            "error_message": self.error_message,
        }


class OCRAnalyzer:
    """Runs bounded, offline OCR for images, PDFs, and video."""

    _SUPPORTED_SOURCE_TYPES = {
        "IMAGE",
        "VIDEO",
        "DOCUMENT",
    }

    def __init__(
        self,
        *,
        tesseract_executable: Path | None = None,
        languages: str | None = None,
        maximum_document_pages: int = 100,
        maximum_video_frames: int = 60,
        video_frame_interval_seconds: float = 2.0,
        item_timeout_seconds: float = 30.0,
        maximum_image_pixels: int = 50_000_000,
    ) -> None:
        if (
            maximum_document_pages < 1
            or maximum_document_pages > 1000
        ):
            raise ValueError(
                "maximum_document_pages must be between "
                "1 and 1000"
            )
        if (
            maximum_video_frames < 1
            or maximum_video_frames > 1000
        ):
            raise ValueError(
                "maximum_video_frames must be between 1 and 1000"
            )
        if video_frame_interval_seconds <= 0:
            raise ValueError(
                "video_frame_interval_seconds must be positive"
            )
        if item_timeout_seconds <= 0:
            raise ValueError(
                "item_timeout_seconds must be positive"
            )
        if maximum_image_pixels < 1_000_000:
            raise ValueError(
                "maximum_image_pixels must be at least 1000000"
            )

        settings = get_settings()
        configured_executable = Path(
            str(settings.tesseract_executable)
        )
        configured_languages = str(
            getattr(
                settings,
                "ocr_languages",
                getattr(
                    settings,
                    "media_ocr_languages",
                    "eng",
                ),
            )
        )

        self._tesseract_executable = (
            tesseract_executable
            or configured_executable
        ).resolve()
        if not self._tesseract_executable.is_file():
            raise MediaRuntimeError(
                "Tesseract executable is unavailable: "
                f"{self._tesseract_executable}"
            )

        pytesseract.pytesseract.tesseract_cmd = str(
            self._tesseract_executable
        )
        self._maximum_document_pages = (
            maximum_document_pages
        )
        self._maximum_video_frames = (
            maximum_video_frames
        )
        self._video_frame_interval_seconds = (
            video_frame_interval_seconds
        )
        self._item_timeout_seconds = item_timeout_seconds
        self._maximum_image_pixels = maximum_image_pixels
        self._languages, self._missing_languages = (
            self._resolve_languages(
                languages or configured_languages
            )
        )
        self._engine_version = self._read_engine_version()

    def analyze(
        self,
        file_path: Path,
        source_media_type: str,
        workspace_path: Path,
        *,
        output_file_path: Path | None = None,
    ) -> tuple[OCRAssessment, str, list[str]]:
        source_path = file_path.resolve()
        if not source_path.is_file():
            raise MediaRuntimeError(
                f"OCR source file does not exist: {source_path}"
            )

        normalized_type = source_media_type.strip().upper()
        if normalized_type not in self._SUPPORTED_SOURCE_TYPES:
            raise MediaRuntimeError(
                "OCR source_media_type must be IMAGE, VIDEO, "
                "or DOCUMENT"
            )

        workspace = workspace_path.resolve()
        workspace.mkdir(parents=True, exist_ok=True)
        warnings = [
            (
                "Requested Tesseract languages are unavailable: "
                + ", ".join(self._missing_languages)
            )
        ] if self._missing_languages else []

        total_pages: int | None = None
        total_frames: int | None = None
        truncated = False

        if normalized_type == "IMAGE":
            image = self._load_image(source_path)
            units = [
                self._ocr_image(
                    image=image,
                    unit_type="IMAGE",
                    unit_number=1,
                    timestamp_seconds=None,
                )
            ]
        elif normalized_type == "DOCUMENT":
            (
                units,
                total_pages,
                truncated,
                document_warnings,
            ) = self._analyze_document(source_path)
            warnings.extend(document_warnings)
        else:
            (
                units,
                total_frames,
                truncated,
                video_warnings,
            ) = self._analyze_video(source_path)
            warnings.extend(video_warnings)

        successful_units = [
            unit
            for unit in units
            if unit.error_message is None
        ]
        text_units = [
            unit
            for unit in successful_units
            if unit.text.strip()
        ]
        failed_units = [
            unit
            for unit in units
            if unit.error_message is not None
        ]

        extracted_text = self._combine_text(
            text_units,
            normalized_type,
        )
        output_path = (
            output_file_path.resolve()
            if output_file_path is not None
            else workspace / "ocr-extracted-text.txt"
        )
        saved_output = self._save_text(
            output_path,
            extracted_text,
        )

        confidence_values = [
            unit.confidence_score
            for unit in text_units
            if unit.confidence_score is not None
        ]
        confidence = (
            float(fmean(confidence_values))
            if confidence_values
            else None
        )
        word_count = len(
            re.findall(r"\S+", extracted_text)
        )
        character_count = len(extracted_text)
        extraction_result = self._extraction_result(
            has_text=bool(extracted_text.strip()),
            successful_count=len(successful_units),
            failure_count=len(failed_units),
            truncated=truncated,
            confidence=confidence,
        )
        requires_manual_correction = (
            extraction_result in {"PARTIAL", "INCONCLUSIVE"}
            or (
                confidence is not None
                and confidence < 75.0
                and bool(extracted_text.strip())
            )
        )

        page_results = [
            unit.to_dict()
            for unit in units
        ]
        bounding_box_data = [
            {
                **box,
                "unit_type": unit.unit_type,
                "unit_number": unit.unit_number,
                "timestamp_seconds": (
                    unit.timestamp_seconds
                ),
            }
            for unit in units
            for box in unit.bounding_boxes
        ]
        preprocessing_variants = sorted(
            {
                unit.preprocessing_variant
                for unit in successful_units
            }
        )
        extraction_methods = sorted(
            {
                unit.extraction_method
                for unit in successful_units
            }
        )

        assessment = OCRAssessment(
            source_media_type=normalized_type,
            extraction_result=extraction_result,
            ocr_engine="TESSERACT",
            engine_version=self._engine_version,
            detected_language=self._languages,
            total_pages=total_pages,
            total_frames=total_frames,
            extracted_text=(
                extracted_text
                if extracted_text
                else None
            ),
            confidence_score=(
                round(confidence, 4)
                if confidence is not None
                else None
            ),
            word_count=word_count,
            character_count=character_count,
            page_results=page_results,
            bounding_box_data=bounding_box_data,
            preprocessing_data={
                "variants_used": preprocessing_variants,
                "maximum_image_pixels": (
                    self._maximum_image_pixels
                ),
                "video_frame_interval_seconds": (
                    self._video_frame_interval_seconds
                ),
                "truncated_by_safety_limit": truncated,
            },
            metadata={
                "source_file_name": source_path.name,
                "source_media_type": normalized_type,
                "configured_languages": self._languages,
                "language_value_source": (
                    "CONFIGURED_TESSERACT_LANGUAGE"
                ),
                "extraction_methods": extraction_methods,
                "processed_unit_count": len(units),
                "successful_unit_count": (
                    len(successful_units)
                ),
                "failed_unit_count": len(failed_units),
            },
            requires_manual_correction=(
                requires_manual_correction
            ),
            output_file_path=saved_output,
        )

        return assessment, "TESSERACT", self._unique(warnings)

    def _analyze_document(
        self,
        file_path: Path,
    ) -> tuple[
        list[OCRUnitResult],
        int,
        bool,
        list[str],
    ]:
        if file_path.suffix.lower() != ".pdf":
            raise MediaRuntimeError(
                "DOCUMENT OCR currently supports PDF files"
            )

        try:
            document = fitz.open(str(file_path))
        except (RuntimeError, ValueError, OSError) as error:
            raise MediaRuntimeError(
                "unable to open PDF document"
            ) from error

        warnings: list[str] = []
        results: list[OCRUnitResult] = []
        try:
            total_pages = int(document.page_count)
            pages_to_process = min(
                total_pages,
                self._maximum_document_pages,
            )
            truncated = total_pages > pages_to_process
            if truncated:
                warnings.append(
                    "PDF OCR was limited to the first "
                    f"{pages_to_process} pages."
                )

            for page_index in range(pages_to_process):
                try:
                    page = document.load_page(page_index)
                    native_result = self._native_pdf_text(
                        page,
                        page_index + 1,
                    )
                    if native_result is not None:
                        results.append(native_result)
                        continue

                    image = self._render_pdf_page(page)
                    results.append(
                        self._ocr_image(
                            image=image,
                            unit_type="PAGE",
                            unit_number=page_index + 1,
                            timestamp_seconds=None,
                        )
                    )
                except Exception as error:
                    results.append(
                        OCRUnitResult(
                            unit_type="PAGE",
                            unit_number=page_index + 1,
                            timestamp_seconds=None,
                            extraction_method="ERROR",
                            text="",
                            confidence_score=None,
                            word_count=0,
                            bounding_boxes=(),
                            preprocessing_variant="NONE",
                            error_message=str(error),
                        )
                    )
            return (
                results,
                total_pages,
                truncated,
                warnings,
            )
        finally:
            document.close()

    def _analyze_video(
        self,
        file_path: Path,
    ) -> tuple[
        list[OCRUnitResult],
        int,
        bool,
        list[str],
    ]:
        capture = cv2.VideoCapture(str(file_path))
        if not capture.isOpened():
            raise MediaRuntimeError(
                "OpenCV could not open video for OCR"
            )

        warnings: list[str] = []
        results: list[OCRUnitResult] = []
        try:
            frames_per_second = float(
                capture.get(cv2.CAP_PROP_FPS)
            )
            if (
                not np.isfinite(frames_per_second)
                or frames_per_second <= 0
            ):
                frames_per_second = 25.0
            declared_frames = max(
                0,
                int(capture.get(cv2.CAP_PROP_FRAME_COUNT)),
            )
            frame_indices = self._video_frame_indices(
                declared_frames,
                frames_per_second,
            )
            truncated = (
                len(frame_indices)
                >= self._maximum_video_frames
                and declared_frames
                > self._maximum_video_frames
            )
            if truncated:
                warnings.append(
                    "Video OCR frame sampling was limited to "
                    f"{self._maximum_video_frames} frames."
                )

            seen_text: set[str] = set()
            for frame_index in frame_indices:
                capture.set(
                    cv2.CAP_PROP_POS_FRAMES,
                    float(frame_index),
                )
                decoded, image = capture.read()
                timestamp = (
                    frame_index / frames_per_second
                )
                if (
                    not decoded
                    or image is None
                    or image.size == 0
                ):
                    results.append(
                        OCRUnitResult(
                            unit_type="FRAME",
                            unit_number=frame_index,
                            timestamp_seconds=round(
                                timestamp,
                                6,
                            ),
                            extraction_method="ERROR",
                            text="",
                            confidence_score=None,
                            word_count=0,
                            bounding_boxes=(),
                            preprocessing_variant="NONE",
                            error_message=(
                                "unable to decode sampled frame"
                            ),
                        )
                    )
                    continue

                result = self._ocr_image(
                    image=image,
                    unit_type="FRAME",
                    unit_number=frame_index,
                    timestamp_seconds=timestamp,
                )
                normalized_text = self._normalize_text_key(
                    result.text
                )
                if (
                    normalized_text
                    and normalized_text in seen_text
                ):
                    result = OCRUnitResult(
                        unit_type=result.unit_type,
                        unit_number=result.unit_number,
                        timestamp_seconds=(
                            result.timestamp_seconds
                        ),
                        extraction_method=(
                            result.extraction_method
                            + "_DEDUPLICATED"
                        ),
                        text="",
                        confidence_score=(
                            result.confidence_score
                        ),
                        word_count=0,
                        bounding_boxes=(
                            result.bounding_boxes
                        ),
                        preprocessing_variant=(
                            result.preprocessing_variant
                        ),
                    )
                elif normalized_text:
                    seen_text.add(normalized_text)
                results.append(result)

            return (
                results,
                declared_frames,
                truncated,
                warnings,
            )
        finally:
            capture.release()

    def _ocr_image(
        self,
        *,
        image: np.ndarray,
        unit_type: str,
        unit_number: int,
        timestamp_seconds: float | None,
    ) -> OCRUnitResult:
        self._validate_image_size(image)
        variants = self._preprocess_variants(image)
        candidates: list[OCRUnitResult] = []

        for variant_name, variant_image in variants:
            try:
                candidates.append(
                    self._run_tesseract(
                        image=variant_image,
                        unit_type=unit_type,
                        unit_number=unit_number,
                        timestamp_seconds=(
                            timestamp_seconds
                        ),
                        variant_name=variant_name,
                    )
                )
            except Exception as error:
                candidates.append(
                    OCRUnitResult(
                        unit_type=unit_type,
                        unit_number=unit_number,
                        timestamp_seconds=(
                            round(timestamp_seconds, 6)
                            if timestamp_seconds is not None
                            else None
                        ),
                        extraction_method="TESSERACT",
                        text="",
                        confidence_score=None,
                        word_count=0,
                        bounding_boxes=(),
                        preprocessing_variant=variant_name,
                        error_message=str(error),
                    )
                )

        successful = [
            candidate
            for candidate in candidates
            if candidate.error_message is None
        ]
        if not successful:
            return candidates[0]

        return max(
            successful,
            key=lambda candidate: (
                candidate.word_count,
                candidate.confidence_score or 0.0,
            ),
        )

    def _run_tesseract(
        self,
        *,
        image: np.ndarray,
        unit_type: str,
        unit_number: int,
        timestamp_seconds: float | None,
        variant_name: str,
    ) -> OCRUnitResult:
        try:
            data = pytesseract.image_to_data(
                image,
                lang=self._languages,
                config="--oem 3 --psm 6",
                output_type=Output.DICT,
                timeout=self._item_timeout_seconds,
            )
        except (
            RuntimeError,
            pytesseract.TesseractError,
            pytesseract.TesseractNotFoundError,
        ) as error:
            raise MediaRuntimeError(
                "Tesseract OCR failed"
            ) from error

        words: list[str] = []
        confidences: list[float] = []
        boxes: list[dict[str, Any]] = []
        line_words: dict[
            tuple[int, int, int],
            list[str],
        ] = {}

        total_items = len(data.get("text", []))
        for index in range(total_items):
            text = str(
                data["text"][index]
            ).strip()
            confidence = self._parse_confidence(
                data.get("conf", [])[index]
                if index < len(data.get("conf", []))
                else None
            )
            if not text:
                continue

            words.append(text)
            if confidence is not None and confidence >= 0:
                confidences.append(confidence)

            block_number = self._safe_int(
                data,
                "block_num",
                index,
            )
            paragraph_number = self._safe_int(
                data,
                "par_num",
                index,
            )
            line_number = self._safe_int(
                data,
                "line_num",
                index,
            )
            line_words.setdefault(
                (
                    block_number,
                    paragraph_number,
                    line_number,
                ),
                [],
            ).append(text)

            boxes.append(
                {
                    "text": text,
                    "confidence": confidence,
                    "x": self._safe_int(
                        data,
                        "left",
                        index,
                    ),
                    "y": self._safe_int(
                        data,
                        "top",
                        index,
                    ),
                    "width": self._safe_int(
                        data,
                        "width",
                        index,
                    ),
                    "height": self._safe_int(
                        data,
                        "height",
                        index,
                    ),
                }
            )

        text = "\n".join(
            " ".join(line)
            for _, line in sorted(line_words.items())
            if line
        ).strip()
        confidence_score = (
            float(fmean(confidences))
            if confidences
            else None
        )

        return OCRUnitResult(
            unit_type=unit_type,
            unit_number=unit_number,
            timestamp_seconds=(
                round(timestamp_seconds, 6)
                if timestamp_seconds is not None
                else None
            ),
            extraction_method="TESSERACT",
            text=text,
            confidence_score=(
                round(confidence_score, 4)
                if confidence_score is not None
                else None
            ),
            word_count=len(words),
            bounding_boxes=tuple(boxes),
            preprocessing_variant=variant_name,
        )

    def _native_pdf_text(
        self,
        page: fitz.Page,
        page_number: int,
    ) -> OCRUnitResult | None:
        text = page.get_text("text").strip()
        if len(re.findall(r"\w+", text)) < 5:
            return None

        boxes: list[dict[str, Any]] = []
        for block in page.get_text("blocks"):
            if len(block) < 5:
                continue
            block_text = str(block[4]).strip()
            if not block_text:
                continue
            x0, y0, x1, y1 = (
                float(block[0]),
                float(block[1]),
                float(block[2]),
                float(block[3]),
            )
            boxes.append(
                {
                    "text": block_text,
                    "confidence": 100.0,
                    "x": x0,
                    "y": y0,
                    "width": max(0.0, x1 - x0),
                    "height": max(0.0, y1 - y0),
                }
            )

        return OCRUnitResult(
            unit_type="PAGE",
            unit_number=page_number,
            timestamp_seconds=None,
            extraction_method="PYMUPDF_NATIVE_TEXT",
            text=text,
            confidence_score=100.0,
            word_count=len(re.findall(r"\S+", text)),
            bounding_boxes=tuple(boxes),
            preprocessing_variant="NATIVE_TEXT",
        )

    def _render_pdf_page(
        self,
        page: fitz.Page,
    ) -> np.ndarray:
        matrix = fitz.Matrix(2.0, 2.0)
        pixmap = page.get_pixmap(
            matrix=matrix,
            alpha=False,
            colorspace=fitz.csRGB,
        )
        image = np.frombuffer(
            pixmap.samples,
            dtype=np.uint8,
        ).reshape(
            pixmap.height,
            pixmap.width,
            pixmap.n,
        )
        image = cv2.cvtColor(
            image,
            cv2.COLOR_RGB2BGR,
        )
        self._validate_image_size(image)
        return image

    def _preprocess_variants(
        self,
        image: np.ndarray,
    ) -> list[tuple[str, np.ndarray]]:
        if image.ndim == 2:
            gray = image
        else:
            gray = cv2.cvtColor(
                image,
                cv2.COLOR_BGR2GRAY,
            )

        height, width = gray.shape[:2]
        if min(height, width) < 1000:
            scale = min(
                3.0,
                max(1.0, 1400.0 / max(height, width)),
            )
            if scale > 1.05:
                gray = cv2.resize(
                    gray,
                    (
                        int(round(width * scale)),
                        int(round(height * scale)),
                    ),
                    interpolation=cv2.INTER_CUBIC,
                )

        denoised = cv2.fastNlMeansDenoising(
            gray,
            None,
            h=12,
            templateWindowSize=7,
            searchWindowSize=21,
        )
        clahe = cv2.createCLAHE(
            clipLimit=2.0,
            tileGridSize=(8, 8),
        )
        enhanced = clahe.apply(denoised)
        thresholded = cv2.adaptiveThreshold(
            enhanced,
            255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY,
            35,
            11,
        )
        return [
            ("GRAYSCALE_CLAHE", enhanced),
            ("ADAPTIVE_THRESHOLD", thresholded),
        ]

    def _video_frame_indices(
        self,
        frame_count: int,
        frames_per_second: float,
    ) -> list[int]:
        if frame_count <= 0:
            return list(
                range(self._maximum_video_frames)
            )

        step = max(
            1,
            int(
                round(
                    frames_per_second
                    * self._video_frame_interval_seconds
                )
            ),
        )
        indices = list(
            range(0, frame_count, step)
        )
        if indices and indices[-1] != frame_count - 1:
            indices.append(frame_count - 1)
        if len(indices) > self._maximum_video_frames:
            indices = sorted(
                {
                    int(round(value))
                    for value in np.linspace(
                        0,
                        frame_count - 1,
                        num=self._maximum_video_frames,
                    )
                }
            )
        return indices

    @staticmethod
    def _load_image(file_path: Path) -> np.ndarray:
        try:
            encoded = np.fromfile(
                str(file_path),
                dtype=np.uint8,
            )
            image = cv2.imdecode(
                encoded,
                cv2.IMREAD_COLOR,
            )
        except (OSError, ValueError, cv2.error) as error:
            raise MediaRuntimeError(
                "unable to load image for OCR"
            ) from error
        if image is None or image.size == 0:
            raise MediaRuntimeError(
                "OCR image is empty or unsupported"
            )
        return image

    def _validate_image_size(
        self,
        image: np.ndarray,
    ) -> None:
        if image is None or image.size == 0:
            raise MediaRuntimeError(
                "OCR image is empty"
            )
        height, width = image.shape[:2]
        if height * width > self._maximum_image_pixels:
            raise MediaRuntimeError(
                "OCR image exceeds the configured pixel limit"
            )

    def _resolve_languages(
        self,
        configured: str,
    ) -> tuple[str, tuple[str, ...]]:
        requested = [
            value.strip()
            for value in re.split(r"[+,]", configured)
            if value.strip()
        ]
        if not requested:
            requested = ["eng"]
        try:
            available = set(
                pytesseract.get_languages(config="")
            )
        except (
            pytesseract.TesseractError,
            pytesseract.TesseractNotFoundError,
        ) as error:
            raise MediaRuntimeError(
                "unable to query Tesseract languages"
            ) from error

        selected = [
            language
            for language in requested
            if language in available
        ]
        missing = tuple(
            language
            for language in requested
            if language not in available
        )
        if not selected:
            if "eng" not in available:
                raise MediaRuntimeError(
                    "Tesseract English language data is missing"
                )
            selected = ["eng"]
        return "+".join(selected), missing

    @staticmethod
    def _read_engine_version() -> str | None:
        try:
            version = str(
                pytesseract.get_tesseract_version()
            ).splitlines()[0].strip()
            return version or None
        except (
            pytesseract.TesseractError,
            pytesseract.TesseractNotFoundError,
        ):
            return None

    @staticmethod
    def _parse_confidence(
        value: Any,
    ) -> float | None:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return None
        if not np.isfinite(parsed) or parsed < 0:
            return None
        return max(0.0, min(100.0, parsed))

    @staticmethod
    def _safe_int(
        data: dict[str, list[Any]],
        key: str,
        index: int,
    ) -> int:
        values = data.get(key, [])
        if index >= len(values):
            return 0
        try:
            return int(values[index])
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _combine_text(
        units: list[OCRUnitResult],
        source_type: str,
    ) -> str:
        sections: list[str] = []
        for unit in units:
            text = unit.text.strip()
            if not text:
                continue
            if source_type == "DOCUMENT":
                heading = f"--- Page {unit.unit_number} ---"
            elif source_type == "VIDEO":
                heading = (
                    "--- Frame "
                    f"{unit.unit_number} at "
                    f"{unit.timestamp_seconds or 0.0:.2f}s ---"
                )
            else:
                heading = "--- Image ---"
            sections.append(f"{heading}\n{text}")
        return "\n\n".join(sections).strip()

    @staticmethod
    def _save_text(
        output_path: Path,
        text: str,
    ) -> str | None:
        if not text:
            return None
        try:
            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            output_path.write_text(
                text,
                encoding="utf-8",
            )
        except OSError as error:
            raise MediaRuntimeError(
                "unable to persist OCR text output"
            ) from error
        return str(output_path)

    @staticmethod
    def _extraction_result(
        *,
        has_text: bool,
        successful_count: int,
        failure_count: int,
        truncated: bool,
        confidence: float | None,
    ) -> str:
        if not has_text:
            if successful_count == 0 and failure_count > 0:
                return "ERROR"
            return "NO_TEXT"
        if (
            failure_count > 0
            or truncated
            or (
                confidence is not None
                and confidence < 60.0
            )
        ):
            return "PARTIAL"
        return "TEXT_FOUND"

    @staticmethod
    def _normalize_text_key(text: str) -> str:
        return re.sub(
            r"\W+",
            "",
            text.lower(),
        )

    @staticmethod
    def _unique(values: list[str]) -> list[str]:
        return list(dict.fromkeys(values))