from __future__ import annotations

import json
import mimetypes
import shutil
import subprocess
from dataclasses import asdict, dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any

import fitz
from PIL import Image, UnidentifiedImageError

from app.media_forensics_runtime import (
    MediaForensicsRuntime,
    MediaRuntimeError,
)


IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".bmp",
    ".tif",
    ".tiff",
}

VIDEO_EXTENSIONS = {
    ".mp4",
    ".mov",
    ".avi",
    ".mkv",
    ".webm",
    ".m4v",
}

AUDIO_EXTENSIONS = {
    ".wav",
    ".mp3",
    ".flac",
    ".ogg",
    ".m4a",
    ".aac",
    ".wma",
}

DOCUMENT_EXTENSIONS = {
    ".pdf",
}


@dataclass(frozen=True)
class MediaProbeResult:
    media_type: str
    detected_mime_type: str

    format_name: str | None
    codec_names: list[str]

    width: int | None
    height: int | None

    duration_seconds: float | None
    frame_rate: float | None
    frame_count: int | None

    sample_rate: int | None
    channels: int | None

    page_count: int | None

    has_video: bool
    has_audio: bool

    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MediaProbe:
    def __init__(
        self,
        runtime: MediaForensicsRuntime,
    ) -> None:
        self.runtime = runtime

    def probe(
        self,
        file_path: Path,
        declared_media_type: str,
        declared_mime_type: str,
    ) -> MediaProbeResult:
        normalized_media_type = (
            declared_media_type.strip().upper()
        )

        detected_media_type = self.infer_media_type(
            file_path,
            declared_mime_type,
        )

        if (
            normalized_media_type !=
            detected_media_type
        ):
            raise MediaRuntimeError(
                "declared media type does not match "
                "the uploaded file"
            )

        if detected_media_type == "IMAGE":
            return self._probe_image(
                file_path,
                declared_mime_type,
            )

        if detected_media_type in {
            "VIDEO",
            "AUDIO",
        }:
            return self._probe_audio_video(
                file_path,
                detected_media_type,
                declared_mime_type,
            )

        if detected_media_type == "DOCUMENT":
            return self._probe_document(
                file_path,
                declared_mime_type,
            )

        raise MediaRuntimeError(
            "unsupported media type"
        )

    @staticmethod
    def infer_media_type(
        file_path: Path,
        declared_mime_type: str,
    ) -> str:
        extension = file_path.suffix.lower()
        normalized_mime_type = (
            declared_mime_type
            .strip()
            .lower()
            .split(
                ";",
                maxsplit=1,
            )[0]
        )

        if (
            extension in IMAGE_EXTENSIONS
            or normalized_mime_type.startswith(
                "image/"
            )
        ):
            return "IMAGE"

        if (
            extension in VIDEO_EXTENSIONS
            or normalized_mime_type.startswith(
                "video/"
            )
        ):
            return "VIDEO"

        if (
            extension in AUDIO_EXTENSIONS
            or normalized_mime_type.startswith(
                "audio/"
            )
        ):
            return "AUDIO"

        if (
            extension in DOCUMENT_EXTENSIONS
            or normalized_mime_type ==
            "application/pdf"
        ):
            return "DOCUMENT"

        guessed_mime_type, _ = (
            mimetypes.guess_type(
                file_path.name,
            )
        )

        if guessed_mime_type:
            if guessed_mime_type.startswith(
                "image/"
            ):
                return "IMAGE"

            if guessed_mime_type.startswith(
                "video/"
            ):
                return "VIDEO"

            if guessed_mime_type.startswith(
                "audio/"
            ):
                return "AUDIO"

            if (
                guessed_mime_type ==
                "application/pdf"
            ):
                return "DOCUMENT"

        raise MediaRuntimeError(
            "unable to determine media type"
        )

    def _probe_image(
        self,
        file_path: Path,
        declared_mime_type: str,
    ) -> MediaProbeResult:
        try:
            with Image.open(file_path) as image:
                width = image.width
                height = image.height
                image_format = image.format
                image_mode = image.mode

                image.verify()
        except (
            OSError,
            UnidentifiedImageError,
        ) as error:
            raise MediaRuntimeError(
                "unable to decode image file"
            ) from error

        detected_mime_type = (
            Image.MIME.get(
                image_format or "",
            )
            or declared_mime_type
            or "application/octet-stream"
        )

        return MediaProbeResult(
            media_type="IMAGE",
            detected_mime_type=(
                detected_mime_type
            ),
            format_name=image_format,
            codec_names=(
                [image_format]
                if image_format
                else []
            ),
            width=width,
            height=height,
            duration_seconds=None,
            frame_rate=None,
            frame_count=None,
            sample_rate=None,
            channels=None,
            page_count=None,
            has_video=True,
            has_audio=False,
            metadata={
                "image_mode": image_mode,
                "file_extension": (
                    file_path.suffix.lower()
                ),
            },
        )

    def _probe_audio_video(
        self,
        file_path: Path,
        media_type: str,
        declared_mime_type: str,
    ) -> MediaProbeResult:
        ffprobe_executable = (
            self._resolve_ffprobe()
        )

        command = [
            ffprobe_executable,
            "-v",
            "error",
            "-print_format",
            "json",
            "-show_format",
            "-show_streams",
            str(file_path),
        ]

        try:
            completed_process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                errors="replace",
            )
        except (
            OSError,
            subprocess.SubprocessError,
        ) as error:
            raise MediaRuntimeError(
                "unable to inspect media file"
            ) from error

        if completed_process.returncode != 0:
            raise MediaRuntimeError(
                "FFprobe could not decode media file"
            )

        try:
            probe_data = json.loads(
                completed_process.stdout,
            )
        except json.JSONDecodeError as error:
            raise MediaRuntimeError(
                "FFprobe returned invalid metadata"
            ) from error

        streams = probe_data.get(
            "streams",
            [],
        )
        format_data = probe_data.get(
            "format",
            {},
        )

        video_stream = next(
            (
                stream
                for stream in streams
                if stream.get("codec_type") ==
                "video"
            ),
            None,
        )
        audio_stream = next(
            (
                stream
                for stream in streams
                if stream.get("codec_type") ==
                "audio"
            ),
            None,
        )

        if (
            media_type == "VIDEO"
            and video_stream is None
        ):
            raise MediaRuntimeError(
                "video stream was not found"
            )

        if (
            media_type == "AUDIO"
            and audio_stream is None
        ):
            raise MediaRuntimeError(
                "audio stream was not found"
            )

        duration_seconds = self._safe_float(
            format_data.get("duration"),
        )

        if duration_seconds is None:
            selected_stream = (
                video_stream
                if media_type == "VIDEO"
                else audio_stream
            )

            if selected_stream is not None:
                duration_seconds = (
                    self._safe_float(
                        selected_stream.get(
                            "duration"
                        ),
                    )
                )

        frame_rate = None
        frame_count = None
        width = None
        height = None

        if video_stream is not None:
            width = self._safe_int(
                video_stream.get("width"),
            )
            height = self._safe_int(
                video_stream.get("height"),
            )
            frame_count = self._safe_int(
                video_stream.get(
                    "nb_frames"
                ),
            )
            frame_rate = self._safe_fraction(
                video_stream.get(
                    "avg_frame_rate"
                ),
            )

        sample_rate = None
        channels = None

        if audio_stream is not None:
            sample_rate = self._safe_int(
                audio_stream.get(
                    "sample_rate"
                ),
            )
            channels = self._safe_int(
                audio_stream.get(
                    "channels"
                ),
            )

        codec_names = [
            str(stream["codec_name"])
            for stream in streams
            if stream.get("codec_name")
        ]

        detected_mime_type = (
            declared_mime_type
            or mimetypes.guess_type(
                file_path.name,
            )[0]
            or "application/octet-stream"
        )

        return MediaProbeResult(
            media_type=media_type,
            detected_mime_type=(
                detected_mime_type
            ),
            format_name=format_data.get(
                "format_name"
            ),
            codec_names=codec_names,
            width=width,
            height=height,
            duration_seconds=duration_seconds,
            frame_rate=frame_rate,
            frame_count=frame_count,
            sample_rate=sample_rate,
            channels=channels,
            page_count=None,
            has_video=video_stream is not None,
            has_audio=audio_stream is not None,
            metadata={
                "format_long_name": (
                    format_data.get(
                        "format_long_name"
                    )
                ),
                "bit_rate": self._safe_int(
                    format_data.get(
                        "bit_rate"
                    ),
                ),
                "tags": format_data.get(
                    "tags",
                    {},
                ),
            },
        )

    @staticmethod
    def _probe_document(
        file_path: Path,
        declared_mime_type: str,
    ) -> MediaProbeResult:
        try:
            document = fitz.open(
                str(file_path),
            )
        except Exception as error:
            raise MediaRuntimeError(
                "unable to decode document file"
            ) from error

        try:
            if document.needs_pass:
                raise MediaRuntimeError(
                    "password-protected document "
                    "cannot be analyzed"
                )

            page_count = document.page_count
            document_metadata = dict(
                document.metadata or {},
            )
        finally:
            document.close()

        return MediaProbeResult(
            media_type="DOCUMENT",
            detected_mime_type=(
                declared_mime_type
                or "application/pdf"
            ),
            format_name="PDF",
            codec_names=[],
            width=None,
            height=None,
            duration_seconds=None,
            frame_rate=None,
            frame_count=None,
            sample_rate=None,
            channels=None,
            page_count=page_count,
            has_video=False,
            has_audio=False,
            metadata={
                "document_metadata": (
                    document_metadata
                ),
                "file_extension": (
                    file_path.suffix.lower()
                ),
            },
        )

    def _resolve_ffprobe(self) -> str:
        ffmpeg_path = Path(
            self.runtime.ffmpeg_executable,
        )

        executable_name = (
            "ffprobe.exe"
            if ffmpeg_path.suffix.lower() ==
            ".exe"
            else "ffprobe"
        )

        sibling_path = (
            ffmpeg_path.parent /
            executable_name
        )

        if sibling_path.is_file():
            return str(sibling_path)

        discovered_path = shutil.which(
            "ffprobe",
        )

        if discovered_path is None:
            raise MediaRuntimeError(
                "FFprobe executable was not found"
            )

        return discovered_path

    @staticmethod
    def _safe_float(
        value: Any,
    ) -> float | None:
        if value in {
            None,
            "",
            "N/A",
        }:
            return None

        try:
            return float(value)
        except (
            TypeError,
            ValueError,
        ):
            return None

    @staticmethod
    def _safe_int(
        value: Any,
    ) -> int | None:
        if value in {
            None,
            "",
            "N/A",
        }:
            return None

        try:
            return int(value)
        except (
            TypeError,
            ValueError,
        ):
            return None

    @staticmethod
    def _safe_fraction(
        value: Any,
    ) -> float | None:
        if value in {
            None,
            "",
            "N/A",
            "0/0",
        }:
            return None

        try:
            return float(
                Fraction(str(value))
            )
        except (
            ValueError,
            ZeroDivisionError,
        ):
            return None