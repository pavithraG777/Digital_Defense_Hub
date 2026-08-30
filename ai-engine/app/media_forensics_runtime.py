from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import UUID

import onnxruntime
import pytesseract
import torch

from app.config import Settings, get_settings


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class MediaRuntimeError(RuntimeError):
    pass


@dataclass(frozen=True)
class RuntimeHealth:
    status: str

    torch_version: str
    torch_device: str
    cuda_available: bool

    onnx_runtime_version: str
    onnx_providers: list[str]

    tesseract_version: str
    ffmpeg_version: str

    model_root: str
    workspace_root: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MediaForensicsRuntime:
    def __init__(
        self,
        settings: Settings,
    ) -> None:
        self.settings = settings

        self.model_root = self._resolve_project_path(
            settings.media_model_root,
        )
        self.workspace_root = self._resolve_project_path(
            settings.media_workspace_root,
        )

        self.backend_storage_root = (
            self._resolve_project_path(
                settings.media_backend_storage_root,
            )
        )
        # Approved training artifacts are written by the backend training
        # worker into a shared, configured root.  They remain hash-verified
        # before inference and are the only model files allowed outside the
        # packaged model directory.
        self.training_artifact_root = (
            self._resolve_project_path(
                settings.training_artifact_root,
            )
        )

        self.tesseract_executable = (
            settings.tesseract_executable
        )
        self.ffmpeg_executable = (
            settings.ffmpeg_executable
        )

        self.torch_device = self._resolve_torch_device()

        self._initialized = False
        self._health: RuntimeHealth | None = None

    def initialize(self) -> RuntimeHealth:
        if self._initialized and self._health is not None:
            return self._health

        self.model_root.mkdir(
            parents=True,
            exist_ok=True,
        )
        self.workspace_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        for directory_name in (
            "input",
            "jobs",
            "output",
            "temporary",
        ):
            (
                self.workspace_root /
                directory_name
            ).mkdir(
                parents=True,
                exist_ok=True,
            )

        tesseract_path = self._resolve_executable(
            self.tesseract_executable,
            "Tesseract",
        )
        ffmpeg_path = self._resolve_executable(
            self.ffmpeg_executable,
            "FFmpeg",
        )

        pytesseract.pytesseract.tesseract_cmd = (
            tesseract_path
        )

        tesseract_version = self._read_version(
            [
                tesseract_path,
                "--version",
            ],
            "Tesseract",
        )
        ffmpeg_version = self._read_version(
            [
                ffmpeg_path,
                "-version",
            ],
            "FFmpeg",
        )

        self.tesseract_executable = tesseract_path
        self.ffmpeg_executable = ffmpeg_path

        self._health = RuntimeHealth(
            status="HEALTHY",
            torch_version=torch.__version__,
            torch_device=str(self.torch_device),
            cuda_available=torch.cuda.is_available(),
            onnx_runtime_version=(
                onnxruntime.__version__
            ),
            onnx_providers=list(
                onnxruntime.get_available_providers()
            ),
            tesseract_version=tesseract_version,
            ffmpeg_version=ffmpeg_version,
            model_root=str(self.model_root),
            workspace_root=str(
                self.workspace_root
            ),
        )

        self._initialized = True

        return self._health

    def health(self) -> RuntimeHealth:
        return self.initialize()

    def prepare_job_workspace(
        self,
        organization_id: UUID,
        analysis_job_id: UUID,
    ) -> dict[str, Path]:
        self.initialize()

        job_root = (
            self.workspace_root /
            "jobs" /
            str(organization_id) /
            str(analysis_job_id)
        ).resolve()

        self._require_within(
            job_root,
            self.workspace_root,
            "job workspace",
        )

        input_directory = job_root / "input"
        output_directory = job_root / "output"
        temporary_directory = job_root / "temporary"

        for directory in (
            input_directory,
            output_directory,
            temporary_directory,
        ):
            directory.mkdir(
                parents=True,
                exist_ok=True,
            )

        return {
            "root": job_root,
            "input": input_directory,
            "output": output_directory,
            "temporary": temporary_directory,
        }

    def resolve_source_file(
        self,
        source_file_path: str,
    ) -> Path:
        self.initialize()

        candidate = Path(
            source_file_path,
        ).expanduser()

        if not candidate.is_absolute():
            candidate = (
                self.workspace_root /
                candidate
            )

        resolved_path = candidate.resolve()

        allowed_source_roots = (
            self.workspace_root,
            self.backend_storage_root,
        )

        source_is_allowed = any(
            resolved_path == allowed_root
            or allowed_root in resolved_path.parents
            for allowed_root in allowed_source_roots
        )

        if not source_is_allowed:
            raise MediaRuntimeError(
                "media source file is outside the "
                "configured workspace"
            )

        if not resolved_path.is_file():
            raise MediaRuntimeError(
                "media source file does not exist"
            )

        file_size = resolved_path.stat().st_size

        if (
            file_size >
            self.settings.media_maximum_file_bytes
        ):
            raise MediaRuntimeError(
                "media source file exceeds the "
                "configured maximum size"
            )

        return resolved_path

    def resolve_model_file(
        self,
        model_file_path: str,
    ) -> Path:
        self.initialize()

        candidate = Path(
            model_file_path,
        ).expanduser()

        if candidate.is_absolute():
            resolved_path = candidate.resolve()
        else:
            project_candidate = (
                PROJECT_ROOT /
                candidate
            ).resolve()

            if any(
                project_candidate.is_relative_to(root)
                for root in self._model_roots()
            ):
                resolved_path = project_candidate
            else:
                resolved_path = (
                    self.model_root /
                    candidate
                ).resolve()

        if not any(
            resolved_path == root or root in resolved_path.parents
            for root in self._model_roots()
        ):
            raise MediaRuntimeError(
                "model file is outside configured model roots"
            )

        if not resolved_path.is_file():
            raise MediaRuntimeError(
                "configured model file does not exist"
            )

        return resolved_path

    def _model_roots(self) -> tuple[Path, ...]:
        return (
            self.model_root,
            self.training_artifact_root,
        )

    def verify_file_hash(
        self,
        file_path: Path,
        expected_hash: str,
    ) -> None:
        calculated_hash = self.calculate_sha256(
            file_path,
        )

        if (
            calculated_hash.lower() !=
            expected_hash.strip().lower()
        ):
            raise MediaRuntimeError(
                "file SHA-256 hash verification failed"
            )

    def verify_model_file(
        self,
        model_file_path: str,
        expected_hash: str,
    ) -> Path:
        resolved_path = self.resolve_model_file(
            model_file_path,
        )

        self.verify_file_hash(
            resolved_path,
            expected_hash,
        )

        return resolved_path

    def runtime_for_model_format(
        self,
        model_format: str,
    ) -> str:
        normalized_format = (
            model_format.strip().upper()
        )

        if normalized_format in {
            "PT",
            "PTH",
        }:
            return "PYTORCH"

        if normalized_format == "ONNX":
            return "ONNX_RUNTIME"

        if normalized_format == "CUSTOM":
            return "HYBRID"

        raise MediaRuntimeError(
            "unsupported model format"
        )

    @staticmethod
    def calculate_sha256(
        file_path: Path,
    ) -> str:
        digest = hashlib.sha256()

        with file_path.open("rb") as source_file:
            while True:
                chunk = source_file.read(
                    1024 * 1024,
                )

                if not chunk:
                    break

                digest.update(chunk)

        return digest.hexdigest()

    def _resolve_torch_device(
        self,
    ) -> torch.device:
        configured_device = (
            self.settings.media_torch_device
        )

        if configured_device == "auto":
            if torch.cuda.is_available():
                return torch.device("cuda")

            return torch.device("cpu")

        if configured_device == "cuda":
            if not torch.cuda.is_available():
                raise MediaRuntimeError(
                    "CUDA was requested but is unavailable"
                )

            return torch.device("cuda")

        return torch.device("cpu")

    @staticmethod
    def _resolve_project_path(
        configured_path: Path,
    ) -> Path:
        if configured_path.is_absolute():
            return configured_path.resolve()

        return (
            PROJECT_ROOT /
            configured_path
        ).resolve()

    @staticmethod
    def _resolve_executable(
        configured_value: str,
        executable_name: str,
    ) -> str:
        configured_path = Path(
            configured_value,
        ).expanduser()

        if configured_path.is_absolute():
            resolved_path = configured_path.resolve()

            if not resolved_path.is_file():
                raise MediaRuntimeError(
                    f"{executable_name} executable "
                    "does not exist"
                )

            return str(resolved_path)

        discovered_path = shutil.which(
            configured_value,
        )

        if discovered_path is None:
            raise MediaRuntimeError(
                f"{executable_name} executable "
                "was not found"
            )

        return discovered_path

    @staticmethod
    def _read_version(
        command: list[str],
        executable_name: str,
    ) -> str:
        try:
            completed_process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                errors="replace",
            )
        except (
            OSError,
            subprocess.SubprocessError,
        ) as error:
            raise MediaRuntimeError(
                f"unable to execute {executable_name}"
            ) from error

        combined_output = "\n".join(
            value
            for value in (
                completed_process.stdout,
                completed_process.stderr,
            )
            if value
        )

        first_line = next(
            (
                line.strip()
                for line in combined_output.splitlines()
                if line.strip()
            ),
            "",
        )

        if (
            completed_process.returncode != 0
            or not first_line
        ):
            raise MediaRuntimeError(
                f"unable to read {executable_name} "
                "version"
            )

        return first_line

    @staticmethod
    def _require_within(
        candidate: Path,
        allowed_root: Path,
        description: str,
    ) -> None:
        if not candidate.is_relative_to(
            allowed_root
        ):
            raise MediaRuntimeError(
                f"{description} is outside the "
                "configured workspace"
            )


@lru_cache(maxsize=1)
def get_media_runtime() -> MediaForensicsRuntime:
    return MediaForensicsRuntime(
        get_settings(),
    )
