from __future__ import annotations

import math
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import cv2
import numpy as np
import onnxruntime
import torch

from app.media_forensics_runtime import (
    MediaForensicsRuntime,
    MediaRuntimeError,
    get_media_runtime,
)
from app.media_forensics_schemas import (
    ModelExecutionSpecification,
)


@dataclass(frozen=True)
class ModelInferenceResult:
    runtime: str
    deepfake_probability: float
    authenticity_probability: float
    confidence_score: float
    raw_output: list[float]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MediaModelRunner:
    def __init__(
        self,
        runtime: MediaForensicsRuntime | None = None,
    ) -> None:
        # Analyzers can be used directly as well as through the application
        # service.  Use the application's singleton runtime in the direct
        # case so model-file validation is always available.
        self.runtime = runtime or get_media_runtime()

        self._pytorch_models: dict[str, Any] = {}
        self._onnx_sessions: dict[
            str,
            onnxruntime.InferenceSession,
        ] = {}

        self._model_lock = threading.RLock()

    def run_image(
        self,
        model: ModelExecutionSpecification,
        image: np.ndarray,
    ) -> ModelInferenceResult:
        if image.size == 0:
            raise MediaRuntimeError(
                "model input image is empty"
            )

        prepared_image = self._prepare_image_region(
            image,
            model.configuration,
        )
        input_array = self._preprocess_image(
            prepared_image,
            model.configuration,
        )

        return self.run_tensor(
            model,
            input_array,
        )

    @staticmethod
    def _prepare_image_region(
        image: np.ndarray,
        configuration: dict[str, Any],
    ) -> np.ndarray:
        preprocessing = str(
            configuration.get("preprocessing", "")
        ).strip().upper()
        if preprocessing not in {
            "FACE_CONTEXT_CROP_V1",
            "EARLY_WINDOW_FACE_CONTEXT_CROP_V2",
        }:
            return image

        context_scale = float(
            configuration.get("context_scale", 2.35)
        )
        if not 1.25 <= context_scale <= 4.0:
            raise MediaRuntimeError(
                "face-context scale is invalid"
            )

        grayscale = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        cascade_name = "haarcascade_frontalface_default.xml"
        cascade_candidates = [
            Path(cv2.data.haarcascades) / cascade_name,
            Path(__file__).resolve().parents[1]
            / "models"
            / "opencv"
            / "haarcascades"
            / cascade_name,
        ]
        cascade_path = next(
            (path for path in cascade_candidates if path.is_file()),
            cascade_candidates[0],
        )
        detector = cv2.CascadeClassifier(str(cascade_path))
        if detector.empty():
            raise MediaRuntimeError(
                "face-context detector is unavailable"
            )
        minimum = max(32, min(image.shape[:2]) // 12)
        faces = detector.detectMultiScale(
            grayscale,
            scaleFactor=1.08,
            minNeighbors=5,
            minSize=(minimum, minimum),
            flags=cv2.CASCADE_SCALE_IMAGE,
        )
        face = None
        if len(faces) > 0:
            face = max(
                faces,
                key=lambda item: int(item[2]) * int(item[3]),
            )

        height, width = image.shape[:2]
        if face is None:
            side = min(height, width)
            center_x, center_y = width / 2, height / 2
        else:
            x, y, face_width, face_height = (
                int(value) for value in face
            )
            side = min(
                max(face_width, face_height) * context_scale,
                width,
                height,
            )
            center_x = x + face_width / 2
            center_y = y + face_height * 0.58

        side = max(1, int(round(side)))
        left = max(
            0,
            min(width - side, int(round(center_x - side / 2))),
        )
        top = max(
            0,
            min(height - side, int(round(center_y - side / 2))),
        )
        return image[top : top + side, left : left + side]

    def run_tensor(
        self,
        model: ModelExecutionSpecification,
        input_array: np.ndarray,
    ) -> ModelInferenceResult:
        model_path = self.runtime.verify_model_file(
            model.model_file_path,
            model.model_file_hash,
        )

        runtime_name = (
            self.runtime.runtime_for_model_format(
                model.model_format,
            )
        )

        if runtime_name == "PYTORCH":
            output = self._run_pytorch(
                model_path,
                input_array,
            )
        elif runtime_name == "ONNX_RUNTIME":
            output = self._run_onnx(
                model_path,
                input_array,
                model.configuration,
            )
        else:
            raise MediaRuntimeError(
                "CUSTOM models must be processed "
                "by a forensic analyzer"
            )

        probability = self._extract_probability(
            output,
            model.configuration,
        )

        deepfake_probability = round(
            probability * 100,
            4,
        )
        authenticity_probability = round(
            100 - deepfake_probability,
            4,
        )
        confidence_score = round(
            50 + abs(
                deepfake_probability - 50
            ),
            4,
        )

        return ModelInferenceResult(
            runtime=runtime_name,
            deepfake_probability=(
                deepfake_probability
            ),
            authenticity_probability=(
                authenticity_probability
            ),
            confidence_score=confidence_score,
            raw_output=[
                round(float(value), 8)
                for value in output.flatten()[:32]
            ],
        )

    def _run_pytorch(
        self,
        model_path: Path,
        input_array: np.ndarray,
    ) -> np.ndarray:
        model_key = (
            f"{model_path}:"
            f"{self.runtime.torch_device}"
        )

        with self._model_lock:
            loaded_model = self._pytorch_models.get(
                model_key,
            )

            if loaded_model is None:
                loaded_model = self._load_pytorch_model(
                    model_path,
                )
                loaded_model.to(self.runtime.torch_device)
                loaded_model.eval()

                self._pytorch_models[
                    model_key
                ] = loaded_model

        tensor = torch.from_numpy(
            np.ascontiguousarray(
                input_array,
            )
        ).to(
            device=self.runtime.torch_device,
            dtype=torch.float32,
        )

        try:
            with torch.inference_mode():
                output = loaded_model(tensor)
        except Exception as error:
            raise MediaRuntimeError(
                "PyTorch inference failed"
            ) from error

        return self._normalize_model_output(
            output,
        )

    def _load_pytorch_model(self, model_path: Path) -> Any:
        """Load either a verified TorchScript model or a DDH training artifact.

        The training pipeline writes a state-dictionary checkpoint rather than
        executable TorchScript.  Restrict checkpoint support to the documented
        DDH architecture and use ``weights_only`` so uploaded model artifacts
        cannot execute Python during deserialization.
        """
        try:
            return torch.jit.load(
                str(model_path),
                map_location="cpu",
            )
        except Exception:
            pass

        try:
            checkpoint = torch.load(
                str(model_path),
                map_location="cpu",
                weights_only=True,
            )
        except Exception as error:
            raise MediaRuntimeError(
                "PyTorch model must be a verified TorchScript model "
                "or DDH training checkpoint"
            ) from error

        if not isinstance(checkpoint, dict):
            raise MediaRuntimeError(
                "DDH training checkpoint must contain an object"
            )
        if checkpoint.get("format_version") != "1.0":
            raise MediaRuntimeError(
                "unsupported DDH training checkpoint format"
            )
        architecture = checkpoint.get("architecture")
        if architecture not in {"ddh_cnn_v1", "mobilenet_v3_small_forensics_v1"}:
            raise MediaRuntimeError(
                "unsupported DDH training checkpoint architecture"
            )
        if checkpoint.get("classes") != ["authentic", "deepfake"]:
            raise MediaRuntimeError(
                "DDH training checkpoint classes are invalid"
            )

        state_dict = checkpoint.get("state_dict")
        if not isinstance(state_dict, dict):
            raise MediaRuntimeError(
                "DDH training checkpoint state dictionary is missing"
            )

        from torch import nn

        if architecture == "ddh_cnn_v1":
            model = nn.Sequential(
                nn.Conv2d(3, 16, kernel_size=3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
                nn.Conv2d(16, 32, kernel_size=3, padding=1), nn.ReLU(),
                nn.AdaptiveAvgPool2d((1, 1)), nn.Flatten(), nn.Linear(32, 2),
            )
        else:
            from torchvision.models import mobilenet_v3_small
            model = mobilenet_v3_small(weights=None)
            model.classifier[-1] = nn.Linear(model.classifier[-1].in_features, 2)
        try:
            model.load_state_dict(state_dict, strict=True)
        except Exception as error:
            raise MediaRuntimeError(
                "DDH training checkpoint weights are invalid"
            ) from error
        return model

    def _run_onnx(
        self,
        model_path: Path,
        input_array: np.ndarray,
        configuration: dict[str, Any],
    ) -> np.ndarray:
        model_key = str(model_path)

        with self._model_lock:
            session = self._onnx_sessions.get(
                model_key,
            )

            if session is None:
                session_options = (
                    onnxruntime.SessionOptions()
                )

                thread_count = int(
                    configuration.get(
                        "intra_op_threads",
                        1,
                    )
                )

                session_options.intra_op_num_threads = (
                    max(
                        1,
                        min(
                            thread_count,
                            16,
                        ),
                    )
                )

                try:
                    session = (
                        onnxruntime.InferenceSession(
                            str(model_path),
                            sess_options=(
                                session_options
                            ),
                            providers=[
                                "CPUExecutionProvider",
                            ],
                        )
                    )
                except Exception as error:
                    raise MediaRuntimeError(
                        "unable to load ONNX model"
                    ) from error

                self._onnx_sessions[
                    model_key
                ] = session

        model_inputs = session.get_inputs()

        if not model_inputs:
            raise MediaRuntimeError(
                "ONNX model has no inputs"
            )

        input_name = str(
            configuration.get(
                "input_name",
                model_inputs[0].name,
            )
        )

        try:
            outputs = session.run(
                None,
                {
                    input_name: (
                        np.ascontiguousarray(
                            input_array,
                        ).astype(
                            np.float32,
                            copy=False,
                        )
                    )
                },
            )
        except Exception as error:
            raise MediaRuntimeError(
                "ONNX inference failed"
            ) from error

        if not outputs:
            raise MediaRuntimeError(
                "ONNX model returned no output"
            )

        output_index = int(
            configuration.get(
                "output_index",
                0,
            )
        )

        if (
            output_index < 0
            or output_index >= len(outputs)
        ):
            raise MediaRuntimeError(
                "configured ONNX output index "
                "is invalid"
            )

        return self._normalize_model_output(
            outputs[output_index],
        )

    @staticmethod
    def _preprocess_image(
        image: np.ndarray,
        configuration: dict[str, Any],
    ) -> np.ndarray:
        input_width = int(
            configuration.get(
                "input_width",
                224,
            )
        )
        input_height = int(
            configuration.get(
                "input_height",
                224,
            )
        )

        if (
            input_width <= 0
            or input_height <= 0
        ):
            raise MediaRuntimeError(
                "model image dimensions are invalid"
            )

        resized_image = cv2.resize(
            image,
            (
                input_width,
                input_height,
            ),
            interpolation=cv2.INTER_AREA,
        )

        channel_order = str(
            configuration.get(
                "channel_order",
                "RGB",
            )
        ).strip().upper()

        if channel_order == "RGB":
            resized_image = cv2.cvtColor(
                resized_image,
                cv2.COLOR_BGR2RGB,
            )
        elif channel_order != "BGR":
            raise MediaRuntimeError(
                "unsupported model channel order"
            )

        normalized_image = (
            resized_image.astype(
                np.float32,
            ) /
            float(
                configuration.get(
                    "pixel_scale",
                    255.0,
                )
            )
        )

        mean = np.asarray(
            configuration.get(
                "mean",
                [
                    0.485,
                    0.456,
                    0.406,
                ],
            ),
            dtype=np.float32,
        )
        standard_deviation = np.asarray(
            configuration.get(
                "std",
                [
                    0.229,
                    0.224,
                    0.225,
                ],
            ),
            dtype=np.float32,
        )

        if (
            mean.shape != (3,)
            or standard_deviation.shape != (3,)
            or np.any(
                standard_deviation == 0
            )
        ):
            raise MediaRuntimeError(
                "model normalization configuration "
                "is invalid"
            )

        normalized_image = (
            normalized_image - mean
        ) / standard_deviation

        tensor = np.transpose(
            normalized_image,
            (
                2,
                0,
                1,
            ),
        )

        return np.expand_dims(
            tensor,
            axis=0,
        )

    @staticmethod
    def _normalize_model_output(
        output: Any,
    ) -> np.ndarray:
        if isinstance(
            output,
            torch.Tensor,
        ):
            return (
                output.detach()
                .cpu()
                .numpy()
                .astype(
                    np.float64,
                    copy=False,
                )
            )

        if isinstance(
            output,
            dict,
        ):
            if not output:
                raise MediaRuntimeError(
                    "model returned an empty mapping"
                )

            output = next(
                iter(
                    output.values()
                )
            )

            return (
                MediaModelRunner
                ._normalize_model_output(
                    output,
                )
            )

        if isinstance(
            output,
            (
                list,
                tuple,
            ),
        ):
            if not output:
                raise MediaRuntimeError(
                    "model returned an empty sequence"
                )

            output = output[0]

            return (
                MediaModelRunner
                ._normalize_model_output(
                    output,
                )
            )

        try:
            normalized_output = np.asarray(
                output,
                dtype=np.float64,
            )
        except (
            TypeError,
            ValueError,
        ) as error:
            raise MediaRuntimeError(
                "model returned unsupported output"
            ) from error

        if normalized_output.size == 0:
            raise MediaRuntimeError(
                "model returned empty output"
            )

        return normalized_output

    @staticmethod
    def _extract_probability(
        output: np.ndarray,
        configuration: dict[str, Any],
    ) -> float:
        flattened_output = (
            output.astype(
                np.float64,
                copy=False,
            ).flatten()
        )

        if flattened_output.size == 0:
            raise MediaRuntimeError(
                "model output is empty"
            )

        output_mode = str(
            configuration.get(
                "output_mode",
                "AUTO",
            )
        ).strip().upper()

        fake_class_index = int(
            configuration.get(
                "deepfake_class_index",
                1,
            )
        )

        if output_mode == "PROBABILITY":
            probability = float(
                flattened_output[
                    min(
                        max(
                            fake_class_index,
                            0,
                        ),
                        flattened_output.size - 1,
                    )
                ]
            )

        elif (
            output_mode ==
            "BINARY_LOGIT"
            or (
                output_mode == "AUTO"
                and flattened_output.size == 1
            )
        ):
            probability = (
                MediaModelRunner._sigmoid(
                    float(
                        flattened_output[0]
                    )
                )
            )

        elif output_mode in {
            "MULTICLASS_LOGITS",
            "AUTO",
        }:
            probabilities = (
                MediaModelRunner._softmax(
                    flattened_output,
                )
            )

            selected_index = min(
                max(
                    fake_class_index,
                    0,
                ),
                probabilities.size - 1,
            )

            probability = float(
                probabilities[
                    selected_index
                ]
            )

        else:
            raise MediaRuntimeError(
                "unsupported model output mode"
            )

        if not math.isfinite(probability):
            raise MediaRuntimeError(
                "model probability is not finite"
            )

        return min(
            1.0,
            max(
                0.0,
                probability,
            ),
        )

    @staticmethod
    def _sigmoid(
        value: float,
    ) -> float:
        if value >= 0:
            exponential = math.exp(-value)
            return 1 / (
                1 + exponential
            )

        exponential = math.exp(value)

        return exponential / (
            1 + exponential
        )

    @staticmethod
    def _softmax(
        values: np.ndarray,
    ) -> np.ndarray:
        shifted_values = (
            values -
            np.max(values)
        )

        exponentials = np.exp(
            shifted_values,
        )

        denominator = np.sum(
            exponentials,
        )

        if denominator <= 0:
            raise MediaRuntimeError(
                "unable to normalize model output"
            )

        return exponentials / denominator
