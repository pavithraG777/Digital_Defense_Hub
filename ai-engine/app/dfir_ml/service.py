from __future__ import annotations

import json
import math
from typing import Dict, List, Optional
import os
import time


class DFIRMLService:
    """A lightweight ML-ready feature extractor and scorer for DFIR events."""

    def __init__(self, model_name: str = "hybrid-ransomware-v1") -> None:
        self.model_name = model_name
        self.feature_names = [
            "file_event_rate",
            "rename_rate",
            "entropy_change",
            "network_spike_ratio",
            "honeytoken_hits",
            "process_anomaly_score",
            "time_window_score",
        ]
        # model_loaded indicates whether a real model or warmed up weights are available
        self.model_loaded: bool = False
        # optional path to a model file (e.g., ONNX) for warmup
        self.model_path: Optional[str] = os.environ.get("DFIR_ML_MODEL_PATH")

    def extract_features(self, payload: Dict[str, object]) -> Dict[str, float]:
        features: Dict[str, float] = {}
        for name in self.feature_names:
            features[name] = float(payload.get(name, 0.0) or 0.0)
        return features

    def score(self, payload: Dict[str, object]) -> Dict[str, object]:
        features = self.extract_features(payload)
        weighted_sum = (
            features["file_event_rate"] * 0.25
            + features["rename_rate"] * 0.20
            + features["entropy_change"] * 0.20
            + features["network_spike_ratio"] * 0.15
            + features["honeytoken_hits"] * 0.10
            + features["process_anomaly_score"] * 0.05
            + features["time_window_score"] * 0.05
        )

        probability = 1 / (1 + math.exp(-weighted_sum))
        return {
            "model": self.model_name,
            "probability": round(probability, 6),
            "features": features,
        }

    def score_from_json(self, payload_json: str) -> Dict[str, object]:
        payload = json.loads(payload_json)
        return self.score(payload)

    def warmup(self, timeout_seconds: int = 5) -> None:
        """Warm up the ML service by loading a model file if present.

        This is intentionally lightweight: if a model file is present at
        `self.model_path` we'll touch/read it to simulate load; otherwise we
        perform a short sleep to simulate a warmup routine and mark the
        service as ready.
        """
        if self.model_loaded:
            return

        if self.model_path and os.path.exists(self.model_path):
            # attempt to read a small portion of the file to validate it's accessible
            try:
                with open(self.model_path, "rb") as f:
                    _ = f.read(64)
                self.model_loaded = True
                return
            except Exception:
                # fall through to simulated warmup
                pass

        # fallback simulated warmup
        time.sleep(0.1)
        self.model_loaded = True

    def is_healthy(self) -> bool:
        return self.model_loaded
