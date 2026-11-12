"""Evaluate held-out public images and screenshot-like copies without retraining.

This is a distribution-shift audit, not a provenance verifier. It excludes
source hashes from V6/V7 manifests and never includes private identity photos.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from collections import defaultdict
from pathlib import Path

import torch
from PIL import Image, ImageOps
from torchvision import transforms
from torchvision.models import mobilenet_v3_small


ROOT = Path(__file__).resolve().parents[2]
EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
SOURCES = (
    ("coco_camera_scene", "authentic", ROOT / "data/downloaded/coco2017/val2017"),
    ("legacy_camera_real", "authentic", ROOT / "data/downloaded/ddata/test/real"),
    ("legacy_ai_generated", "deepfake", ROOT / "data/downloaded/ddata/test/fake"),
)


def excluded_hashes() -> set[str]:
    hashes: set[str] = set()
    for name in ("v6", "v7"):
        manifest = ROOT / f"datasets/unified-manipulation-detection-{name}-20000/provenance.csv"
        with manifest.open(newline="", encoding="utf-8") as stream:
            hashes.update(row["source_sha256"].lower() for row in csv.DictReader(stream))
    return hashes


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def select_samples(limit: int) -> list[tuple[str, str, Path]]:
    excluded = excluded_hashes()
    selected: list[tuple[str, str, Path]] = []
    seen: set[str] = set()
    for category, label, folder in SOURCES:
        if not folder.is_dir():
            raise FileNotFoundError(f"Public source is missing: {folder}")
        count = 0
        for path in sorted(folder.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in EXTENSIONS:
                continue
            digest = sha256(path)
            if digest in excluded or digest in seen:
                continue
            try:
                with Image.open(path) as image:
                    image.verify()
            except OSError:
                continue
            seen.add(digest)
            selected.append((category, label, path))
            count += 1
            if count == limit:
                break
        if count < limit:
            raise ValueError(f"Only {count} unused public images in {category}; requested {limit}")
    return selected


def variants(image: Image.Image) -> dict[str, Image.Image]:
    original = ImageOps.exif_transpose(image).convert("RGB")
    buffer = io.BytesIO()
    original.save(buffer, "JPEG", quality=85)
    buffer.seek(0)
    with Image.open(buffer) as copy:
        recompressed = copy.convert("RGB").copy()
    # A captured display adds borders and resampling, without changing the
    # underlying label. This approximates a screenshot; it is not a browser capture.
    screen = Image.new("RGB", (1200, 900), (18, 18, 18))
    fitted = ImageOps.contain(original, (1000, 780), Image.Resampling.LANCZOS)
    screen.paste(fitted, ((1200 - fitted.width) // 2, (900 - fitted.height) // 2))
    return {"original": original, "jpeg_reencoded": recompressed, "screen_like": screen}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", type=Path, default=ROOT / "data/colab-trained/ensemble-v2/ddh-whole-image-ai-v2.pth")
    parser.add_argument("--per-source", type=int, default=50)
    parser.add_argument("--threshold", type=float)
    args = parser.parse_args()
    if not 1 <= args.per_source <= 500:
        parser.error("--per-source must be between 1 and 500")
    checkpoint = torch.load(args.checkpoint, map_location="cpu", weights_only=False)
    model = mobilenet_v3_small(weights=None)
    model.classifier[-1] = torch.nn.Linear(model.classifier[-1].in_features, 2)
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    torch.set_num_threads(min(4, torch.get_num_threads()))
    size = int(checkpoint.get("image_size", 224))
    transform = transforms.Compose([
        transforms.Resize((size, size)), transforms.ToTensor(),
        transforms.Normalize((.485, .456, .406), (.229, .224, .225)),
    ])
    threshold = float(args.threshold if args.threshold is not None else checkpoint.get("decision_threshold", .66))
    if not 0 < threshold < 1:
        parser.error("--threshold must be between 0 and 1")
    scores: dict[tuple[str, str], list[float]] = defaultdict(list)
    flips: dict[tuple[str, str], int] = defaultdict(int)
    with torch.inference_mode():
        for category, label, path in select_samples(args.per_source):
            with Image.open(path) as image:
                copies = variants(image)
            names = list(copies)
            batch = torch.stack([transform(copies[name]) for name in names])
            probabilities = torch.softmax(model(batch), 1)[:, 1].tolist()
            baseline = probabilities[0] >= threshold
            for name, score in zip(names, probabilities):
                scores[(category, name)].append(score)
                if (score >= threshold) != baseline:
                    flips[(category, name)] += 1
    results = []
    for (category, variant), values in sorted(scores.items()):
        label = next(source_label for source_category, source_label, _ in SOURCES if source_category == category)
        errors = sum((score >= threshold) != (label == "deepfake") for score in values)
        suspicious = sum(threshold - .15 <= score < threshold for score in values)
        results.append({
            "category": category, "label": label, "variant": variant,
            "samples": len(values), "mean_deepfake_score": round(sum(values) / len(values), 4),
            "classification_errors": errors, "suspicious_band": suspicious,
            "prediction_flips_from_original": flips[(category, variant)],
        })
    print(json.dumps({
        "checkpoint": args.checkpoint.name, "threshold": threshold,
        "source_policy": "public files excluded by V6/V7 source SHA256; no private photos",
        "warning": "Screen-like transformations are simulated; this is not a new independent source benchmark.",
        "results": results,
    }, indent=2))


if __name__ == "__main__":
    main()
