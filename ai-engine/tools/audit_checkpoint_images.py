from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import torch
from PIL import Image
from torchvision import transforms
from torchvision.models import mobilenet_v3_small


EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("images", type=Path)
    parser.add_argument("--exclude-provenance", type=Path)
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args()

    checkpoint = torch.load(args.checkpoint, map_location="cpu", weights_only=False)
    model = mobilenet_v3_small(weights=None)
    model.classifier[-1] = torch.nn.Linear(model.classifier[-1].in_features, 2)
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    size = int(checkpoint.get("image_size", 224))
    transform = transforms.Compose(
        [
            transforms.Resize((size, size)),
            transforms.ToTensor(),
            transforms.Normalize((.485, .456, .406), (.229, .224, .225)),
        ]
    )
    excluded: set[Path] = set()
    if args.exclude_provenance:
        with args.exclude_provenance.open(newline="", encoding="utf-8") as stream:
            excluded = {Path(row["source_relative_path"]).resolve() for row in csv.DictReader(stream)}
    images = sorted(
        path for path in args.images.rglob("*")
        if path.is_file() and path.suffix.lower() in EXTENSIONS and path.resolve() not in excluded
    )
    scores: list[tuple[Path, float]] = []
    with torch.no_grad():
        for path in images:
            try:
                with Image.open(path) as image:
                    tensor = transform(image.convert("RGB")).unsqueeze(0)
                score = torch.softmax(model(tensor), dim=1)[0, 1].item()
                scores.append((path, score))
            except OSError:
                continue
    predicted_deepfake = sum(score >= args.threshold for _, score in scores)
    ordered = sorted(scores, key=lambda item: item[1], reverse=True)
    result = {
        "valid_images": len(scores),
        "threshold": args.threshold,
        "predicted_deepfake": predicted_deepfake,
        "predicted_authentic": len(scores) - predicted_deepfake,
        "deepfake_rate": predicted_deepfake / len(scores) if scores else None,
        "mean_deepfake_probability": sum(score for _, score in scores) / len(scores) if scores else None,
        "highest_deepfake_scores": [
            {"path": str(path), "deepfake_probability": score} for path, score in ordered[:10]
        ],
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
