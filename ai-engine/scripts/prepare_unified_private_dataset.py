from __future__ import annotations

import csv
import hashlib
import json
import random
import shutil
from collections import Counter
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "datasets" / "unified-manipulation-detection-v5-10000"
SEED = 42
EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp"}

QUOTAS = [
    ("authentic", "camera_original_public", ROOT / "datasets/unified-image-detection-v3-10000/authentic", 3400, "public-real"),
    ("authentic", "faceforensics_authentic", ROOT / "datasets/faceforensics-expanded-face-context-v3/authentic", 1500, "faceforensics-real"),
    ("authentic", "private_camera", ROOT / "data/private-training/camera-originals", 100, "train-only:private-owner"),
    ("deepfake", "ai_generated", ROOT / "datasets/unified-image-detection-v3-10000/deepfake", 2850, "public-ai"),
    ("deepfake", "modern_ai_generated", ROOT / "data/downloaded/modern-ai-generated/synthbuster-plus", 500, "synthbuster"),
    ("deepfake", "face_swap", ROOT / "datasets/faceforensics-expanded-face-context-v3/deepfake", 1500, "faceforensics-fake"),
    ("deepfake", "snapchat_filtered", ROOT / "data/private-training/snapchat-filtered", 100, "train-only:private-owner"),
    ("deepfake", "remini_enhanced", ROOT / "data/private-training/remini-enhanced", 50, "train-only:private-owner"),
]


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def candidates(root: Path) -> list[tuple[Path, str]]:
    result = []
    seen = set()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in EXTENSIONS:
            continue
        try:
            with Image.open(path) as image:
                image.verify()
        except OSError:
            continue
        checksum = digest(path)
        if checksum not in seen:
            seen.add(checksum)
            result.append((path, checksum))
    return result


def main() -> None:
    if OUTPUT.exists():
        raise SystemExit(f"output already exists: {OUTPUT}")
    temporary = OUTPUT.with_name(f".{OUTPUT.name}.preparing")
    if temporary.exists():
        raise SystemExit(f"temporary output already exists: {temporary}")
    randomizer = random.Random(SEED)
    rows = []
    groups = []
    selected_hashes = set()
    counters = Counter()
    temporary.mkdir(parents=True)
    try:
        for label, category, source_root, count, group_prefix in QUOTAS:
            pool = candidates(source_root)
            randomizer.shuffle(pool)
            chosen = []
            for source, checksum in pool:
                if checksum in selected_hashes:
                    continue
                chosen.append((source, checksum))
                selected_hashes.add(checksum)
                if len(chosen) == count:
                    break
            if len(chosen) != count:
                raise ValueError(f"{category}: required {count}, found {len(chosen)}")
            destination = temporary / label
            destination.mkdir(exist_ok=True)
            for source, checksum in chosen:
                counters[label] += 1
                target = destination / f"{counters[label]:05d}{source.suffix.lower()}"
                shutil.copy2(source, target)
                relative = target.relative_to(temporary).as_posix()
                rows.append({
                    "relative_path": relative,
                    "class": label,
                    "positive_class_semantics": "CAMERA_ORIGINAL" if label == "authentic" else "AI_GENERATED_OR_FACE_MANIPULATED",
                    "category": category,
                    "source_relative_path": str(source),
                    "source_sha256": checksum,
                })
                source_group = f"{group_prefix}:{checksum}"
                if group_prefix == "train-only:private-owner":
                    source_group = group_prefix
                groups.append({"relative_path": relative, "source_group": source_group})

        with (temporary / "provenance.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader(); writer.writerows(rows)
        with (temporary / "group_manifest.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=["relative_path", "source_group"])
            writer.writeheader(); writer.writerows(groups)
        categories = Counter(row["category"] for row in rows)
        manifest = {
            "type": "image_classification",
            "task": "unified_manipulated_image_detection",
            "classes": ["authentic", "deepfake"],
            "positive_class_semantics": "AI_GENERATED_OR_FACE_MANIPULATED",
            "negative_class_semantics": "CAMERA_ORIGINAL",
            "image_size": 224,
            "record_count": len(rows),
            "class_distribution": dict(counters),
            "category_distribution": dict(categories),
            "selection_seed": SEED,
            "sources": [str(item[2]) for item in QUOTAS],
            "provenance_manifest": "provenance.csv",
            "group_manifest": "group_manifest.csv",
            "split_strategy": "source_group_stratified_with_train_only_private_identity",
            "source_group_count": len({row["source_group"] for row in groups}),
            "content_deduplication": "SHA256",
            "manifest_sha256": digest(temporary / "group_manifest.csv"),
        }
        (temporary / "dataset.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        temporary.rename(OUTPUT)
        print(json.dumps(manifest, indent=2))
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


if __name__ == "__main__":
    main()
