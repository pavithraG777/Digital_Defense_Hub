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
OUTPUT = ROOT / "datasets" / "unified-manipulation-detection-v6-20000"
SEED = 42
EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp"}

# V6 deliberately adds high-resolution, non-face real-world camera scenes.
# Private identity data remains train-only. Existing upstream test folders are
# never copied into the training split.
QUOTAS = [
    ("train", "authentic", "coco_camera_scene", ROOT / "data/downloaded/coco2017/val2017", 3500, False),
    ("train", "authentic", "legacy_camera_real", ROOT / "data/downloaded/ddata/train/real", 3200, False),
    ("train", "authentic", "faceforensics_real", ROOT / "datasets/faceforensics-expanded-face-context-v3/authentic", 1300, False),
    ("train", "authentic", "private_camera", ROOT / "data/private-training/camera-originals", 200, True),
    ("validation", "authentic", "legacy_camera_real", ROOT / "data/downloaded/ddata/test/real", 900, False),
    ("test", "authentic", "legacy_camera_real", ROOT / "data/downloaded/ddata/test/real", 900, False),
    ("train", "deepfake", "legacy_ai_generated", ROOT / "data/downloaded/ddata/train/fake", 6000, False),
    ("train", "deepfake", "face_swap", ROOT / "datasets/faceforensics-expanded-face-context-v3/deepfake", 1300, False),
    ("train", "deepfake", "modern_ai_generated", ROOT / "data/downloaded/modern-ai-generated/synthbuster-plus", 460, False),
    ("train", "deepfake", "snapchat_filtered", ROOT / "data/private-training/snapchat-filtered", 250, True),
    ("train", "deepfake", "remini_enhanced", ROOT / "data/private-training/remini-enhanced", 190, True),
    ("validation", "deepfake", "legacy_ai_generated", ROOT / "data/downloaded/ddata/test/fake", 900, False),
    ("test", "deepfake", "legacy_ai_generated", ROOT / "data/downloaded/ddata/test/fake", 900, False),
]


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def candidates(root: Path) -> list[Path]:
    if not root.is_dir():
        raise ValueError(f"required source is missing: {root}")
    result = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in EXTENSIONS:
            continue
        try:
            with Image.open(path) as image:
                image.verify()
            result.append(path)
        except OSError:
            continue
    return result


def main() -> None:
    if OUTPUT.exists():
        raise SystemExit(f"output already exists: {OUTPUT}")
    temporary = OUTPUT.with_name(f".{OUTPUT.name}.preparing")
    if temporary.exists():
        raise SystemExit(f"temporary output already exists: {temporary}")
    randomizer = random.Random(SEED)
    selected_hashes: set[str] = set()
    used_paths: set[Path] = set()
    counters: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    split_counts: Counter[str] = Counter()
    provenance: list[dict[str, str]] = []
    groups: list[dict[str, str]] = []
    splits: list[dict[str, str]] = []
    temporary.mkdir(parents=True)
    try:
        for split, label, category, source_root, count, private in QUOTAS:
            pool = [path for path in candidates(source_root) if path not in used_paths]
            randomizer.shuffle(pool)
            chosen = []
            for source in pool:
                checksum = digest(source)
                if checksum in selected_hashes:
                    continue
                chosen.append((source, checksum))
                selected_hashes.add(checksum)
                used_paths.add(source)
                if len(chosen) == count:
                    break
            if len(chosen) != count:
                raise ValueError(f"{split}/{category}: required {count}, found {len(chosen)}")
            destination = temporary / label
            destination.mkdir(exist_ok=True)
            for source, checksum in chosen:
                counters[label] += 1
                categories[f"{split}:{category}"] += 1
                split_counts[f"{split}:{label}"] += 1
                target = destination / f"{counters[label]:05d}{source.suffix.lower()}"
                try:
                    target.hardlink_to(source)
                except OSError:
                    shutil.copy2(source, target)
                relative = target.relative_to(temporary).as_posix()
                provenance.append({"relative_path": relative, "split": split, "class": label, "category": category, "source_relative_path": str(source), "source_sha256": checksum})
                groups.append({"relative_path": relative, "source_group": "train-only:private-owner" if private else f"{category}:{checksum}"})
                splits.append({"relative_path": relative, "split": split})
        for name, rows in (("provenance.csv", provenance), ("group_manifest.csv", groups), ("split_manifest.csv", splits)):
            with (temporary / name).open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
                writer.writeheader(); writer.writerows(rows)
        manifest = {
            "type": "image_classification", "task": "unified_manipulated_image_detection",
            "classes": ["authentic", "deepfake"],
            "positive_class_semantics": "AI_GENERATED_OR_FACE_MANIPULATED",
            "negative_class_semantics": "CAMERA_ORIGINAL", "image_size": 224,
            "record_count": sum(counters.values()), "class_distribution": dict(counters),
            "split_distribution": dict(split_counts), "category_distribution": dict(categories),
            "selection_seed": SEED, "provenance_manifest": "provenance.csv",
            "group_manifest": "group_manifest.csv", "split_manifest": "split_manifest.csv",
            "split_strategy": "explicit_source_isolated_with_private_train_only",
            "content_deduplication": "SHA256",
            "manifest_sha256": digest(temporary / "split_manifest.csv"),
        }
        (temporary / "dataset.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        temporary.rename(OUTPUT)
        print(json.dumps(manifest, indent=2))
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


if __name__ == "__main__":
    main()
