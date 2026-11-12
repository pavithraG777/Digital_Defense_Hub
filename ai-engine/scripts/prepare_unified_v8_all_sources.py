"""Build one deduplicated all-source dataset for the final unified V8 run."""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
from collections import Counter
from pathlib import Path

from PIL import Image, ImageEnhance, ImageFilter, ImageOps

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "datasets" / "unified-deepfake-v8-all-sources"
EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp"}
SEED = "ddh-v8-20260918"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def split_for(group: str, train=70, validation=15) -> str:
    bucket = int(hashlib.sha256(f"{SEED}:{group}".encode()).hexdigest()[:8], 16) % 100
    return "train" if bucket < train else "validation" if bucket < train + validation else "test"


def images(root: Path):
    if not root.is_dir():
        raise ValueError(f"Missing source: {root}")
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in EXTENSIONS)


def main() -> None:
    if OUTPUT.exists():
        raise SystemExit(f"Output already exists: {OUTPUT}")
    temporary = OUTPUT.with_name(f".{OUTPUT.name}.preparing")
    if temporary.exists():
        raise SystemExit(f"Temporary output already exists: {temporary}")
    temporary.mkdir(parents=True)
    seen: set[str] = set()
    rows: list[dict[str, str]] = []
    counts: Counter[str] = Counter()
    skipped: Counter[str] = Counter()

    def add(path: Path, label: str, category: str, source: str, split: str, group: str) -> None:
        try:
            with Image.open(path) as image:
                image.verify()
        except Exception:
            skipped["invalid"] += 1
            return
        checksum = digest(path)
        if checksum in seen:
            skipped["exact_duplicate"] += 1
            return
        seen.add(checksum)
        counts[f"{split}:{label}:{category}"] += 1
        destination_dir = temporary / label
        destination_dir.mkdir(exist_ok=True)
        destination = destination_dir / f"{len(rows) + 1:06d}{path.suffix.lower()}"
        try:
            destination.hardlink_to(path)
        except OSError:
            shutil.copy2(path, destination)
        rows.append({
            "relative_path": destination.relative_to(temporary).as_posix(),
            "split": split, "class": label, "category": category, "source": source,
            "source_group": group, "source_sha256": checksum, "source_path": str(path.resolve()),
        })

    # Largest raw source. Preserve its downloaded test partition as final test.
    ddata = ROOT / "data/downloaded/ddata"
    for original_split in ("train", "test"):
        for folder, label in (("real", "authentic"), ("fake", "deepfake")):
            for path in images(ddata / original_split / folder):
                split = "test" if original_split == "test" else split_for(f"ddata:{path.stem}", 90, 10)
                add(path, label, "legacy_camera_real" if label == "authentic" else "legacy_ai_generated", "ddata", split, f"ddata:{path.stem}")

    # Modern generators: keep the same prompt/image id in one split across generators.
    synth = ROOT / "data/downloaded/modern-ai-generated/synthbuster-plus"
    for row in csv.DictReader((synth / "manifest.csv").open(encoding="utf-8", newline="")):
        path = synth / row["file"]
        image_id = path.stem.rsplit("__", 1)[-1]
        add(path, "deepfake", "modern_ai_generated", f"synthbuster:{row['source']}", split_for(f"synth-prompt:{image_id}"), f"synth-prompt:{image_id}")

    # FaceForensics context crops: split at video/pair group, never at frame level.
    face_root = ROOT / "datasets/faceforensics-expanded-face-context-v4"
    face_manifest = list(csv.DictReader((face_root / "group_manifest.csv").open(encoding="utf-8", newline="")))
    for row in face_manifest:
        label = row.get("label") or ("deepfake" if row["relative_path"].startswith("deepfake/") else "authentic")
        group = row.get("source_group") or row.get("pair_id") or row["relative_path"].split("-frame-", 1)[0]
        add(face_root / row["relative_path"], label, "face_swap" if label == "deepfake" else "faceforensics_real", "faceforensics++", split_for(f"face:{group}"), f"face:{group}")

    # Public/private real sources and user-provided manipulation categories.
    simple_sources = [
        (ROOT / "data/downloaded/coco2017/val2017", "authentic", "coco_camera_scene", "coco"),
        (ROOT / "datasets/kaggle-ai-vs-real-source/real_dataset", "authentic", "kaggle_camera_real", "kaggle-real"),
        (ROOT / "datasets/kaggle-ai-vs-real-source/Ai_generated_dataset", "deepfake", "kaggle_ai_generated", "kaggle-ai"),
        (ROOT / "data/private-training/camera-originals", "authentic", "private_camera", "private-camera"),
        (ROOT / "data/private-training/snapchat-filtered", "deepfake", "snapchat_filtered", "snapchat"),
        (ROOT / "data/private-training/remini-enhanced", "deepfake", "remini_enhanced", "remini"),
    ]
    for root, label, category, source in simple_sources:
        for path in images(root):
            group = f"{source}:{path.stem}"
            add(path, label, category, source, split_for(group), group)

    # Recover any unique files that existed only inside an older prepared version.
    prepared = [
        "synthetic-image-detection-v1-500", "synthetic-image-detection-v2-1000",
        "unified-image-detection-v3-10000", "unified-manipulation-detection-v4-13000",
        "unified-manipulation-detection-v5-10000", "unified-manipulation-detection-v6-20000",
        "unified-manipulation-detection-v7-20000", "ddh-whole-image-v4",
    ]
    for name in prepared:
        dataset = ROOT / "datasets" / name
        manifest = dataset / "provenance.csv"
        if not manifest.is_file():
            continue
        for row in csv.DictReader(manifest.open(encoding="utf-8", newline="")):
            path = dataset / row["relative_path"]
            label = row.get("class") or row.get("label")
            category = row.get("category") or ("legacy_ai_generated" if label == "deepfake" else "legacy_camera_real")
            group = row.get("source_group") or f"prepared:{name}:{Path(row['relative_path']).stem}"
            split = row.get("split") or split_for(group)
            add(path, label, category, f"prepared:{name}", split, group)

    # Controlled synthetic morphs. These are training evidence, not a claim of
    # validation on a real-world morphing benchmark.
    authentic_by_split: dict[str, list[tuple[Path, str]]] = {"train": [], "validation": [], "test": []}
    for row in face_manifest:
        if (row.get("label") or "authentic") != "authentic":
            continue
        group = row.get("source_group") or row["relative_path"].split("-frame-", 1)[0]
        authentic_by_split[split_for(f"face:{group}")].append((face_root / row["relative_path"], group))
    for values in authentic_by_split.values():
        values.sort(key=lambda item: hashlib.sha256(f"{SEED}:{item[1]}".encode()).hexdigest())
    morph_dir = temporary / "generated_morphs"; morph_dir.mkdir()
    morph_index = 0
    for split, required in (("train", 840), ("validation", 180), ("test", 180)):
        values = authentic_by_split[split]
        if len(values) < 2:
            raise ValueError(f"Not enough {split} authentic faces for morph generation")
        for index in range(required):
            left_path, left_group = values[(index * 2) % len(values)]
            right_path, right_group = values[(index * 2 + 1) % len(values)]
            with Image.open(left_path) as left_image, Image.open(right_path) as right_image:
                left = ImageOps.fit(left_image.convert("RGB"), (256, 256), Image.Resampling.LANCZOS)
                right = ImageOps.fit(right_image.convert("RGB"), (256, 256), Image.Resampling.LANCZOS)
                morphed = Image.blend(left, right, 0.5).filter(ImageFilter.GaussianBlur(0.35))
                morphed = ImageEnhance.Sharpness(morphed).enhance(1.15)
                generated = morph_dir / f"morph-{morph_index:04d}.jpg"
                morphed.save(generated, "JPEG", quality=92)
            group = f"morph:{left_group}:{right_group}"
            add(generated, "deepfake", "synthetic_morph", "ddh-controlled-morph", split, group)
            morph_index += 1

    with (temporary / "provenance.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    split_distribution = Counter(f"{row['split']}:{row['class']}" for row in rows)
    category_distribution = Counter(f"{row['split']}:{row['category']}" for row in rows)
    manifest = {
        "name": "DDH Unified Deepfake V8 All Sources", "task": "unified_manipulated_image_detection",
        "classes": ["authentic", "deepfake"], "record_count": len(rows),
        "class_distribution": dict(Counter(row["class"] for row in rows)),
        "split_distribution": dict(split_distribution), "category_distribution": dict(category_distribution),
        "content_deduplication": "SHA256 across all sources and prepared versions",
        "split_strategy": "source/prompt/video-group isolated; original ddata test preserved",
        "morphing_scope": "controlled synthetic face blends; not a real-world morph benchmark",
        "skipped": dict(skipped), "provenance_manifest": "provenance.csv",
    }
    (temporary / "dataset.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    temporary.rename(OUTPUT)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
