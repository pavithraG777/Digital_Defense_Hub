from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import sys
from collections import Counter
from pathlib import Path

from PIL import Image, ImageFilter, UnidentifiedImageError


CATEGORIES = ("animals", "city", "food", "nature", "people")
SUPPORTED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp"}
MANIPULATION_TYPES = (
    ("COPY_MOVE", 15),
    ("REGION_SPLICE", 15),
    ("REGION_REPLACEMENT", 10),
    ("OBJECT_REMOVAL_PATCH", 10),
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def valid_images(root: Path) -> list[Path]:
    images: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        try:
            with Image.open(path) as image:
                image.verify()
        except (OSError, UnidentifiedImageError):
            continue
        images.append(path)
    return sorted(images)


def relative_source(path: Path, source_root: Path) -> str:
    return path.relative_to(source_root).as_posix()


def save_jpeg(image: Image.Image, target: Path, quality: int) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    image.convert("RGB").save(target, "JPEG", quality=quality, optimize=True)


def random_box(image: Image.Image, randomizer: random.Random) -> tuple[int, int, int, int]:
    width, height = image.size
    box_width = max(24, int(width * randomizer.uniform(0.18, 0.35)))
    box_height = max(24, int(height * randomizer.uniform(0.18, 0.35)))
    box_width = min(box_width, width)
    box_height = min(box_height, height)
    left = randomizer.randint(0, max(0, width - box_width))
    top = randomizer.randint(0, max(0, height - box_height))
    return left, top, left + box_width, top + box_height


def destination_for(
    image: Image.Image, patch: Image.Image, randomizer: random.Random
) -> tuple[int, int]:
    return (
        randomizer.randint(0, max(0, image.width - patch.width)),
        randomizer.randint(0, max(0, image.height - patch.height)),
    )


def manipulate(
    source: Path,
    donor: Path,
    subtype: str,
    randomizer: random.Random,
) -> Image.Image:
    with Image.open(source) as opened:
        image = opened.convert("RGB")
    if image.width < 64 or image.height < 64:
        image = image.resize((max(64, image.width), max(64, image.height)))

    source_box = random_box(image, randomizer)
    if subtype == "COPY_MOVE":
        patch = image.crop(source_box)
        image.paste(patch, destination_for(image, patch, randomizer))
        return image

    if subtype == "OBJECT_REMOVAL_PATCH":
        patch = image.crop(source_box).filter(ImageFilter.GaussianBlur(radius=2.0))
        destination = destination_for(image, patch, randomizer)
        mask = Image.new("L", patch.size, 220).filter(ImageFilter.GaussianBlur(radius=5.0))
        image.paste(patch, destination, mask)
        return image

    with Image.open(donor) as opened:
        donor_image = opened.convert("RGB")
    donor_patch = donor_image.crop(random_box(donor_image, randomizer))
    target_width = max(24, source_box[2] - source_box[0])
    target_height = max(24, source_box[3] - source_box[1])
    donor_patch = donor_patch.resize((target_width, target_height))
    destination = (source_box[0], source_box[1])

    if subtype == "REGION_REPLACEMENT":
        image.paste(donor_patch, destination)
        return image

    mask = Image.new("L", donor_patch.size, 235).filter(ImageFilter.GaussianBlur(radius=3.0))
    image.paste(donor_patch, destination, mask)
    return image


def metadata_record(
    target: Path,
    output_root: Path,
    label: str,
    subtype: str,
    category: str,
    source: Path,
    source_root: Path,
    donor: Path | None = None,
    source_reused: bool = False,
) -> dict[str, object]:
    return {
        "file": target.relative_to(output_root).as_posix(),
        "label": label,
        "forensic_subtype": subtype,
        "category": category,
        "source": relative_source(source, source_root),
        "donor": relative_source(donor, source_root) if donor else None,
        "source_reused": source_reused,
        "sha256": sha256_file(target),
    }


def prepare_dataset(source_root: Path, output_root: Path, seed: int) -> dict[str, object]:
    source_root = source_root.resolve()
    output_root = output_root.resolve()
    real_root = source_root / "real_dataset"
    generated_root = source_root / "Ai_generated_dataset"
    if not source_root.is_dir():
        raise FileNotFoundError(f"source dataset directory does not exist: {source_root}")
    if not real_root.is_dir() or not generated_root.is_dir():
        raise FileNotFoundError(
            "source must contain real_dataset and Ai_generated_dataset directories"
        )
    if output_root.exists():
        raise FileExistsError(f"output already exists: {output_root}")
    temporary_root = output_root.with_name(f".{output_root.name}.preparing")
    if temporary_root.exists():
        raise FileExistsError(f"temporary output already exists: {temporary_root}")

    randomizer = random.Random(seed)
    records: list[dict[str, object]] = []
    manipulation_sources: dict[str, list[Path]] = {}
    ai_sources: dict[str, list[Path]] = {}

    try:
        temporary_root.mkdir(parents=True)
        for category in CATEGORIES:
            real = valid_images(real_root / category)
            generated = valid_images(generated_root / category)
            if len(real) < 101 or len(generated) < 50:
                raise ValueError(
                    f"insufficient valid images for category {category}: "
                    f"found {len(real)} authentic and {len(generated)} AI-generated; "
                    "need at least 101 authentic and 50 AI-generated"
                )
            randomizer.shuffle(real)
            randomizer.shuffle(generated)
            authentic, manipulation_sources[category] = real[:100], real[100:]
            ai_sources[category] = generated[:50]

            for index, source in enumerate(authentic, start=1):
                target = temporary_root / "authentic" / f"{category}-{index:03d}.jpg"
                with Image.open(source) as image:
                    save_jpeg(image, target, quality=92)
                records.append(
                    metadata_record(
                        target, temporary_root, "authentic", "CAMERA_ORIGINAL", category,
                        source, source_root,
                    )
                )

            for index, source in enumerate(ai_sources[category], start=1):
                target = temporary_root / "deepfake" / f"{category}-ai-{index:03d}.jpg"
                with Image.open(source) as image:
                    save_jpeg(image, target, quality=92)
                records.append(
                    metadata_record(
                        target, temporary_root, "deepfake", "AI_GENERATED", category,
                        source, source_root,
                    )
                )

        all_manipulation_sources = [
            path for category in CATEGORIES for path in manipulation_sources[category]
        ]
        for category in CATEGORIES:
            sources = manipulation_sources[category]
            expanded_sources = sources + sources[: max(0, 50 - len(sources))]
            randomizer.shuffle(expanded_sources)
            subtypes = [
                subtype
                for subtype, count in MANIPULATION_TYPES
                for _ in range(count)
            ]
            randomizer.shuffle(subtypes)
            usage = Counter[Path]()
            for index, (source, subtype) in enumerate(
                zip(expanded_sources[:50], subtypes, strict=True), start=1
            ):
                usage[source] += 1
                donor_candidates = [path for path in all_manipulation_sources if path != source]
                donor = randomizer.choice(donor_candidates)
                result = manipulate(source, donor, subtype, randomizer)
                target = temporary_root / "deepfake" / f"{category}-manipulated-{index:03d}.jpg"
                save_jpeg(result, target, quality=randomizer.randint(86, 95))
                records.append(
                    metadata_record(
                        target, temporary_root, "deepfake", subtype, category, source,
                        source_root, donor if subtype in {"REGION_SPLICE", "REGION_REPLACEMENT"} else None,
                        source_reused=usage[source] > 1,
                    )
                )

        records.sort(key=lambda record: str(record["file"]))
        metadata_path = temporary_root / "forensic_metadata.jsonl"
        metadata_path.write_text(
            "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
            encoding="utf-8",
        )
        image_hashes = hashlib.sha256()
        for record in records:
            image_hashes.update(str(record["file"]).encode("utf-8"))
            image_hashes.update(str(record["sha256"]).encode("ascii"))
        subtype_counts = Counter(str(record["forensic_subtype"]) for record in records)
        manifest: dict[str, object] = {
            "type": "image_classification",
            "classes": ["authentic", "deepfake"],
            "image_size": 224,
            "record_count": 1000,
            "class_distribution": {"authentic": 500, "deepfake": 500},
            "category_distribution": {category: 200 for category in CATEGORIES},
            "forensic_subtype_distribution": dict(sorted(subtype_counts.items())),
            "selection_seed": seed,
            "source": str(source_root),
            "sha256": image_hashes.hexdigest(),
            "metadata_sha256": sha256_file(metadata_path),
            "provenance_complete": True,
        }
        (temporary_root / "dataset.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        temporary_root.rename(output_root)
        return manifest
    except Exception:
        if temporary_root.exists():
            shutil.rmtree(temporary_root)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare the 1000-image forensic dataset.")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=20260818)
    arguments = parser.parse_args()
    try:
        manifest = prepare_dataset(arguments.source, arguments.output, arguments.seed)
    except (FileExistsError, FileNotFoundError, ValueError) as error:
        print(f"dataset preparation failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
