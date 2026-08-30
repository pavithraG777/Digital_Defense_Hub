from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import sys
from pathlib import Path

from PIL import Image, UnidentifiedImageError


SUPPORTED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp"}


def valid_images(source: Path) -> list[Path]:
    candidates: list[Path] = []
    for path in source.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        try:
            with Image.open(path) as image:
                image.verify()
        except (OSError, UnidentifiedImageError):
            continue
        candidates.append(path)
    return candidates


def copy_class_sample(
    source: Path,
    destination: Path,
    count: int,
    randomizer: random.Random,
) -> list[Path]:
    images = valid_images(source)
    if len(images) < count:
        raise ValueError(
            f"{source} contains {len(images)} valid images; {count} are required"
        )
    randomizer.shuffle(images)
    selected = images[:count]
    destination.mkdir(parents=True, exist_ok=False)
    copied: list[Path] = []
    for index, source_path in enumerate(selected, start=1):
        target = destination / f"{index:04d}{source_path.suffix.lower()}"
        shutil.copy2(source_path, target)
        copied.append(target)
    return copied


def dataset_digest(files: list[Path], root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def prepare_dataset(
    source_root: Path,
    output_root: Path,
    authentic_source: str,
    deepfake_source: str,
    total: int,
    seed: int,
    image_size: int,
) -> dict[str, object]:
    if total < 4 or total % 2 != 0:
        raise ValueError("total must be an even number of at least 4")
    if image_size < 32 or image_size > 1024:
        raise ValueError("image size must be between 32 and 1024")
    if output_root.exists():
        raise FileExistsError(f"output already exists: {output_root}")

    source_root = source_root.resolve()
    output_root = output_root.resolve()
    authentic_root = (source_root / authentic_source).resolve()
    deepfake_root = (source_root / deepfake_source).resolve()
    for class_root in (authentic_root, deepfake_root):
        try:
            class_root.relative_to(source_root)
        except ValueError as error:
            raise ValueError("class source must stay inside source root") from error
        if not class_root.is_dir():
            raise FileNotFoundError(f"class directory does not exist: {class_root}")

    temporary_root = output_root.with_name(f".{output_root.name}.preparing")
    if temporary_root.exists():
        raise FileExistsError(f"temporary output already exists: {temporary_root}")

    count_per_class = total // 2
    randomizer = random.Random(seed)
    try:
        temporary_root.mkdir(parents=True, exist_ok=False)
        copied = copy_class_sample(
            authentic_root, temporary_root / "authentic", count_per_class, randomizer
        )
        copied.extend(
            copy_class_sample(
                deepfake_root, temporary_root / "deepfake", count_per_class, randomizer
            )
        )
        manifest: dict[str, object] = {
            "type": "image_classification",
            "classes": ["authentic", "deepfake"],
            "image_size": image_size,
            "record_count": total,
            "class_distribution": {
                "authentic": count_per_class,
                "deepfake": count_per_class,
            },
            "selection_seed": seed,
            "source": str(source_root),
            "sha256": dataset_digest(copied, temporary_root),
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


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a balanced, laptop-safe deepfake ImageFolder subset."
    )
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--authentic-source", default="authentic")
    parser.add_argument("--deepfake-source", default="deepfake")
    parser.add_argument("--total", type=int, default=500)
    parser.add_argument("--seed", type=int, default=20260815)
    parser.add_argument("--image-size", type=int, default=224)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        manifest = prepare_dataset(
            arguments.source,
            arguments.output,
            arguments.authentic_source,
            arguments.deepfake_source,
            arguments.total,
            arguments.seed,
            arguments.image_size,
        )
    except (FileExistsError, FileNotFoundError, ValueError) as error:
        print(f"dataset preparation failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
