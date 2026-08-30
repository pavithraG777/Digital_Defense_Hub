from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import shutil
import sys
from collections import defaultdict
from pathlib import Path

from PIL import Image, UnidentifiedImageError


SUPPORTED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp"}


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def valid_images_by_category(
    root: Path,
    *,
    max_images: int | None = None,
    randomizer: random.Random | None = None,
) -> dict[str, list[tuple[Path, str]]]:
    result: dict[str, list[tuple[Path, str]]] = defaultdict(list)
    seen_hashes: set[str] = set()
    candidates = sorted(root.rglob("*"))
    if max_images is not None and randomizer is not None:
        randomizer.shuffle(candidates)
    print(f"Scanning {root} ({len(candidates):,} paths)...", file=sys.stderr, flush=True)
    scanned = 0
    for path in candidates:
        if not path.is_file() or path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        scanned += 1
        if scanned % 1_000 == 0:
            print(
                f"  verified {scanned:,} image candidates; {sum(map(len, result.values())):,} unique valid images",
                file=sys.stderr,
                flush=True,
            )
        try:
            with Image.open(path) as image:
                image.verify()
        except (OSError, UnidentifiedImageError):
            continue
        digest = file_sha256(path)
        if digest in seen_hashes:
            continue
        seen_hashes.add(digest)
        relative = path.relative_to(root)
        category = relative.parts[0] if len(relative.parts) > 1 else "uncategorized"
        result[category].append((path, digest))
        if max_images is not None and sum(map(len, result.values())) >= max_images:
            break
    print(
        f"  complete: {scanned:,} image candidates; {sum(map(len, result.values())):,} unique valid images",
        file=sys.stderr,
        flush=True,
    )
    return dict(result)


def class_roots(source_root: Path) -> tuple[Path, Path]:
    """Return the authentic and generated-image directories for a source."""
    supported_layouts = (
        (source_root / "real_dataset", source_root / "Ai_generated_dataset"),
        (source_root / "train" / "real", source_root / "train" / "fake"),
        (source_root / "real", source_root / "fake"),
        (source_root / "authentic", source_root / "deepfake"),
    )
    selected_layout = next(
        (
            (real_candidate, synthetic_candidate)
            for real_candidate, synthetic_candidate in supported_layouts
            if real_candidate.is_dir() and synthetic_candidate.is_dir()
        ),
        None,
    )
    if selected_layout is None:
        raise FileNotFoundError(
            f"source has no supported class layout: {source_root}; expected "
            "real_dataset/Ai_generated_dataset, train/real and train/fake, "
            "real/fake, or authentic/deepfake"
        )
    return selected_layout


def combine_sources(
    source_roots: list[Path],
    *,
    target_per_class: int | None = None,
    randomizer: random.Random | None = None,
) -> tuple[dict[str, list[tuple[Path, str]]], dict[str, list[tuple[Path, str]]]]:
    """Merge class pools across sources while retaining category balancing."""
    real: dict[str, list[tuple[Path, str]]] = defaultdict(list)
    synthetic: dict[str, list[tuple[Path, str]]] = defaultdict(list)
    real_hashes: set[str] = set()
    synthetic_hashes: set[str] = set()
    for source_root in source_roots:
        real_root, synthetic_root = class_roots(source_root)
        for category, items in valid_images_by_category(
            real_root,
            max_images=target_per_class,
            randomizer=randomizer,
        ).items():
            for item in items:
                if item[1] not in real_hashes:
                    real[category].append(item)
                    real_hashes.add(item[1])
        for category, items in valid_images_by_category(
            synthetic_root,
            max_images=target_per_class,
            randomizer=randomizer,
        ).items():
            for item in items:
                if item[1] not in synthetic_hashes:
                    synthetic[category].append(item)
                    synthetic_hashes.add(item[1])
    return dict(real), dict(synthetic)


def balanced_selection(
    grouped: dict[str, list[tuple[Path, str]]], count: int, randomizer: random.Random
) -> list[tuple[Path, str, str]]:
    if sum(len(items) for items in grouped.values()) < count:
        raise ValueError(f"source contains fewer than {count} unique valid images")
    categories = sorted(grouped)
    if not categories:
        raise ValueError("source contains no valid image categories")
    for items in grouped.values():
        randomizer.shuffle(items)
    selected: list[tuple[Path, str, str]] = []
    offsets = {category: 0 for category in categories}
    while len(selected) < count:
        made_progress = False
        for category in categories:
            offset = offsets[category]
            if offset >= len(grouped[category]):
                continue
            path, digest = grouped[category][offset]
            offsets[category] += 1
            selected.append((path, digest, category))
            made_progress = True
            if len(selected) == count:
                break
        if not made_progress:
            raise ValueError("category-balanced selection exhausted before target count")
    return selected


def dataset_digest(files: list[Path], root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(file_sha256(path).encode("ascii"))
    return digest.hexdigest()


def prepare_synthetic_dataset(
    source_root: Path | list[Path],
    output_root: Path,
    total: int = 500,
    seed: int = 20260823,
    image_size: int = 224,
    task: str = "synthetic_image_detection",
    positive_class_semantics: str = "AI_GENERATED",
) -> dict[str, object]:
    if total < 10 or total % 2:
        raise ValueError("total must be an even number of at least 10")
    if not 32 <= image_size <= 1024:
        raise ValueError("image size must be between 32 and 1024")
    if output_root.exists():
        raise FileExistsError(f"output already exists: {output_root}")

    source_roots = source_root if isinstance(source_root, list) else [source_root]
    source_roots = [root.resolve() for root in source_roots]
    if not source_roots:
        raise ValueError("at least one source is required")
    output_root = output_root.resolve()
    temporary = output_root.with_name(f".{output_root.name}.preparing")
    if temporary.exists():
        raise FileExistsError(f"temporary output already exists: {temporary}")

    randomizer = random.Random(seed)
    per_class = total // 2
    real_pool, synthetic_pool = combine_sources(
        source_roots,
        target_per_class=per_class,
        randomizer=randomizer,
    )
    real = balanced_selection(real_pool, per_class, randomizer)
    synthetic = balanced_selection(synthetic_pool, per_class, randomizer)
    real_hashes = {digest for _, digest, _ in real}
    if real_hashes.intersection(digest for _, digest, _ in synthetic):
        raise ValueError("identical content occurs in both classes")

    copied: list[Path] = []
    rows: list[dict[str, object]] = []
    category_counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"authentic": 0, "ai_generated": 0}
    )
    try:
        temporary.mkdir(parents=True, exist_ok=False)
        for class_name, provenance, samples in (
            ("authentic", "CAMERA_ORIGINAL", real),
            ("deepfake", "AI_GENERATED", synthetic),
        ):
            destination = temporary / class_name
            destination.mkdir()
            for index, (source, digest, category) in enumerate(samples, start=1):
                target = destination / f"{index:04d}{source.suffix.lower()}"
                shutil.copy2(source, target)
                copied.append(target)
                category_counts[category][
                    "authentic" if class_name == "authentic" else "ai_generated"
                ] += 1
                rows.append(
                    {
                        "relative_path": target.relative_to(temporary).as_posix(),
                        "class": class_name,
                        "positive_class_semantics": (
                            positive_class_semantics
                            if class_name == "deepfake"
                            else "CAMERA_ORIGINAL"
                        ),
                        "category": category,
                        "source_relative_path": str(source),
                        "source_sha256": digest,
                    }
                )

        with (temporary / "provenance.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

        manifest: dict[str, object] = {
            "type": "image_classification",
            "task": task,
            # The generic trainer treats ImageFolder class index 1 as the positive class.
            "classes": ["authentic", "deepfake"],
            "positive_class_semantics": positive_class_semantics,
            "negative_class_semantics": "CAMERA_ORIGINAL",
            "image_size": image_size,
            "record_count": total,
            "class_distribution": {"authentic": per_class, "deepfake": per_class},
            "category_distribution": dict(sorted(category_counts.items())),
            "selection_seed": seed,
            "sources": [str(root) for root in source_roots],
            "provenance_manifest": "provenance.csv",
            "content_deduplication": "SHA256",
            "sha256": dataset_digest(copied, temporary),
        }
        (temporary / "dataset.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        temporary.rename(output_root)
        return manifest
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a balanced, deduplicated real-vs-AI-generated image dataset."
    )
    parser.add_argument(
        "--source", type=Path, required=True, action="append",
        help="Source root; specify this option more than once to combine datasets.",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--total", type=int, default=500)
    parser.add_argument("--seed", type=int, default=20260823)
    parser.add_argument("--image-size", type=int, default=224)
    parser.add_argument("--task", default="synthetic_image_detection")
    parser.add_argument("--positive-class-semantics", default="AI_GENERATED")
    arguments = parser.parse_args()
    try:
        manifest = prepare_synthetic_dataset(
            arguments.source,
            arguments.output,
            arguments.total,
            arguments.seed,
            arguments.image_size,
            arguments.task,
            arguments.positive_class_semantics,
        )
    except (FileExistsError, FileNotFoundError, ValueError) as error:
        print(f"synthetic dataset preparation failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
