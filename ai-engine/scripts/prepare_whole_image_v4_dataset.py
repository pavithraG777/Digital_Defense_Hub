"""Build the locked, source-aware DDH whole-image detector V4 dataset."""

from __future__ import annotations

import csv
import hashlib
import json
import random
import shutil
from collections import Counter, defaultdict
from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "datasets" / "ddh-whole-image-v4"
SYNTH_ROOT = ROOT / "data" / "downloaded" / "modern-ai-generated" / "synthbuster-plus"
REAL_SOURCES = {
    "coco_camera_scene": ROOT / "data" / "downloaded" / "coco2017" / "val2017",
    "legacy_camera_real": ROOT / "data" / "downloaded" / "ddata" / "train" / "real",
}
SEED = 20260916
EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp"}

# These assignments are part of the evaluation contract. Do not tune against
# the final-test generators and then continue calling that set a holdout.
VALIDATION_GENERATORS = {"SD3-medium"}
TEST_GENERATORS = {"dalle3", "imagen3"}
SPLIT_PROMPT_BUCKETS = {"train": 320, "validation": 160, "test": 160}
SPLIT_GENERATOR_QUOTAS = {"train": 300, "validation": 150, "test": 150}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stable_order(value: str) -> str:
    return hashlib.sha256(f"{SEED}:{value}".encode()).hexdigest()


def valid_images(root: Path) -> list[Path]:
    if not root.is_dir():
        raise ValueError(f"Required image source is missing: {root}")
    result = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in EXTENSIONS:
            continue
        try:
            with Image.open(path) as image:
                image.verify()
            result.append(path)
        except OSError:
            continue
    return result


def choose_unique(
    candidates: list[tuple[Path, str, str]], count: int, used_hashes: set[str]
) -> list[tuple[Path, str, str, str]]:
    selected = []
    for path, source, group in sorted(candidates, key=lambda item: stable_order(f"{item[1]}:{item[2]}")):
        checksum = sha256(path)
        if checksum in used_hashes:
            continue
        used_hashes.add(checksum)
        selected.append((path, source, group, checksum))
        if len(selected) == count:
            return selected
    raise ValueError(f"Required {count} unique images, found {len(selected)}")


def main() -> None:
    if OUTPUT.exists():
        raise SystemExit(f"Output already exists: {OUTPUT}")
    temporary = OUTPUT.with_name(f".{OUTPUT.name}.preparing")
    if temporary.exists():
        raise SystemExit(f"Temporary output already exists: {temporary}")

    manifest_path = SYNTH_ROOT / "manifest.csv"
    if not manifest_path.is_file():
        raise ValueError(f"SynthBuster manifest is missing: {manifest_path}")
    synth_rows = list(csv.DictReader(manifest_path.open(encoding="utf-8", newline="")))
    by_generator: dict[str, list[tuple[Path, str, str]]] = defaultdict(list)
    for row in synth_rows:
        path = SYNTH_ROOT / row["file"]
        image_id = path.stem.rsplit("__", 1)[-1]
        by_generator[row["source"]].append((path, row["source"], f"prompt:{image_id}"))
    if len(by_generator) != 13:
        raise ValueError(f"Expected 13 generators, found {sorted(by_generator)}")

    prompt_ids = sorted(
        {group.removeprefix("prompt:") for rows in by_generator.values() for _, _, group in rows},
        key=stable_order,
    )
    if len(prompt_ids) != sum(SPLIT_PROMPT_BUCKETS.values()):
        raise ValueError(f"Expected 640 shared prompt IDs, found {len(prompt_ids)}")
    allowed_prompts: dict[str, set[str]] = {}
    start = 0
    for split in ("train", "validation", "test"):
        end = start + SPLIT_PROMPT_BUCKETS[split]
        allowed_prompts[split] = set(prompt_ids[start:end])
        start = end

    used_hashes: set[str] = set()
    records: list[dict[str, str]] = []
    split_ai_counts: Counter[str] = Counter()
    selected_generator_counts: Counter[str] = Counter()
    for generator, candidates in sorted(by_generator.items()):
        split = (
            "validation" if generator in VALIDATION_GENERATORS
            else "test" if generator in TEST_GENERATORS
            else "train"
        )
        candidates = [
            item for item in candidates
            if item[2].removeprefix("prompt:") in allowed_prompts[split]
        ]
        quota = SPLIT_GENERATOR_QUOTAS[split]
        for path, source, group, checksum in choose_unique(candidates, quota, used_hashes):
            records.append({
                "source_path": str(path.resolve()), "class": "deepfake", "split": split,
                "category": "ai_generated", "source": source, "source_group": group,
                "source_sha256": checksum,
            })
            split_ai_counts[split] += 1
            selected_generator_counts[source] += 1

    # Match authentic counts to each AI split and draw equally from two camera
    # sources. Paths are selected once, so authentic content cannot cross splits.
    real_pools = {
        name: [(path, name, f"file:{path.resolve()}") for path in valid_images(root)]
        for name, root in REAL_SOURCES.items()
    }
    for source, pool in real_pools.items():
        random.Random(SEED).shuffle(pool)
    for split in ("train", "validation", "test"):
        required = split_ai_counts[split]
        base, remainder = divmod(required, len(real_pools))
        for index, (source, pool) in enumerate(sorted(real_pools.items())):
            count = base + (index < remainder)
            chosen = choose_unique(pool, count, used_hashes)
            chosen_paths = {item[0] for item in chosen}
            real_pools[source] = [item for item in pool if item[0] not in chosen_paths]
            for path, _, group, checksum in chosen:
                records.append({
                    "source_path": str(path.resolve()), "class": "authentic", "split": split,
                    "category": source, "source": source, "source_group": group,
                    "source_sha256": checksum,
                })

    temporary.mkdir(parents=True)
    counters: Counter[str] = Counter()
    output_rows = []
    try:
        for record in sorted(records, key=lambda row: (row["split"], row["class"], stable_order(row["source_path"]))):
            source_path = Path(record.pop("source_path"))
            counters[record["class"]] += 1
            destination_dir = temporary / record["class"]
            destination_dir.mkdir(exist_ok=True)
            destination = destination_dir / f"{counters[record['class']]:05d}{source_path.suffix.lower()}"
            try:
                destination.hardlink_to(source_path)
            except OSError:
                shutil.copy2(source_path, destination)
            output_rows.append({"relative_path": destination.relative_to(temporary).as_posix(), **record})

        manifest_csv = temporary / "provenance.csv"
        with manifest_csv.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(output_rows[0]))
            writer.writeheader()
            writer.writerows(output_rows)

        distribution = Counter((row["split"], row["class"]) for row in output_rows)
        contract = {
            "name": "DDH Whole Image V4",
            "task": "camera_authentic_vs_ai_generated",
            "record_count": len(output_rows),
            "class_distribution": dict(counters),
            "split_distribution": {f"{split}:{label}": count for (split, label), count in sorted(distribution.items())},
            "generator_distribution": dict(sorted(selected_generator_counts.items())),
            "validation_only_generators": sorted(VALIDATION_GENERATORS),
            "final_test_only_generators": sorted(TEST_GENERATORS),
            "selection_seed": SEED,
            "prompt_split_bucket_counts": SPLIT_PROMPT_BUCKETS,
            "generator_quota_by_split": SPLIT_GENERATOR_QUOTAS,
            "prompt_split_isolation": "No prompt/image_id crosses train, validation, or final test",
            "content_deduplication": "SHA256 across every class and split",
            "copy_augmentation_policy": "Apply equivalent screenshot/JPEG/resize transforms to both labels during training",
            "threshold_policy": "Calibrate on validation only; report final test once before deployment",
            "provenance_manifest": "provenance.csv",
            "provenance_sha256": sha256(manifest_csv),
        }
        (temporary / "dataset.json").write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
        temporary.rename(OUTPUT)
        print(json.dumps(contract, indent=2))
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


if __name__ == "__main__":
    main()
