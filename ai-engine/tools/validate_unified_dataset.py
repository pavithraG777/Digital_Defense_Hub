from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from app.config import get_settings
from app.image_training_service import validate_image_dataset


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path)
    args = parser.parse_args()
    path, manifest = validate_image_dataset(str(args.dataset), get_settings().training_dataset_root)
    provenance = list(csv.DictReader((path / str(manifest["provenance_manifest"])).open(newline="", encoding="utf-8")))
    groups = list(csv.DictReader((path / str(manifest["group_manifest"])).open(newline="", encoding="utf-8")))
    split_manifest_name = manifest.get("split_manifest")
    splits = (
        list(csv.DictReader((path / str(split_manifest_name)).open(newline="", encoding="utf-8")))
        if split_manifest_name
        else []
    )
    hashes = [row["source_sha256"] for row in provenance]
    private = [row for row in groups if row["source_group"].startswith("train-only:")]
    split_by_path = {row["relative_path"]: row["split"] for row in splits}
    private_outside_train = [
        row["relative_path"] for row in private if split_by_path.get(row["relative_path"]) != "train"
    ]
    splits_by_group: dict[str, set[str]] = {}
    for row in groups:
        splits_by_group.setdefault(row["source_group"], set()).add(
            split_by_path.get(row["relative_path"], "missing")
        )
    cross_split_groups = {
        group: sorted(values) for group, values in splits_by_group.items() if len(values) > 1
    }
    split_distribution = Counter(
        f'{row["split"]}:{row["class"]}' for row in provenance
    )
    result = {
        "path": str(path),
        "record_count": manifest["record_count"],
        "class_distribution": manifest["class_distribution"],
        "category_distribution": manifest["category_distribution"],
        "provenance_rows": len(provenance),
        "group_rows": len(groups),
        "split_rows": len(splits),
        "split_distribution": dict(split_distribution),
        "unique_source_hashes": len(set(hashes)),
        "duplicate_source_hashes": len(hashes) - len(set(hashes)),
        "train_only_private_records": len(private),
        "train_only_groups": dict(Counter(row["source_group"] for row in private)),
        "private_records_outside_train": len(private_outside_train),
        "cross_split_source_groups": len(cross_split_groups),
    }
    if len(provenance) != manifest["record_count"] or len(groups) != manifest["record_count"]:
        raise SystemExit("manifest row count mismatch")
    if len(hashes) != len(set(hashes)):
        raise SystemExit("duplicate source content found")
    if splits and len(splits) != manifest["record_count"]:
        raise SystemExit("split manifest row count mismatch")
    if splits and len(split_by_path) != len(splits):
        raise SystemExit("duplicate paths found in split manifest")
    if private_outside_train:
        raise SystemExit("private train-only records leaked outside the training split")
    if cross_split_groups:
        raise SystemExit("source groups leaked across dataset splits")
    expected_split_distribution = manifest.get("split_distribution")
    if expected_split_distribution and dict(split_distribution) != expected_split_distribution:
        raise SystemExit("split distribution does not match dataset manifest")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
