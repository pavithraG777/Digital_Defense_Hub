#!/usr/bin/env python
"""Attach source-group split metadata to a merged image dataset."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def main() -> None:
    dataset = Path(__file__).parents[2] / "datasets" / "unified-manipulation-detection-v4-13000"
    source_manifest = dataset.parents[0] / "faceforensics-expanded-face-context-v3" / "group_manifest.csv"
    group_lookup: dict[str, str] = {}
    with source_manifest.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            group_lookup[row["relative_path"].replace("\\", "/")] = row["source_group"]

    rows: list[dict[str, str]] = []
    with (dataset / "provenance.csv").open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            source = Path(row["source_relative_path"])
            marker = "faceforensics-expanded-face-context-v3"
            source_group = None
            if marker in source.parts:
                relative = Path(*source.parts[source.parts.index(marker) + 1 :]).as_posix()
                source_group = group_lookup.get(relative)
            group = f"faceforensics:{source_group}" if source_group else f"standalone:{row['source_sha256']}"
            rows.append({"relative_path": row["relative_path"], "source_group": group})

    manifest_path = dataset / "group_manifest.csv"
    with manifest_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["relative_path", "source_group"])
        writer.writeheader()
        writer.writerows(rows)

    metadata_path = dataset / "dataset.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["group_manifest"] = manifest_path.name
    metadata["split_strategy"] = "source_group_stratified"
    metadata["source_group_count"] = len({row["source_group"] for row in rows})
    metadata["manifest_sha256"] = digest(manifest_path)
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"record_count": len(rows), "source_group_count": metadata["source_group_count"], "manifest_sha256": metadata["manifest_sha256"]}, indent=2))


if __name__ == "__main__":
    main()