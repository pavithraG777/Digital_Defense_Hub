from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from collections import defaultdict
from pathlib import Path

from PIL import Image, ImageOps


EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp"}


def dhash(image: Image.Image, size: int = 8) -> int:
    gray = ImageOps.grayscale(image).resize((size + 1, size), Image.Resampling.LANCZOS)
    pixels = list(gray.getdata())
    value = 0
    for row in range(size):
        offset = row * (size + 1)
        for col in range(size):
            value = (value << 1) | (pixels[offset + col] > pixels[offset + col + 1])
    return value


def distance(left: int, right: int) -> int:
    return (left ^ right).bit_count()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--quarantine", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--near-distance", type=int, default=1)
    args = parser.parse_args()

    root = args.root.resolve()
    files = sorted(path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in EXTENSIONS)
    records = []
    invalid = []
    exact_groups: dict[str, list[dict]] = defaultdict(list)

    for path in files:
        try:
            raw_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            with Image.open(path) as image:
                image.load()
                width, height = image.size
                visual_hash = dhash(image)
            record = {"path": path, "width": width, "height": height, "pixels": width * height, "sha256": raw_hash, "dhash": visual_hash}
            records.append(record)
            exact_groups[raw_hash].append(record)
        except Exception as exc:  # report damaged or unsupported images
            invalid.append({"path": path, "reason": str(exc)})

    removals: dict[Path, str] = {item["path"]: "invalid" for item in invalid}
    exact_duplicate_groups = []
    for group in exact_groups.values():
        if len(group) < 2:
            continue
        keep = max(group, key=lambda item: (item["pixels"], -len(str(item["path"]))))
        exact_duplicate_groups.append([str(item["path"].relative_to(root)) for item in group])
        for item in group:
            if item is not keep:
                removals[item["path"]] = f"exact duplicate of {keep['path'].relative_to(root)}"

    # Only compare within the same label folder. Keep the highest-resolution
    # member of conservative dHash distance 0/1 clusters.
    candidates = [item for item in records if item["path"] not in removals]
    near_pairs = []
    for index, left in enumerate(candidates):
        for right in candidates[index + 1 :]:
            if left["path"].parent != right["path"].parent:
                continue
            delta = distance(left["dhash"], right["dhash"])
            if delta <= args.near_distance:
                keep, remove = (left, right) if left["pixels"] >= right["pixels"] else (right, left)
                if remove["path"] not in removals:
                    removals[remove["path"]] = f"near duplicate (dHash {delta}) of {keep['path'].relative_to(root)}"
                    near_pairs.append({"keep": str(keep["path"].relative_to(root)), "remove": str(remove["path"].relative_to(root)), "distance": delta})

    low_resolution = [str(item["path"].relative_to(root)) for item in records if min(item["width"], item["height"]) < 224]
    report = {
        "root": str(root),
        "scanned": len(files),
        "valid": len(records),
        "invalid": [{"path": str(item["path"].relative_to(root)), "reason": item["reason"]} for item in invalid],
        "exact_duplicate_groups": exact_duplicate_groups,
        "near_duplicate_pairs": near_pairs,
        "low_resolution_under_224": low_resolution,
        "removal_count": len(removals),
        "removals": [{"path": str(path.relative_to(root)), "reason": reason} for path, reason in sorted(removals.items())],
    }

    if args.apply:
        if not args.quarantine:
            parser.error("--quarantine is required with --apply")
        quarantine = args.quarantine.resolve()
        for path in removals:
            target = quarantine / path.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                target = target.with_name(f"{target.stem}-{hashlib.sha256(str(path).encode()).hexdigest()[:8]}{target.suffix}")
            shutil.move(str(path), str(target))
        report["quarantine"] = str(quarantine)

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
