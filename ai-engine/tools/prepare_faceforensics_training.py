#!/usr/bin/env python
"""Prepare a holdout-excluded FaceForensics++ frame training dataset."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def output(arguments: list[str]) -> str:
    return subprocess.run(arguments, check=True, capture_output=True, text=True).stdout.strip()


def duration(video: Path, ffprobe: str) -> float:
    value = float(output([ffprobe, "-v", "error", "-show_entries", "format=duration", "-of", "default=noprint_wrappers=1:nokey=1", str(video)]))
    if value <= 0:
        raise ValueError(f"Video has no usable duration: {video}")
    return value


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def groups(fake_videos: list[Path]) -> dict[str, str]:
    result: dict[str, str] = {}
    for video in fake_videos:
        members = video.stem.split("_")
        group = "_".join(sorted(members))
        result[video.stem] = group
        for member in members:
            result[member] = group
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("holdout", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--frames-per-video", type=int, default=6)
    parser.add_argument("--image-size", type=int, default=224)
    parser.add_argument("--ffmpeg", default="ffmpeg")
    parser.add_argument("--ffprobe", default="ffprobe")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    if args.frames_per_video < 1:
        raise ValueError("frames-per-video must be positive")
    if not shutil.which(args.ffmpeg) or not shutil.which(args.ffprobe):
        raise RuntimeError("ffmpeg and ffprobe must be available on PATH")

    relative_authentic = Path("original_sequences/youtube/c40/videos")
    relative_fake = Path("manipulated_sequences/Deepfakes/c40/videos")
    authentic = sorted((args.source / relative_authentic).glob("*.mp4"))
    fake = sorted((args.source / relative_fake).glob("*.mp4"))
    holdout_authentic = sorted((args.holdout / relative_authentic).glob("*.mp4"))
    holdout_fake = sorted((args.holdout / relative_fake).glob("*.mp4"))
    if not authentic or not fake or not holdout_authentic or not holdout_fake:
        raise FileNotFoundError("Training and holdout authentic/deepfake video folders are required")

    group_lookup = groups(fake)
    holdout_group_lookup = groups(holdout_fake)
    excluded_groups = set(holdout_group_lookup.values())
    excluded_groups.update(group_lookup.get(video.stem, video.stem) for video in holdout_authentic)
    selected_authentic = [video for video in authentic if group_lookup.get(video.stem, video.stem) not in excluded_groups]
    selected_fake = [video for video in fake if group_lookup.get(video.stem, video.stem) not in excluded_groups]
    if not selected_authentic or not selected_fake:
        raise ValueError("Holdout exclusion left no training videos")

    if args.output.exists():
        if not args.overwrite:
            raise FileExistsError(f"Output already exists: {args.output}")
        shutil.rmtree(args.output)
    (args.output / "authentic").mkdir(parents=True)
    (args.output / "deepfake").mkdir(parents=True)

    records: list[dict[str, object]] = []
    for label, videos in (("authentic", selected_authentic), ("deepfake", selected_fake)):
        for video in videos:
            video_duration = duration(video, args.ffprobe)
            source_group = group_lookup.get(video.stem, "_".join(sorted(video.stem.split("_"))))
            for frame_index in range(args.frames_per_video):
                timestamp = video_duration * (frame_index + 0.5) / args.frames_per_video
                target = args.output / label / f"{video.stem}-frame-{frame_index + 1:02d}.jpg"
                subprocess.run([args.ffmpeg, "-hide_banner", "-loglevel", "error", "-y", "-ss", f"{timestamp:.6f}", "-i", str(video), "-frames:v", "1", "-q:v", "2", str(target)], check=True)
                records.append({"relative_path": target.relative_to(args.output).as_posix(), "label": label, "source_video": video.name, "source_group": source_group, "frame_index": frame_index + 1, "timestamp_seconds": f"{timestamp:.6f}", "sha256": digest(target)})

    manifest_path = args.output / "group_manifest.csv"
    with manifest_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    class_counts = {label: sum(record["label"] == label for record in records) for label in ("authentic", "deepfake")}
    dataset_digest = hashlib.sha256()
    for record in sorted(records, key=lambda item: str(item["relative_path"])):
        dataset_digest.update(str(record["relative_path"]).encode("utf-8"))
        dataset_digest.update(str(record["sha256"]).encode("ascii"))
    dataset = {
        "type": "image_classification", "classes": ["authentic", "deepfake"],
        "image_size": args.image_size, "record_count": len(records),
        "class_distribution": class_counts, "frames_per_video": args.frames_per_video,
        "source_group_count": len({record["source_group"] for record in records}),
        "group_manifest": manifest_path.name, "split_strategy": "source_group_stratified",
        "holdout_excluded": True, "excluded_holdout_groups": sorted(excluded_groups),
        "source": str(args.source.resolve()), "holdout_source": str(args.holdout.resolve()),
        "manifest_sha256": digest(manifest_path),
        "sha256": dataset_digest.hexdigest(),
    }
    (args.output / "dataset.json").write_text(json.dumps(dataset, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dataset, indent=2))


if __name__ == "__main__":
    main()
