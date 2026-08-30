#!/usr/bin/env python
"""Prepare a leakage-safe FaceForensics++ frame holdout with provenance."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def command_output(arguments: list[str]) -> str:
    result = subprocess.run(arguments, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def duration_seconds(video: Path, ffprobe: str) -> float:
    value = command_output([
        ffprobe,
        "-v", "error",
        "-show_entries", "format=duration",
        "-of", "default=noprint_wrappers=1:nokey=1",
        str(video),
    ])
    duration = float(value)
    if duration <= 0:
        raise ValueError(f"Video has no usable duration: {video}")
    return duration


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def pair_map(fake_videos: list[Path]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for video in fake_videos:
        members = video.stem.split("_")
        group = "_".join(sorted(members))
        for member in members:
            mapping[member] = group
    return mapping


def extract_frame(video: Path, output: Path, timestamp: float, ffmpeg: str) -> None:
    subprocess.run([
        ffmpeg,
        "-hide_banner", "-loglevel", "error", "-y",
        "-ss", f"{timestamp:.6f}", "-i", str(video),
        "-frames:v", "1", "-q:v", "2", str(output),
    ], check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="FaceForensics++ data root")
    parser.add_argument("output", type=Path, help="Prepared holdout output directory")
    parser.add_argument("--frames-per-video", type=int, default=10)
    parser.add_argument("--ffmpeg", default="ffmpeg")
    parser.add_argument("--ffprobe", default="ffprobe")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()

    if args.frames_per_video < 1:
        raise ValueError("frames-per-video must be positive")
    if shutil.which(args.ffmpeg) is None or shutil.which(args.ffprobe) is None:
        raise RuntimeError("ffmpeg and ffprobe must be available on PATH")

    authentic_root = args.source / "original_sequences" / "youtube" / "c40" / "videos"
    deepfake_root = args.source / "manipulated_sequences" / "Deepfakes" / "c40" / "videos"
    authentic_videos = sorted(authentic_root.glob("*.mp4"))
    deepfake_videos = sorted(deepfake_root.glob("*.mp4"))
    if not authentic_videos or not deepfake_videos:
        raise FileNotFoundError("Both authentic and Deepfakes video folders are required")

    if args.output.exists() and any(args.output.iterdir()):
        if not args.overwrite:
            raise FileExistsError(f"Output is not empty: {args.output}")
        shutil.rmtree(args.output)
    (args.output / "authentic").mkdir(parents=True, exist_ok=True)
    (args.output / "deepfake").mkdir(parents=True, exist_ok=True)

    groups = pair_map(deepfake_videos)
    rows: list[dict[str, object]] = []
    for label, videos in (("authentic", authentic_videos), ("deepfake", deepfake_videos)):
        for video in videos:
            duration = duration_seconds(video, args.ffprobe)
            group = groups.get(video.stem, "_".join(sorted(video.stem.split("_"))))
            for frame_index in range(args.frames_per_video):
                timestamp = duration * (frame_index + 0.5) / args.frames_per_video
                filename = f"{video.stem}_frame_{frame_index + 1:02d}.jpg"
                frame_path = args.output / label / filename
                extract_frame(video, frame_path, timestamp, args.ffmpeg)
                rows.append({
                    "relative_path": frame_path.relative_to(args.output).as_posix(),
                    "label": label,
                    "source_video": video.name,
                    "source_group": group,
                    "frame_index": frame_index + 1,
                    "timestamp_seconds": f"{timestamp:.6f}",
                    "sha256": sha256(frame_path),
                })

    manifest = args.output / "manifest.csv"
    with manifest.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    summary = {
        "authentic_videos": len(authentic_videos),
        "deepfake_videos": len(deepfake_videos),
        "frames_per_video": args.frames_per_video,
        "authentic_frames": sum(row["label"] == "authentic" for row in rows),
        "deepfake_frames": sum(row["label"] == "deepfake" for row in rows),
        "matched_source_groups": len(set(str(row["source_group"]) for row in rows)),
        "manifest_sha256": sha256(manifest),
    }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
