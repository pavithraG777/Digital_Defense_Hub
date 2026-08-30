from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
from pathlib import Path

import cv2

from prepare_faceforensics_face_context import (
    dataset_digest,
    has_green_codec_corruption,
    largest_face,
    square_context_crop,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a balanced, paired, early-window FaceForensics face-context dataset."
    )
    parser.add_argument("video_root", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--frames-per-group", type=int, default=2)
    parser.add_argument("--image-size", type=int, default=224)
    parser.add_argument("--context-scale", type=float, default=2.35)
    parser.add_argument("--holdout-manifest", type=Path)
    return parser.parse_args()


def video_metadata(path: Path) -> tuple[int, float]:
    capture = cv2.VideoCapture(str(path))
    try:
        frames = int(capture.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = float(capture.get(cv2.CAP_PROP_FPS))
    finally:
        capture.release()
    if frames <= 0 or fps <= 0:
        raise RuntimeError(f"invalid video metadata: {path}")
    return frames, fps


def read_fraction(path: Path, fraction: float):
    frames, fps = video_metadata(path)
    frame_number = max(0, min(frames - 1, round((frames - 1) * fraction)))
    capture = cv2.VideoCapture(str(path))
    try:
        capture.set(cv2.CAP_PROP_POS_FRAMES, frame_number)
        ok, image = capture.read()
    finally:
        capture.release()
    if not ok or image is None:
        return None
    return image, frame_number, frame_number / fps


def load_detector() -> cv2.CascadeClassifier:
    root = Path(__file__).resolve().parents[1]
    cascade = root / "ai-engine" / "models" / "opencv" / "haarcascades" / "haarcascade_frontalface_default.xml"
    detector = cv2.CascadeClassifier(str(cascade))
    if detector.empty():
        raise RuntimeError("OpenCV frontal-face detector could not be loaded")
    return detector


def main() -> None:
    args = parse_args()
    video_root = args.video_root.resolve()
    destination = args.destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise SystemExit(f"destination must be empty: {destination}")
    if not 1 <= args.frames_per_group <= 4:
        raise SystemExit("frames per group must be between 1 and 4")

    original_dir = video_root / "original_sequences" / "youtube" / "c40" / "videos"
    deepfake_dir = video_root / "manipulated_sequences" / "Deepfakes" / "c40" / "videos"
    if not original_dir.is_dir() or not deepfake_dir.is_dir():
        raise SystemExit("FaceForensics original and Deepfakes c40 video directories are required")

    holdout_groups: set[str] = set()
    if args.holdout_manifest:
        holdout = json.loads(args.holdout_manifest.read_text(encoding="utf-8"))
        holdout_groups = set(holdout.get("excluded_holdout_groups", []))

    fake_names = {path.stem for path in deepfake_dir.glob("*.mp4")}
    groups: list[tuple[str, str, str]] = []
    for name in sorted(fake_names):
        parts = name.split("_")
        if len(parts) != 2:
            continue
        first, second = parts
        canonical = "_".join(sorted((first, second)))
        if name != canonical or f"{second}_{first}" not in fake_names:
            continue
        if canonical in holdout_groups:
            continue
        if not (original_dir / f"{first}.mp4").is_file() or not (original_dir / f"{second}.mp4").is_file():
            continue
        groups.append((canonical, first, second))

    detector = load_detector()
    fractions = (0.04, 0.07, 0.10, 0.13, 0.16, 0.19, 0.22, 0.25)
    rows: list[dict[str, str]] = []
    relative_paths: list[str] = []
    retained_groups = 0
    rejected_groups: list[str] = []
    destination.mkdir(parents=True, exist_ok=True)
    try:
        for group, first, second in groups:
            sources = (
                ("authentic", f"{first}.mp4", original_dir / f"{first}.mp4"),
                ("authentic", f"{second}.mp4", original_dir / f"{second}.mp4"),
                ("deepfake", f"{first}_{second}.mp4", deepfake_dir / f"{first}_{second}.mp4"),
                ("deepfake", f"{second}_{first}.mp4", deepfake_dir / f"{second}_{first}.mp4"),
            )
            accepted: list[list[tuple[str, str, object, tuple[int, int, int, int], int, float]]] = []
            for fraction in fractions:
                candidate = []
                for label, video_name, path in sources:
                    decoded = read_fraction(path, fraction)
                    if decoded is None:
                        candidate = []
                        break
                    image, frame_number, timestamp = decoded
                    face = largest_face(detector, image)
                    if face is None or has_green_codec_corruption(image):
                        candidate = []
                        break
                    candidate.append((label, video_name, image, face, frame_number, timestamp))
                if candidate:
                    accepted.append(candidate)
                if len(accepted) == args.frames_per_group:
                    break
            if len(accepted) != args.frames_per_group:
                rejected_groups.append(group)
                continue

            retained_groups += 1
            for sample_number, candidate in enumerate(accepted, start=1):
                for label, video_name, image, face, frame_number, timestamp in candidate:
                    crop, method, face_box, crop_box = square_context_crop(image, face, args.context_scale)
                    resized = cv2.resize(crop, (args.image_size, args.image_size), interpolation=cv2.INTER_AREA)
                    relative_path = f"{label}/{Path(video_name).stem}-frame-{sample_number:02d}.jpg"
                    output_path = destination / relative_path
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    if not cv2.imwrite(str(output_path), resized, [cv2.IMWRITE_JPEG_QUALITY, 95]):
                        raise RuntimeError(f"cannot write image: {relative_path}")
                    image_hash = hashlib.sha256(output_path.read_bytes()).hexdigest()
                    rows.append({
                        "relative_path": relative_path,
                        "label": label,
                        "source_video": video_name,
                        "source_group": group,
                        "frame_index": str(sample_number),
                        "source_frame_number": str(frame_number),
                        "timestamp_seconds": f"{timestamp:.6f}",
                        "sha256": image_hash,
                        "crop_method": method,
                        "detected_face_box": face_box,
                        "context_crop_box": crop_box,
                    })
                    relative_paths.append(relative_path)

        if not rows:
            raise RuntimeError("no complete clean source groups were found")
        with (destination / "group_manifest.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        authentic_count = sum(row["label"] == "authentic" for row in rows)
        deepfake_count = len(rows) - authentic_count
        dataset = {
            "type": "image_classification",
            "classes": ["authentic", "deepfake"],
            "image_size": args.image_size,
            "record_count": len(rows),
            "class_distribution": {"authentic": authentic_count, "deepfake": deepfake_count},
            "frames_per_group": args.frames_per_group,
            "source_group_count": retained_groups,
            "group_manifest": "group_manifest.csv",
            "split_strategy": "source_group_stratified",
            "holdout_excluded": True,
            "excluded_holdout_groups": sorted(holdout_groups),
            "rejected_incomplete_groups": rejected_groups,
            "source": str(video_root),
            "preprocessing": "EARLY_WINDOW_FACE_CONTEXT_CROP_V2",
            "context_scale": args.context_scale,
            "codec_corruption_validation": "PASS",
            "face_fallback_count": 0,
            "whole_image_analysis": False,
            "face_context_analysis": True,
            "sha256": dataset_digest(destination, relative_paths),
        }
        (destination / "dataset.json").write_text(json.dumps(dataset, indent=2) + "\n", encoding="utf-8")
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise

    print(json.dumps({
        "destination": str(destination),
        "record_count": len(rows),
        "authentic_count": authentic_count,
        "deepfake_count": deepfake_count,
        "source_group_count": retained_groups,
        "rejected_group_count": len(rejected_groups),
        "sha256": dataset["sha256"],
    }, indent=2))


if __name__ == "__main__":
    main()
