from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
from collections import defaultdict
from pathlib import Path

import cv2
import numpy as np


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a leakage-safe face-context derivative of a FaceForensics image dataset."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--image-size", type=int, default=224)
    parser.add_argument("--context-scale", type=float, default=2.35)
    return parser.parse_args()


def largest_face(detector: cv2.CascadeClassifier, image) -> tuple[int, int, int, int] | None:
    grayscale = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    minimum = max(32, min(image.shape[:2]) // 12)
    faces = detector.detectMultiScale(
        grayscale,
        scaleFactor=1.08,
        minNeighbors=5,
        minSize=(minimum, minimum),
        flags=cv2.CASCADE_SCALE_IMAGE,
    )
    if len(faces) == 0:
        return None
    return tuple(int(value) for value in max(faces, key=lambda face: int(face[2]) * int(face[3])))


def square_context_crop(image, face: tuple[int, int, int, int] | None, scale: float):
    height, width = image.shape[:2]
    if face is None:
        side = min(height, width)
        center_x, center_y = width / 2, height / 2
        method = "CENTER_CONTEXT_FALLBACK"
        face_values = ""
    else:
        x, y, face_width, face_height = face
        side = min(max(face_width, face_height) * scale, width, height)
        center_x = x + face_width / 2
        center_y = y + face_height * 0.58
        method = "HAAR_FACE_CONTEXT"
        face_values = f"{x}:{y}:{face_width}:{face_height}"

    side = max(1, int(round(side)))
    left = max(0, min(width - side, int(round(center_x - side / 2))))
    top = max(0, min(height - side, int(round(center_y - side / 2))))
    return image[top : top + side, left : left + side], method, face_values, f"{left}:{top}:{side}:{side}"


def dataset_digest(root: Path, relative_paths: list[str]) -> str:
    digest = hashlib.sha256()
    for relative_path in sorted(relative_paths):
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        with (root / relative_path).open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def has_green_codec_corruption(image) -> bool:
    blue, green, red = cv2.split(image)
    bright_green = (green > 180) & (blue < 80) & (red < 80)
    green_16 = green.astype(np.int16)
    dominant_green = (
        (green > 70)
        & (green_16 > red.astype(np.int16) + 35)
        & (green_16 > blue.astype(np.int16) + 35)
    )
    pixel_count = float(green.size)
    return (
        float(np.count_nonzero(bright_green)) / pixel_count >= 0.08
        or float(np.count_nonzero(dominant_green)) / pixel_count >= 0.25
    )


def main() -> None:
    args = parse_args()
    source = args.source.resolve()
    destination = args.destination.resolve()
    if not 64 <= args.image_size <= 1024:
        raise SystemExit("image size must be between 64 and 1024")
    if not 1.25 <= args.context_scale <= 4.0:
        raise SystemExit("context scale must be between 1.25 and 4.0")
    if destination.exists() and any(destination.iterdir()):
        raise SystemExit(f"destination must be empty: {destination}")

    manifest_path = source / "group_manifest.csv"
    dataset_path = source / "dataset.json"
    if not manifest_path.is_file() or not dataset_path.is_file():
        raise SystemExit("source dataset.json and group_manifest.csv are required")

    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    with manifest_path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != int(dataset.get("record_count", -1)):
        raise SystemExit("manifest record count does not match dataset.json")

    cascade_name = "haarcascade_frontalface_default.xml"
    cascade_candidates = [
        Path(cv2.data.haarcascades) / cascade_name,
        Path(__file__).resolve().parents[1] / "ai-engine" / "models" / "opencv" / "haarcascades" / cascade_name,
    ]
    cascade_path = next((path for path in cascade_candidates if path.is_file()), None)
    if cascade_path is None:
        raise SystemExit("OpenCV frontal-face detector model is missing")
    detector = cv2.CascadeClassifier(str(cascade_path))
    if detector.empty():
        raise SystemExit("OpenCV frontal-face detector could not be loaded")

    destination.mkdir(parents=True, exist_ok=True)
    output_rows: list[dict[str, str]] = []
    relative_paths: list[str] = []
    direct_faces: dict[str, tuple[int, int, int, int] | None] = {}
    image_shapes: dict[str, tuple[int, int]] = {}
    sequence_faces: dict[tuple[str, str], list[tuple[int, str, tuple[int, int, int, int]]]] = defaultdict(list)
    corrupt_images: list[str] = []
    corrupt_pair_keys: set[tuple[str, str]] = set()
    for row in rows:
        relative_path = row["relative_path"].replace("\\", "/")
        image = cv2.imread(str(source / relative_path), cv2.IMREAD_COLOR)
        if image is None:
            raise SystemExit(f"cannot decode source image: {relative_path}")
        corrupted = has_green_codec_corruption(image)
        if corrupted:
            corrupt_images.append(relative_path)
            corrupt_pair_keys.add((row["source_group"], row["frame_index"]))
        image_shapes[relative_path] = image.shape[:2]
        face = largest_face(detector, image)
        direct_faces[relative_path] = face
        if face is not None and not corrupted:
            sequence_faces[(row["label"], row["source_video"])].append(
                (int(row["frame_index"]), relative_path, face)
            )

    rows = [
        row for row in rows
        if (row["source_group"], row["frame_index"]) not in corrupt_pair_keys
    ]
    if not rows:
        raise SystemExit("all source rows failed codec-corruption validation")

    retained_paths = {row["relative_path"].replace("\\", "/") for row in rows}
    direct_count = sum(
        face is not None and relative_path in retained_paths
        for relative_path, face in direct_faces.items()
    )
    propagated_count = 0
    fallback_count = 0
    try:
        for row in rows:
            relative_path = row["relative_path"].replace("\\", "/")
            image = cv2.imread(str(source / relative_path), cv2.IMREAD_COLOR)
            if image is None:
                raise RuntimeError(f"cannot decode source image: {relative_path}")
            face = direct_faces[relative_path]
            propagated = False
            if face is None:
                candidates = sequence_faces[(row["label"], row["source_video"])]
                if candidates:
                    _, candidate_path, candidate_face = min(
                        candidates,
                        key=lambda item: abs(item[0] - int(row["frame_index"])),
                    )
                    source_height, source_width = image_shapes[candidate_path]
                    target_height, target_width = image_shapes[relative_path]
                    x, y, width, height = candidate_face
                    face = (
                        round(x * target_width / source_width),
                        round(y * target_height / source_height),
                        round(width * target_width / source_width),
                        round(height * target_height / source_height),
                    )
                    propagated = True
            crop, method, face_box, crop_box = square_context_crop(image, face, args.context_scale)
            if propagated:
                method = "TRACKED_FACE_CONTEXT"
                propagated_count += 1
            elif face is None:
                fallback_count += 1
            resized = cv2.resize(crop, (args.image_size, args.image_size), interpolation=cv2.INTER_AREA)
            output_path = destination / relative_path
            output_path.parent.mkdir(parents=True, exist_ok=True)
            if not cv2.imwrite(str(output_path), resized, [cv2.IMWRITE_JPEG_QUALITY, 95]):
                raise RuntimeError(f"cannot write derived image: {relative_path}")
            output_hash = hashlib.sha256(output_path.read_bytes()).hexdigest()
            output_rows.append(
                {
                    **row,
                    "sha256": output_hash,
                    "crop_method": method,
                    "detected_face_box": face_box,
                    "context_crop_box": crop_box,
                }
            )
            relative_paths.append(relative_path)

        fieldnames = list(output_rows[0])
        with (destination / "group_manifest.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(output_rows)

        dataset.update(
            {
                "image_size": args.image_size,
                "record_count": len(rows),
                "class_distribution": {
                    label: sum(row["label"] == label for row in rows)
                    for label in dataset["classes"]
                },
                "derived_from": str(source),
                "preprocessing": "FACE_CONTEXT_CROP_V1",
                "context_scale": args.context_scale,
                "face_detected_count": direct_count,
                "face_propagated_count": propagated_count,
                "face_fallback_count": fallback_count,
                "codec_corrupt_source_count": len(corrupt_images),
                "excluded_corrupt_pair_count": len(corrupt_pair_keys),
                "whole_image_analysis": False,
                "face_context_analysis": True,
                "sha256": dataset_digest(destination, relative_paths),
            }
        )
        (destination / "dataset.json").write_text(json.dumps(dataset, indent=2) + "\n", encoding="utf-8")
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise

    print(json.dumps({
        "destination": str(destination),
        "record_count": len(rows),
        "face_detected_count": direct_count,
        "face_propagated_count": propagated_count,
        "face_fallback_count": fallback_count,
        "sha256": dataset["sha256"],
    }, indent=2))


if __name__ == "__main__":
    main()
