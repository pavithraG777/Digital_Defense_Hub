"""Download a resumable, labelled subset of SynthBuster+ from Hugging Face."""

from __future__ import annotations

import argparse
import csv
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path

from PIL import Image


ROWS_API = "https://datasets-server.huggingface.co/rows"
DATASET = "marco-willi/synthbuster-plus"


def fetch_json(url: str, attempts: int = 5) -> dict:
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=90) as response:
                return json.load(response)
        except Exception:
            if attempt + 1 == attempts:
                raise
            time.sleep(2 ** attempt)
    raise RuntimeError("unreachable")


def download(url: str, destination: Path, attempts: int = 5) -> None:
    temporary = destination.with_suffix(destination.suffix + ".part")
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=120) as response:
                temporary.write_bytes(response.read())
            with Image.open(temporary) as image:
                image.verify()
            temporary.replace(destination)
            return
        except Exception:
            temporary.unlink(missing_ok=True)
            if attempt + 1 == attempts:
                raise
            time.sleep(2 ** attempt)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=4000)
    parser.add_argument("--split", default="train")
    args = parser.parse_args()
    if args.count < 1:
        raise SystemExit("--count must be positive")

    args.output.mkdir(parents=True, exist_ok=True)
    manifest_path = args.output / "manifest.csv"
    existing = {path.stem for path in args.output.glob("*.jpg")}
    manifest_rows: list[dict[str, str]] = []
    if manifest_path.exists():
        with manifest_path.open("r", encoding="utf-8", newline="") as handle:
            manifest_rows = list(csv.DictReader(handle))

    page_size = 100
    manifested = {Path(row["file"]).stem for row in manifest_rows}
    downloaded = len(existing)
    failed_in_pass = 0
    offset = 0
    total = None
    while downloaded < args.count and (total is None or offset < total):
        query = urllib.parse.urlencode({
            "dataset": DATASET,
            "config": "default",
            "split": args.split,
            "offset": offset,
            "length": page_size,
        })
        payload = fetch_json(f"{ROWS_API}?{query}")
        total = int(payload["num_rows_total"])
        for item in payload.get("rows", []):
            row = item["row"]
            if int(row.get("label", -1)) != 1:
                continue
            image_id = str(row["image_id"])
            if image_id in existing:
                if image_id not in manifested:
                    manifest_rows.append({
                        "file": f"{image_id}.jpg",
                        "label": "deepfake",
                        "category": "ai_generated",
                        "source": str(row.get("source", "unknown")),
                        "dataset": DATASET,
                    })
                    manifested.add(image_id)
                continue
            destination = args.output / f"{image_id}.jpg"
            try:
                download(str(row["image"]["src"]), destination, attempts=8)
            except Exception as error:
                failed_in_pass += 1
                print(f"skipped {image_id}: {error}", flush=True)
                continue
            manifest_rows.append({
                "file": destination.name,
                "label": "deepfake",
                "category": "ai_generated",
                "source": str(row.get("source", "unknown")),
                "dataset": DATASET,
            })
            existing.add(image_id)
            manifested.add(image_id)
            downloaded += 1
            if downloaded % 100 == 0:
                print(f"downloaded {downloaded}/{args.count}", flush=True)
            if downloaded >= args.count:
                break
        offset += page_size

        with manifest_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["file", "label", "category", "source", "dataset"],
            )
            writer.writeheader()
            writer.writerows(manifest_rows)

    print(
        f"complete: {downloaded} valid AI-generated images in {args.output}; "
        f"temporary failures={failed_in_pass}"
    )


if __name__ == "__main__":
    main()
