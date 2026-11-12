"""Download a resumable, labelled subset of SynthBuster+ from Hugging Face."""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import csv
import json
import re
import time
import urllib.parse
import urllib.request
from urllib.error import HTTPError
from pathlib import Path

from PIL import Image


ROWS_API = "https://datasets-server.huggingface.co/rows"
DATASET = "marco-willi/synthbuster-plus"


def fetch_json(url: str, attempts: int = 12) -> dict:
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=90) as response:
                return json.load(response)
        except HTTPError as error:
            if attempt + 1 == attempts:
                raise
            retry_after = error.headers.get("Retry-After")
            delay = float(retry_after) if retry_after else min(60, 5 * (attempt + 1))
            print(f"metadata HTTP {error.code}; retrying in {delay:g}s", flush=True)
            time.sleep(delay)
        except Exception:
            if attempt + 1 == attempts:
                raise
            time.sleep(min(60, 2 ** attempt))
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
    parser.add_argument(
        "--balanced-by-source",
        action="store_true",
        help="Distribute the requested images as evenly as possible across generators.",
    )
    parser.add_argument(
        "--metadata-delay",
        type=float,
        default=1.25,
        help="Delay between dataset metadata pages to avoid HTTP 429 responses.",
    )
    parser.add_argument("--workers", type=int, default=8)
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
    def row_image_id(row: dict[str, str]) -> str:
        return Path(row["file"]).stem.rsplit("__", 1)[-1]

    manifested_keys = {
        (row.get("source", "unknown"), row_image_id(row)) for row in manifest_rows
    }
    manifested = {row_image_id(row) for row in manifest_rows}
    downloaded = len(existing)
    failed_in_pass = 0

    if args.balanced_by_source:
        # Read the lightweight row metadata first.  Taking the first N positive
        # rows is unsafe because Hugging Face datasets are commonly grouped by
        # generator (which previously produced a DALL-E2-only subset here).
        metadata_cache = args.output / ".synthbuster-metadata-cache.json"
        candidates: dict[str, list[dict]] = collections.defaultdict(list)
        offset = 0
        total = None
        if metadata_cache.exists():
            cached = json.loads(metadata_cache.read_text(encoding="utf-8"))
            offset = int(cached.get("offset", 0))
            total = cached.get("total")
            for source, rows in cached.get("candidates", {}).items():
                candidates[source].extend(rows)
            print(f"resuming metadata scan at {offset}/{total or '?'}", flush=True)
        pages_without_ai = 0
        while total is None or offset < total:
            query = urllib.parse.urlencode({
                "dataset": DATASET,
                "config": "default",
                "split": args.split,
                "offset": offset,
                "length": 100,
            })
            payload = fetch_json(f"{ROWS_API}?{query}")
            total = int(payload["num_rows_total"])
            positives_on_page = 0
            for item in payload.get("rows", []):
                row = item["row"]
                if int(row.get("label", -1)) == 1:
                    candidates[str(row.get("source", "unknown"))].append(row)
                    positives_on_page += 1
            pages_without_ai = pages_without_ai + 1 if positives_on_page == 0 else 0
            offset += 100
            if offset % 1000 == 0 or offset >= total:
                found = {source: len(rows) for source, rows in candidates.items()}
                print(f"metadata {min(offset, total)}/{total}; AI sources={found}", flush=True)
                metadata_cache.write_text(json.dumps({
                    "offset": offset,
                    "total": total,
                    "candidates": candidates,
                }), encoding="utf-8")
            # SynthBuster+ is ordered with generated examples before authentic
            # examples. Five complete empty pages provide a conservative
            # boundary check while avoiding thousands of unnecessary API rows.
            if candidates and pages_without_ai >= 5:
                print(f"AI section ended before row {offset}; stopping metadata scan", flush=True)
                break
            time.sleep(max(0.0, args.metadata_delay))

        sources = sorted(candidates)
        if not sources:
            raise SystemExit("No AI-generated rows were found")
        base, remainder = divmod(args.count, len(sources))
        quotas = {
            source: min(len(candidates[source]), base + (index < remainder))
            for index, source in enumerate(sources)
        }
        counts = collections.Counter(row.get("source", "unknown") for row in manifest_rows)
        print(f"sources={sources}; target quotas={quotas}; existing={dict(counts)}", flush=True)

        pending: list[tuple[str, str, Path, str]] = []
        for source in sources:
            safe_source = re.sub(r"[^A-Za-z0-9._-]+", "-", source).strip("-") or "unknown"
            for row in candidates[source]:
                if counts[source] + sum(item[0] == source for item in pending) >= quotas[source]:
                    break
                image_id = str(row["image_id"])
                if (source, image_id) in manifested_keys:
                    continue
                destination = args.output / f"{safe_source}__{image_id}.jpg"
                pending.append((source, image_id, destination, str(row["image"]["src"])))

        def fetch_image(task: tuple[str, str, Path, str]) -> tuple[str, str, Path]:
            source, image_id, destination, url = task
            download(url, destination, attempts=8)
            return source, image_id, destination

        completed_since_save = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
            futures = {executor.submit(fetch_image, task): task for task in pending}
            for future in concurrent.futures.as_completed(futures):
                try:
                    source, image_id, destination = future.result()
                except Exception as error:
                    failed_in_pass += 1
                    task = futures[future]
                    print(f"skipped {task[0]}/{task[1]}: {error}", flush=True)
                    continue
                manifest_rows.append({
                    "file": destination.name, "label": "deepfake",
                    "category": "ai_generated", "source": source, "dataset": DATASET,
                })
                existing.add(destination.stem)
                manifested_keys.add((source, image_id))
                counts[source] += 1
                downloaded += 1
                completed_since_save += 1
                if downloaded % 100 == 0:
                    print(f"downloaded {downloaded}/{args.count}; source={source}", flush=True)
                if completed_since_save >= 25:
                    completed_since_save = 0
                    with manifest_path.open("w", encoding="utf-8", newline="") as handle:
                        writer = csv.DictWriter(handle, fieldnames=["file", "label", "category", "source", "dataset"])
                        writer.writeheader()
                        writer.writerows(manifest_rows)

        with manifest_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["file", "label", "category", "source", "dataset"])
            writer.writeheader()
            writer.writerows(manifest_rows)

        print(
            f"complete: {len(existing)} valid AI-generated images; "
            f"source counts={dict(counts)}; temporary failures={failed_in_pass}"
        )
        return

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
