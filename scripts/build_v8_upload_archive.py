from pathlib import Path
import hashlib
import os
import zipfile

SOURCE = Path("datasets/unified-deepfake-v8-all-sources")
TARGET = Path("data/colab-upload/unified-deepfake-v8-all-sources.zip")
TEMP = TARGET.with_suffix(".zip.building")
IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".webp", ".bmp"}

if not SOURCE.is_dir():
    raise SystemExit(f"Missing source dataset: {SOURCE}")
TARGET.parent.mkdir(parents=True, exist_ok=True)
if TEMP.exists():
    TEMP.unlink()

files = sorted(path for path in SOURCE.rglob("*") if path.is_file())
images = sum(path.suffix.lower() in IMAGE_SUFFIXES for path in files)
print(f"Adding {len(files)} files ({images} images)", flush=True)

with zipfile.ZipFile(TEMP, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
    for index, path in enumerate(files, 1):
        archive.write(path, Path(SOURCE.name, path.relative_to(SOURCE)).as_posix())
        if index % 5000 == 0:
            print(f"Added {index}/{len(files)}", flush=True)

with zipfile.ZipFile(TEMP, "r", allowZip64=True) as archive:
    bad = archive.testzip()
    if bad is not None:
        raise SystemExit(f"Archive validation failed at {bad}")
    if len(archive.infolist()) != len(files):
        raise SystemExit("Archive entry count does not match source file count")

os.replace(TEMP, TARGET)
sha256 = hashlib.sha256()
with TARGET.open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        sha256.update(chunk)
print(f"READY {TARGET} bytes={TARGET.stat().st_size} sha256={sha256.hexdigest()}", flush=True)
