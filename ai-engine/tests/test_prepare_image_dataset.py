import importlib.util
import json
import tempfile
from pathlib import Path

from PIL import Image


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "prepare_image_dataset.py"
SPEC = importlib.util.spec_from_file_location("prepare_image_dataset", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def create_image(path: Path, colour: tuple[int, int, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    Image.new("RGB", (16, 16), colour).save(path)


def test_prepare_dataset_creates_balanced_deterministic_subset() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "source"
        for index in range(4):
            create_image(source / "real" / f"real-{index}.png", (index, 0, 0))
            create_image(source / "fake" / f"fake-{index}.png", (0, index, 0))

        output = root / "prepared"
        manifest = MODULE.prepare_dataset(
            source, output, "real", "fake", total=6, seed=42, image_size=224
        )

        assert len(list((output / "authentic").glob("*.png"))) == 3
        assert len(list((output / "deepfake").glob("*.png"))) == 3
        assert manifest["record_count"] == 6
        assert manifest["class_distribution"] == {"authentic": 3, "deepfake": 3}
        assert len(str(manifest["sha256"])) == 64
        assert json.loads((output / "dataset.json").read_text())["classes"] == [
            "authentic",
            "deepfake",
        ]


def test_prepare_dataset_rejects_insufficient_class_images() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "source"
        create_image(source / "authentic" / "one.png", (1, 1, 1))
        create_image(source / "deepfake" / "one.png", (2, 2, 2))

        try:
            MODULE.prepare_dataset(
                source, root / "prepared", "authentic", "deepfake", 4, 1, 64
            )
        except ValueError as error:
            assert "valid images" in str(error)
        else:
            raise AssertionError("insufficient classes must be rejected")
