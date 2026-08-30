import importlib.util
import tempfile
from pathlib import Path

from PIL import Image


SCRIPT = Path(__file__).parents[1] / "scripts" / "prepare_synthetic_image_dataset.py"
SPEC = importlib.util.spec_from_file_location("prepare_synthetic_image_dataset", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def image(path: Path, colour: tuple[int, int, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    Image.new("RGB", (20, 20), colour).save(path)


def test_builds_balanced_deduplicated_provenance_dataset() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "source"
        for index in range(6):
            image(source / "real_dataset" / ("people" if index % 2 else "city") / f"r{index}.png", (index, 1, 1))
            image(source / "Ai_generated_dataset" / ("people" if index % 2 else "city") / f"s{index}.png", (1, index, 2))
        output = root / "prepared"
        manifest = MODULE.prepare_synthetic_dataset(source, output, total=10, seed=7)
        assert manifest["task"] == "synthetic_image_detection"
        assert manifest["positive_class_semantics"] == "AI_GENERATED"
        assert manifest["class_distribution"] == {"authentic": 5, "deepfake": 5}
        assert len(list((output / "authentic").glob("*"))) == 5
        assert len(list((output / "deepfake").glob("*"))) == 5
        assert len((output / "provenance.csv").read_text().splitlines()) == 11


def test_rejects_cross_class_duplicate_content() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "source"
        for index in range(5):
            image(source / "real_dataset" / "all" / f"r{index}.png", (index, 0, 0))
            image(source / "Ai_generated_dataset" / "all" / f"s{index}.png", (0, index, 0))
        # Deliberately duplicate one real file in the positive class.
        (source / "Ai_generated_dataset" / "all" / "s0.png").write_bytes(
            (source / "real_dataset" / "all" / "r0.png").read_bytes()
        )
        try:
            MODULE.prepare_synthetic_dataset(source, root / "prepared", total=10, seed=1)
        except ValueError as error:
            assert "both classes" in str(error)
        else:
            raise AssertionError("cross-class duplicates must be rejected")
