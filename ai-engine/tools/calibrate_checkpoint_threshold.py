from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import torch
from PIL import Image
from torchvision import transforms
from torchvision.models import mobilenet_v3_small


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--split", default="test")
    args = parser.parse_args()
    manifest = json.loads((args.dataset / "dataset.json").read_text(encoding="utf-8"))
    split_rows = list(csv.DictReader((args.dataset / manifest["split_manifest"]).open(newline="", encoding="utf-8")))
    labels = {name: index for index, name in enumerate(manifest["classes"])}
    checkpoint = torch.load(args.checkpoint, map_location="cpu", weights_only=False)
    model = mobilenet_v3_small(weights=None)
    model.classifier[-1] = torch.nn.Linear(model.classifier[-1].in_features, 2)
    model.load_state_dict(checkpoint["state_dict"]); model.eval()
    size = int(checkpoint.get("image_size", 224))
    transform = transforms.Compose([transforms.Resize((size, size)), transforms.ToTensor(), transforms.Normalize((.485,.456,.406),(.229,.224,.225))])
    selected = [row for row in split_rows if row["split"].lower() == args.split.lower()]
    values: list[tuple[int, float]] = []
    with torch.no_grad():
        for start in range(0, len(selected), 64):
            rows = selected[start:start + 64]
            tensors = []
            for row in rows:
                with Image.open(args.dataset / row["relative_path"]) as image:
                    tensors.append(transform(image.convert("RGB")))
            scores = torch.softmax(model(torch.stack(tensors)), 1)[:, 1].tolist()
            values.extend(
                (labels[Path(row["relative_path"]).parts[0]], score)
                for row, score in zip(rows, scores)
            )
    results = []
    for threshold in (.5, .6, .7, .75, .8, .85, .9, .95):
        tp = sum(label == 1 and score >= threshold for label, score in values)
        fp = sum(label == 0 and score >= threshold for label, score in values)
        tn = sum(label == 0 and score < threshold for label, score in values)
        fn = sum(label == 1 and score < threshold for label, score in values)
        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        specificity = tn / (tn + fp) if tn + fp else 0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
        results.append({"threshold":threshold,"tp":tp,"fp":fp,"tn":tn,"fn":fn,"precision":precision,"recall":recall,"specificity":specificity,"f1":f1,"balanced_accuracy":(recall+specificity)/2})
    print(json.dumps({"samples":len(values),"thresholds":results}, indent=2))


if __name__ == "__main__":
    main()
