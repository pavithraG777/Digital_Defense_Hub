from pathlib import Path

import torch
import torch.nn as nn


class TinyDeepfakeNet(nn.Module):
    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(
            nn.Flatten(),
            nn.Linear(3 * 224 * 224, 128),
            nn.ReLU(),
            nn.Linear(128, 2),
        )

    def forward(self, x):
        return self.net(x)


model = TinyDeepfakeNet().eval()
dummy_input = torch.randn(1, 3, 224, 224)

base_dir = Path(__file__).resolve().parent
output_dir = base_dir / "models" / "deepfake" / "image" / "1.0.0"
output_dir.mkdir(parents=True, exist_ok=True)
output_path = output_dir / "deepfake_image_detector.onnx"

# Export the model to ONNX
torch.onnx.export(
    model,
    dummy_input,
    str(output_path),
    input_names=["input"],
    output_names=["output"],
    opset_version=17,
)

print("ONNX model created at:", output_path)