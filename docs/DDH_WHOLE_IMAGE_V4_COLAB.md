# DDH Whole Image V4 Colab Runbook

> V4 is retained for reproducibility. New all-source training must use the V8
> resumable trainer described in `DDH_UNIFIED_V8_CHUNKED_COLAB.md`.

## Files to upload

Upload both files to the same Google Drive account, under `MyDrive/DDH/`:

1. `data/colab-upload/ddh-whole-image-v4.zip`
2. `ai-engine/notebooks/ddh_whole_image_v4_colab_training.py`

The Drive account does not need to match the Digital Defense Hub admin email.

## Colab execution

1. Open a new Google Colab notebook.
2. Select **Runtime → Change runtime type → T4 GPU → Save**.
3. Reconnect and confirm that the top-right runtime shows a GPU.
4. Run this single cell:

```python
from google.colab import drive
drive.mount('/content/drive')

from pathlib import Path
script = Path('/content/drive/MyDrive/DDH/ddh_whole_image_v4_colab_training.py')
assert script.is_file(), f'Upload the trainer to {script}'
exec(compile(script.read_text(encoding='utf-8'), str(script), 'exec'))
```

The trainer writes these files to `MyDrive/DDH/whole-image-v4-training-output/`:

- `ddh-whole-image-ai-v4.pth`
- `whole-image-v4-metrics.json`

## Acceptance gate

Do not upload or activate the V4 checkpoint until the metrics JSON is reviewed.
The minimum deployment gate is:

- original final-test balanced accuracy: at least `0.85`;
- screenshot final-test balanced accuracy: at least `0.80`;
- authentic specificity in every evaluated view: at least `0.85`;
- AI recall in every evaluated view: at least `0.80`;
- no individual final-test AI generator recall below `0.75`.

The final test contains unseen prompts and the held-out DALL-E 3 and Imagen 3
generators. Never retrain directly against final-test mistakes and continue to
report the same set as an untouched test. If the gate fails, add new training
and validation sources, create a new untouched test contract, and train V5.
