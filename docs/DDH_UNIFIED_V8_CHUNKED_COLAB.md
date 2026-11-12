# DDH Unified V8 resumable Colab training

## What this solves

The dataset is divided into deterministic 2,000-image training parts. Every run
loads the same model and optimizer checkpoint, trains the next two parts, and
saves the exact cursor to Google Drive. These are not independently trained
models and their weights are not averaged. They are consecutive updates to one
model, so the final output is one deployable version.

## Prepare and upload

1. Run `ai-engine/scripts/prepare_unified_v8_all_sources.py` where all source
   folders are available.
2. Review `dataset.json` and `provenance.csv` in
   `datasets/unified-deepfake-v8-all-sources`.
3. Zip that dataset folder as
   `MyDrive/DDH/unified-deepfake-v8-all-sources.zip`.
4. Upload `ai-engine/notebooks/ddh_unified_v8_chunked_colab_training.py` to
   `MyDrive/DDH/`.

The preparation script prints the authoritative record, class, split and
category counts. Do not use a guessed count.

## Run in Colab

Choose a GPU runtime and execute:

```python
from google.colab import drive
drive.mount('/content/drive')
from pathlib import Path
trainer = Path('/content/drive/MyDrive/DDH/ddh_unified_v8_chunked_colab_training.py')
exec(compile(trainer.read_text(encoding='utf-8'), str(trainer), 'exec'))
```

Run the same cell again whenever it asks to continue. Progress is stored under
`MyDrive/DDH/unified-v8-training-output/`. Training is complete only when
`training-complete.json` and `ddh-unified-deepfake-v8.pth` exist.

Before activation, review final-test balanced accuracy, precision, recall and
specificity from `training-complete.json`. Upload the final PTH as a new model
version; never activate `resume-state.pth`.
