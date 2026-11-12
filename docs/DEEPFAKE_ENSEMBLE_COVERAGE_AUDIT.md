# Deepfake image ensemble coverage audit

This is a read-only audit. No model was trained, activated, rolled back, or
deleted during this audit.

## What the earlier training contributes

| Artifact | Supported role | Evidence | Decision |
|---|---|---|---|
| Whole-image V4 | Modern AI-generated images and transformed copies | Source-isolated V4 final test: 93.33% AI recall; V7 modern-AI category: 91.5% recall | Keep as modern AI specialist |
| Face-swap V2 | FaceForensics-style face manipulation | V7 face-swap category: 88.33% recall; face-real specificity: 91% | Keep as face-swap specialist |
| Unified V6 | Legacy AI images; partial face/filter coverage | At 50%: 98% legacy-AI recall, but unacceptable 64.67% legacy-real specificity | Retain as a candidate, do not OR at 50% |
| Face-swap V3 | Copy-robust face experiment | Recorded test recall 78.59%, below V2's 82.90%; screenshot recall improved but screenshot real specificity fell to 73.13% | Do not replace V2 based on existing evidence |
| Whole-image V2/V3 | Previous AI-image experiments | Same-benchmark AI recall 15.67% and 19.33%, below V4's 87.33% with application preprocessing | Retain for rollback/audit only |

The artifacts therefore are not interchangeable versions of one universal
model. They are experiments or specialists with different training scopes.

## V7 category audit

The audit uses 1,800 existing V7 test records. It is not a new independent
benchmark. Face applicability is inferred from the prepared category and does
not replay the live face detector.

| Category | Samples | Selected specialist result |
|---|---:|---:|
| Modern AI generated | 200 | V4 recall 91.5% |
| Face swap | 300 | Face-swap V2 recall 88.33% |
| FaceForensics real | 200 | Face-swap V2 specificity 91% |
| COCO camera real | 400 | V4 specificity 89.5% |
| Legacy camera real | 300 | V4 specificity 99% |
| Legacy AI generated | 400 | V4 recall 0%; Unified V6 recall 98% at its original 50% audit threshold |

Blindly OR-ing Unified V6 at 50% is rejected: although it restores legacy-AI
coverage, legacy-camera specificity falls to 64.67% and face-real specificity
to 73%.

An exploratory threshold sweep on this reused test set found that Unified V6
at 85% gives 85.75% legacy-AI recall, 92.67% legacy-camera specificity, 100%
COCO specificity, and 100% face-real specificity. This is only a candidate:
the threshold was inspected on the test set, so it must not be deployed or
reported as independently validated without a fresh holdout.

## Unsupported or unproven categories

| Category | Current state |
|---|---|
| Morphing | No separately labelled morphing folder, manifest category, checkpoint, or holdout was found |
| Snapchat filtered | 250 V7 training records; no V7 validation/test records |
| Remini enhanced | 190 V7 training records; no V7 validation/test records |

The private source currently contains 223 camera originals, 259 Snapchat
filtered files, and 200 Remini-enhanced files. These are not morphing data.
Calling those files morphing would be incorrect.

## Practical decision

For the current practical demonstration:

1. Use Whole-image V4 for modern AI-generated images.
2. Use Face-swap V2 for FaceForensics-style face manipulation.
3. Keep Unified V6 disabled as a production OR detector until its candidate
   threshold is checked on a new balanced legacy-AI/camera holdout.
4. Describe morphing, Snapchat, and Remini coverage as unsupported or
   unvalidated; do not claim complete multi-manipulation detection.
5. Keep all old checkpoints. They provide rollback and category-specific
   evidence, even when they should not be active.

Machine-readable evidence:
`data/diagnostics/deepfake-ensemble-category-audit.json`.
Reproduce with:
`ai-engine/.venv/Scripts/python.exe ai-engine/tools/audit_deepfake_ensemble_categories.py`.

