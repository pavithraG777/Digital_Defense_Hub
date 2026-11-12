# Whole-image checkpoint comparison

No model activation, training, or threshold tuning was performed. Scores are direct whole-image detector outputs, not full face-detector ensemble evaluations.

The benchmark is the existing V4 test set: 300 real and 300 AI images. Reusing it makes this a regression audit, not a new independent holdout. Older datasets overlap with some real images. A secondary subset excludes exact source hashes found in all other local training/validation manifests; missing manifests, prompt overlap and near-duplicates remain unverified.

| Version | Deployed threshold | App original accuracy | AI recall | Real specificity | Simulated screenshot accuracy |
|---|---:|---:|---:|---:|---:|
| V2 | 66% | 56.17% | 15.67% | 96.67% | 50.67% |
| V3 | 60% | 58.50% | 19.33% | 97.67% | 55.83% |
| V4 | 59% | 91.17% | 87.33% | 95.00% | 92.17% |

Exact-hash exclusion subset: 384 images. Use balanced accuracy because the class counts are no longer equal.

| Version | Subset balanced accuracy | AI recall | Real specificity |
|---|---:|---:|---:|
| V2 | 54.86% | 15.67% | 94.05% |
| V3 | 57.29% | 19.33% | 95.24% |
| V4 | 93.07% | 87.33% | 98.81% |

## User-reported generated image

Both files are views of one scene, not independent examples. All three versions miss both at their configured thresholds.

| Version | Original AI score | Screenshot AI score |
|---|---:|---:|
| V2 | 0.72% | 0.72% |
| V3 | 1.71% | 1.63% |
| V4 | 2.94% | 3.50% |

## Findings and practical decision

- Keep V4 active pending a genuinely independent application-focused evaluation. The benchmark supports improvement over older checkpoints, not reliable detection of every new generator.
- V4 training preprocessing reproduces the saved 93% test accuracy. Application preprocessing gets 91.17%; AI recall falls from 93.33% to 87.33%, while real specificity increases from 92.67% to 95%. Resize parity needs a separately validated change, not an untested live switch.
- Matching training preprocessing still misses the new scene (9.02% original, 7.42% screenshot against 59%). Resize parity alone is not a solution.
- V3 metrics record a 30% threshold but the supplied deployed record uses 60%. At the recorded 30%, this benchmark has 62.50% accuracy, 34.00% AI recall and 91.00% real specificity. Neither user image reaches 30%. The current analyzer only accepts calibrated thresholds between 50% and 99%, so this requires a separately tested threshold-contract correction if V3 is ever redeployed.
- For the practical: describe this as an experimental AI-image detector with known false negatives. Do not describe AUTHENTIC or the confidence gauge as proof of camera origin. Show both successful and failed examples.
- Before spending another training run: freeze an independent set of current-generator scenes and real camera images, grouped with their screenshot variants. Compare candidates on the same set; keep these evaluation scenes out of training. Do not select a threshold using the two failed files.

Reproduce: run compare_whole_image_versions.py, then summarize_whole_image_comparison.py using ai-engine/.venv/Scripts/python.exe. Source paths and checkpoint hashes are in the JSON; per-image outputs are in the CSV.
