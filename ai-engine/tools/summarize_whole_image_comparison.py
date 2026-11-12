"""Summarize saved predictions without rerunning inference or tuning thresholds."""
import csv
import json
from pathlib import Path
from compare_whole_image_versions import metrics

ROOT = Path(__file__).resolve().parents[2]
out = ROOT / 'data/diagnostics'
report = json.loads((out/'whole-image-version-comparison.json').read_text())
predictions = list(csv.DictReader((out/'whole-image-version-predictions.csv').open()))
for r in predictions:
    r['score'] = float(r['score']); r['label'] = int(r['label'])
known_hashes = set()
for manifest in (ROOT/'datasets').glob('*/provenance.csv'):
    if manifest.parent.name == 'ddh-whole-image-v4':
        continue
    with manifest.open(encoding='utf-8-sig') as stream:
        for row in csv.DictReader(stream):
            if row.get('split','train') in ('train','validation'):
                known_hashes.add(row.get('source_sha256'))
with (ROOT/'datasets/ddh-whole-image-v4/provenance.csv').open() as stream:
    clean_paths = {r['relative_path'] for r in csv.DictReader(stream)
                   if r['split']=='test' and r['source_sha256'] not in known_hashes}
summary = {'subset_note':'Excludes exact source hashes found in other local training/validation manifests; not proof of prompt, near-duplicate or complete historical independence.',
           'remaining_samples':len(clean_paths),'versions':{}}
lines = ['# Whole-image checkpoint comparison', '',
    'No model activation, training, or threshold tuning was performed. Scores are direct whole-image detector outputs, not full face-detector ensemble evaluations.', '',
    'The benchmark is the existing V4 test set: 300 real and 300 AI images. Reusing it makes this a regression audit, not a new independent holdout. Older datasets overlap with some real images. A secondary subset excludes exact source hashes found in all other local training/validation manifests; missing manifests, prompt overlap and near-duplicates remain unverified.', '',
    '| Version | Deployed threshold | App original accuracy | AI recall | Real specificity | Simulated screenshot accuracy |',
    '|---|---:|---:|---:|---:|---:|']
for v,result in report['versions'].items():
    m=result['views']['app_original']['overall']; screen=result['views']['app_simulated_screenshot']['overall']
    lines.append(f"| V{v} | {result['configured_threshold']:.0%} | {m['accuracy']:.2%} | {m['ai_recall']:.2%} | {m['real_specificity']:.2%} | {screen['accuracy']:.2%} |")
    subset=[r for r in predictions if r['version']==v and r['view']=='app_original' and r['path'] in clean_paths]
    summary['versions'][v]=metrics(subset,result['configured_threshold'])
v3=[r for r in predictions if r['version']=='3' and r['view']=='app_original']
summary['v3_at_recorded_training_threshold_0_30']=metrics(v3,.3)
lines += ['',f"Exact-hash exclusion subset: {len(clean_paths)} images. Use balanced accuracy because the class counts are no longer equal.", '',
          '| Version | Subset balanced accuracy | AI recall | Real specificity |','|---|---:|---:|---:|']
for v,m in summary['versions'].items():
    lines.append(f"| V{v} | {m['balanced_accuracy']:.2%} | {m['ai_recall']:.2%} | {m['real_specificity']:.2%} |")
lines += ['', '## User-reported generated image', '',
          'Both files are views of one scene, not independent examples. All three versions miss both at their configured thresholds.', '',
          '| Version | Original AI score | Screenshot AI score |','|---|---:|---:|']
for v,r in report['versions'].items():
    lines.append(f"| V{v} | {r['user_images'][0]['scores']['app']:.2%} | {r['user_images'][1]['scores']['app']:.2%} |")
m=summary['v3_at_recorded_training_threshold_0_30']
lines += ['', '## Findings and practical decision', '',
    '- Keep V4 active pending a genuinely independent application-focused evaluation. The benchmark supports improvement over older checkpoints, not reliable detection of every new generator.',
    '- V4 training preprocessing reproduces the saved 93% test accuracy. Application preprocessing gets 91.17%; AI recall falls from 93.33% to 87.33%, while real specificity increases from 92.67% to 95%. Resize parity needs a separately validated change, not an untested live switch.',
    '- Matching training preprocessing still misses the new scene (9.02% original, 7.42% screenshot against 59%). Resize parity alone is not a solution.',
    f'- V3 metrics record a 30% threshold but the supplied deployed record uses 60%. At the recorded 30%, this benchmark has {m["accuracy"]:.2%} accuracy, {m["ai_recall"]:.2%} AI recall and {m["real_specificity"]:.2%} real specificity. Neither user image reaches 30%. The current analyzer only accepts calibrated thresholds between 50% and 99%, so this requires a separately tested threshold-contract correction if V3 is ever redeployed.',
    '- For the practical: describe this as an experimental AI-image detector with known false negatives. Do not describe AUTHENTIC or the confidence gauge as proof of camera origin. Show both successful and failed examples.',
    '- Before spending another training run: freeze an independent set of current-generator scenes and real camera images, grouped with their screenshot variants. Compare candidates on the same set; keep these evaluation scenes out of training. Do not select a threshold using the two failed files.', '',
    'Reproduce: run compare_whole_image_versions.py, then summarize_whole_image_comparison.py using ai-engine/.venv/Scripts/python.exe. Source paths and checkpoint hashes are in the JSON; per-image outputs are in the CSV.', '']
(out/'whole-image-comparison-summary.json').write_text(json.dumps(summary,indent=2))
(ROOT/'docs/WHOLE_IMAGE_VERSION_COMPARISON.md').write_text('\n'.join(lines),encoding='utf-8')
print(json.dumps(summary,indent=2))
