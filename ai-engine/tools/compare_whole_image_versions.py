"""Read-only V2/V3/V4 regression comparison; does not tune or activate models."""
import csv
import hashlib
import io
import json
import sys
from pathlib import Path

import cv2
import numpy as np
import torch
from PIL import Image, ImageOps
from torchvision import transforms
from torchvision.models import mobilenet_v3_small

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ai-engine'))
from app.media_model_runner import MediaModelRunner


def metrics(rows, threshold):
    tp = sum(r['label'] == 1 and r['score'] >= threshold for r in rows)
    fn = sum(r['label'] == 1 and r['score'] < threshold for r in rows)
    fp = sum(r['label'] == 0 and r['score'] >= threshold for r in rows)
    tn = sum(r['label'] == 0 and r['score'] < threshold for r in rows)
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    return dict(n=len(rows), tp=tp, fn=fn, fp=fp, tn=tn, ai_recall=recall,
                real_specificity=specificity, accuracy=(tp+tn)/len(rows),
                balanced_accuracy=(recall+specificity)/2 if recall is not None and specificity is not None else None)


def main():
    torch.set_num_threads(2)
    dataset = ROOT / 'datasets/ddh-whole-image-v4'
    records = [r for r in csv.DictReader((dataset/'provenance.csv').open()) if r['split'] == 'test']
    transform = transforms.Compose([transforms.Resize((224,224)), transforms.ToTensor(),
        transforms.Normalize((.485,.456,.406),(.229,.224,.225))])
    tensors = {k: [] for k in ('app_original','training_original','app_simulated_screenshot')}
    for r in records:
        with Image.open(dataset/r['relative_path']) as source:
            im = source.convert('RGB')
        tensors['training_original'].append(transform(im))
        canvas = Image.new('RGB',(1366,768),(24,24,24))
        fitted = ImageOps.contain(im,(1220,680),Image.Resampling.LANCZOS)
        canvas.paste(fitted,((1366-fitted.width)//2,(768-fitted.height)//2))
        buffer = io.BytesIO(); canvas.save(buffer,'JPEG',quality=72); buffer.seek(0)
        with Image.open(buffer) as copied:
            screen = copied.convert('RGB')
        for key, image in [('app_original',im),('app_simulated_screenshot',screen)]:
            bgr = cv2.cvtColor(np.asarray(image),cv2.COLOR_RGB2BGR)
            tensors[key].append(torch.from_numpy(MediaModelRunner._preprocess_image(bgr,{}))[0])
    user_paths = [Path(r'C:\Users\acer\Downloads\ChatGPT Image Sep 17, 2026, 09_14_11 PM.png'),
                  Path(r'C:\Users\acer\OneDrive\Pictures\Screenshots\Screenshot 2026-09-17 211716.png')]
    report = {'limitations': ['V4 test set is an existing benchmark, not a new independent holdout.',
        'Overlap with V2/V3 training has not been excluded; cross-version ranking is provisional.',
        'Two user files are two views of one scene, not two independent samples.',
        'Screenshot benchmark uses a synthetic canvas, not real screen captures.'], 'versions': {}}
    predictions = []
    for version, threshold in [(2,.66),(3,.60),(4,.59)]:
        path = ROOT / f'data/colab-trained/ensemble-v{version}/ddh-whole-image-ai-v{version}.pth'
        checkpoint = torch.load(path,map_location='cpu',weights_only=True)
        assert checkpoint['classes'] == ['authentic','deepfake']
        model = mobilenet_v3_small(weights=None)
        model.classifier[-1] = torch.nn.Linear(model.classifier[-1].in_features,2)
        model.load_state_dict(checkpoint['state_dict'],strict=True); model.eval()
        result = {'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                  'configured_threshold':threshold,'checkpoint_threshold':checkpoint.get('decision_threshold'), 'views':{},'user_images':[]}
        with torch.inference_mode():
            for view, inputs in tensors.items():
                values=[]
                for start in range(0,len(inputs),32):
                    values.extend(torch.softmax(model(torch.stack(inputs[start:start+32])),1)[:,1].tolist())
                rows=[dict(version=version,view=view,path=r['relative_path'],source=r['source'],label=int(r['class']=='deepfake'),score=s) for r,s in zip(records,values)]
                predictions.extend(rows)
                result['views'][view]={'overall':metrics(rows,threshold),'sources':{s:metrics([r for r in rows if r['source']==s],threshold) for s in sorted({r['source'] for r in rows})}}
            for path in user_paths:
                with Image.open(path) as image:
                    im=image.convert('RGB')
                inputs={'app':torch.from_numpy(MediaModelRunner._preprocess_image(cv2.cvtColor(np.asarray(im),cv2.COLOR_RGB2BGR),{})), 'training':transform(im).unsqueeze(0)}
                result['user_images'].append({'path':str(path),'scores':{k:float(torch.softmax(model(t),1)[0,1]) for k,t in inputs.items()}})
        report['versions'][str(version)]=result
        print(json.dumps({'version':version,'threshold':threshold,'views':{k:v['overall'] for k,v in result['views'].items()},'user_images':result['user_images']}),flush=True)
    output=ROOT/'data/diagnostics'; output.mkdir(exist_ok=True)
    (output/'whole-image-version-comparison.json').write_text(json.dumps(report,indent=2))
    with (output/'whole-image-version-predictions.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(predictions[0])); writer.writeheader();writer.writerows(predictions)


if __name__ == '__main__':
    main()
