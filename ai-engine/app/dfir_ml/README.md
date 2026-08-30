DFIR ML microservice

Run locally (install dependencies listed in `ai-engine/requirements.txt`):

python -m uvicorn app:app --host 0.0.0.0 --port 8080

Docker build:

docker build -t ddh-dfir-ml:latest .
docker run -p 8080:8080 ddh-dfir-ml:latest

Endpoint: POST /score
Payload: JSON features matching the field names in `service.py` or `ScoreRequest`.

Examples:

- Check health:

```bash
curl -sS http://127.0.0.1:8080/health
```

- Warm up the model (loads model or performs warmup routine):

```bash
curl -X POST http://127.0.0.1:8080/warmup
```

- Score example:

```bash
curl -X POST -H "Content-Type: application/json" \
	-d '{"file_event_rate":1.2, "rename_rate":0.5}' \
	http://127.0.0.1:8080/score
```
