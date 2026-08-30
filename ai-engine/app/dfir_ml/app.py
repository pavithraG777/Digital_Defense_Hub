from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from .service import DFIRMLService

app = FastAPI(title="DFIR ML Service")
ml = DFIRMLService()


class ScoreRequest(BaseModel):
    # Accept arbitrary numeric features; clients can send any subset
    file_event_rate: float = 0.0
    rename_rate: float = 0.0
    entropy_change: float = 0.0
    network_spike_ratio: float = 0.0
    honeytoken_hits: float = 0.0
    process_anomaly_score: float = 0.0
    time_window_score: float = 0.0


@app.post("/score")
def score(req: ScoreRequest):
    try:
        result = ml.score(req.dict())
        return {"success": True, "model": result["model"], "probability": result["probability"], "features": result["features"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
def health():
    if ml.is_healthy():
        return {"healthy": True, "model_loaded": True}
    raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="model not loaded")


@app.post("/warmup")
def warmup():
    try:
        ml.warmup()
        return {"success": True, "model_loaded": ml.model_loaded}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
