import json
import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from risk_engine import load_model, score_url
from database import init_db, save_scan, get_history, get_stats

app = FastAPI(title="Phishing Website Detection & Risk Analysis API")

# Allow requests from any origin (needed so a simple HTML frontend
# opened from a file, or on a different port, can call this API)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load the trained model once at startup, not on every request
model, feature_names = load_model()

# Create scans.db (if it doesn't exist yet) so scan history persists
init_db()


class URLRequest(BaseModel):
    url: str


class BulkURLRequest(BaseModel):
    urls: list[str]


@app.get("/")
def root():
    return {"message": "Phishing Detection API is running. See /docs for usage."}


@app.post("/analyze")
def analyze(request: URLRequest):
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    try:
        result = score_url(url, model, feature_names)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not analyze URL: {e}")

    save_scan(result)
    return result


@app.post("/analyze-bulk")
def analyze_bulk(request: BulkURLRequest):
    results = []
    for url in request.urls:
        url = url.strip()
        if not url:
            continue
        try:
            result = score_url(url, model, feature_names)
            save_scan(result)
            results.append(result)
        except Exception as e:
            results.append({"url": url, "error": str(e)})
    return {"results": results}


@app.get("/history")
def history(limit: int = 50):
    return {"history": get_history(limit)}


@app.get("/stats")
def stats():
    return get_stats()


@app.get("/model-info")
def model_info():
    """Real training metrics and feature importance, saved by train_model.py."""
    if not os.path.exists("model_metrics.json"):
        raise HTTPException(status_code=404, detail="model_metrics.json not found - retrain the model to generate it")
    with open("model_metrics.json") as f:
        return json.load(f)
