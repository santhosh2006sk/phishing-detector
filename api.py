"""
Step 5: Web API
-----------------
Exposes the risk engine as a web API using FastAPI.

Run with:
    uvicorn api:app --reload

Then open http://127.0.0.1:8000/docs to try it in the browser,
or POST to http://127.0.0.1:8000/analyze with JSON: {"url": "http://..."}
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from risk_engine import load_model, score_url

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

    return result


@app.post("/analyze-bulk")
def analyze_bulk(request: BulkURLRequest):
    results = []
    for url in request.urls:
        url = url.strip()
        if not url:
            continue
        try:
            results.append(score_url(url, model, feature_names))
        except Exception as e:
            results.append({"url": url, "error": str(e)})
    return {"results": results}
