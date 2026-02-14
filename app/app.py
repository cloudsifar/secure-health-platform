""" Basic functional script for the container """

from fastapi import FastAPI
from datetime import datetime, timezone

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}

@app.get("/records")
def records():
    return {
        "records": [
            {"id": "a1", "type": "lab_result", "status": "mock"},
            {"id": "b2", "type": "imaging_ref", "status": "mock"},
        ]
    }
