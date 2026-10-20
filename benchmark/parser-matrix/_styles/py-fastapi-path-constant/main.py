from fastapi import FastAPI

app = FastAPI()
HEALTH_PATH = "/health"


@app.get(HEALTH_PATH)
def health():
    return {"status": "ok"}
