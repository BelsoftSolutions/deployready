import requests
from fastapi import FastAPI, Depends
from auth import current_user

app = FastAPI()


@app.get("/api/preview")
def link_preview(url: str, user=Depends(current_user)):
    r = requests.get(url, timeout=5)
    return {"status": r.status_code, "body": r.text[:2000]}
