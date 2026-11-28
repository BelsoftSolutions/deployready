from urllib.parse import urlparse
import requests
from fastapi import FastAPI, Depends, HTTPException
from auth import current_user

app = FastAPI()
ALLOWED_HOSTS = {"api.github.com", "api.openweathermap.org"}


@app.get("/api/preview")
def link_preview(url: str, user=Depends(current_user)):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise HTTPException(status_code=400, detail="host not allowed")
    r = requests.get(url, timeout=5, allow_redirects=False)
    return {"status": r.status_code, "body": r.text[:2000]}
