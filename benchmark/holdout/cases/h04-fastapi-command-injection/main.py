import subprocess
from fastapi import FastAPI, Depends
from auth import current_user

app = FastAPI()


@app.get("/api/diagnostics/ping")
def ping(host: str, user=Depends(current_user)):
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return {"output": out.stdout}
