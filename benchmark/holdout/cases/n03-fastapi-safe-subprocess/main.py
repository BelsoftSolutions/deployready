import ipaddress
import subprocess
from fastapi import FastAPI, Depends, HTTPException
from auth import current_user

app = FastAPI()


@app.get("/api/diagnostics/ping")
def ping(host: str, user=Depends(current_user)):
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid address")
    out = subprocess.run(["ping", "-c", "1", str(addr)], capture_output=True, text=True, timeout=5)
    return {"output": out.stdout}
