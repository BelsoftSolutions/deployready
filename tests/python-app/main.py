# Intentionally vulnerable FastAPI app — test fixture for DeployReady. DO NOT deploy.
import subprocess
from fastapi import FastAPI
from .routers import auth
from .routers.users import router as users_router

app = FastAPI()

# VULN: hardcoded secrets in source
SECRET_KEY = "sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz"
DATABASE_URL = "postgres://admin:supersecretpassword@localhost:5432/app"

# Sub-router mounts — routes inside these files live under these prefixes.
app.include_router(auth.router, prefix="/api/auth")
app.include_router(users_router, prefix="/api/users")


@app.get("/")
def root():
    return {"ok": True}


# VULN: eval of user input (code injection)
@app.get("/calc")
def calc(expr: str):
    return {"result": eval(expr)}


# VULN: SQL built with an f-string (SQL injection)
@app.get("/raw/{item_id}")
def raw(item_id: str):
    query = f"SELECT * FROM items WHERE id = {item_id}"
    return {"query": query}


# VULN: subprocess with shell=True (command injection)
@app.get("/ping")
def ping(host: str):
    subprocess.run("ping " + host, shell=True)
    return {"pinged": host}
