# Intentionally vulnerable FastAPI app — test fixture for DeployReady. DO NOT deploy.
import subprocess
from fastapi import FastAPI
from .routers import auth
from .routers.users import router as users_router

app = FastAPI()

# VULN: hardcoded secrets in source.
# NOTE: the values below are FAKE, non-functional test data used only to exercise
# DeployReady's hardcoded-secret detection. They are NOT real credentials. Do not
# replace them with anything resembling a live key (it would trip secret scanners).
SECRET_KEY = "FAKE_TEST_SECRET_not_a_real_key_0000000000"  # fake — for tests only
DATABASE_URL = "postgres://admin:supersecretpassword@localhost:5432/app"  # fake — for tests only

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
