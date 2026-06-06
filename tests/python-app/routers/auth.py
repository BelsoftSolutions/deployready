# Auth router for the sample FastAPI app.
from fastapi import APIRouter

router = APIRouter()


@router.post("/login")  # mounted -> /api/auth/login
def login():
    return {"token": "demo"}


@router.get("/me")  # mounted -> /api/auth/me
def me():
    return {"user": "demo"}
