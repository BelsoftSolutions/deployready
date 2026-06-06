# Users router for the sample FastAPI app.
from fastapi import APIRouter

router = APIRouter()


@router.get("/list")  # mounted -> /api/users/list
def list_users():
    return {"users": []}
