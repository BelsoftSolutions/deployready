from fastapi import APIRouter, Depends

from deps import get_current_user

router = APIRouter()


@router.get("/")
def list_users():
    return []


@router.get("/{user_id}")
def get_user(user_id: int):
    return {"id": user_id}


@router.post("/", dependencies=[Depends(get_current_user)])
def create_user(payload: dict):
    return payload
