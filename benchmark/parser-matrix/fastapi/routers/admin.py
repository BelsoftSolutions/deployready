from fastapi import APIRouter

router = APIRouter()


@router.get("/stats")
def stats():
    return {"users": 0}


@router.delete("/users/{user_id}")
def delete_user(user_id: int):
    return {"deleted": user_id}
