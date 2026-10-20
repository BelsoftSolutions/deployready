from fastapi import Header, HTTPException


def get_current_user(authorization: str = Header(default="")):
    if not authorization:
        raise HTTPException(status_code=401)
    return {"id": 1}


def get_current_admin(authorization: str = Header(default="")):
    if not authorization:
        raise HTTPException(status_code=403)
    return {"id": 1, "admin": True}
