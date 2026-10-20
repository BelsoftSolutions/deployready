from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException


def verify_token(authorization: str = Header(default="")):
    if not authorization:
        raise HTTPException(status_code=401)


app = FastAPI()
router = APIRouter()


@router.get("/secret")
def secret():
    return {"secret": 42}


app.include_router(router, prefix="/v1", dependencies=[Depends(verify_token)])
