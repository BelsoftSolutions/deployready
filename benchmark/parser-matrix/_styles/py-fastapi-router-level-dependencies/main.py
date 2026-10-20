from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException

app = FastAPI()


def get_current_user(authorization: str = Header(default="")):
    if not authorization:
        raise HTTPException(status_code=401)


router = APIRouter(dependencies=[Depends(get_current_user)])


@router.get("/secret")
def secret():
    return {"secret": 42}


app.include_router(router)
