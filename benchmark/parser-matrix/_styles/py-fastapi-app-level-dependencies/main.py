from fastapi import Depends, FastAPI, Header, HTTPException


def get_current_user(authorization: str = Header(default="")):
    if not authorization:
        raise HTTPException(status_code=401)


app = FastAPI(dependencies=[Depends(get_current_user)])


@app.get("/secret")
def secret():
    return {"secret": 42}
