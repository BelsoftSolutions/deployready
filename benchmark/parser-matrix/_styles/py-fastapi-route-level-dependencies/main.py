from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException

app = FastAPI()


def get_db():
    yield object()


def require_admin(authorization: str = Header(default="")):
    if authorization != "admin":
        raise HTTPException(status_code=403)


@app.get("/admin/stats", dependencies=[Depends(require_admin)])
def stats():
    return {}


items = APIRouter(dependencies=[Depends(get_db)])


@items.get("/items")
def list_items():
    return []


app.include_router(items)
