from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer

app = FastAPI()
oauth2 = OAuth2PasswordBearer(tokenUrl="token")
ITEMS = {}


def current_user(token: str = Depends(oauth2)):
    if token != "valid":
        raise HTTPException(status_code=401)
    return token


@app.delete("/items/{item_id}")
def delete_item(item_id: int, user=Depends(current_user)):
    ITEMS.pop(item_id, None)
    return {"ok": True}
