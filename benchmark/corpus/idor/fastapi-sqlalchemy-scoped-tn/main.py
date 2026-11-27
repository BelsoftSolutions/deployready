from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from .auth import get_current_user
from .db import get_db
from .models import Item, User

app = FastAPI()


@app.get("/items")
def list_items(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Item).filter(Item.owner_id == current_user.id).all()


@app.get("/items/{item_id}")
def read_item(item_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    item = db.query(Item).filter(Item.id == item_id, Item.owner_id == current_user.id).first()
    if item is None:
        raise HTTPException(status_code=404)
    return item


@app.delete("/items/{item_id}")
def delete_item(item_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    item = db.query(Item).filter_by(id=item_id, owner_id=current_user.id).first()
    if item is None:
        raise HTTPException(status_code=404)
    db.delete(item)
    db.commit()
    return {"ok": True}
