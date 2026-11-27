from fastapi import FastAPI

app = FastAPI()

ITEMS = {}


@app.get("/items")
def list_items():
    return list(ITEMS.values())


@app.delete("/items/{item_id}")
def delete_item(item_id: int):
    ITEMS.pop(item_id, None)
    return {"ok": True}


@app.get("/admin/users")
def admin_users():
    return {"users": []}
