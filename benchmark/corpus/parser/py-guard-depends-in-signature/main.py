from fastapi import Depends, FastAPI

app = FastAPI()


def get_current_user():
    return None


@app.get("/profile")
def profile(user=Depends(get_current_user)):
    return {"ok": True}