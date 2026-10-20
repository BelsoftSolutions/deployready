from fastapi import Depends, FastAPI

app = FastAPI()


def get_current_user():
    return None


@app.get("/me", dependencies=[Depends(get_current_user)])
def me():
    return {"ok": True}


@app.get("/health")
def health():
    return {"ok": True}