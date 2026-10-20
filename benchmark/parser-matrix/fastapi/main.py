from fastapi import Depends, FastAPI

from deps import get_current_admin
from routers import admin, users

app = FastAPI()

app.include_router(users.router, prefix="/api/users")
app.include_router(admin.router, prefix="/admin", dependencies=[Depends(get_current_admin)])


@app.get("/health")
def health():
    return {"status": "ok"}
