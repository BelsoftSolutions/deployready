from fastapi import FastAPI

from routers import api

app = FastAPI()
app.include_router(api.router, prefix="/api")
