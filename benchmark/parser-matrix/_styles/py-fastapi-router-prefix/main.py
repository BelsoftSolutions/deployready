from fastapi import FastAPI

from items import router

app = FastAPI()
app.include_router(router)
