from fastapi import APIRouter

from routers import items

router = APIRouter(prefix="/v1")
router.include_router(items.router)
