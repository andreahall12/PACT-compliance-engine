from fastapi import APIRouter
from app.api.v1.endpoints import compliance, chat, ingest

api_router = APIRouter()

api_router.include_router(compliance.router, prefix="/compliance", tags=["compliance"])
api_router.include_router(chat.router, prefix="/chat", tags=["chat"])
api_router.include_router(ingest.router, prefix="/ingest", tags=["ingest"])



