from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from app.core.config import BASE_DIR

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
def serve_viz():
    """
    Serves the dashboard UI.
    """
    file_path = BASE_DIR / "frontend" / "index.html"
    with open(file_path, "r") as f:
        return f.read()

