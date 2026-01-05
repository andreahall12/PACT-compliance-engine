from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from app.api.v1.api import api_router
from app.api.v1.endpoints import visualize
from app.core.config import get_cors_allow_origins
from app.core.security import get_request_api_key, is_api_key_required, is_valid_api_key
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="PACT Compliance API", version="1.1.0")

# Enable CORS for the visualization frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_allow_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"message": "PACT Compliance Engine is Running. Access docs at /docs"}

# Global API-key protection (covers EVERYTHING: /, /docs, /openapi.json, /visualize, /v1/*)
@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    if not is_api_key_required():
        return await call_next(request)

    provided = get_request_api_key(request, request.headers.get("X-API-Key"))
    if not is_valid_api_key(provided):
        return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})

    # If key was provided via query param on a GET, set a cookie and redirect to a clean URL
    if request.method == "GET" and ("api_key" in request.query_params or "key" in request.query_params):
        # Strip api_key/key from query string
        kept = [(k, v) for (k, v) in request.query_params.multi_items() if k not in ("api_key", "key")]
        from urllib.parse import urlencode
        url = request.url.replace(query=urlencode(kept, doseq=True))
        resp = RedirectResponse(url=str(url))
        resp.set_cookie(
            "pact_api_key",
            provided,
            httponly=True,
            samesite="lax",
        )
        return resp

    response = await call_next(request)
    return response

# Include the API router
app.include_router(api_router, prefix="/v1")

# Move visualization to root level for easier access
app.include_router(visualize.router, prefix="/visualize", tags=["visualization"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)



